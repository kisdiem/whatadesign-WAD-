from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import torch
from torch import nn

from src.common.schema import EventFrame
from src.semantic.security_log_text import security_log_text


class SecurityAdapter(nn.Module):
    def __init__(self, hidden_size: int = 768, bottleneck_dim: int = 96, dropout: float = 0.1) -> None:
        super().__init__()
        self.down = nn.Linear(hidden_size, bottleneck_dim)
        self.up = nn.Linear(bottleneck_dim, hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.norm = nn.LayerNorm(hidden_size)

    def forward(self, hidden: torch.Tensor) -> torch.Tensor:
        return self.norm(hidden + self.up(self.dropout(torch.nn.functional.gelu(self.down(hidden)))))


class DebertaSecurityEncoder(nn.Module):
    """Frozen DeBERTa plus a security adapter; classifier is training-only."""
    def __init__(self, backbone: nn.Module, hidden_size: int = 768, bottleneck_dim: int = 96) -> None:
        super().__init__()
        self.backbone = backbone
        self.adapter = SecurityAdapter(hidden_size, bottleneck_dim)
        self.classifier = nn.Linear(hidden_size, 1)

    def freeze_backbone(self) -> None:
        for parameter in self.backbone.parameters(): parameter.requires_grad = False

    def encode(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        output = self.backbone(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        pooled = (output * attention_mask.unsqueeze(-1)).sum(1) / attention_mask.sum(1, keepdim=True).clamp_min(1)
        return self.adapter(pooled.to(self.adapter.down.weight.dtype))

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.encode(input_ids, attention_mask)).squeeze(-1)

    def export_embedding_state(self) -> dict:
        return {"backbone": self.backbone.state_dict(), "adapter": self.adapter.state_dict(), "hidden_size": self.adapter.norm.normalized_shape[0], "classifier_included": False}


class FrozenDebertaSecurityEmbedder:
    """Inference-only M1 encoder backed by the completed MLM + Adapter run."""

    def __init__(self, model, tokenizer, encoder: DebertaSecurityEncoder, *, device: str | torch.device = "cpu") -> None:
        self.model, self.tokenizer, self.encoder = model, tokenizer, encoder
        self.device = torch.device(device)
        self.encoder.to(self.device).eval()
        self.encoder.freeze_backbone()
        for parameter in self.encoder.parameters():
            parameter.requires_grad = False

    @classmethod
    def load(cls, mlm_dir: str | Path, adapter_checkpoint: str | Path, *, device: str | torch.device = "cpu") -> "FrozenDebertaSecurityEmbedder":
        from transformers import AutoModel, AutoTokenizer
        mlm_dir = Path(mlm_dir)
        tokenizer = AutoTokenizer.from_pretrained(mlm_dir, local_files_only=True)
        backbone = AutoModel.from_pretrained(mlm_dir, local_files_only=True)
        state = torch.load(adapter_checkpoint, map_location="cpu", weights_only=True)
        encoder = DebertaSecurityEncoder(backbone, hidden_size=int(state["hidden_size"]))
        encoder.backbone.load_state_dict(state["backbone"])
        encoder.adapter.load_state_dict(state["adapter"])
        return cls(backbone, tokenizer, encoder, device=device)

    @staticmethod
    def _payload(frame: EventFrame) -> dict[str, object]:
        """Allow-list normalized facts; labels and split metadata have no path here."""
        def clean(value: object) -> object:
            forbidden = {"label", "class", "attack", "malicious", "ground_truth", "target_label", "attack_label", "anomaly_label", "split", "is_attack"}
            if isinstance(value, dict):
                return {str(key): clean(item) for key, item in value.items() if str(key).lower() not in forbidden}
            if isinstance(value, list):
                return [clean(item) for item in value]
            return value
        return {
            "record_kind": frame.record_kind,
            "relation_type": frame.relation_type,
            "action_family": frame.action_family,
            "action_leaf": frame.action_leaf,
            "roles": clean(frame.roles),
            "outcome": frame.outcome,
            "entity_mentions": clean(frame.entity_mentions),
            "key_attributes": clean(frame.key_attributes),
        }

    @torch.inference_mode()
    def encode_frames(self, frames: list[EventFrame], batch_size: int = 32) -> list[EventFrame]:
        result: list[EventFrame] = []
        for offset in range(0, len(frames), batch_size):
            rows = frames[offset:offset + batch_size]
            texts = [security_log_text(frame.dataset_id, self._payload(frame)) for frame in rows]
            tokens = self.tokenizer(texts, return_tensors="pt", padding=True, truncation=True, max_length=192).to(self.device)
            embeddings = self.encoder.encode(tokens.input_ids, tokens.attention_mask).float().cpu()
            result.extend(replace(frame, semantic_embedding=embedding.tolist(), semantic_version="deberta_security_adapter_v1") for frame, embedding in zip(rows, embeddings))
        return result
