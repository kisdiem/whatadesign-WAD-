from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class BackboneManifest:
    name: str
    mode: str
    model_loaded: bool
    inference_mode: str
    hidden_size: int


class BackboneAdapter:
    """M1 backbone boundary. Mock is explicit; no silent random fallback."""
    def __init__(self, name: str = "microsoft/deberta-v3-base", mode: str = "mock", hidden_size: int = 768, local_files_only: bool = True):
        if mode not in {"mock", "pretrained", "frozen", "finetune"}:
            raise ValueError(f"unsupported backbone mode: {mode}")
        self.name, self.mode, self.hidden_size, self.local_files_only = name, mode, hidden_size, local_files_only
        self.model_loaded = False
        self.model = None
        if mode != "mock":
            try:
                from transformers import AutoModel
                self.model = AutoModel.from_pretrained(name, local_files_only=local_files_only)
                self.hidden_size = int(self.model.config.hidden_size)
                self.model_loaded = True
                if mode == "frozen":
                    for p in self.model.parameters(): p.requires_grad = False
            except Exception as exc:
                raise RuntimeError(f"failed to load backbone {name!r} in mode {mode!r}; use mode='mock' explicitly: {exc}") from exc

    def encode(self, input_ids: Tensor, attention_mask: Tensor | None = None) -> Tensor:
        if not self.model_loaded:
            return torch.zeros((*input_ids.shape, self.hidden_size), dtype=torch.float32, device=input_ids.device)
        return self.model(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state

    def export_backbone_manifest(self) -> dict[str, Any]:
        return BackboneManifest(self.name, self.mode, self.model_loaded, "mock" if not self.model_loaded else self.mode, self.hidden_size).__dict__


class M1Encoder(nn.Module):
    def __init__(self, backbone: BackboneAdapter | None = None, projection_dim: int = 256):
        super().__init__()
        self.backbone = backbone or BackboneAdapter()
        self.projection = nn.Linear(self.backbone.hidden_size, projection_dim)

    def encode(self, input_ids: Tensor, attention_mask: Tensor | None = None) -> Tensor:
        return self.projection(self.backbone.encode(input_ids, attention_mask))

    def build_event_frame(self, predictions: dict[str, Any], *, dataset_id: str, record_id: str, timestamp: str | None, source_record_ref: str):
        from src.common.schema import EventFrame
        return EventFrame(dataset_id=dataset_id, record_id=record_id, timestamp=timestamp,
                          record_kind=predictions.get("record_kind", "unknown"),
                          relation_type=predictions.get("relation_type", "unknown"),
                          action_family=predictions.get("action_family", "unknown"),
                          action_leaf=predictions.get("action_leaf", "unknown"),
                          roles=predictions.get("roles", {}), outcome=predictions.get("outcome", "unknown"),
                          key_attributes=predictions.get("key_attributes", {}),
                          entity_mentions=predictions.get("entity_mentions", []),
                          semantic_confidence=float(predictions.get("semantic_confidence", 0.0)),
                          unknown_score=float(predictions.get("unknown_score", 1.0)),
                          source_record_ref=source_record_ref, semantic_version="m1-encoder-1")
