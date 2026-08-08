from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
import torch
from torch import Tensor

from src.common.schema import EventFrame


# These values are evaluation/training supervision or post-hoc metadata.  They
# must never be represented in a Qwen window prompt.
FORBIDDEN_WINDOW_FIELDS = frozenset({
    "target_label", "attack_label", "anomaly_label", "is_attack", "split",
    "ground_truth", "scenario_truth", "post_hoc_score", "result",
})


@dataclass(frozen=True)
class QwenManifest:
    name: str
    mode: str
    model_loaded: bool
    hidden_size: int
    local_files_only: bool


class QwenBackboneAdapter:
    def __init__(self, name: str = "Qwen/Qwen3-0.6B-Base", mode: str = "mock", local_files_only: bool = True):
        if mode not in {"mock", "pretrained", "frozen", "lora"}:
            raise ValueError(f"unsupported Qwen mode: {mode}")
        self.name, self.mode, self.local_files_only = name, mode, local_files_only
        self.tokenizer = self.model = None
        self.model_loaded = False
        self.hidden_size = 1024
        if mode != "mock":
            try:
                from transformers import AutoModel, AutoTokenizer
                self.tokenizer = AutoTokenizer.from_pretrained(name, local_files_only=local_files_only)
                self.model = AutoModel.from_pretrained(name, local_files_only=local_files_only)
                self.hidden_size = int(self.model.config.hidden_size)
                self.model_loaded = True
                if mode == "frozen":
                    for p in self.model.parameters(): p.requires_grad = False
            except Exception as exc:
                raise RuntimeError(f"Qwen backbone unavailable in {mode} mode; use mode='mock' explicitly: {exc}") from exc

    def load_tokenizer(self):
        return self.tokenizer

    def load_model(self):
        return self.model

    def project_query_tokens(self, hidden: Tensor, projection: torch.nn.Module | None = None) -> Tensor:
        return projection(hidden) if projection is not None else hidden

    def decode_event_frame(self, hidden: Tensor) -> dict[str, Tensor]:
        return {"hidden": hidden}

    def validate_hidden_size(self, hidden: Tensor) -> None:
        if hidden.shape[-1] != self.hidden_size:
            raise ValueError(f"hidden size {hidden.shape[-1]} != backbone size {self.hidden_size}")

    @staticmethod
    def _timestamp(value: str | None) -> datetime:
        if not value:
            # EventFrame timestamps are mandatory for a causal window.  The
            # caller must isolate invalid rows instead of silently ordering them.
            raise ValueError("Qwen window EventFrame is missing timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid EventFrame timestamp: {value!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @staticmethod
    def _safe_value(value: Any) -> str:
        if isinstance(value, dict):
            return "{" + ",".join(
                f"{key}:{QwenBackboneAdapter._safe_value(item)}"
                for key, item in sorted(value.items())
                if key not in FORBIDDEN_WINDOW_FIELDS
            ) + "}"
        if isinstance(value, (list, tuple)):
            return "[" + ",".join(QwenBackboneAdapter._safe_value(item) for item in value) + "]"
        return str(value)

    @classmethod
    def serialize_window(cls, frames: Iterable[EventFrame]) -> str:
        """Serialize only approved normalized EventFrame fields in time order.

        This deliberately has no generic ``vars(frame)`` path: future schema
        additions such as labels cannot accidentally enter the backbone input.
        """
        ordered = sorted(frames, key=lambda frame: (cls._timestamp(frame.timestamp), frame.record_id))
        if not ordered:
            return "[EMPTY_WINDOW]"
        anchor = cls._timestamp(ordered[0].timestamp)
        lines: list[str] = []
        for frame in ordered:
            offset = (cls._timestamp(frame.timestamp) - anchor).total_seconds()
            entity_types = [
                mention.get("entity_type", mention.get("type", "unknown"))
                if isinstance(mention, dict) else "unknown"
                for mention in frame.entity_mentions
            ]
            # key_attributes may contain useful normalized categorical fields,
            # but forbidden keys are always excluded recursively by _safe_value.
            lines.extend((
                f"[T={offset:.3f}]",
                f"record_kind={cls._safe_value(frame.record_kind)}",
                f"relation_type={cls._safe_value(frame.relation_type)}",
                f"action_family={cls._safe_value(frame.action_family)}",
                f"action_leaf={cls._safe_value(frame.action_leaf)}",
                f"roles={cls._safe_value(frame.roles)}",
                f"outcome={cls._safe_value(frame.outcome)}",
                f"entity_types={cls._safe_value(entity_types)}",
                f"key_attributes={cls._safe_value(frame.key_attributes)}",
            ))
        return "\n".join(lines)

    def _mock_window_embedding(self, serialized: str) -> Tensor:
        """Deterministic test-only embedding; it is never a pretrained result."""
        values: list[float] = []
        counter = 0
        while len(values) < self.hidden_size:
            digest = hashlib.sha256(f"{counter}|{serialized}".encode("utf-8")).digest()
            values.extend((byte / 127.5) - 1.0 for byte in digest)
            counter += 1
        return torch.tensor(values[:self.hidden_size], dtype=torch.float32)

    def encode_window(self, frames: Iterable[EventFrame], *, device: torch.device | str | None = None) -> dict[str, Any]:
        """Return an attention-mask-aware 5-minute Qwen representation.

        The return value records the mode so a mock embedding cannot be mistaken
        for a real Qwen output in downstream provenance.
        """
        serialized = self.serialize_window(frames)
        if self.mode == "mock":
            return {
                "embedding": self._mock_window_embedding(serialized),
                "serialized": serialized,
                "mode": "mock",
                "is_mock": True,
            }
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("Qwen model/tokenizer not loaded")
        model_device = torch.device(device) if device is not None else next(self.model.parameters()).device
        tokens = self.tokenizer(serialized, return_tensors="pt", truncation=True, padding=True)
        tokens = {name: value.to(model_device) for name, value in tokens.items()}
        context = torch.no_grad() if self.mode == "frozen" else torch.enable_grad()
        with context:
            output = self.model(**tokens)
            hidden = output.last_hidden_state
            mask = tokens["attention_mask"].unsqueeze(-1).to(dtype=hidden.dtype)
            embedding = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp_min(1.0)
        self.validate_hidden_size(embedding)
        return {
            "embedding": embedding.squeeze(0),
            "serialized": serialized,
            "mode": self.mode,
            "is_mock": False,
        }

    def encode_windows(self, windows: Iterable[Iterable[EventFrame]], *, device: torch.device | str | None = None) -> dict[str, Any]:
        """Batch window encoding for offline M4 dataset preparation.

        The input remains structured, normalized EventFrames. It is not a raw
        log batch and has the same label-free serialization boundary as
        :meth:`encode_window`.
        """
        serialized = [self.serialize_window(frames) for frames in windows]
        if not serialized:
            return {"embeddings": torch.zeros((0, self.hidden_size)), "serialized": [], "mode": self.mode, "is_mock": self.mode == "mock"}
        if self.mode == "mock":
            return {"embeddings": torch.stack([self._mock_window_embedding(item) for item in serialized]), "serialized": serialized, "mode": "mock", "is_mock": True}
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("Qwen model/tokenizer not loaded")
        model_device = torch.device(device) if device is not None else next(self.model.parameters()).device
        tokens = self.tokenizer(serialized, return_tensors="pt", truncation=True, padding=True)
        tokens = {name: value.to(model_device) for name, value in tokens.items()}
        context = torch.no_grad() if self.mode == "frozen" else torch.enable_grad()
        with context:
            output = self.model(**tokens)
            hidden = output.last_hidden_state
            mask = tokens["attention_mask"].unsqueeze(-1).to(dtype=hidden.dtype)
            embeddings = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp_min(1.0)
        self.validate_hidden_size(embeddings)
        return {"embeddings": embeddings, "serialized": serialized, "mode": self.mode, "is_mock": False}

    def export_backbone_manifest(self) -> dict[str, Any]:
        return asdict(QwenManifest(self.name, self.mode, self.model_loaded, self.hidden_size, self.local_files_only))
