from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
import torch
from torch import Tensor


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

    def export_backbone_manifest(self) -> dict[str, Any]:
        return asdict(QwenManifest(self.name, self.mode, self.model_loaded, self.hidden_size, self.local_files_only))
