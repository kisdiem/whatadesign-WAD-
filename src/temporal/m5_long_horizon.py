from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M5Config:
    embedding_dim: int = 128
    hidden_dim: int = 128
    decay_hours: tuple[float, ...] = (1.0, 6.0, 24.0)
    version: str = "m5_long_horizon_link_v1"


class M5LongHorizonLinker(nn.Module):
    """Learned cross-window link scorer with explicit time-decay features."""

    def __init__(self, config: M5Config | None = None) -> None:
        super().__init__()
        self.config = config or M5Config()
        c = self.config
        self.link_head = nn.Sequential(
            nn.Linear(c.embedding_dim * 4 + len(c.decay_hours), c.hidden_dim),
            nn.LayerNorm(c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, 1),
        )

    def forward(self, source: Tensor, target: Tensor, delta_seconds: Tensor) -> Tensor:
        if source.shape != target.shape or source.ndim != 2 or source.shape[-1] != self.config.embedding_dim:
            raise ValueError("source and target must have shape [batch, embedding_dim]")
        if delta_seconds.ndim != 1 or delta_seconds.shape[0] != source.shape[0]:
            raise ValueError("delta_seconds must have shape [batch]")
        delta_hours = delta_seconds.to(source.dtype).clamp_min(0) / 3600.0
        decay = torch.stack([torch.exp(-delta_hours / h) for h in self.config.decay_hours], dim=-1)
        features = torch.cat([source, target, source * target, (source - target).abs(), decay], dim=-1)
        return self.link_head(features).squeeze(-1)

    def probability(self, source: Tensor, target: Tensor, delta_seconds: Tensor) -> Tensor:
        return torch.sigmoid(self.forward(source, target, delta_seconds))
