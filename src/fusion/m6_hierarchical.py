from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M6Config:
    embedding_dim: int = 128
    hidden_dim: int = 128
    version: str = "m6_hierarchical_fusion_v1"


class M6HierarchicalFusion(nn.Module):
    """Event, micro-window and macro/campaign heads with explicit fusion."""

    def __init__(self, config: M6Config | None = None) -> None:
        super().__init__()
        self.config = config or M6Config()
        c = self.config
        self.event_head = nn.Sequential(nn.LayerNorm(c.embedding_dim), nn.Linear(c.embedding_dim, c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, 1))
        self.micro_head = nn.Sequential(nn.Linear(c.embedding_dim + 1, c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, 1))
        self.macro_head = nn.Sequential(nn.Linear(c.embedding_dim + 2, c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, 1))
        self.fusion = nn.Sequential(nn.Linear(3, c.hidden_dim), nn.LayerNorm(c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, 1))

    def forward(self, embedding: Tensor, graph_score: Tensor, long_horizon_score: Tensor) -> dict[str, Tensor]:
        if embedding.ndim != 2 or embedding.shape[-1] != self.config.embedding_dim:
            raise ValueError("embedding must have shape [batch, embedding_dim]")
        batch = embedding.shape[0]
        if graph_score.shape != (batch,) or long_horizon_score.shape != (batch,):
            raise ValueError("graph_score and long_horizon_score must have shape [batch]")
        event = self.event_head(embedding).squeeze(-1)
        micro_input = torch.cat([embedding, graph_score[:, None]], dim=-1)
        micro = self.micro_head(micro_input).squeeze(-1)
        macro_input = torch.cat([embedding, graph_score[:, None], long_horizon_score[:, None]], dim=-1)
        macro = self.macro_head(macro_input).squeeze(-1)
        fused = self.fusion(torch.stack([event, micro, macro], dim=-1)).squeeze(-1)
        return {"event_logit": event, "micro_logit": micro, "macro_logit": macro, "fused_logit": fused}
