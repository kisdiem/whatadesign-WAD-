"""Frozen-M1 ATT&CK semantic adapter.

The module consumes M1 event embeddings and independently encoded technique
cards.  Ground-truth labels are accepted only by ``loss`` and never by
``forward``.
"""
from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class AttackTechniqueAdapterConfig:
    event_dim: int = 768
    card_dim: int = 768
    hidden_dim: int = 256
    temperature: float = 0.07
    version: str = "attack-technique-adapter-v1"


class AttackTechniqueAdapter(nn.Module):
    """Pair scorer with a trainable event-side adapter over frozen M1 vectors."""

    def __init__(self, config: AttackTechniqueAdapterConfig | None = None) -> None:
        super().__init__()
        self.config = config or AttackTechniqueAdapterConfig()
        c = self.config
        self.event_adapter = nn.Sequential(nn.LayerNorm(c.event_dim), nn.Linear(c.event_dim, c.hidden_dim), nn.GELU(), nn.Linear(c.hidden_dim, c.hidden_dim))
        self.card_projection = nn.Sequential(nn.LayerNorm(c.card_dim), nn.Linear(c.card_dim, c.hidden_dim))
        self.bias = nn.Parameter(torch.zeros(()))

    def forward(self, event_embeddings: Tensor, card_embeddings: Tensor) -> dict[str, Tensor]:
        if event_embeddings.ndim != 2 or event_embeddings.shape[-1] != self.config.event_dim:
            raise ValueError("event_embeddings must have shape [batch, event_dim]")
        if card_embeddings.ndim != 2 or card_embeddings.shape[-1] != self.config.card_dim:
            raise ValueError("card_embeddings must have shape [techniques, card_dim]")
        events = nn.functional.normalize(self.event_adapter(event_embeddings), dim=-1)
        cards = nn.functional.normalize(self.card_projection(card_embeddings), dim=-1)
        logits = events @ cards.transpose(0, 1) / self.config.temperature + self.bias
        return {"logits": logits, "event_features": events, "card_features": cards}

    @staticmethod
    def loss(output: dict[str, Tensor], targets: Tensor, weights: Tensor | None = None) -> Tensor:
        """Multi-label BCE; targets originate only from separate supervision records."""
        logits = output["logits"]
        if targets.shape != logits.shape:
            raise ValueError("targets must have same shape as logits")
        loss = nn.functional.binary_cross_entropy_with_logits(logits, targets.float(), reduction="none")
        if weights is not None:
            if weights.shape != logits.shape:
                raise ValueError("weights must have same shape as logits")
            loss = loss * weights
        return loss.mean()
