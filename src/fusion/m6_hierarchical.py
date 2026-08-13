from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M6Config:
    embedding_dim: int = 128
    hidden_dim: int = 128
    focal_gamma: float = 2.0
    hierarchy_weight: float = 0.2
    ranking_weight: float = 0.2
    version: str = "m6_frozen_hierarchical_v2"


@dataclass(frozen=True)
class FrozenFeatureRecord:
    record_id: str
    dataset_id: str
    event_embedding: Tensor
    graph_score: float
    long_horizon_score: float
    attack_id: str | None = None
    scenario: str | None = None

    def model_features(self) -> tuple[Tensor, Tensor, Tensor]:
        # Dataset and attack metadata remain provenance, never model features.
        return self.event_embedding, torch.tensor(self.graph_score), torch.tensor(self.long_horizon_score)


class M6HierarchicalFusion(nn.Module):
    """Frozen-feature event, micro-window and macro-campaign fusion heads."""

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
        micro = self.micro_head(torch.cat([embedding, graph_score[:, None]], dim=-1)).squeeze(-1)
        macro = self.macro_head(torch.cat([embedding, graph_score[:, None], long_horizon_score[:, None]], dim=-1)).squeeze(-1)
        fused = self.fusion(torch.stack([event, micro, macro], dim=-1)).squeeze(-1)
        return {"event_logit": event, "micro_logit": micro, "macro_logit": macro, "fused_logit": fused}

    @staticmethod
    def focal_bce(logits: Tensor, labels: Tensor, gamma: float = 2.0) -> Tensor:
        labels = labels.float()
        bce = nn.functional.binary_cross_entropy_with_logits(logits, labels, reduction="none")
        probability = torch.sigmoid(logits)
        pt = probability * labels + (1 - probability) * (1 - labels)
        return (((1 - pt).clamp_min(1e-6) ** gamma) * bce).mean()

    @staticmethod
    def pairwise_ranking(logits: Tensor, labels: Tensor, margin: float = 1.0) -> Tensor:
        positive = logits[labels.bool()]
        negative = logits[~labels.bool()]
        if not len(positive) or not len(negative):
            return logits.new_zeros(())
        return nn.functional.softplus(margin - positive[:, None] + negative[None, :]).mean()

    def loss(self, outputs: dict[str, Tensor], labels: Tensor) -> dict[str, Tensor]:
        event = self.focal_bce(outputs["event_logit"], labels, self.config.focal_gamma)
        micro = self.focal_bce(outputs["micro_logit"], labels, self.config.focal_gamma)
        macro = self.focal_bce(outputs["macro_logit"], labels, self.config.focal_gamma)
        fused = self.focal_bce(outputs["fused_logit"], labels, self.config.focal_gamma)
        ranking = self.pairwise_ranking(outputs["fused_logit"], labels)
        consistency = (torch.sigmoid(outputs["event_logit"]) - torch.sigmoid(outputs["micro_logit"])).abs().mean()
        total = event + micro + macro + fused + self.config.ranking_weight * ranking + self.config.hierarchy_weight * consistency
        return {"event": event, "micro": micro, "macro": macro, "fused": fused, "ranking": ranking, "hierarchy": consistency, "total": total}


@dataclass(frozen=True)
class SourceCalibration:
    temperature: float
    threshold: float
    source_name: str


def fit_source_calibration(logits: Tensor, labels: Tensor, source_name: str) -> SourceCalibration:
    if not source_name or source_name.lower().startswith("ait"):
        raise ValueError("calibration must be fitted on a non-AIT source")
    probability = torch.sigmoid(logits)
    negatives = probability[labels == 0]
    threshold = float(torch.quantile(negatives, 0.995).item()) if len(negatives) else 0.5
    return SourceCalibration(1.0, threshold, source_name)
