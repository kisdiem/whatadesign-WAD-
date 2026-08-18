from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn
import torch.nn.functional as F


LINK_FEATURE_NAMES = (
    "entity",
    "semantic",
    "progress",
    "transition",
    "time",
    "graph",
    "source_relevance",
    "target_relevance",
)


@dataclass(frozen=True)
class M5LearnedLinkScorerConfig:
    hidden_dim: int = 32
    residual_scale: float = 0.20
    initial_feature_weights: tuple[float, ...] = (0.30, 0.24, 0.18, 0.10, 0.10, 0.08)

    def __post_init__(self) -> None:
        if self.hidden_dim <= 0:
            raise ValueError("hidden_dim must be positive")
        if not 0.0 <= self.residual_scale <= 1.0:
            raise ValueError("residual_scale must be in [0, 1]")
        if len(self.initial_feature_weights) != 6:
            raise ValueError("initial_feature_weights must cover the six structural features")
        if any(weight <= 0 for weight in self.initial_feature_weights):
            raise ValueError("initial feature weights must be positive")


class M5LearnedLinkScorer(nn.Module):
    """Trainable link scorer initialized from the previous interpretable rule.

    The six structural feature weights are trainable through a softmax. A small
    nonlinear residual MLP starts at zero, so before training the scorer behaves
    like the previous weighted rule, while supervision can learn nonlinear
    interactions and re-weight every feature.
    """

    def __init__(self, config: M5LearnedLinkScorerConfig | None = None) -> None:
        super().__init__()
        self.config = config or M5LearnedLinkScorerConfig()
        initial = torch.tensor(self.config.initial_feature_weights, dtype=torch.float32)
        initial = initial / initial.sum()
        self.feature_logits = nn.Parameter(initial.log())
        self.residual = nn.Sequential(
            nn.Linear(len(LINK_FEATURE_NAMES), self.config.hidden_dim),
            nn.GELU(),
            nn.Linear(self.config.hidden_dim, 1),
        )
        nn.init.zeros_(self.residual[-1].weight)
        nn.init.zeros_(self.residual[-1].bias)

    def feature_weights(self) -> Tensor:
        return torch.softmax(self.feature_logits, dim=0)

    def forward(self, features: Tensor) -> Tensor:
        squeeze = False
        if features.ndim == 1:
            features = features.unsqueeze(0)
            squeeze = True
        if features.ndim != 2 or features.shape[-1] != len(LINK_FEATURE_NAMES):
            raise ValueError(
                f"features must have shape [batch, {len(LINK_FEATURE_NAMES)}]"
            )
        structural = features[:, :6]
        base = (structural * self.feature_weights()).sum(dim=-1)
        residual = self.config.residual_scale * torch.tanh(self.residual(features).squeeze(-1))
        relevance_gate = torch.sqrt(
            features[:, 6].clamp(0.0, 1.0) * features[:, 7].clamp(0.0, 1.0)
        )
        score = (base + residual).clamp(0.0, 1.0) * relevance_gate
        return score[0] if squeeze else score

    def loss(self, features: Tensor, targets: Tensor) -> Tensor:
        scores = self.forward(features)
        targets = targets.to(device=scores.device, dtype=scores.dtype)
        if targets.shape != scores.shape:
            raise ValueError("targets shape must match scorer output")
        return F.binary_cross_entropy(scores.clamp(1e-6, 1.0 - 1e-6), targets)
