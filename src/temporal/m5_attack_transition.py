from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class AttackTransitionConfig:
    """Learnable ATT&CK-stage transition compatibility prior."""

    num_positions: int = 10
    same_stage: float = 0.95
    forward_adjacent: float = 0.98
    forward_skip: float = 0.82
    one_step_back: float = 0.62
    large_backtrack: float = 0.25
    learnable: bool = True

    def __post_init__(self) -> None:
        if self.num_positions <= 0:
            raise ValueError("num_positions must be positive")
        for name in (
            "same_stage",
            "forward_adjacent",
            "forward_skip",
            "one_step_back",
            "large_backtrack",
        ):
            value = float(getattr(self, name))
            if not 0.0 < value < 1.0:
                raise ValueError(f"{name} must be in (0, 1)")


class AttackTransitionCompatibility(nn.Module):
    """Score source/target ATT&CK position distributions with a learnable matrix.

    The prior favors staying in the same tactic, moving forward, or making a
    short backward revisit. Large backward jumps are allowed but penalized.
    The matrix remains trainable so source-domain supervision can calibrate the
    generic prior instead of hard-coding a strict linear attack sequence.
    """

    def __init__(self, config: AttackTransitionConfig | None = None) -> None:
        super().__init__()
        self.config = config or AttackTransitionConfig()
        prior = self._build_prior(self.config)
        logits = torch.logit(prior.clamp(1e-4, 1.0 - 1e-4))
        if self.config.learnable:
            self.transition_logits = nn.Parameter(logits)
        else:
            self.register_buffer("transition_logits", logits)

    @staticmethod
    def _build_prior(config: AttackTransitionConfig) -> Tensor:
        matrix = torch.empty(config.num_positions, config.num_positions)
        for source in range(config.num_positions):
            for target in range(config.num_positions):
                delta = target - source
                if delta == 0:
                    value = config.same_stage
                elif delta == 1:
                    value = config.forward_adjacent
                elif delta > 1:
                    value = config.forward_skip
                elif delta == -1:
                    value = config.one_step_back
                else:
                    value = config.large_backtrack
                matrix[source, target] = value
        return matrix

    def matrix(self) -> Tensor:
        return torch.sigmoid(self.transition_logits)

    def forward(self, source_probabilities: Tensor, target_probabilities: Tensor) -> Tensor:
        source = source_probabilities
        target = target_probabilities
        squeeze = False
        if source.ndim == 1 and target.ndim == 1:
            source = source.unsqueeze(0)
            target = target.unsqueeze(0)
            squeeze = True
        if source.ndim != 2 or target.ndim != 2 or source.shape != target.shape:
            raise ValueError("source and target position probabilities must share shape [batch, num_positions]")
        if source.shape[-1] != self.config.num_positions:
            raise ValueError(
                f"position probability width must equal configured num_positions={self.config.num_positions}"
            )
        source = source.to(dtype=self.transition_logits.dtype, device=self.transition_logits.device).clamp_min(0)
        target = target.to(dtype=self.transition_logits.dtype, device=self.transition_logits.device).clamp_min(0)
        source = source / source.sum(dim=-1, keepdim=True).clamp_min(1e-8)
        target = target / target.sum(dim=-1, keepdim=True).clamp_min(1e-8)
        compatibility = torch.einsum("bi,ij,bj->b", source, self.matrix(), target)
        return compatibility[0] if squeeze else compatibility
