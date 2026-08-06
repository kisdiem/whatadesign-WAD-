from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M1ModelConfig:
    hidden_dim: int = 256
    record_kind_count: int = 32
    relation_count: int = 64
    action_count: int = 128
    role_count: int = 32
    outcome_count: int = 16
    entity_family_count: int = 32
    bio_count: int = 3
    prototype_count: int = 256
    backbone_name: str = "microsoft/deberta-v3-base"
    version: str = "m1_deberta_multitask_v1"


class M1DebertaMultiTask(nn.Module):
    """Multi-task semantic head over DeBERTa-compatible hidden states."""

    def __init__(self, config: M1ModelConfig | None = None) -> None:
        super().__init__()
        self.config = config or M1ModelConfig()
        c = self.config
        h = c.hidden_dim
        self.record_kind = nn.Linear(h, c.record_kind_count)
        self.relation = nn.Linear(h, c.relation_count)
        self.action = nn.Linear(h, c.action_count)
        self.role = nn.Linear(h, c.role_count)
        self.outcome = nn.Linear(h, c.outcome_count)
        self.entity_family = nn.Linear(h, c.entity_family_count)
        self.bio = nn.Linear(h, c.bio_count)
        self.prototype = nn.Linear(h, c.prototype_count)
        self.ood = nn.Sequential(nn.LayerNorm(h), nn.Linear(h, 1))

    def forward(self, hidden_states: Tensor, attention_mask: Tensor | None = None) -> dict[str, Tensor]:
        if hidden_states.ndim != 3 or hidden_states.shape[-1] != self.config.hidden_dim:
            raise ValueError("hidden_states must have shape [batch, tokens, hidden_dim]")
        if attention_mask is None:
            attention_mask = torch.ones(hidden_states.shape[:2], device=hidden_states.device, dtype=torch.bool)
        pooled = (hidden_states * attention_mask.unsqueeze(-1)).sum(dim=1) / attention_mask.sum(dim=1, keepdim=True).clamp_min(1)
        return {
            "record_kind_logits": self.record_kind(pooled), "relation_logits": self.relation(pooled),
            "action_logits": self.action(pooled), "role_logits": self.role(pooled),
            "outcome_logits": self.outcome(pooled), "entity_family_logits": self.entity_family(hidden_states),
            "bio_logits": self.bio(hidden_states), "prototype_logits": self.prototype(pooled),
            "ood_logit": self.ood(pooled).squeeze(-1), "embedding": pooled,
        }

    def loss(self, output: dict[str, Tensor], targets: dict[str, Tensor], ignore_index: int = -100) -> dict[str, Tensor]:
        losses: dict[str, Tensor] = {}
        for name in ("record_kind", "relation", "action", "role", "outcome", "prototype"):
            target = targets.get(name)
            if target is not None:
                losses[name] = nn.functional.cross_entropy(output[f"{name}_logits"], target.long(), ignore_index=ignore_index)
        for name in ("entity_family", "bio"):
            target = targets.get(name)
            if target is not None:
                losses[name] = nn.functional.cross_entropy(output[f"{name}_logits"].transpose(1, 2), target.long(), ignore_index=ignore_index)
        if targets.get("ood") is not None:
            losses["ood"] = nn.functional.binary_cross_entropy_with_logits(output["ood_logit"], targets["ood"].float())
        losses["total"] = sum(losses.values()) if losses else output["ood_logit"].new_zeros(())
        return losses

    @staticmethod
    def inverse_action_margin(action_logits: Tensor, inverse_pairs: list[tuple[int, int]]) -> Tensor:
        margins = [torch.relu(1.0 - action_logits[:, left] + action_logits[:, right]).mean() for left, right in inverse_pairs]
        return sum(margins) / len(margins) if margins else action_logits.new_zeros(())
