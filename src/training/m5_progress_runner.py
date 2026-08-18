from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor

from src.temporal.m5_knowledge_progress import (
    AttackKnowledgeIndex,
    M5KnowledgeProgressTransformer,
    M5LossConfig,
    m5_multitask_loss,
)


@dataclass(frozen=True)
class M5TrainBatch:
    token_ids: Tensor
    attention_mask: Tensor
    attack_targets: Tensor
    position_targets: Tensor
    progress_targets: Tensor
    progress_mask: Tensor | None = None
    ranking_pairs: Tensor | None = None
    allowed_knowledge_mask: Tensor | None = None


class M5ProgressRunner:
    """Minimal M5 train/inference runner.

    Tokenization, production knowledge-database I/O, and ANN prefiltering remain
    outside this class. The runner operates on the bounded candidate knowledge
    set passed to the model.
    """

    def __init__(self, model: M5KnowledgeProgressTransformer, loss_config: M5LossConfig | None = None) -> None:
        self.model = model
        self.loss_config = loss_config or M5LossConfig()

    def train_step(
        self,
        batch: M5TrainBatch,
        knowledge: AttackKnowledgeIndex,
        optimizer: torch.optim.Optimizer,
    ) -> dict[str, float]:
        self.model.train()
        optimizer.zero_grad(set_to_none=True)
        output = self.model(
            batch.token_ids,
            batch.attention_mask,
            knowledge,
            allowed_knowledge_mask=batch.allowed_knowledge_mask,
        )
        losses = m5_multitask_loss(
            output,
            attack_targets=batch.attack_targets,
            position_targets=batch.position_targets,
            progress_targets=batch.progress_targets,
            progress_mask=batch.progress_mask,
            ranking_pairs=batch.ranking_pairs,
            config=self.loss_config,
        )
        losses["loss"].backward()
        optimizer.step()
        return {name: float(value.detach().cpu()) for name, value in losses.items()}

    @torch.no_grad()
    def infer(
        self,
        token_ids: Tensor,
        attention_mask: Tensor,
        knowledge: AttackKnowledgeIndex,
        *,
        allowed_knowledge_mask: Tensor | None = None,
    ) -> dict[str, Tensor]:
        self.model.eval()
        return self.model(
            token_ids,
            attention_mask,
            knowledge,
            allowed_knowledge_mask=allowed_knowledge_mask,
        )
