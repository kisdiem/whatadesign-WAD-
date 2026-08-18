from __future__ import annotations

import torch
from torch import Tensor

from src.temporal.m5_entity_progress_linker import (
    M5EntityProgressLinker,
    PersistentEntityMemory,
    ProgressEvent,
)


class M5LinkTrainingRunner:
    """Minimal optimizer step for supervised long-horizon candidate pairs."""

    def __init__(self, linker: M5EntityProgressLinker) -> None:
        self.linker = linker

    def train_step(
        self,
        pairs: list[tuple[ProgressEvent, ProgressEvent]],
        labels: Tensor,
        memory: PersistentEntityMemory,
        optimizer: torch.optim.Optimizer,
    ) -> dict[str, object]:
        self.linker.train()
        optimizer.zero_grad(set_to_none=True)
        loss = self.linker.supervised_link_loss(pairs, labels, memory)
        loss.backward()
        optimizer.step()
        return {
            "loss": float(loss.detach().cpu().item()),
            "feature_weights": {
                name: float(value)
                for name, value in zip(
                    ("entity", "semantic", "progress", "transition", "time", "graph"),
                    self.linker.scorer.feature_weights().detach().cpu().tolist(),
                )
            },
        }
