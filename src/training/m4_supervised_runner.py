from __future__ import annotations

"""Source-only supervised optimization for the frozen-backbone M4 model."""

import torch
from torch import Tensor


class M4SupervisedRunner:
    """Updates M4 only; targets are supplied separately at loss time."""

    def __init__(self, model: torch.nn.Module, *, device: str = "cuda", learning_rate: float = 1e-4) -> None:
        self.device = torch.device(device)
        self.model = model.to(self.device)
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=learning_rate)
        self.loss = torch.nn.BCEWithLogitsLoss()

    def _forward(self, batch: dict[str, Tensor]) -> dict[str, Tensor]:
        moved = {key: value.to(self.device) for key, value in batch.items()}
        return self.model.forward_micro_windows(
            moved["micro_event_embeddings"], moved["qwen_window_embeddings"], moved["current_event_embedding"],
            event_valid_mask=moved["micro_event_valid_mask"], micro_window_mask=moved["micro_window_mask"],
        )

    def train_one(self, batch: dict[str, Tensor], *, loss_label: int) -> float:
        self.model.train(); self.optimizer.zero_grad(set_to_none=True)
        output = self._forward(batch)
        label = torch.tensor([loss_label], dtype=torch.float32, device=self.device)
        loss = self.loss(output["score_logit"].reshape(-1), label)
        loss.backward(); self.optimizer.step()
        return float(loss.detach().cpu())

    @torch.no_grad()
    def evaluate_one(self, batch: dict[str, Tensor], *, loss_label: int) -> tuple[float, float]:
        self.model.eval(); output = self._forward(batch)
        label = torch.tensor([loss_label], dtype=torch.float32, device=self.device)
        loss = self.loss(output["score_logit"].reshape(-1), label)
        return float(loss.cpu()), float(torch.sigmoid(output["score_logit"])[0].cpu())
