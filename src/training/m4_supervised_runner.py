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

    def train_triplet(
        self,
        anchor_batch: dict[str, Tensor],
        positive_batch: dict[str, Tensor],
        negative_batch: dict[str, Tensor],
        *,
        anchor_label: int,
        positive_label: int,
        negative_label: int,
        contrastive_weight: float,
        temperature: float,
    ) -> dict[str, float]:
        """Joint BCE plus source-fact InfoNCE over M4 event embeddings.

        Pair membership is constructed outside this class from M3/M2 facts.
        The three labels are used only for their independent BCE terms.
        """
        if contrastive_weight < 0 or temperature <= 0:
            raise ValueError("contrastive_weight must be >= 0 and temperature > 0")
        self.model.train(); self.optimizer.zero_grad(set_to_none=True)
        anchor = self._forward(anchor_batch)
        positive = self._forward(positive_batch)
        negative = self._forward(negative_batch)
        outputs = (anchor, positive, negative)
        labels = torch.tensor([anchor_label, positive_label, negative_label], dtype=torch.float32, device=self.device)
        logits = torch.cat([item["score_logit"].reshape(-1) for item in outputs])
        bce = self.loss(logits, labels)
        embeddings = [torch.nn.functional.normalize(item["event_embedding"], dim=-1) for item in outputs]
        positive_similarity = (embeddings[0] * embeddings[1]).sum(dim=-1) / temperature
        negative_similarity = (embeddings[0] * embeddings[2]).sum(dim=-1) / temperature
        contrastive = -torch.nn.functional.logsigmoid(positive_similarity - negative_similarity).mean()
        total = bce + contrastive_weight * contrastive
        total.backward(); self.optimizer.step()
        return {"loss": float(total.detach().cpu()), "bce_loss": float(bce.detach().cpu()),
                "contrastive_loss": float(contrastive.detach().cpu())}

    @torch.no_grad()
    def evaluate_one(self, batch: dict[str, Tensor], *, loss_label: int) -> tuple[float, float]:
        self.model.eval(); output = self._forward(batch)
        label = torch.tensor([loss_label], dtype=torch.float32, device=self.device)
        loss = self.loss(output["score_logit"].reshape(-1), label)
        return float(loss.cpu()), float(torch.sigmoid(output["score_logit"])[0].cpu())
