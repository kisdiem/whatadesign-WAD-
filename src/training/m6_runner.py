from __future__ import annotations
import torch

class M6Runner:
    """M6-only optimizer. It accepts frozen feature tensors, never upstream modules."""
    def __init__(self, model, optimizer=None):
        self.model = model
        self.optimizer = optimizer or torch.optim.AdamW(self.model.parameters(), lr=1e-3)

    def train_step(self, frozen_features, labels):
        self.optimizer.zero_grad(set_to_none=True)
        output = self.model(**frozen_features) if isinstance(frozen_features, dict) else self.model(frozen_features)
        loss = torch.nn.functional.binary_cross_entropy_with_logits(output["fused_logit"], labels.float())
        loss.backward(); self.optimizer.step()
        return float(loss.detach())
