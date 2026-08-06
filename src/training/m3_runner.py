from __future__ import annotations
import torch

class M3Runner:
    def __init__(self, model, optimizer=None):
        self.model = model
        self.optimizer = optimizer or torch.optim.AdamW(model.parameters(), lr=1e-4)

    def train_batch(self, graph_batch, targets):
        self.optimizer.zero_grad(set_to_none=True)
        output = self.model(graph_batch)
        loss = output["loss"] if isinstance(output, dict) and "loss" in output else torch.nn.functional.mse_loss(output, targets)
        loss.backward(); self.optimizer.step()
        return float(loss.detach())
