from __future__ import annotations
import torch

class M1Runner:
    def __init__(self, encoder, heads, optimizer=None):
        self.encoder, self.heads = encoder, heads
        self.optimizer = optimizer or torch.optim.AdamW(list(encoder.parameters()) + list(heads.parameters()), lr=1e-4)

    def train_batch(self, input_ids, targets, attention_mask=None):
        self.optimizer.zero_grad(set_to_none=True)
        hidden = self.encoder.encode(input_ids, attention_mask)
        output = self.heads(hidden, attention_mask)
        losses = self.heads.loss(output, targets)
        losses["total"].backward(); self.optimizer.step()
        return {name: float(value.detach()) for name, value in losses.items()}
