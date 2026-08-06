from __future__ import annotations
import torch

class M4Runner:
    def __init__(self, model, optimizer=None):
        self.model = model
        self.optimizer = optimizer or torch.optim.AdamW(model.parameters(), lr=1e-4)

    def train_batch(self, batch, target_slot_ids=None):
        if not getattr(batch, "strict_mode", True): raise ValueError("strict M4 runner requires strict_mode=True")
        self.optimizer.zero_grad(set_to_none=True)
        output = self.model(history_events=batch.history_events, current_event=batch.current_event, graph_before_current_event=batch.graph_before_current_event, padding_mask=batch.history_padding_mask)
        loss = output["slot_nll"] if target_slot_ids is not None else output["score_logit"].mean() * 0
        if target_slot_ids is not None: loss.backward(); self.optimizer.step()
        return {"loss": float(loss.detach()), "model_loaded": bool(output.get("model_loaded", False))}
