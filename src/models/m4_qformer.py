from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class M4Config:
    input_dim: int = 128
    hidden_dim: int = 128
    query_count: int = 8
    slot_count: int = 8
    slot_vocab_size: int = 256
    heads: int = 4
    layers: int = 2
    dropout: float = 0.1
    backbone_name: str = "Qwen/Qwen3-0.6B-Base"
    version: str = "m4_current_event_qformer_v2"


class EventSerializer:
    """Serialize EventFrame fields without importing target labels."""

    def __init__(self, input_dim: int) -> None:
        self.input_dim = input_dim

    def __call__(self, fields: list[dict[str, object]], device: torch.device | None = None) -> Tensor:
        values = []
        for field in fields:
            raw = "|".join(f"{key}={field[key]}" for key in sorted(field))
            digest = torch.tensor(list(raw.encode("utf-8")), dtype=torch.float32)
            vector = torch.zeros(self.input_dim, dtype=torch.float32)
            if digest.numel():
                vector[: min(self.input_dim, digest.numel())] = digest[: self.input_dim] / 255.0
            values.append(vector)
        result = torch.stack(values) if values else torch.zeros((0, self.input_dim))
        return result.to(device=device) if device is not None else result


class M4QFormerDecoder(nn.Module):
    """Current-event-conditioned two-stage Q-Former.

    The V3 path supplies history_events and graph_before_current_event with the
    current event excluded, then supplies current_event separately.
    """

    def __init__(self, config: M4Config | None = None) -> None:
        super().__init__()
        self.config = config or M4Config()
        c = self.config
        self.input_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.query_tokens = nn.Parameter(torch.randn(c.query_count, c.hidden_dim) * 0.02)
        self.stage1_attention = nn.MultiheadAttention(c.hidden_dim, c.heads, dropout=c.dropout, batch_first=True)
        self.stage2_attention = nn.MultiheadAttention(c.hidden_dim, c.heads, dropout=c.dropout, batch_first=True)
        self.history_encoder = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(c.hidden_dim, c.heads, c.hidden_dim * 4, c.dropout, batch_first=True, norm_first=True),
            num_layers=c.layers,
        )
        self.current_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.slot_context = nn.Linear(c.hidden_dim * 2, c.hidden_dim)
        self.slot_head = nn.Linear(c.hidden_dim, c.slot_count * c.slot_vocab_size)
        self.raw_event_head = nn.Sequential(nn.LayerNorm(c.hidden_dim), nn.Linear(c.hidden_dim, 1))

    def forward(self, history_events: Tensor, current_event: Tensor | None = None,
                graph_before_current_event: Tensor | None = None,
                padding_mask: Tensor | None = None) -> dict[str, Tensor]:
        if current_event is not None and current_event.ndim == 2 and current_event.shape[-1] != self.config.input_dim:
            # Legacy call: forward(sequence, padding_mask).
            padding_mask = current_event.bool()
            current_event = None
        if current_event is None:
            if history_events.ndim != 3 or history_events.shape[1] < 1:
                raise ValueError("history_events must have shape [batch, time, input_dim]")
            current_event = history_events[:, -1, :]
            history_events = history_events[:, :-1, :]
        if history_events.ndim != 3 or current_event.ndim != 2:
            raise ValueError("history_events=[batch,time,input_dim], current_event=[batch,input_dim]")
        if history_events.shape[0] != current_event.shape[0] or history_events.shape[-1] != self.config.input_dim:
            raise ValueError("history and current event dimensions do not match")
        batch = history_events.shape[0]
        if graph_before_current_event is None:
            graph_before_current_event = history_events.new_zeros((batch, 1, self.config.input_dim))
        if graph_before_current_event.ndim != 3 or graph_before_current_event.shape[0] != batch:
            raise ValueError("graph_before_current_event must have shape [batch, graph_nodes, input_dim]")

        history = self.input_projection(history_events)
        if history.shape[1]:
            history = self.history_encoder(history, src_key_padding_mask=padding_mask)
        graph = self.input_projection(graph_before_current_event)
        queries = self.query_tokens.unsqueeze(0).expand(batch, -1, -1)
        stage1, _ = self.stage1_attention(queries, graph, graph)
        stage2_context = torch.cat([history, stage1], dim=1)
        stage2, _ = self.stage2_attention(stage1, stage2_context, stage2_context)
        context = stage2.mean(dim=1)
        current = self.current_projection(current_event)
        joint = torch.tanh(self.slot_context(torch.cat([context, current], dim=-1)))
        slot_logits = self.slot_head(joint).view(batch, self.config.slot_count, self.config.slot_vocab_size)
        raw_event_logit = self.raw_event_head(joint).squeeze(-1)
        return {"context": context, "embedding": joint, "slot_logits": slot_logits,
                "raw_event_logit": raw_event_logit, "score_logit": raw_event_logit}

    def slot_nll(self, output: dict[str, Tensor], target_slot_ids: Tensor, ignore_index: int = -100) -> Tensor:
        logits = output["slot_logits"]
        if target_slot_ids.shape != logits.shape[:2]:
            raise ValueError("target_slot_ids must have shape [batch, slot_count]")
        return nn.functional.cross_entropy(logits.transpose(1, 2), target_slot_ids.long(), ignore_index=ignore_index)
