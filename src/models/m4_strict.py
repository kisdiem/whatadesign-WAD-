from __future__ import annotations

import torch
from torch import Tensor, nn
from src.models.m4_qformer import EventSerializer, M4Config


class M4StrictQFormerDecoder(nn.Module):
    def __init__(self, config: M4Config | None = None):
        super().__init__()
        self.config = config or M4Config(input_dim=32, hidden_dim=32, heads=4, query_count=4, slot_count=4, slot_vocab_size=32)
        c = self.config
        self.serializer = EventSerializer(c.input_dim)
        self.current_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.history_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.graph_projection = nn.Linear(c.input_dim, c.hidden_dim)
        self.queries = nn.Parameter(torch.randn(c.query_count, c.hidden_dim) * 0.02)
        self.stage1 = nn.MultiheadAttention(c.hidden_dim, c.heads, batch_first=True)
        self.stage2 = nn.MultiheadAttention(c.hidden_dim, c.heads, batch_first=True)
        self.slot_head = nn.Linear(c.hidden_dim, c.slot_count * c.slot_vocab_size)
        self.raw_head = nn.Linear(c.hidden_dim, 1)

    def _event_vector(self, event: dict) -> Tensor:
        return self.serializer([event])[0]

    def forward(self, *, history_events: list[dict], current_event: dict, graph_before_current_event: dict, target_slot_ids: Tensor | None = None) -> dict[str, Tensor | str | bool]:
        current_id = current_event.get("record_id")
        if not current_id: raise ValueError("current_event.record_id is required")
        if any(row.get("record_id") == current_id for row in history_events): raise ValueError("current event leaked into history")
        nodes = graph_before_current_event.get("node_records", graph_before_current_event.get("nodes", []))
        edges = graph_before_current_event.get("edge_records", graph_before_current_event.get("edges", []))
        if any(node.get("node_id") in {current_id, "event:" + current_id} for node in nodes): raise ValueError("current event leaked into graph")
        if any(edge.get("source") in {current_id, "event:" + current_id} or edge.get("target") in {current_id, "event:" + current_id} for edge in edges): raise ValueError("current event edge leaked into graph")
        device = self.queries.device
        current = self.current_projection(self._event_vector(current_event).to(device)).unsqueeze(0).unsqueeze(1)
        queries = self.queries.unsqueeze(0)
        stage1, _ = self.stage1(queries, current, current)
        history_vectors = self.serializer(history_events, device=device) if history_events else torch.zeros((0, self.config.input_dim), device=device)
        graph_vectors = self.serializer(nodes, device=device) if nodes else torch.zeros((0, self.config.input_dim), device=device)
        context_source = torch.cat([self.history_projection(history_vectors), self.graph_projection(graph_vectors)], dim=0).unsqueeze(0)
        if context_source.shape[1] == 0: context_source = torch.zeros((1, 1, self.config.hidden_dim), device=device)
        stage2, _ = self.stage2(stage1, context_source, context_source)
        context = stage2.mean(dim=1)
        logits = self.slot_head(context).view(1, self.config.slot_count, self.config.slot_vocab_size)
        raw = self.raw_head(context).squeeze(-1)
        output = {"context_embedding": context, "event_embedding": context, "slot_logits": logits, "raw_event_logit": raw, "stage1_source": "current_event", "stage2_sources": ["history_events", "graph_before_current_event"]}
        if target_slot_ids is not None: output["slot_nll"] = self.slot_nll(output, target_slot_ids)
        return output

    def slot_nll(self, output: dict, target_slot_ids: Tensor, ignore_index: int = -100) -> Tensor:
        logits = output["slot_logits"]
        if target_slot_ids.shape != logits.shape[:2]: raise ValueError("target_slot_ids shape mismatch")
        return nn.functional.cross_entropy(logits.transpose(1, 2), target_slot_ids.long(), ignore_index=ignore_index)
