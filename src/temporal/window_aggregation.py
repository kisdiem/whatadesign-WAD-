from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import torch
from src.common.schema import EventFrame
from src.graph.strict_graph import StrictGraph
from src.temporal.m5_long_horizon import M5LongHorizonLinker, WindowRecord, WindowLink, AttackQueue


@dataclass(frozen=True)
class AggregatedWindow:
    window_id: str
    dataset_id: str
    start: str
    end: str
    event_ids: tuple[str, ...]
    entities: dict[str, tuple[str, ...]]
    actions: tuple[str, ...]
    event_count: int
    embedding: tuple[float, ...]
    graph_summary: dict
    suspicious_score: float


class WindowAggregator:
    def __init__(self, m5: M5LongHorizonLinker, embedding_dim: int = 32): self.m5, self.embedding_dim = m5, embedding_dim

    @staticmethod
    def _time(frame):
        parsed = datetime.fromisoformat(frame.timestamp.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def aggregate(self, frames: list[EventFrame], m4_outputs: dict[str, dict], graph: StrictGraph, minutes: int) -> list[AggregatedWindow]:
        groups = defaultdict(list)
        for frame in frames:
            stamp = self._time(frame); start = stamp.replace(minute=(stamp.minute // minutes) * minutes, second=0, microsecond=0)
            groups[(frame.dataset_id, start)].append(frame)
        windows = []
        for (dataset_id, start), rows in sorted(groups.items(), key=lambda item: item[0][1]):
            event_ids = tuple(row.record_id for row in rows)
            entity_map = defaultdict(set)
            for row in rows:
                for mention in row.entity_mentions:
                    if isinstance(mention, dict): entity_map[self._entity_type(mention["raw_value"], mention.get("role", ""))].add(mention["raw_value"])
            embeddings = [m4_outputs[event_id]["event_embedding"].detach().reshape(-1) for event_id in event_ids]
            vector = torch.stack(embeddings).mean(dim=0).detach().cpu()
            if vector.numel() < self.embedding_dim: vector = torch.nn.functional.pad(vector, (0, self.embedding_dim-vector.numel()))
            vector = vector[:self.embedding_dim]
            score = float(torch.sigmoid(torch.stack([m4_outputs[event_id]["raw_event_logit"].reshape(-1)[0] for event_id in event_ids])).mean())
            window_id = "window:" + hashlib.sha256(f"{dataset_id}|{minutes}|{start.isoformat()}".encode()).hexdigest()[:16]
            windows.append(AggregatedWindow(window_id, dataset_id, start.isoformat(), (start + timedelta(minutes=minutes)).isoformat(), event_ids, {k: tuple(sorted(v)) for k, v in entity_map.items()}, tuple(sorted({r.action_family for r in rows})), len(rows), tuple(float(x) for x in vector), {"node_count": len(graph.node_records), "edge_count": len(graph.edge_records)}, score))
        return windows

    @staticmethod
    def _entity_type(raw, role):
        import re
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", raw): return "ip"
        return {"actor": "user", "destination_host": "host", "process": "process", "object": "file"}.get(role, "unknown")

    def to_m5_records(self, windows: list[AggregatedWindow]) -> list[WindowRecord]:
        return [WindowRecord(w.window_id, datetime.fromisoformat(w.start), datetime.fromisoformat(w.end), torch.tensor(w.embedding), {k: frozenset(v) for k, v in w.entities.items()}, frozenset(w.actions), frozenset(w.event_ids), torch.tensor(w.embedding), w.suspicious_score) for w in windows]
