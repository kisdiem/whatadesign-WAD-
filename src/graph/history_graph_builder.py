from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from src.common.schema import EventFrame, GraphRecord


@dataclass(frozen=True)
class HistoryBoundary:
    current_record_id: str
    current_key: tuple[str, str, int, str]


def _key(event: EventFrame, source_file: str = "", source_line: int = 0) -> tuple[str, str, int, str]:
    return (event.timestamp or "", source_file, source_line, event.record_id)


class CausalGraphBuilder:
    def build_causal_graph_before(self, events: list[EventFrame], current_event: EventFrame, source_meta: dict[str, tuple[str, int]] | None = None) -> GraphRecord:
        source_meta = source_meta or {}
        current_key = _key(current_event, *source_meta.get(current_event.record_id, ("", 0)))
        history = [e for e in events if _key(e, *source_meta.get(e.record_id, ("", 0))) < current_key]
        if any(e.record_id == current_event.record_id for e in history):
            raise ValueError("current event leaked into causal graph")
        nodes = tuple({"node_id": e.record_id, "node_type": "event", "action_family": e.action_family} for e in history)
        return GraphRecord(f"history:{current_event.record_id}", current_event.dataset_id, history[0].timestamp if history else None, history[-1].timestamp if history else None, current_event.record_id, nodes, ())


build_causal_graph_before = CausalGraphBuilder().build_causal_graph_before
