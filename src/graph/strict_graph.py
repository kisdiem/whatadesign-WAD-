from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from src.common.schema import EventFrame, GraphRecord
from src.entities.m2_pipeline import EventEntityLink


@dataclass(frozen=True)
class StrictGraph:
    graph_id: str
    dataset_id: str
    node_records: tuple[dict[str, Any], ...]
    edge_records: tuple[dict[str, Any], ...]
    current_record_id: str | None = None


def event_order(frame: EventFrame, source_file: str = "", source_line: int = 0):
    return (frame.timestamp or "", source_file, source_line, frame.record_id)


class StrictGraphBuilder:
    @staticmethod
    def _event_key(frame: EventFrame):
        metadata = frame.attributes or {}
        return event_order(frame, str(metadata.get("source_file", "")), int(metadata.get("source_line", 0)))

    def build(self, frames: list[EventFrame], links: list[EventEntityLink]) -> StrictGraph:
        nodes: dict[str, dict[str, Any]] = {}
        for frame in frames:
            nodes[f"event:{frame.record_id}"] = {"node_id": f"event:{frame.record_id}", "node_type": "event", "action_family": frame.action_family, "outcome": frame.outcome}
        for link in links:
            nodes.setdefault(link.entity_id, {"node_id": link.entity_id, "node_type": "unknown"})
        edges = [{"source": link.entity_id, "target": f"event:{link.event_id}", "role": self._role(link.role), "confidence": link.confidence} for link in links]
        return StrictGraph("graph:strict", frames[0].dataset_id if frames else "", tuple(nodes.values()), tuple(edges))

    def build_before_current_event(self, frames: list[EventFrame], links: list[EventEntityLink], current: EventFrame) -> StrictGraph:
        ordered = sorted(frames, key=self._event_key)
        current_key = self._event_key(current)
        history = [frame for frame in ordered if self._event_key(frame) < current_key]
        ids = {frame.record_id for frame in history}
        history_links = [link for link in links if link.event_id in ids]
        graph = self.build(history, history_links)
        return StrictGraph(graph.graph_id + ":before:" + current.record_id, graph.dataset_id, graph.node_records, graph.edge_records, current.record_id)

    @staticmethod
    def _role(role: str) -> str:
        return {"actor": "actor_of", "destination_host": "destination_of", "process": "process_of", "object": "object_of", "destination_ip": "destination_of"}.get(role, "session_of")

    @staticmethod
    def graph_summary(graph: StrictGraph) -> dict[str, Any]:
        return {"node_count": len(graph.node_records), "edge_count": len(graph.edge_records), "relations": sorted({edge["role"] for edge in graph.edge_records})}
