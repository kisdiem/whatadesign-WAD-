from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from src.common.schema import EventFrame
from src.entities.m2_resolver import ResolvedEntity


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    value: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    weight: float = 1.0
    timestamp: str | None = None


@dataclass(frozen=True)
class EventGraph:
    window_id: str
    window_start: str | None
    window_end: str | None
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    schema_version: str = "m3_event_graph_v1"


class M3EventGraphBuilder:
    VERSION = "m3_event_graph_v1"

    def __init__(self, window_seconds: int = 1800) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds

    def build(self, frames: Iterable[tuple[EventFrame, list[ResolvedEntity]]]) -> EventGraph:
        rows = list(frames)
        timestamps = [
            self._parse_timestamp(x.attributes.get("timestamp"))
            for x, _ in rows
            if x.attributes.get("timestamp")
        ]
        start = min(timestamps) if timestamps else None
        end = max(timestamps) if timestamps else None
        window_id = self._window_id(start, rows)
        nodes: dict[str, GraphNode] = {}
        edges: dict[tuple[str, str, str], GraphEdge] = {}
        for frame, entities in rows:
            event_id = f"event:{frame.record_id}"
            nodes[event_id] = GraphNode(event_id, "event", frame.action, {"outcome": frame.outcome})
            for entity in entities:
                nodes.setdefault(entity.entity_id, GraphNode(entity.entity_id, entity.entity_type, entity.canonical_value))
                self._add_edge(edges, entity.entity_id, event_id, "participates", frame)
            action_id = self._stable_node("action", frame.action)
            nodes.setdefault(action_id, GraphNode(action_id, "action", frame.action))
            self._add_edge(edges, event_id, action_id, "has_action", frame)
        return EventGraph(window_id, self._format(start), self._format(end), tuple(nodes.values()), tuple(edges.values()))

    def _add_edge(self, edges: dict[tuple[str, str, str], GraphEdge], source: str, target: str, relation: str, frame: EventFrame) -> None:
        key = (source, target, relation)
        old = edges.get(key)
        edges[key] = GraphEdge(source, target, relation, (old.weight + 1.0 if old else 1.0), frame.attributes.get("timestamp"))

    def _window_id(self, start: datetime | None, rows: list[tuple[EventFrame, list[ResolvedEntity]]]) -> str:
        anchor = self._format(start) or (rows[0][0].record_id if rows else "empty")
        return f"window:{hashlib.sha256(anchor.encode()).hexdigest()[:16]}"

    @staticmethod
    def _stable_node(kind: str, value: str) -> str:
        return f"{kind}:{hashlib.sha256(value.encode()).hexdigest()[:24]}"

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _format(value: datetime | None) -> str | None:
        return value.astimezone(timezone.utc).isoformat() if value else None
