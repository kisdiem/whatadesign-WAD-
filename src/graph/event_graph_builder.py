from __future__ import annotations
from src.common.schema import EventFrame, GraphRecord
from src.graph.vocabulary import NODE_TYPE_VOCAB, EDGE_ROLE_VOCAB


class EventGraphBuilder:
    def build(self, event: EventFrame) -> GraphRecord:
        nodes = [{"node_id": event.record_id, "node_type": "event", "action_family": event.action_family, "outcome": event.outcome}]
        edges = []
        for mention in event.entity_mentions or event.entities:
            value = mention if isinstance(mention, str) else mention.get("entity_id", "")
            if value:
                nodes.append({"node_id": value, "node_type": (mention.get("entity_type", "unknown") if isinstance(mention, dict) else "unknown")})
                edges.append({"source": value, "target": event.record_id, "role": "actor_of"})
        return GraphRecord(f"graph:{event.record_id}", event.dataset_id, event.timestamp, event.timestamp, event.record_id, tuple(nodes), tuple(edges))
