from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class M4StrictBatch:
    record_id: str
    dataset_id: str
    history_events: tuple[dict[str, Any], ...]
    history_padding_mask: Any
    current_event: dict[str, Any]
    current_event_tokens: Any
    graph_before_current_event: dict[str, Any]
    graph_padding_mask: Any
    target_slot_ids: Any = None
    source_record_ref: str = ""
    strict_mode: bool = True

    def __post_init__(self):
        current_id = self.current_event.get("record_id") if isinstance(self.current_event, dict) else None
        if current_id != self.record_id: raise ValueError("current event record_id mismatch")
        if any(isinstance(item, dict) and item.get("record_id") == self.record_id for item in self.history_events):
            raise ValueError("current_event must not be in history_events")
        graph_current = self.graph_before_current_event.get("current_record_id") if isinstance(self.graph_before_current_event, dict) else None
        if graph_current == self.record_id: raise ValueError("current event must not be in graph_before_current_event")
