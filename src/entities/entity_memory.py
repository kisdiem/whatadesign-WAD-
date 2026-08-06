from __future__ import annotations
from dataclasses import dataclass, field
from src.common.schema import EntityRecord


@dataclass
class EntityMemory:
    records: dict[str, EntityRecord] = field(default_factory=dict)

    def add(self, record: EntityRecord) -> None:
        self.records[record.entity_id] = record

    def get(self, entity_id: str) -> EntityRecord | None:
        return self.records.get(entity_id)
