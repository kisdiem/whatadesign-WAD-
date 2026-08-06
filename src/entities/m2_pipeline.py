from __future__ import annotations

from dataclasses import dataclass
from src.common.schema import EntityRecord, EventFrame
from src.entities.entity_id import scoped_entity_id
from src.entities.entity_normalizer import normalize


@dataclass(frozen=True)
class EventEntityLink:
    event_id: str
    entity_id: str
    role: str
    confidence: float


class M2Pipeline:
    def resolve_frame(self, frame: EventFrame) -> tuple[list[EntityRecord], list[EventEntityLink]]:
        entities: list[EntityRecord] = []
        links: list[EventEntityLink] = []
        for mention in frame.entity_mentions:
            if not isinstance(mention, dict): continue
            raw = str(mention.get("raw_value", "")).strip()
            role = str(mention.get("role", "unknown"))
            if not raw: continue
            entity_type = self._type_of(raw, role)
            canonical = normalize(raw, entity_type, "windows" if "\\" in raw else "linux")
            context = self._context(frame, entity_type, raw)
            entity_id = scoped_entity_id(frame.dataset_id, entity_type, canonical, context)
            confidence = 0.4 if entity_type == "ip" else 0.9
            entities.append(EntityRecord(frame.dataset_id, entity_id, entity_type, raw, canonical, context,
                                         host_scope=str(frame.roles.get("destination_host", "")),
                                         confidence=confidence, resolution_method="m1_role_rule",
                                         source_record_refs=(frame.source_record_ref,)))
            links.append(EventEntityLink(frame.record_id, entity_id, role, confidence))
        return entities, links

    @staticmethod
    def _context(frame: EventFrame, entity_type: str, raw: str) -> str:
        if entity_type == "process": return f"{frame.roles.get('destination_host', '')}|{raw}|{frame.timestamp or ''}"
        return str(frame.roles.get("destination_host", ""))

    @staticmethod
    def _type_of(raw: str, role: str) -> str:
        import re
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", raw): return "ip"
        if role == "actor": return "user"
        if role == "destination_host": return "host"
        if role == "process": return "process"
        if role == "object" or raw.startswith(("/", "C:\\")): return "file"
        return "unknown"
