from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Protocol

from src.common.schema import EventFrame


class EntityKnowledgeProvider(Protocol):
    """Optional knowledge lookup; it may enrich aliases but never labels."""

    def resolve_alias(self, value: str, entity_type: str) -> str | None: ...


@dataclass(frozen=True)
class ResolvedEntity:
    entity_id: str
    entity_type: str
    value: str
    canonical_value: str
    confidence: float


class M2EntityResolver:
    VERSION = "m2_entity_resolver_v1"

    def __init__(self, provider: EntityKnowledgeProvider | None = None) -> None:
        self.provider = provider

    def resolve(self, frame: EventFrame) -> list[ResolvedEntity]:
        resolved: list[ResolvedEntity] = []
        for value in frame.entities:
            entity_type = self._type_of(value)
            canonical = self._canonical(value, entity_type)
            if self.provider is not None:
                alias = self.provider.resolve_alias(canonical, entity_type)
                if alias:
                    canonical = alias.strip().lower()
            digest = hashlib.sha256(f"{entity_type}|{canonical}".encode()).hexdigest()[:24]
            resolved.append(ResolvedEntity(f"{entity_type}:{digest}", entity_type, value, canonical, 0.95))
        return resolved

    @staticmethod
    def _type_of(value: str) -> str:
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
            return "ip"
        if value.startswith("/") or re.match(r"^[A-Za-z]:\\", value):
            return "path"
        if "@" in value or "\\" in value:
            return "account"
        return "token"

    @staticmethod
    def _canonical(value: str, entity_type: str) -> str:
        value = value.strip()
        if entity_type == "ip":
            return value
        return value.replace("\\", "/").rstrip("/").lower()
