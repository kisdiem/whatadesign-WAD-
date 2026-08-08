from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from src.common.schema import EventFrame, SyntaxParse


class TaxonomyProvider(Protocol):
    """Optional OCSF/knowledge database hook; it must not provide labels."""

    def classify(self, template: str, fields: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class M1Config:
    version: str = "m1_role_aware_v1"
    min_confidence: float = 0.35


class M1SemanticNormalizer:
    VERSION = "m1_role_aware_v1"

    _IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _PATH = re.compile(r"(?:[A-Za-z]:\\|/)[^\s,;]+")
    _USER = re.compile(r"(?:user|account|login|uid)[=: ]+([A-Za-z0-9_.@\\-]+)", re.I)

    def __init__(self, taxonomy_provider: TaxonomyProvider | None = None, config: M1Config | None = None) -> None:
        self.taxonomy_provider = taxonomy_provider
        self.config = config or M1Config()

    def normalize(self, parsed: SyntaxParse) -> EventFrame:
        template = str(parsed.fields.get("template", ""))
        lowered = template.lower()
        action = self._action(lowered)
        outcome = self._outcome(lowered)
        entities = self._entities(template)
        flow = self._flow_fields(parsed.fields)
        if flow:
            entities = list(dict.fromkeys(entities + [item["raw_value"] for item in flow["mentions"]]))
        actor = self._actor(template, entities)
        obj = self._object(template, entities)
        attributes: dict[str, Any] = {
            "template_id": parsed.template_id,
            "parser_version": "m0_drain_v1",
            "semantic_version": self.VERSION,
            "dataset_id": parsed.dataset_id,
        }
        if self.taxonomy_provider is not None:
            extra = self.taxonomy_provider.classify(template, dict(parsed.fields))
            # Knowledge augmentation is descriptive only; labels are rejected.
            attributes.update({k: v for k, v in extra.items() if "label" not in k.lower()})
        confidence = max(0.0, min(1.0, parsed.parse_confidence * (0.75 if action == "unknown" else 1.0)))
        if confidence < self.config.min_confidence:
            attributes["quarantined_reason"] = "low_semantic_confidence"
        return EventFrame(
            dataset_id=parsed.dataset_id,
            record_id=parsed.record_id,
            timestamp=parsed.timestamp,
            record_kind="network" if flow else "unknown",
            relation_type="flow" if flow else "unknown",
            action_family="connect" if flow else action,
            action_leaf=flow["protocol"] if flow else action,
            roles=flow["roles"] if flow else {},
            actor=actor,
            action=action,
            object=obj,
            location={"source_file": parsed.source_file, "source_line": parsed.source_line},
            outcome=outcome,
            entities=entities,
            entity_mentions=flow["mentions"] if flow else [],
            key_attributes=flow["attributes"] if flow else {},
            attributes=attributes,
            semantic_confidence=confidence,
            source_record_ref=parsed.raw_record_ref,
        )

    @staticmethod
    def _flow_fields(fields: dict[str, Any]) -> dict[str, Any] | None:
        """Map structured flow columns without importing source labels."""
        source = str(fields.get("SrcAddr", fields.get("src_ip", ""))).strip()
        destination = str(fields.get("DstAddr", fields.get("dst_ip", ""))).strip()
        if not source and not destination:
            return None
        protocol = str(fields.get("Proto", fields.get("protocol", "unknown"))).strip().lower() or "unknown"
        mentions = []
        if source: mentions.append({"raw_value": source, "role": "source_ip", "entity_type": "ip"})
        if destination: mentions.append({"raw_value": destination, "role": "destination_ip", "entity_type": "ip"})
        for value, role in ((fields.get("Sport"), "source_port"), (fields.get("Dport"), "destination_port")):
            if value not in (None, ""): mentions.append({"raw_value": str(value), "role": role, "entity_type": "service"})
        attributes = {key: fields[key] for key in ("Proto", "State", "Dir", "Dur", "TotPkts", "TotBytes", "SrcBytes") if key in fields}
        return {"protocol": protocol, "roles": {"source_ip": source, "destination_ip": destination}, "mentions": mentions, "attributes": attributes}

    @staticmethod
    def _action(text: str) -> str:
        for key, value in ((
            ("login", "authenticate"), ("logon", "authenticate"), ("connect", "connect"),
            ("failed", "fail"), ("error", "error"), ("delete", "delete"),
            ("create", "create"), ("write", "write"), ("read", "read"),
            ("execute", "execute"), ("start", "start"), ("stop", "stop"),
        )):
            if key in text:
                return value
        return "unknown"

    @staticmethod
    def _outcome(text: str) -> str:
        if any(x in text for x in ("fail", "error", "denied", "reject")):
            return "failure"
        if any(x in text for x in ("success", "accepted", "complete", "ok")):
            return "success"
        return "unknown"

    def _entities(self, text: str) -> list[str]:
        values = self._IP.findall(text) + self._PATH.findall(text)
        values += [match.group(1) for match in self._USER.finditer(text)]
        return list(dict.fromkeys(values))

    @staticmethod
    def _actor(text: str, entities: list[str]) -> dict[str, Any]:
        users = [x for x in entities if "\\" in x or "@" in x]
        return {"principal": users[0] if users else "unknown"}

    @staticmethod
    def _object(text: str, entities: list[str]) -> dict[str, Any]:
        paths = [x for x in entities if x.startswith("/") or re.match(r"^[A-Za-z]:\\", x)]
        return {"resource": paths[0] if paths else "unknown"}
