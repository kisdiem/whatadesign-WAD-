from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from src.common.schema import EventFrame, SyntaxParse


@dataclass(frozen=True)
class M1RulePipeline:
    version: str = "m1-rule-pipeline-1"

    def infer(self, parsed: SyntaxParse) -> EventFrame:
        text = str(parsed.fields.get("message", parsed.template_text or parsed.fields.get("template", "")))
        lowered = text.lower()
        user = self._capture(text, r"(?:user|account|principal)\s+([A-Za-z][\w.-]*)")
        host = self._capture(text, r"host[- ]?([A-Za-z0-9_.-]+)")
        process = self._capture(text, r"(?:process|started)\s+([\w.-]+\.exe)")
        path = self._capture(text, r"((?:[A-Za-z]:\\|/)[^\s,;]+)")
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        ip = ip_match.group(0) if ip_match else None
        if "login" in lowered or "logon" in lowered or "authenticated" in lowered:
            family, leaf, kind, relation = "authentication", "login", "authentication", "actor_of"
        elif "process" in lowered or "started" in lowered or ".exe" in lowered:
            family, leaf, kind, relation = "process", "start", "process", "process_of"
        elif "download" in lowered:
            family, leaf, kind, relation = "file", "download", "file", "object_of"
        elif "accessed" in lowered or "read" in lowered:
            family, leaf, kind, relation = "file", "read", "file", "object_of"
        elif "connect" in lowered or "network" in lowered:
            family, leaf, kind, relation = "network", "connect", "network", "destination_of"
        else:
            family, leaf, kind, relation = "unknown", "unknown", "unknown", "unknown"
        outcome = "failure" if any(word in lowered for word in ("failed", "denied", "error")) else ("success" if any(word in lowered for word in ("success", "completed", "ok")) else "unknown")
        roles: dict[str, Any] = {}
        if user: roles["actor"] = user
        if host: roles["destination_host"] = host
        if process: roles["process"] = process
        if path: roles["object"] = path
        if ip: roles["destination_ip"] = ip
        mentions = [{"raw_value": value, "role": role} for role, value in roles.items()]
        confidence = 0.9 if family != "unknown" else 0.35
        return EventFrame(dataset_id=parsed.dataset_id, record_id=parsed.record_id, timestamp=parsed.timestamp,
                          record_kind=kind, relation_type=relation, action_family=family, action_leaf=leaf,
                          roles=roles, outcome=outcome, key_attributes={"template_id": parsed.template_id},
                          entity_mentions=mentions, semantic_confidence=confidence, unknown_score=1.0-confidence,
                          source_record_ref=parsed.source_record_ref, semantic_version=self.version,
                          action=leaf, entities=[str(value) for value in roles.values()],
                          attributes={"source_file": parsed.source_file, "source_line": parsed.source_line})

    @staticmethod
    def _capture(text: str, pattern: str) -> str | None:
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).rstrip(".,;)") if match else None
