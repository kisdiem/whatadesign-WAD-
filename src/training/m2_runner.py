from __future__ import annotations
from src.entities.m2_rule_resolver import M2RuleResolver

class M2Runner:
    def __init__(self, resolver=None): self.resolver = resolver or M2RuleResolver()
    def build(self, records):
        resolved = []
        for row in records:
            resolved.append(self.resolver.resolve(dataset_id=row["dataset_id"], entity_type=row["entity_type"], raw_value=row["raw_value"], instance_context=row.get("instance_context", ""), host_scope=row.get("host_scope", ""), source_record_ref=row.get("source_record_ref", ""), platform=row.get("platform", "unknown"), confidence=float(row.get("confidence", 1.0))))
        return resolved
