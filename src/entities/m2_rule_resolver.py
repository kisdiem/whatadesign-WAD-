from __future__ import annotations
from src.common.schema import EntityRecord
from src.entities.entity_id import scoped_entity_id
from src.entities.entity_normalizer import normalize


class M2RuleResolver:
    def resolve(self, *, dataset_id: str, entity_type: str, raw_value: str, instance_context: str = "", host_scope: str = "", source_record_ref: str = "", platform: str = "unknown", confidence: float = 1.0) -> EntityRecord:
        canonical = normalize(raw_value, entity_type, platform)
        return EntityRecord(dataset_id, scoped_entity_id(dataset_id, entity_type, canonical, instance_context), entity_type, raw_value, canonical, instance_context, host_scope=host_scope, confidence=confidence, resolution_method="rule", source_record_refs=(source_record_ref,) if source_record_ref else ())
