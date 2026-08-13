from __future__ import annotations
import hashlib


def scoped_entity_id(dataset_id: str, entity_type: str, canonical_value: str, instance_context: str = "") -> str:
    value = "|".join((dataset_id, entity_type, canonical_value, instance_context))
    return hashlib.sha256(value.encode()).hexdigest()
