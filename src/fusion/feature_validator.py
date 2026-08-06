from __future__ import annotations
from src.common.schema import FrozenFeatureRecord

def validate_feature_record(record: FrozenFeatureRecord) -> None:
    if record.feature_schema_version == "": raise ValueError("feature schema version is required")
    if "dataset_id" in record.model_features() or "attack_id" in record.model_features(): raise ValueError("metadata leaked into model features")
