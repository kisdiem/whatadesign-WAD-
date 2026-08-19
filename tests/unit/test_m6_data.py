import json

import pytest

from src.common.schema import FrozenFeatureRecord
from src.training.m6_data import M6Split, read_labels, read_records, validate_split


def _record(record_id: str) -> dict:
    return FrozenFeatureRecord(
        record_id=record_id, dataset_id="ait", timestamp=None,
        event_embedding=[0.1, 0.2], producer_checkpoint_hashes={"m1": "abc"},
    ).to_dict()


def test_frozen_features_fail_closed_without_embedding(tmp_path):
    path = tmp_path / "features.jsonl"
    path.write_text(json.dumps({"record_id": "x", "dataset_id": "ait", "timestamp": None}) + "\n")
    with pytest.raises(ValueError, match="event_embedding"):
        read_records(path)


def test_m6_split_rejects_overlap(tmp_path):
    path = tmp_path / "features.jsonl"
    path.write_text("\n".join(json.dumps(_record(i)) for i in ("a", "b", "c")) + "\n")
    records = read_records(path)
    labels_path = tmp_path / "labels.jsonl"
    labels_path.write_text("\n".join(json.dumps({"record_id": i, "label": 0}) for i in ("a", "b", "c")) + "\n")
    labels = read_labels(labels_path)
    with pytest.raises(ValueError, match="overlap"):
        validate_split(M6Split(("a", "b"), ("b",), ("c",)), records, labels)


def test_m6_split_accepts_ait_dominant_train_pool(tmp_path):
    path = tmp_path / "features.jsonl"
    path.write_text("\n".join(json.dumps(_record(i)) for i in ("ait-1", "ait2-1", "ait2-v", "ait2-t")) + "\n")
    records = read_records(path)
    labels_path = tmp_path / "labels.jsonl"
    labels_path.write_text("\n".join(json.dumps({"record_id": i, "label": 0}) for i in records) + "\n")
    labels = read_labels(labels_path)
    validate_split(M6Split(("ait-1", "ait2-1"), ("ait2-v",), ("ait2-t",)), records, labels)
