import json

import pytest

from src.training.m4_source_dataset import StrictM4SourceDataset


def _write(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_labels_are_separate_from_feature_targets(tmp_path):
    targets, labels = tmp_path / "targets.jsonl", tmp_path / "labels.jsonl"
    _write(targets, [{"dataset_id": "source", "record_id": "r1", "timestamp": "2025-01-01T00:00:00+00:00", "split": "train"}])
    _write(labels, [{"dataset_id": "source", "record_id": "r1", "label": 1}])
    dataset = StrictM4SourceDataset(targets, labels)
    target = dataset.split_targets("train")[0]
    assert target.record_id == "r1"
    assert not hasattr(target, "label")
    assert dataset.loss_label(target) == 1


def test_feature_target_rejects_supervision_field(tmp_path):
    targets, labels = tmp_path / "targets.jsonl", tmp_path / "labels.jsonl"
    _write(targets, [{"dataset_id": "source", "record_id": "r1", "timestamp": "2025-01-01T00:00:00+00:00", "split": "train", "label": 1}])
    _write(labels, [{"dataset_id": "source", "record_id": "r1", "label": 1}])
    with pytest.raises(ValueError, match="forbidden"):
        StrictM4SourceDataset(targets, labels)
