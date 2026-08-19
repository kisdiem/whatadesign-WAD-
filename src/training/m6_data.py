"""Strict M6 split and frozen-feature data contracts.

Labels and split metadata are kept outside FrozenFeatureRecord.  This module
only joins them at loss/evaluation time and refuses incomplete feature rows.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from src.common.schema import FrozenFeatureRecord


@dataclass(frozen=True)
class M6Split:
    train: tuple[str, ...]
    validation: tuple[str, ...]
    test: tuple[str, ...]


def _read_jsonl(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL: {path}:{line_no}") from exc


def read_records(path: Path) -> dict[str, FrozenFeatureRecord]:
    result: dict[str, FrozenFeatureRecord] = {}
    for row in _read_jsonl(path):
        record = FrozenFeatureRecord.from_dict(row)
        if not record.event_embedding:
            raise ValueError(f"missing event_embedding for {record.record_id}")
        if not record.producer_checkpoint_hashes:
            raise ValueError(f"missing producer checkpoint hashes for {record.record_id}")
        if record.record_id in result:
            raise ValueError(f"duplicate frozen feature record: {record.record_id}")
        result[record.record_id] = record
    if not result:
        raise ValueError("no frozen feature records")
    dimensions = {len(row.event_embedding) for row in result.values()}
    if len(dimensions) != 1:
        raise ValueError(f"inconsistent event_embedding dimensions: {sorted(dimensions)}")
    return result


def read_labels(path: Path) -> dict[str, int]:
    labels: dict[str, int] = {}
    for row in _read_jsonl(path):
        if set(row) - {"record_id", "label"}:
            raise ValueError("labels file may contain only record_id and label")
        record_id = str(row["record_id"])
        label = int(row["label"])
        if label not in (0, 1):
            raise ValueError(f"binary label required for {record_id}")
        if record_id in labels:
            raise ValueError(f"duplicate label: {record_id}")
        labels[record_id] = label
    return labels


def validate_split(split: M6Split, records: dict[str, FrozenFeatureRecord], labels: dict[str, int]) -> None:
    groups = [set(split.train), set(split.validation), set(split.test)]
    if any(not group for group in groups):
        raise ValueError("train, validation and test must all be non-empty")
    if groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2]:
        raise ValueError("M6 split overlap detected")
    known = set(records) & set(labels)
    for name, group in zip(("train", "validation", "test"), groups):
        missing = group - known
        if missing:
            raise ValueError(f"{name} contains records without frozen features and labels: {len(missing)}")


def write_split(path: Path, split: M6Split, provenance: dict) -> None:
    payload = {
        "schema_version": "m6-split-v1",
        "policy": {
            "ait": "primary_train_pool_all_eligible",
            "ait2": "small_train_adaptation_pool; validation_and_test_disjoint",
            "labels": "loss_or_post_seal_evaluation_only",
        },
        "train": list(split.train),
        "validation": list(split.validation),
        "test": list(split.test),
        "provenance": provenance,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
