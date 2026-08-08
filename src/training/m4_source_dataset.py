from __future__ import annotations

"""Strict source-only data boundary for Q-Former supervised training.

Feature targets deliberately carry identity, timestamp, and split metadata
only.  Labels are loaded from a separate loss-only file and are exposed only
by :meth:`loss_label`; no EventFrame or Qwen serialization receives them.
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceTarget:
    record_id: str
    dataset_id: str
    timestamp: str
    split: str


class StrictM4SourceDataset:
    def __init__(self, targets_path: str | Path, labels_path: str | Path) -> None:
        self.targets: dict[tuple[str, str], SourceTarget] = {}
        for row in self._jsonl(targets_path):
            forbidden = {"label", "target_label", "attack_label", "anomaly_label", "ground_truth"} & set(row)
            if forbidden:
                raise ValueError(f"feature target contains forbidden supervision fields: {sorted(forbidden)}")
            target = SourceTarget(
                record_id=str(row["record_id"]), dataset_id=str(row["dataset_id"]),
                timestamp=str(row["timestamp"]), split=str(row["split"]),
            )
            key = (target.dataset_id, target.record_id)
            if key in self.targets:
                raise ValueError(f"duplicate target identity: {key}")
            self.targets[key] = target
        self._labels: dict[tuple[str, str], int] = {}
        for row in self._jsonl(labels_path):
            allowed = {"dataset_id", "record_id", "label"}
            extra = set(row) - allowed
            if extra:
                raise ValueError(f"loss-only label row has unsupported fields: {sorted(extra)}")
            label = int(row["label"])
            if label not in {0, 1}:
                raise ValueError("M4 event labels must be binary")
            key = (str(row["dataset_id"]), str(row["record_id"]))
            if key in self._labels:
                raise ValueError(f"duplicate label identity: {key}")
            self._labels[key] = label
        if set(self.targets) != set(self._labels):
            missing = set(self.targets) ^ set(self._labels)
            raise ValueError(f"target/label identity mismatch: {len(missing)} records")

    @staticmethod
    def _jsonl(path: str | Path):
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)

    def split_targets(self, split: str) -> list[SourceTarget]:
        if split not in {"train", "validation", "test"}:
            raise ValueError("split must be train, validation, or test")
        return [target for target in self.targets.values() if target.split == split]

    def loss_label(self, target: SourceTarget) -> int:
        """Return supervision only at loss construction time."""
        return self._labels[(target.dataset_id, target.record_id)]
