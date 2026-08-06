from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SplitRecord:
    dataset_id: str
    record_id: str
    split: str
    group_id: str
    split_reason: str
    split_version: str = "grouped-v1"


class SplitManager:
    def __init__(self, seed: int = 42):
        self.seed = seed

    def assign(self, records: list[dict], train_ratio: float = .7, validation_ratio: float = .15) -> list[SplitRecord]:
        groups: dict[str, list[dict]] = defaultdict(list)
        for row in records:
            group = str(row.get("attack_id") or row.get("scenario") or row.get("host") or row.get("dataset_id"))
            groups[f"{row.get('dataset_id','')}:{group}"].append(row)
        ordered = sorted(groups, key=lambda group: hashlib.sha256(f"{self.seed}|{group}".encode()).hexdigest())
        output = []
        for index, group in enumerate(ordered):
            fraction = index / max(len(ordered), 1)
            split = "train" if fraction < train_ratio else "validation" if fraction < train_ratio + validation_ratio else "test"
            for row in groups[group]:
                output.append(SplitRecord(str(row["dataset_id"]), str(row["record_id"]), split, group, "attack_or_scenario_group"))
        return output

    @staticmethod
    def leakage_report(splits: list[SplitRecord]) -> dict:
        by_group = defaultdict(set)
        for row in splits:
            by_group[row.group_id].add(row.split)
        overlap = {group: sorted(values) for group, values in by_group.items() if len(values) > 1}
        return {"status": "FAILED" if overlap else "PASSED", "group_overlap": overlap, "record_count": len(splits)}
