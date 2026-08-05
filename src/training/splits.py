from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class SourceSplit:
    train: tuple[dict[str, Any], ...]
    validation: tuple[dict[str, Any], ...]
    test: tuple[dict[str, Any], ...]
    held_out_source: str


def source_held_out(records: Iterable[dict[str, Any]], held_out_source: str) -> SourceSplit:
    rows = list(records)
    if not held_out_source:
        raise ValueError("held_out_source is required")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        source = str(row.get("source_dataset", ""))
        if not source:
            raise ValueError("every record must have source_dataset")
        groups[source].append(dict(row))
    if held_out_source not in groups:
        raise ValueError(f"held-out source not found: {held_out_source}")
    test = tuple(groups.pop(held_out_source))
    train: list[dict[str, Any]] = []
    validation: list[dict[str, Any]] = []
    for source, source_rows in sorted(groups.items()):
        ordered = sorted(source_rows, key=lambda row: hashlib.sha256(str(row.get("record_id", "")).encode()).hexdigest())
        cut = max(1, int(len(ordered) * 0.8)) if len(ordered) > 1 else len(ordered)
        train.extend(ordered[:cut])
        validation.extend(ordered[cut:])
    return SourceSplit(tuple(train), tuple(validation), test, held_out_source)
