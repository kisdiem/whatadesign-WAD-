from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class RegistryError(ValueError):
    pass


REQUIRED_DATASET_FIELDS = {"display_name", "role", "tier", "official_url", "status", "allowed_label_usage", "prohibited_usage"}
VALID_STATUS = {"unavailable", "metadata_only", "downloaded", "verified", "normalized", "ready", "not_accessed"}


def load_registry(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    datasets = document.get("datasets")
    if not isinstance(datasets, dict) or not datasets:
        raise RegistryError("registry.datasets must be a non-empty mapping")
    for dataset_id, entry in datasets.items():
        missing = REQUIRED_DATASET_FIELDS - set(entry)
        if missing:
            raise RegistryError(f"{dataset_id}: missing fields {sorted(missing)}")
        if entry["status"] not in VALID_STATUS:
            raise RegistryError(f"{dataset_id}: invalid status {entry['status']}")
        if entry["role"] == "target_test" and entry.get("allowed_label_usage") != "evaluation_only_p1":
            raise RegistryError(f"{dataset_id}: target label usage must be evaluation_only_p1")
    return document
