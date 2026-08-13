from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.common.schema import SCHEMA_VERSION


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_commit(root: str | Path = ".") -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


@dataclass(frozen=True)
class StageManifest:
    stage: str
    status: str
    commit: str
    schema_version: str = SCHEMA_VERSION
    config_version: str = "unknown"
    module_version: str = "unknown"
    strict_mode: bool = True
    input_hashes: dict[str, str] = field(default_factory=dict)
    output_hashes: dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    real_data_used: bool = False
    real_training_completed: bool = False
    execution_mode: str = "real"
    config_hash: str = ""
    input_paths: tuple[str, ...] = ()
    output_paths: tuple[str, ...] = ()
    record_count: int = 0
    rejected_count: int = 0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    release_eligible: bool = False

    def write(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8")
        return target


def hash_inputs(paths: Iterable[str | Path]) -> dict[str, str]:
    return {str(Path(path)): sha256_file(path) for path in paths if Path(path).is_file()}
