from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.pipeline.artifact_store import ArtifactStore


ALLOWED_STATUSES = {"COMPLETED", "FAILED", "SKIPPED_HASH_MATCH", "BLOCKED_MISSING_DATA", "BLOCKED_MISSING_WEIGHTS", "BLOCKED_INVALID_CONFIG", "BLOCKED_PROTOCOL"}


@dataclass
class RunState:
    run_id: str
    execution_mode: str
    seed: int
    stages: dict[str, dict[str, Any]]

    def record(self, stage: str, status: str, **fields: Any) -> None:
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"invalid stage status: {status}")
        self.stages[stage] = {"stage": stage, "status": status, "completed_at": datetime.now(timezone.utc).isoformat(), **fields}

    def save(self, store: ArtifactStore) -> None:
        store.atomic_json("run_state.json", {"run_id": self.run_id, "execution_mode": self.execution_mode, "seed": self.seed, "stages": self.stages})
