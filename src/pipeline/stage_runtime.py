from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterable

from src.common.manifest import StageManifest, current_commit, hash_inputs


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    rows = []
    for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {source}:{line_no}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"JSONL row must be an object at {source}:{line_no}")
        rows.append(value)
    return rows


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")
    return target


def run_stage(stage: str, input_path: str | Path, output_path: str | Path,
              transform: Callable[[dict[str, Any]], dict[str, Any]],
              manifest_path: str | Path, *, commit_root: str | Path = ".") -> StageManifest:
    rows = read_jsonl(input_path)
    output = write_jsonl(output_path, (transform(row) for row in rows))
    manifest = StageManifest(stage=stage, status="COMPLETED", commit=current_commit(commit_root),
                             input_hashes=hash_inputs([input_path]), output_hashes=hash_inputs([output]),
                             real_data_used=True)
    manifest.write(manifest_path)
    return manifest
