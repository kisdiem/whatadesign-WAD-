from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.common.audit import append_operation


def file_hash(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(root: Path, name: str, datasets: dict) -> dict:
    selected = {}
    for dataset_id, entry in datasets.items():
        if entry.get("tier") == "target" or dataset_id in {"ait_lds_v2", "ait_ads"}:
            continue
        if name == "release_strict" and dataset_id == "cam_lds_filtered":
            continue
        local = Path(entry.get("local_path", "")) if entry.get("local_path") else None
        selected[dataset_id] = {
            "role": entry["role"],
            "status": entry["status"],
            "official_url": entry["official_url"],
            "local_path": str(local) if local else None,
            "local_sha256": file_hash(local) if local else None,
            "allowed_label_usage": entry["allowed_label_usage"],
            "prohibited_usage": entry["prohibited_usage"],
        }
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip() or None
    manifest = {
        "release_id": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": commit,
        "ait_accessed": False,
        "target_labels_included": False,
        "datasets": selected,
    }
    output = root / "outputs" / name / "release_manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    registry = yaml.safe_load((root / "configs/data/data_registry.yaml").read_text(encoding="utf-8"))
    strict = build(root, "release_strict", registry["datasets"])
    enhanced = build(root, "release_enhanced", registry["datasets"])
    result = {"strict_datasets": len(strict["datasets"]), "enhanced_datasets": len(enhanced["datasets"]), "ait_accessed": False}
    append_operation(root / "logs/operations.jsonl", "build_release", "completed", **result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
