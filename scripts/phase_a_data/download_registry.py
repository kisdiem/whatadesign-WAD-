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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    config = yaml.safe_load((root / "configs/data/download_targets.yaml").read_text(encoding="utf-8"))
    data_root = Path("/root/autodl-tmp/semantic-graph-apt/data/replacement_sources")
    manifest_root = root / "outputs/source_validation/manifests"
    manifest_root.mkdir(parents=True, exist_ok=True)
    results = []
    for target in config["targets"]:
        dataset_id = target["dataset_id"]
        destination = Path(target.get("output_dir", str(data_root / dataset_id)))
        destination.mkdir(parents=True, exist_ok=True)
        output = destination / target["filename"]
        row = {
            "dataset_id": dataset_id,
            "url": target["url"],
            "output_path": str(output),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "ait_accessed": False,
        }
        if output.exists() and output.stat().st_size <= target["max_bytes"]:
            row["status"] = "existing_reused"
            row["size_bytes"] = output.stat().st_size
            row["sha256"] = sha256(output)
        elif dataset_id.startswith("ait") or "ait" in target["url"].lower():
            row["status"] = "blocked_target_dataset"
        else:
            command = [
                "curl", "-L", "-C", "-", "--fail", "--retry", "8", "--retry-delay", "5",
                "--connect-timeout", "20", "--max-time", "3600", "-o", str(output), target["url"],
            ]
            completed = subprocess.run(command, capture_output=True, text=True)
            if completed.returncode != 0:
                row["status"] = "download_failed"
                row["error"] = completed.stderr[-1000:]
            elif not output.exists() or output.stat().st_size > target["max_bytes"]:
                row["status"] = "rejected_size"
                row["size_bytes"] = output.stat().st_size if output.exists() else 0
            else:
                row["status"] = "downloaded"
                row["size_bytes"] = output.stat().st_size
                row["sha256"] = sha256(output)
        (manifest_root / f"{dataset_id}.json").write_text(json.dumps(row, indent=2), encoding="utf-8")
        append_operation(root / "logs/operations.jsonl", "download_registry", row["status"], **{k: v for k, v in row.items() if k != "status"})
        results.append(row)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
