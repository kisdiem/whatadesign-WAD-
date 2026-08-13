from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def command_output(command: list[str]) -> str | None:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
    except Exception:
        return None


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / "outputs/environment/environment.json"
    registry = root / "configs/data/data_registry.yaml"
    data_root = Path("/root/autodl-tmp")
    report = {
        "python": sys.version,
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "git_commit": command_output(["git", "rev-parse", "HEAD"]),
        "nvidia_smi": command_output(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"]),
        "disk_free_bytes": shutil.disk_usage(root).free,
        "data_disk_free_bytes": shutil.disk_usage(data_root).free if data_root.exists() else None,
        "registry_sha256": hashlib.sha256(registry.read_bytes()).hexdigest() if registry.exists() else None,
        "ait_accessed": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
