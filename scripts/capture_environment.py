from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import torch


def main():
    root = Path(__file__).resolve().parents[1]
    payload = {
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "python": sys.version,
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "cuda_available": torch.cuda.is_available(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "data_root_exists": Path("/root/autodl-tmp/semantic-graph-apt/data").exists(),
        "model_cache": str(Path(__file__).resolve().parents[1] / "models"),
        "model_cache_exists": (root / "models").exists(),
    }
    target = root / "outputs/audit/pre_modification_environment.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
