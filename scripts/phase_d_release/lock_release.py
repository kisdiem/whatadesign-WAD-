from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


REQUIRED = ("release_manifest.json", "thresholds.json", "calibration.json", "model_hashes.json", "requirements_lock.txt")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_release(release_dir: Path) -> list[str]:
    missing = [name for name in REQUIRED if not (release_dir / name).is_file()]
    checkpoints = list((release_dir / "checkpoints").glob("*.pt")) if (release_dir / "checkpoints").is_dir() else []
    if not checkpoints:
        missing.append("checkpoints/*.pt")
    return missing


def lock_release(release_dir: Path) -> Path:
    missing = validate_release(release_dir)
    if missing:
        raise RuntimeError("cannot lock release; missing: " + ", ".join(missing))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=release_dir.parents[1], capture_output=True, text=True, check=True).stdout.strip()
    manifest = {"status": "RELEASE_LOCKED", "git_commit": commit, "files": {str(path.relative_to(release_dir)): sha256(path) for path in release_dir.rglob("*") if path.is_file()}}
    (release_dir / "release_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    marker = release_dir / "RELEASE_LOCKED"
    marker.write_text(commit + "\n", encoding="utf-8")
    return marker


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_dir", type=Path)
    args = parser.parse_args()
    print(lock_release(args.release_dir))


if __name__ == "__main__":
    main()
