from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class ProtocolViolation(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_locked_release(release_dir: Path) -> None:
    marker = release_dir / "RELEASE_LOCKED"
    if not marker.is_file():
        raise ProtocolViolation("AIT inference requires RELEASE_LOCKED")
    required = ("thresholds.json", "calibration.json", "model_hashes.json", "release_manifest.json")
    missing = [name for name in required if not (release_dir / name).is_file()]
    if missing:
        raise ProtocolViolation(f"locked release missing: {', '.join(missing)}")


def require_sealed_predictions(prediction_manifest: Path) -> None:
    if not prediction_manifest.is_file():
        raise ProtocolViolation("AIT labels require a prediction manifest")
    payload = json.loads(prediction_manifest.read_text(encoding="utf-8"))
    if payload.get("status") != "PREDICTIONS_SEALED":
        raise ProtocolViolation("AIT labels require PREDICTIONS_SEALED")
    for item in payload.get("predictions", []):
        path = Path(item["path"])
        if not path.is_file() or sha256_file(path) != item.get("sha256"):
            raise ProtocolViolation(f"prediction hash changed or file missing: {path}")


def seal_predictions(release_dir: Path, prediction_files: list[Path], release_id: str) -> Path:
    require_locked_release(release_dir)
    missing = [str(path) for path in prediction_files if not path.is_file()]
    if missing:
        raise ProtocolViolation(f"cannot seal missing prediction files: {', '.join(missing)}")
    manifest = {
        "status": "PREDICTIONS_SEALED",
        "release_id": release_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label_access": False,
        "predictions": [{"path": str(path.resolve()), "sha256": sha256_file(path)} for path in prediction_files],
    }
    output = release_dir / "prediction_manifest.json"
    output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return output
