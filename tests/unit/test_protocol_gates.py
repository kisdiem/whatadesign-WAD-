import json

import pytest

from src.evaluation.protocol_gates import ProtocolViolation, require_locked_release, require_sealed_predictions, seal_predictions


def test_ait_requires_locked_release(tmp_path):
    with pytest.raises(ProtocolViolation):
        require_locked_release(tmp_path)


def test_sealed_predictions_require_lock_and_hash(tmp_path):
    for name in ("thresholds.json", "calibration.json", "model_hashes.json", "release_manifest.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    (tmp_path / "RELEASE_LOCKED").write_text("", encoding="utf-8")
    prediction = tmp_path / "predictions.jsonl"
    prediction.write_text('{"record_id":"r1"}\n', encoding="utf-8")
    manifest = seal_predictions(tmp_path, [prediction], "test_release")
    assert json.loads(manifest.read_text(encoding="utf-8"))["status"] == "PREDICTIONS_SEALED"
    require_sealed_predictions(manifest)
