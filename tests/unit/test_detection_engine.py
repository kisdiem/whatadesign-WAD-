import json
from pathlib import Path

import pytest

from src.detection.engine import DetectionEngine
from src.detection.schema import load_jsonl


def test_detector_rejects_ground_truth_fields(tmp_path: Path) -> None:
    path = tmp_path / "leaked.jsonl"
    path.write_text(json.dumps({"timestamp": "2026-01-01T00:00:00Z", "message": "ok", "label": 1}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="target leakage"):
        list(load_jsonl(path))


def test_weak_and_unsupervised_detection_is_label_free() -> None:
    repo = Path(__file__).resolve().parents[2]
    events = list(load_jsonl(repo / "data/demo/real_logs.jsonl"))
    rows = DetectionEngine().score_events(events)
    by_id = {row["event_id"]: row for row in rows}
    assert by_id["EVT-005"]["weak_score"] > 0.9
    assert by_id["EVT-005"]["risk_score"] > by_id["EVT-001"]["risk_score"]
    assert all("label" not in row and "ground_truth" not in row for row in rows)


def test_real_pipeline_exports_traceable_dashboard_state(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    result = DetectionEngine().run(repo / "data/demo/real_logs.jsonl", tmp_path)
    assert result.input_count == 16
    assert result.finding_count >= 2
    assert result.manifest["labels_accessed"] is False
    windows = json.loads((tmp_path / "windows.json").read_text(encoding="utf-8"))
    assert any(window["provenance"] for window in windows)
    assert all(event["raw_log_ref"] for window in windows for event in window["events"])
