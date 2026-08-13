import json
import subprocess
import sys
from pathlib import Path


def test_real_detection_and_evaluation_are_reproducible(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    logs = repo / "data/demo/real_logs.jsonl"
    labels = repo / "data/demo/evaluation_labels.json"
    state = tmp_path / "state"
    report_dir = tmp_path / "report"
    subprocess.run([sys.executable, "scripts/run_real_detection.py", "--input", str(logs), "--output-dir", str(state)], cwd=repo, check=True)
    subprocess.run([sys.executable, "scripts/evaluate_detection.py", "--input", str(logs), "--labels", str(labels), "--output-dir", str(report_dir), "--repeats", "2"], cwd=repo, check=True)
    manifest = json.loads((state / "detection_manifest.json").read_text(encoding="utf-8"))
    report = json.loads((report_dir / "evaluation_report.json").read_text(encoding="utf-8"))
    assert manifest["execution_mode"] == "real_log_file"
    assert manifest["labels_accessed"] is False
    assert report["labels_used_for_training"] is False
    assert report["labels_read_after_prediction"] is True
    assert {"full", "weak_only", "unsupervised_only", "without_chain_aggregation"}.issubset(report["ablations"])
    assert 0 <= report["metrics"]["fpr"] <= 1
    assert report["throughput"]["median_events_per_second"] > 0
