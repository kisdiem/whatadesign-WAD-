from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap


def rows(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--work-dir", required=True); parser.add_argument("--calibration", required=True); parser.add_argument("--output", required=True); parser.add_argument("--formal", action="store_true")
    args = parser.parse_args(); root = Path(args.work_dir); calibration = json.loads(Path(args.calibration).read_text(encoding="utf-8"))
    if args.formal and calibration.get("checkpoint_mode") != "train": raise SystemExit("formal evaluation rejected: calibration is not from a formal train checkpoint")
    split = json.loads((root / "splits.json").read_text(encoding="utf-8")); labels = {row["record_id"]: int(row.get("label", 0)) for row in rows(root / "labels.jsonl")}; predictions = {row["record_id"]: float(row["score"]) for row in rows(root / "m6_development/validation_predictions.jsonl")}
    ids = split["test"] if args.formal else split["validation"]; values = [(predictions[x], labels.get(x, 0)) for x in ids if x in predictions]
    threshold = float(calibration["threshold"]); tp = sum(score >= threshold and label for score, label in values); fp = sum(score >= threshold and not label for score, label in values); fn = sum(score < threshold and label for score, label in values); precision = tp / max(tp + fp, 1); recall = tp / max(tp + fn, 1); f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    result = {"status": "FORMAL" if args.formal else "DEVELOPMENT_ONLY", "split": "test" if args.formal else "validation", "record_count": len(values), "precision": precision, "recall": recall, "f1": f1, "threshold_source": "source_validation", "test_used_for_calibration": False, "ait_accessed": False}
    target = Path(args.output); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(json.dumps(result, indent=2), encoding="utf-8"); print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
