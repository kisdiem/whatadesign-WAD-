from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap


def load(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.work_dir)
    split = json.loads((root / "splits.json").read_text(encoding="utf-8"))
    labels = {row["record_id"]: int(row.get("label", 0)) for row in load(root / "labels.jsonl")}
    predictions = {row["record_id"]: float(row["score"]) for row in load(root / "m6_development/validation_predictions.jsonl")}
    ids = [record_id for record_id in split["validation"] if record_id in predictions]
    if not ids:
        raise RuntimeError("source validation predictions are empty")
    scores = [(predictions[x], labels.get(x, 0)) for x in ids]
    negatives = sorted(score for score, label in scores if label == 0)
    threshold = negatives[max(0, int(len(negatives) * 0.995) - 1)] if negatives else 0.5
    result = {"status": "DEVELOPMENT_ONLY", "source": "source_validation", "record_count": len(scores), "positive_count": sum(label for _, label in scores), "negative_count": sum(1 - label for _, label in scores), "threshold": float(threshold), "test_used": False, "ait_accessed": False, "checkpoint_mode": "smoke"}
    target = Path(args.output); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
