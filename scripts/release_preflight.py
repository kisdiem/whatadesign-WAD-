from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--work-dir", required=True); parser.add_argument("--calibration", required=True); parser.add_argument("--evaluation", required=True); parser.add_argument("--output", required=True)
    args = parser.parse_args(); root = Path(args.work_dir); calibration = json.loads(Path(args.calibration).read_text(encoding="utf-8")); evaluation = json.loads(Path(args.evaluation).read_text(encoding="utf-8")); reasons = []
    if root.name.endswith("smoke_run") or calibration.get("checkpoint_mode") != "train": reasons.append("smoke/development checkpoint")
    if evaluation.get("status") != "FORMAL": reasons.append("formal held-out test is incomplete")
    if calibration.get("test_used_for_calibration") or evaluation.get("test_used_for_calibration"): reasons.append("test data used for calibration")
    if calibration.get("ait_accessed") or evaluation.get("ait_accessed"): reasons.append("AIT access detected")
    result = {"status": "RELEASE_LOCKED" if not reasons else "RELEASE_REJECTED", "reasons": reasons, "ait_accessed": False, "formal_metrics": not bool(reasons)}
    target = Path(args.output); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(json.dumps(result, indent=2), encoding="utf-8"); print(json.dumps(result, indent=2)); raise SystemExit(0 if not reasons else 2)


if __name__ == "__main__":
    main()
