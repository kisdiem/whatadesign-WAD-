"""Strict serial orchestration: LoRA completion -> new M1 -> M5 training."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def run(command: list[str], log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write("$ " + " ".join(command) + "\n")
        result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, text=True)
    if result.returncode:
        raise SystemExit(f"stage failed: {command[0]} (see {log})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--lora-report", type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--input-root", type=Path, required=True)
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--work-root", type=Path, required=True)
    ap.add_argument("--m5-epochs", type=int, default=8)
    ap.add_argument("--poll-seconds", type=int, default=30)
    args = ap.parse_args()
    script_root = Path(__file__).resolve().parent
    log = args.work_root / "pipeline.log"
    while not args.lora_report.exists():
        time.sleep(args.poll_seconds)
    report = json.loads(args.lora_report.read_text(encoding="utf-8"))
    if report.get("status") != "COMPLETED":
        raise SystemExit("LoRA report exists but is not COMPLETED")
    adapter = args.lora_report.parent
    smoke_root = args.work_root / "m1_smoke"
    full_root = args.work_root / "m1_lora"
    run([args.python, str(script_root / "regenerate_m1_with_lora.py"), "--model", str(args.model),
         "--adapter", str(adapter), "--input-root", str(args.input_root), "--output-root", str(smoke_root), "--smoke"], log)
    smoke_manifest = json.loads((smoke_root / "m1_smoke_manifest.json").read_text(encoding="utf-8"))
    if smoke_manifest.get("total_events", 0) <= 0:
        raise SystemExit("M1 LoRA smoke produced no events")
    run([args.python, str(script_root / "regenerate_m1_with_lora.py"), "--model", str(args.model),
         "--adapter", str(adapter), "--input-root", str(args.input_root), "--output-root", str(full_root)], log)
    run([args.python, str(script_root / "train_m5_two_models.py"), "--events-root", str(full_root),
         "--labels", str(args.labels), "--output-dir", str(args.work_root / "m5_smoke"), "--smoke"], log)
    run([args.python, str(script_root / "train_m5_two_models.py"), "--events-root", str(full_root),
         "--labels", str(args.labels), "--output-dir", str(args.work_root / "m5_final"),
         "--epochs", str(args.m5_epochs)], log)
    (args.work_root / "pipeline_status.json").write_text(json.dumps({"status": "COMPLETED",
        "lora_report": str(args.lora_report), "m1_root": str(full_root),
        "m5_report": str(args.work_root / "m5_final" / "training_report.json")}, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
