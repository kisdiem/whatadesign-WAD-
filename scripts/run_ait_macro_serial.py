"""Serial AIT preprocessing queue for one-graph-per-macro-window M3."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


SCENARIOS = ("fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson")


def run(command: list[str], env: dict[str, str]) -> None:
    print("QUEUE_START", " ".join(command), flush=True)
    subprocess.run(command, check=True, env=env)
    print("QUEUE_DONE", command[2], flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--artifact-root", type=Path, required=True)
    p.add_argument("--m1-model", type=Path, required=True)
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--batch-size", type=int, default=16)
    args = p.parse_args()
    root = args.artifact_root
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{Path.cwd()}:{env.get('PYTHONPATH', '')}"
    queue_manifest = root / "serial_queue_manifest.json"
    state = {"status": "RUNNING", "scenarios": [], "labels_read": False}
    queue_manifest.write_text(json.dumps(state, indent=2), encoding="utf-8")
    for scenario in SCENARIOS:
        selected_windows = root / f"{scenario}_windows_selected.jsonl"
        if not selected_windows.exists():
            raise FileNotFoundError(selected_windows)
        m3_output = root / f"{scenario}_macro_m3.jsonl"
        if m3_output.exists() and m3_output.with_suffix(".manifest.json").exists():
            state["scenarios"].append({"scenario": scenario, "status": "REUSED_MACRO_M3"})
            queue_manifest.write_text(json.dumps(state, indent=2), encoding="utf-8")
            continue
        raw = root / f"{scenario}_selected_raw.jsonl"
        m1m2 = root / f"{scenario}_m1_m2"
        run([args.python, "scripts/build_real_m1_m3_features.py", "--input", str(raw), "--output", str(m1m2), "--dataset-id", "ait", "--m1-model", str(args.m1_model), "--limit", str(sum(1 for _ in raw.open(encoding='utf-8'))), "--batch-size", str(args.batch_size), "--device", "cuda", "--skip-m3"], env)
        run([args.python, "scripts/build_macro_m3_features.py", "--eventframes", str(m1m2 / "m1_eventframes.jsonl"), "--windows", str(selected_windows), "--output", str(m3_output), "--dataset-id", "ait"], env)
        state["scenarios"].append({"scenario": scenario, "status": "MACRO_M3_READY"})
        queue_manifest.write_text(json.dumps(state, indent=2), encoding="utf-8")
    state["status"] = "ALL_MACRO_M3_READY"
    queue_manifest.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(json.dumps(state, ensure_ascii=False))


if __name__ == "__main__":
    main()
