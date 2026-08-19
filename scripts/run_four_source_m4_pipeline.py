"""Resume the four-source M4 data contract with bounded CPU/GPU overlap.

The source order is fixed by the experiment protocol: Fox, Harrison, Santos
and RussellMitchell.  Fox is validated as already processed.  For the other
sources, macro M3 is built before the frozen-Qwen M4 feature pass.  While one
source is in the Qwen pass, the next source prepares M1/M2/M3.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SOURCES = ("harrison", "santos", "russellmitchell")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def line_count(path: Path) -> int:
    with path.open(encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


class Pipeline:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = args.artifact_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "four_source_m4_pipeline_manifest.json"
        self.operations_path = self.root / "four_source_m4_operations.jsonl"
        self.state: dict[str, Any] = {
            "status": "RUNNING",
            "started_at": utc_now(),
            "labels_read": False,
            "sources": {"fox": {"status": "VALIDATING"}},
        }
        self.env = os.environ.copy()
        current_path = self.env.get("PYTHONPATH", "")
        self.env["PYTHONPATH"] = f"{Path.cwd()}:{current_path}" if current_path else str(Path.cwd())
        self.save_state()

    def save_state(self) -> None:
        self.state_path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def operation(self, **payload: Any) -> None:
        payload.update({"timestamp": utc_now(), "labels_read": False})
        with self.operations_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def source_state(self, source: str, **payload: Any) -> None:
        self.state["sources"].setdefault(source, {}).update(payload)
        self.save_state()

    def run_stage(self, source: str, stage: str, command: list[str]) -> None:
        log_path = self.root / f"{source}_{stage}.log"
        self.source_state(source, status=f"{stage.upper()}_RUNNING", stage=stage, log=str(log_path))
        self.operation(source=source, stage=stage, status="STARTED", command=command, log=str(log_path))
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(command, cwd=Path.cwd(), env=self.env, stdout=log, stderr=subprocess.STDOUT)
        if completed.returncode:
            self.source_state(source, status=f"{stage.upper()}_FAILED", returncode=completed.returncode)
            self.operation(source=source, stage=stage, status="FAILED", returncode=completed.returncode)
            raise RuntimeError(f"{source} {stage} failed; see {log_path}")
        self.operation(source=source, stage=stage, status="COMPLETED")

    def start_qwen(self, source: str) -> tuple[subprocess.Popen[str], Path]:
        output = self.root / f"{source}_m4_full_windows.jsonl"
        log_path = self.root / f"{source}_m4_full_windows.log"
        command = [
            self.args.python, "scripts/build_real_m4_features.py",
            "--eventframes", str(self.root / f"{source}_m1_m2" / "m1_eventframes.jsonl"),
            "--output", str(output),
            "--qwen-model", str(self.args.qwen_model),
            "--m4-checkpoint", str(self.args.m4_checkpoint),
            "--limit", str(line_count(self.root / f"{source}_m1_m2" / "m1_eventframes.jsonl")),
            "--macro-windows", str(self.root / f"{source}_macro_m3.jsonl"),
        ]
        self.source_state(source, status="QWEN_M4_RUNNING", stage="qwen_m4", log=str(log_path), output=str(output))
        self.operation(source=source, stage="qwen_m4", status="STARTED", command=command, log=str(log_path))
        log = log_path.open("w", encoding="utf-8")
        process = subprocess.Popen(command, cwd=Path.cwd(), env=self.env, stdout=log, stderr=subprocess.STDOUT, text=True)
        return process, log_path

    def wait_qwen(self, source: str, process: subprocess.Popen[str], log_path: Path) -> None:
        returncode = process.wait()
        if returncode:
            self.source_state(source, status="QWEN_M4_FAILED", returncode=returncode)
            self.operation(source=source, stage="qwen_m4", status="FAILED", returncode=returncode)
            raise RuntimeError(f"{source} qwen_m4 failed; see {log_path}")
        manifest = self.root / f"{source}_m4_full_windows.manifest.json"
        if not manifest.exists() or read_json(manifest).get("status") != "M4_FEATURES_READY_M5_PENDING":
            raise RuntimeError(f"{source} qwen_m4 completed without a valid manifest")
        self.source_state(source, status="M4_FEATURES_READY", qwen_manifest=str(manifest))
        self.operation(source=source, stage="qwen_m4", status="COMPLETED", manifest=str(manifest))

    def ensure_upstream(self, source: str) -> None:
        m1m2 = self.root / f"{source}_m1_m2"
        m1_manifest = m1m2 / "manifest.json"
        m1_ready = m1_manifest.exists() and read_json(m1_manifest).get("status") == "M1_M2_READY_MACRO_M3_PENDING"
        if not m1_ready:
            raw = self.root / f"{source}_selected_raw.jsonl"
            if not raw.exists():
                raise FileNotFoundError(raw)
            command = [
                self.args.python, "scripts/build_real_m1_m3_features.py",
                "--input", str(raw), "--output", str(m1m2), "--dataset-id", "ait",
                "--m1-model", str(self.args.m1_model), "--limit", str(line_count(raw)),
                "--batch-size", str(self.args.m1_batch_size), "--device", "cuda", "--skip-m3",
            ]
            self.run_stage(source, "m1_m2", command)
        macro = self.root / f"{source}_macro_m3.jsonl"
        macro_manifest = macro.with_suffix(".manifest.json")
        macro_ready = macro_manifest.exists() and read_json(macro_manifest).get("status") == "M3_MACRO_WINDOWS_READY_M4_RETRAIN_PENDING"
        if not macro_ready:
            command = [
                self.args.python, "scripts/build_macro_m3_features.py",
                "--eventframes", str(m1m2 / "m1_eventframes.jsonl"),
                "--windows", str(self.root / f"{source}_windows_selected.jsonl"),
                "--output", str(macro), "--dataset-id", "ait",
            ]
            self.run_stage(source, "macro_m3", command)
        self.source_state(source, status="UPSTREAM_READY", macro_manifest=str(macro_manifest))

    def validate_fox(self) -> None:
        manifest = self.root / "fox_m4_full_windows.manifest.json"
        if not manifest.exists():
            raise FileNotFoundError("Fox full-window M4 manifest is required before continuing")
        metadata = read_json(manifest)
        if metadata.get("status") != "M4_FEATURES_READY_M5_PENDING" or not metadata.get("macro_window_mode"):
            raise RuntimeError("Fox does not have a valid full-window Qwen/M4 artifact")
        self.source_state("fox", status="M4_FEATURES_READY", qwen_manifest=str(manifest), count=metadata.get("count"))

    def run(self) -> None:
        self.validate_fox()
        self.ensure_upstream("harrison")
        active, active_log = self.start_qwen("harrison")
        self.ensure_upstream("santos")
        self.wait_qwen("harrison", active, active_log)
        active, active_log = self.start_qwen("santos")
        self.ensure_upstream("russellmitchell")
        self.wait_qwen("santos", active, active_log)
        active, active_log = self.start_qwen("russellmitchell")
        self.wait_qwen("russellmitchell", active, active_log)
        self.state.update({"status": "ALL_M4_TRAINING_FEATURES_READY", "completed_at": utc_now()})
        self.save_state()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--m1-model", type=Path, required=True)
    parser.add_argument("--qwen-model", type=Path, required=True)
    parser.add_argument("--m4-checkpoint", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--m1-batch-size", type=int, default=8)
    Pipeline(parser.parse_args()).run()


if __name__ == "__main__":
    main()
