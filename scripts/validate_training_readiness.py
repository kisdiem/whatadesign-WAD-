from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import _bootstrap
from src.pipeline.pipeline_config import load_config, save_resolved_config


def _readable_path(value: str) -> bool:
    path = Path(value)
    return path.exists() and any(path.iterdir()) if path.is_dir() else path.is_file()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("smoke", "train", "infer"), default=None)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        config, config_hash = load_config(args.config)
    except Exception as exc:
        result = {
            "status": "BLOCKED_INVALID_CONFIG",
            "mode": args.mode,
            "blocking_reasons": [str(exc)],
        }
    else:
        mode = args.mode or ("train" if config.get("execution_mode") == "source" else "smoke")
        data_checks = []
        missing_sources = []
        for source in config.get("data_sources", []):
            if not source.get("enabled"):
                continue
            root = str(source.get("root", "")).strip()
            available = bool(root) and _readable_path(root)
            data_checks.append({"id": source.get("id"), "root": root, "readable": available})
            if not available:
                missing_sources.append(source.get("id", "unknown"))

        reasons = []
        if missing_sources:
            reasons.append(f"enabled data sources unavailable: {', '.join(missing_sources)}")

        weights = str(config.get("model_cache", "")).strip()
        if config.get("execution_mode") == "source" and not _readable_path(weights):
            reasons.append(f"model cache unavailable: {weights or 'MODEL_CACHE is unset'}")

        source_entry = Path("scripts/run_source_v3_pipeline.py")
        if config.get("execution_mode") == "source" and not source_entry.is_file():
            reasons.append(f"source pipeline entry missing: {source_entry}")

        if mode == "train":
            ctu = next((item for item in config.get("data_sources", []) if item.get("adapter") == "ctu13"), None)
            if ctu and ctu.get("enabled") and not _readable_path(str(ctu.get("root", ""))):
                reasons.append("CTU-13 stable conversion prerequisite is unavailable")

        if reasons:
            status = "BLOCKED_MISSING_DATA" if missing_sources else "BLOCKED_INCOMPLETE_PREPROCESSING"
        else:
            status = "READY"
        result = {
            "status": status,
            "mode": mode,
            "config_hash": config_hash,
            "git_commit": os.popen("git rev-parse HEAD 2>/dev/null").read().strip(),
            "data_checks": data_checks,
            "model_checks": {"model_cache": weights, "readable": _readable_path(weights)},
            "pipeline_checks": {"source_entry": str(source_entry), "exists": source_entry.is_file()},
            "missing_items": missing_sources,
            "blocking_reasons": reasons,
            "warnings": ["DARPA TC, LANL, CERT and AIT are not required source inputs for this configuration."],
        }
        save_resolved_config(config, output.with_name("resolved_config.yaml"))

    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "READY" else 2)


if __name__ == "__main__":
    main()
