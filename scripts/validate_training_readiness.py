from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap
from src.pipeline.pipeline_config import load_config, save_resolved_config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config_path = Path(args.config)
    try:
        config, config_hash = load_config(config_path)
    except Exception as exc:
        result = {"status": "BLOCKED_INVALID_CONFIG", "reason": str(exc)}
    else:
        missing = []
        for source in config.get("data_sources", []):
            root = str(source.get("root", "")).strip()
            if source.get("enabled") and (not root or not Path(root).exists()):
                missing.append(source["id"])
        weights = config.get("model_cache", "")
        if missing:
            result = {"status": "BLOCKED_MISSING_DATA", "missing_sources": missing, "config_hash": config_hash}
        elif config.get("execution_mode") == "source" and (not str(weights).strip() or not Path(weights).exists()):
            result = {"status": "BLOCKED_MISSING_WEIGHTS", "missing_weights": weights or "MODEL_CACHE is unset", "config_hash": config_hash}
        else:
            result = {"status": "READY", "config_hash": config_hash, "missing_sources": []}
        save_resolved_config(config, Path(args.output).with_name("resolved_config.yaml"))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "READY" else 2)


if __name__ == "__main__":
    main()
