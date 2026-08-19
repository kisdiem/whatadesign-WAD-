"""Write a label-free ATT&CK candidate sidecar from EventFrame JSONL."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from _bootstrap import *  # noqa: F401,F403
from src.common.schema import EventFrame
from src.knowledge.attack_mapping import mapping_record


def _observables(row: dict) -> dict:
    """Extract only descriptive security facts from a raw Wazuh/IDS record."""
    payload = row.get("raw_payload") if isinstance(row.get("raw_payload"), dict) else row
    decoder = payload.get("decoder") if isinstance(payload.get("decoder"), dict) else {}
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    return {
        "message": str(payload.get("full_log", "")),
        "decoder_name": str(decoder.get("name", "")),
        "rule_id": str(rule.get("id", "")),
        "rule_level": str(rule.get("level", "")),
        "rule_description": str(rule.get("description", "")),
        "rule_groups": [str(value) for value in rule.get("groups", [])] if isinstance(rule.get("groups"), list) else [],
        "location": str(payload.get("location", "")),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eventframes", type=Path, required=True)
    parser.add_argument("--raw-records", type=Path, help="optional raw records keyed by record_id")
    parser.add_argument("--policy", choices=("balanced", "balanced_plus", "recall_first"), default="balanced")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw_by_id = {}
    if args.raw_records:
        with args.raw_records.open(encoding="utf-8") as raw_source:
            for line in raw_source:
                if line.strip():
                    row = json.loads(line)
                    raw_by_id[str(row.get("record_id", ""))] = _observables(row)
    total = mapped = raw_joined = 0
    with args.eventframes.open(encoding="utf-8") as source, args.output.open("w", encoding="utf-8") as sink:
        for line_no, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                frame = EventFrame.from_dict(json.loads(line))
                observables = raw_by_id.get(frame.record_id)
                row = mapping_record(frame, observables, args.policy)
            except Exception as exc:
                raise ValueError(f"mapping failed at {args.eventframes}:{line_no}") from exc
            sink.write(json.dumps(row, ensure_ascii=False) + "\n")
            total += 1
            mapped += int(bool(row["candidates"]))
            raw_joined += int(observables is not None)
    print(json.dumps({"status": "COMPLETED", "policy": args.policy, "events": total, "raw_joined_events": raw_joined, "mapped_events": mapped, "unknown_events": total - mapped, "output": str(args.output)}))


if __name__ == "__main__":
    main()
