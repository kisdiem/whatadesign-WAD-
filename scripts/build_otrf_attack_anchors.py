"""Extract content-evidenced ATT&CK anchors from OTRF JSONL telemetry."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from src.knowledge.attack_techniques import TechniqueSupervision, validate_event_payload


def is_eventlog_service_disabled(row: dict[str, object]) -> bool:
    """Recognize an explicit EventLog service startup disable, not generic registry use."""
    message = str(row.get("Message", "")).lower()
    event_id = str(row.get("EventID", ""))
    target = str(row.get("TargetObject", row.get("ObjectName", ""))).lower()
    details = str(row.get("Details", row.get("NewValue", ""))).lower()
    command = "services\\eventlog" in message and "/v start" in message and "/d 4" in message
    registry_change = event_id in {"4657", "13"} and "services\\eventlog" in target and target.endswith("\\start") and ("0x00000004" in details or details == "4")
    return command or registry_change


def stable_record_id(source: Path, line_number: int, row: dict[str, object]) -> str:
    digest = hashlib.sha256(f"{source}|{line_number}|{json.dumps(row, sort_keys=True)}".encode()).hexdigest()
    return f"otrf-anchor-{digest[:24]}"


def build(source: Path, event_output: Path, supervision_output: Path) -> Counter[str]:
    event_output.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    with source.open(encoding="utf-8") as raw, event_output.open("w", encoding="utf-8") as events, supervision_output.open("w", encoding="utf-8") as supervision:
        for line_number, line in enumerate(raw, start=1):
            row = json.loads(line)
            validate_event_payload(row)
            if not is_eventlog_service_disabled(row):
                continue
            record_id = stable_record_id(source, line_number, row)
            technique_id = "T1562.001"
            event = {
                "record_id": record_id,
                "dataset_id": "otrf_security_datasets",
                "raw_format": "jsonl_windows_event",
                "raw_payload": row,
                "source_file": str(source),
                "source_record_index": line_number,
                "parser_version": "otrf_jsonl_v1",
                "anchor_rule_id": "eventlog_service_start_disabled",
            }
            events.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            supervision.write(json.dumps(TechniqueSupervision(
                record_id=record_id,
                technique_id=technique_id,
                provenance="otrf_security_datasets/content_rule:eventlog_service_start_disabled",
                confidence=0.95,
                reviewer="codex-audited-rule-v1",
                notes="OTRF raw JSONL event with explicit EventLog service Start=4 disable evidence; scenario directory is provenance only.",
            ).to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
            counts[technique_id] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--event-output", type=Path, required=True)
    parser.add_argument("--supervision-output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({"total": sum(build(args.source, args.event_output, args.supervision_output).values())}))


if __name__ == "__main__":
    main()
