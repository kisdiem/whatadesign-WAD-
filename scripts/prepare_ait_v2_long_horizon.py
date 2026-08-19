from __future__ import annotations

"""Build a branch-isolated AIT v2 source manifest for M4 and M5.

The output deliberately separates three concerns:

* ``raw_records.jsonl`` and ``feature_targets.jsonl`` contain no labels;
* ``loss_labels.jsonl`` contains event labels for supervised loss only;
* ``attack_intervals.jsonl`` contains the interval supervision used to build
  long-horizon candidates, never model input text.

This is an AIT branch-training protocol, not the previous AIT target-only
evaluation protocol.  The manifest records that change explicitly.
"""

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_SPLITS = {
    "fox": "train",
    "harrison": "train",
    "santos": "train",
    "wardbeck": "train",
    "wheeler": "train",
    "russellmitchell": "validation",
    "shaw": "test",
    "wilson": "test",
}


def parse_time(value: object) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        if text.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def find_timestamp(value: object) -> datetime | None:
    if isinstance(value, dict):
        for key in ("@timestamp", "timestamp", "event_time", "time"):
            parsed = parse_time(value.get(key))
            if parsed:
                return parsed
        for nested in value.values():
            parsed = find_timestamp(nested)
            if parsed:
                return parsed
    return None


def stable_id(scenario: str, path: Path, line_no: int) -> str:
    return hashlib.sha256(f"ait-v2-wazuh|{scenario}|{path}|{line_no}".encode()).hexdigest()


def load_intervals(path: Path) -> dict[str, list[dict]]:
    intervals: dict[str, list[dict]] = defaultdict(list)
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            scenario = str(row["scenario"]).strip()
            start = parse_time(row["start"])
            end = parse_time(row["end"])
            if not scenario or start is None or end is None or end < start:
                raise ValueError(f"invalid AIT interval: {row}")
            intervals[scenario].append({
                "scenario": scenario,
                "attack": str(row["attack"]).strip(),
                "start": start.isoformat(),
                "end": end.isoformat(),
                "start_epoch": start.timestamp(),
                "end_epoch": end.timestamp(),
            })
    return intervals


def row_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def write_jsonl(path: Path, rows) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
            count += 1
    return count


def process_scenario(path: Path, scenario: str, split: str, intervals: list[dict], output: Path, limit: int) -> dict:
    targets = []
    labels = []
    raw_records = []
    macro_members: dict[int, list[str]] = defaultdict(list)
    minimum: datetime | None = None
    maximum: datetime | None = None
    parse_failures = 0
    origin: datetime | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                parse_failures += 1
                continue
            timestamp = find_timestamp(payload)
            if timestamp is None:
                parse_failures += 1
                continue
            if origin is None:
                origin = timestamp
            minimum = timestamp if minimum is None or timestamp < minimum else minimum
            maximum = timestamp if maximum is None or timestamp > maximum else maximum
            record_id = stable_id(scenario, path, line_no)
            raw_records.append({
                "dataset_id": f"ait_v2_wazuh:{scenario}",
                "record_id": record_id,
                "source_file": str(path),
                "source_line": line_no,
                "timestamp": row_timestamp(timestamp),
                "raw_payload": payload,
                "adapter_version": "ait_wazuh_jsonl_v1",
                "labels_in_payload": False,
            })
            # The feature side carries identity/time and sanitized raw content.
            # Labels and attack names are intentionally absent here.
            target = {
                "record_id": record_id,
                "dataset_id": f"ait_v2_wazuh:{scenario}",
                "scenario": scenario,
                "timestamp": row_timestamp(timestamp),
                "source_file": str(path),
                "source_line": line_no,
                "split": split,
                "raw_record_ref": f"{path}:{line_no}",
            }
            targets.append(target)
            epoch = timestamp.timestamp()
            active = [item for item in intervals if item["start_epoch"] <= epoch <= item["end_epoch"]]
            labels.append({"dataset_id": target["dataset_id"], "record_id": record_id, "label": int(bool(active))})
            bucket = int((timestamp - origin).total_seconds() // 1800)
            macro_members[bucket].append(record_id)
            if limit and len(targets) >= limit:
                break

    paired = sorted(zip(targets, labels, raw_records), key=lambda item: (item[0]["timestamp"], item[0]["record_id"]))
    targets = [item[0] for item in paired]
    labels = [item[1] for item in paired]
    raw_records = [item[2] for item in paired]
    scenario_dir = output / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)
    raw_count = write_jsonl(scenario_dir / "raw_records.jsonl", raw_records)
    target_count = write_jsonl(scenario_dir / "feature_targets.jsonl", targets)
    label_count = write_jsonl(scenario_dir / "loss_labels.jsonl", labels)
    macro_rows = []
    macro_labels = []
    if origin is not None:
        for bucket, record_ids in sorted(macro_members.items()):
            start = origin + timedelta(seconds=bucket * 1800)
            end = start + timedelta(seconds=1800)
            window_id = f"ait-m5:{scenario}:{bucket:08d}"
            macro_rows.append({
                "window_id": window_id,
                "dataset_id": f"ait_v2_wazuh:{scenario}",
                "scenario": scenario,
                "split": split,
                "start": row_timestamp(start),
                "end": row_timestamp(end),
                "record_ids": record_ids,
            })
            active_attacks = [item["attack"] for item in intervals if item["start_epoch"] < end.timestamp() and item["end_epoch"] >= start.timestamp()]
            macro_labels.append({
                "window_id": window_id,
                "label": int(bool(active_attacks)),
                "attack_types": sorted(set(active_attacks)),
            })
    write_jsonl(scenario_dir / "m5_feature_windows.jsonl", macro_rows)
    write_jsonl(scenario_dir / "m5_loss_labels.jsonl", macro_labels)
    return {
        "scenario": scenario,
        "split": split,
        "records": target_count,
        "raw_records": raw_count,
        "labels": label_count,
        "macro_windows": len(macro_rows),
        "positive_events": sum(row["label"] for row in labels),
        "positive_macro_windows": sum(row["label"] for row in macro_labels),
        "timestamp_failures": parse_failures,
        "start": row_timestamp(minimum) if minimum else None,
        "end": row_timestamp(maximum) if maximum else None,
        "span_seconds": (maximum - minimum).total_seconds() if minimum and maximum else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-records-per-scenario", type=int, default=0)
    parser.add_argument("--split-map", default="")
    args = parser.parse_args()
    raw_dir = Path(args.raw_dir)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    split_map = dict(DEFAULT_SPLITS)
    if args.split_map:
        for item in args.split_map.split(","):
            scenario, split = item.split("=", 1)
            split_map[scenario.strip()] = split.strip()
    if set(split_map.values()) != {"train", "validation", "test"}:
        raise ValueError("split map must contain train, validation, and test")
    all_intervals = load_intervals(Path(args.labels))
    summaries = []
    for path in sorted(raw_dir.glob("*_wazuh.json")):
        scenario = path.name.removesuffix("_wazuh.json")
        if scenario not in split_map:
            raise ValueError(f"scenario missing from split map: {scenario}")
        summaries.append(process_scenario(path, scenario, split_map[scenario], all_intervals.get(scenario, []), output, args.max_records_per_scenario))
    if not summaries:
        raise ValueError(f"no *_wazuh.json files under {raw_dir}")
    manifest = {
        "schema_version": "ait-v2-branch-training-v1",
        "protocol": "ait_branch_generalization_v1",
        "warning": "AIT is used for source training/validation/test in this manifest; it is not target-only evaluation.",
        "labels_separated_from_features": True,
        "macro_seconds": 1800,
        "micro_seconds": 300,
        "stride_seconds": 150,
        "split_map": split_map,
        "scenarios": summaries,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (output / "attack_intervals.jsonl").write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for rows in all_intervals.values() for row in rows), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
