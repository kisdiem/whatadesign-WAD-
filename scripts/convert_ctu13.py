from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import time
from pathlib import Path

import _bootstrap


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable(path: Path) -> tuple[bool, int, int]:
    first = path.stat()
    time.sleep(0.05)
    second = path.stat()
    return first.st_size == second.st_size and first.st_mtime_ns == second.st_mtime_ns, second.st_size, second.st_mtime_ns


def clean(row: dict[str, str]) -> tuple[dict[str, str], str]:
    label = row.get("Label", row.get("label", row.get("Class", "")))
    blocked = {"label", "class", "attack", "malicious", "ground_truth", "is_attack", "is_malicious"}
    return {str(k): str(v) for k, v in row.items() if str(k).lower() not in blocked}, str(label)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    source_root, output_root = Path(args.input), Path(args.output)
    output_root.mkdir(parents=True, exist_ok=True)
    manifest_path = output_root / "ctu13_conversion_manifest.json"
    previous = json.loads(manifest_path.read_text(encoding="utf-8")) if args.resume and manifest_path.is_file() else {}
    completed = previous.get("files", {})
    files = sorted(source_root.rglob("*.binetflow"))
    stats = {"discovered_files": len(files), "stable_files": 0, "processed_files": 0, "rejected_files": 0, "raw_count": 0, "label_count": 0, "positive_count": 0, "negative_count": 0, "quarantine_count": 0}
    file_manifest = dict(completed)
    timestamp_min = None; timestamp_max = None
    for path in files:
        key = str(path)
        ok, size, mtime_ns = stable(path)
        if not ok:
            stats["rejected_files"] += 1; file_manifest[key] = {"status": "rejected", "reason": "file_not_stable"}; continue
        stats["stable_files"] += 1
        prior = completed.get(key, {})
        if args.resume and prior.get("status") == "processed" and prior.get("size") == size and prior.get("mtime_ns") == mtime_ns:
            stats["processed_files"] += 1
            for name in ("raw_count", "label_count", "positive_count", "negative_count", "quarantine_count"):
                stats[name] += int(prior.get(name, 0))
            continue
        scenario = path.parent.name
        scenario_dir = output_root / f"scenario_{scenario}"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        raw_path = scenario_dir / "raw_records.jsonl"; label_path = scenario_dir / "labels.jsonl"; quarantine_path = scenario_dir / "quarantine.jsonl"
        source_hash = file_hash(path); raw_count = label_count = positive = negative = quarantine = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle, raw_path.open("a", encoding="utf-8") as raw_out, label_path.open("a", encoding="utf-8") as label_out:
                reader = csv.DictReader(handle)
                for line, row in enumerate(reader, 2):
                    payload, label = clean(row)
                    record_id = hashlib.sha256(f"ctu13|{path}|{line}".encode()).hexdigest()
                    record = {"dataset_id": "ctu13", "record_id": record_id, "timestamp_utc": payload.get("StartTime") or payload.get("Timestamp"), "source_file": str(path), "source_line": line, "source_hash": source_hash, "scenario": scenario, "features": payload}
                    raw_out.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
                    label_text = str(label).lower()
                    positive_flag = not (label_text == "" or "normal" in label_text or "benign" in label_text or "background" in label_text or label_text in {"0", "false"})
                    label_out.write(json.dumps({"dataset_id": "ctu13", "record_id": record_id, "label": int(positive_flag), "label_source": "ctu13_flow_label", "verified": False, "weak_supervision": True, "scenario": scenario}, ensure_ascii=True, sort_keys=True) + "\n")
                    raw_count += 1; label_count += 1; positive += int(positive_flag); negative += int(not positive_flag)
                    timestamp = record["timestamp_utc"]
                    if timestamp and (timestamp_min is None or timestamp < timestamp_min): timestamp_min = timestamp
                    if timestamp and (timestamp_max is None or timestamp > timestamp_max): timestamp_max = timestamp
            stats["processed_files"] += 1
            stats["raw_count"] += raw_count; stats["label_count"] += label_count; stats["positive_count"] += positive; stats["negative_count"] += negative; stats["quarantine_count"] += quarantine
            file_manifest[key] = {"status": "processed", "size": size, "mtime_ns": mtime_ns, "source_hash": source_hash, "scenario": scenario, "raw_count": raw_count, "label_count": label_count, "positive_count": positive, "negative_count": negative, "quarantine_count": quarantine}
        except Exception as exc:
            stats["rejected_files"] += 1; file_manifest[key] = {"status": "rejected", "size": size, "mtime_ns": mtime_ns, "reason": f"{type(exc).__name__}: {exc}"}
    rejected = [key for key, value in file_manifest.items() if value.get("status") == "rejected"]
    result = {"dataset_id": "ctu13", "input_root": str(source_root), "output_root": str(output_root), "resume": args.resume, **stats, "timestamp_min": timestamp_min, "timestamp_max": timestamp_max, "files": file_manifest, "all_stable_files_accounted_for": len(file_manifest) == len(files), "rejected_file_paths": rejected}
    temporary = manifest_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, manifest_path)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if not rejected and result["all_stable_files_accounted_for"] else 2)


if __name__ == "__main__":
    main()
