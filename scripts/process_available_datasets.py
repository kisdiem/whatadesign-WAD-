"""Stream available replacement sources into auditable M0-ready JSONL artifacts.

This intentionally never reads AIT as training data and never converts source labels
into APT labels.  It preserves each dataset boundary and quarantines malformed,
missing-timestamp, and duplicate records instead of silently dropping them.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap
from src.common.manifest import current_commit, sha256_file
from src.common.schema import RawRecord
from src.parsers.m0_parser import M0Parser
from src.pipeline.stage_runtime import write_jsonl

TIME_RE = re.compile(r"(?:TimeCreated[^>]+SystemTime='|UtcTime'?>|timestamp[=:])\s*([^<'\s,]+(?:[ T][^<'\s,]+)?)", re.I)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record(dataset: str, path: str, line: int, timestamp: str | None, payload: str | dict, version: str) -> RawRecord:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True) if isinstance(payload, dict) else str(payload)
    source_hash = hashlib.sha256(encoded.encode()).hexdigest()
    return RawRecord(dataset, path, line, timestamp, payload, version, version,
                     hashlib.sha256(f"{dataset}|{path}|{line}".encode()).hexdigest(), source_hash)


def iter_csv(path: Path, dataset: str):
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for line, row in enumerate(csv.DictReader(stream), 2):
            timestamp = row.get("Timestamp") or row.get("StartTime") or row.get("timestamp")
            yield record(dataset, str(path), line, timestamp, dict(row), "csv_stream_v1")


def iter_text(path: Path, dataset: str):
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line, text in enumerate(stream, 1):
            text = text.rstrip("\r\n")
            if not text.strip():
                continue
            match = TIME_RE.search(text)
            timestamp = match.group(1) if match else None
            yield record(dataset, str(path), line, timestamp, text, "text_stream_v1")


def iter_sources(root: Path):
    sandworm = root / "replacement_sources/sandworm/SandwormAPT_flow_labelled.csv"
    if sandworm.is_file():
        yield "sandworm_flow", sandworm, iter_csv(sandworm, "sandworm_flow")
    for path in sorted((root / "replacement_sources/ctu13").glob("scenario_*/*")):
        # Scenario 1/10 are still being downloaded.  Do not process mutable files.
        if path.parent.name == "scenario_5" and path.is_file() and not path.name.endswith(".part"):
            yield "ctu13_selected", path, iter_csv(path, "ctu13_selected")
    for path in sorted((root / "replacement_sources/splunk_attack_data").rglob("*.log")):
        yield "splunk_attack_data", path, iter_text(path, "splunk_attack_data")


def process_dataset(dataset: str, source: Path, records, out_root: Path) -> dict:
    target = out_root / dataset / source.stem
    target.mkdir(parents=True, exist_ok=True)
    parser = M0Parser()
    seen: set[str] = set()
    raw_count = parsed_count = rejected_count = duplicate_count = 0
    raw_path = target / "raw_records.jsonl"
    syntax_path = target / "syntax_parses.jsonl"
    quarantine_path = target / "quarantine.jsonl"

    # First seal a raw JSONL snapshot.  The second pass reads that immutable
    # snapshot, so parsing cannot race a background downloader.
    materialized = []
    for raw in records:
        raw_count += 1
        if raw.source_hash in seen:
            duplicate_count += 1
            continue
        seen.add(raw.source_hash)
        materialized.append(raw)
    write_jsonl(raw_path, (row.to_dict() for row in materialized))

    parsed = [parser.parse(raw) for raw in materialized if raw.source_hash in seen]
    parsed_count = len(parsed)
    rejected_count = sum(item.quarantined for item in parsed)
    write_jsonl(syntax_path, (item.to_dict() for item in parsed if not item.quarantined))
    write_jsonl(quarantine_path, (item.to_dict() for item in parsed if item.quarantined))
    manifest = {
        "stage": "available_dataset_processing",
        "dataset_id": dataset,
        "status": "COMPLETED",
        "execution_mode": "real_source_preprocessing",
        "git_commit": current_commit(Path(__file__).resolve().parents[1]),
        "source_path": str(source),
        "source_hash": sha256_file(source),
        "raw_count": raw_count,
        "parsed_count": parsed_count - rejected_count,
        "quarantine_count": rejected_count,
        "duplicate_count": duplicate_count,
        "outputs": {str(p.name): sha256_file(p) for p in (raw_path, syntax_path, quarantine_path)},
        "real_data_used": True,
        "labels_used_as_apt_targets": False,
        "ait_accessed": False,
        "started_at": now(),
        "completed_at": now(),
    }
    (target / "processing_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", default="/root/autodl-tmp/semantic-graph-apt/data")
    parser.add_argument("--output-root", default="/root/autodl-tmp/semantic-graph-apt/data/processed_available")
    args = parser.parse_args()
    root, output = Path(args.data_root), Path(args.output_root)
    manifests = []
    for dataset, source, records in iter_sources(root):
        manifests.append(process_dataset(dataset, source, records, output))
    summary = {"status": "COMPLETED", "datasets": manifests, "ait_accessed": False, "cert_accessed": False, "labels_used_as_apt_targets": False}
    (output / "processing_manifest.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": summary["status"], "datasets": [(m["dataset_id"], m["raw_count"], m["quarantine_count"]) for m in manifests]}, indent=2))


if __name__ == "__main__":
    main()
