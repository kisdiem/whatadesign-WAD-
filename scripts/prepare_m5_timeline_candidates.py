from __future__ import annotations

"""Materialize auditable M5 long-horizon timeline candidates.

Labels are used only to create a separate supervision audit.  The feature
manifest deliberately contains event identity and time only; M2/M4 features
are joined later from frozen artifacts.
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def rows(path: str):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line:
            yield json.loads(line)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare source-only M5 timeline candidates")
    parser.add_argument("--targets", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--macro-seconds", type=int, default=1800)
    parser.add_argument("--max-gap-hours", type=float, default=24.0)
    args = parser.parse_args()
    labels = {(row["dataset_id"], row["record_id"]): int(row["label"]) for row in rows(args.labels)}
    source = [row for row in rows(args.targets) if row["dataset_id"] == args.dataset]
    source.sort(key=lambda row: (utc(row["timestamp"]), row["record_id"]))
    if not source:
        raise ValueError(f"no targets for dataset {args.dataset}")
    origin = utc(source[0]["timestamp"])
    buckets: dict[int, list[dict]] = defaultdict(list)
    for row in source:
        bucket = int((utc(row["timestamp"]) - origin).total_seconds() // args.macro_seconds)
        buckets[bucket].append(row)
    feature_rows, supervision_rows = [], []
    for bucket, members in sorted(buckets.items()):
        start = origin + timedelta(seconds=bucket * args.macro_seconds)
        end = start + timedelta(seconds=args.macro_seconds)
        window_id = f"m5:{args.dataset}:{bucket:08d}"
        feature_rows.append({"window_id": window_id, "dataset_id": args.dataset, "start": start.isoformat(), "end": end.isoformat(), "record_ids": [row["record_id"] for row in members]})
        supervision_rows.append({"window_id": window_id, "positive_events": sum(labels[(row["dataset_id"], row["record_id"])] for row in members), "event_count": len(members)})
    output = Path(args.output_dir); output.mkdir(parents=True, exist_ok=True)
    (output / f"{args.dataset}_feature_manifest.jsonl").write_text("".join(json.dumps(row) + "\n" for row in feature_rows), encoding="utf-8")
    (output / f"{args.dataset}_supervision_audit.jsonl").write_text("".join(json.dumps(row) + "\n" for row in supervision_rows), encoding="utf-8")
    manifest = {"dataset": args.dataset, "windows": len(feature_rows), "macro_seconds": args.macro_seconds, "max_gap_hours": args.max_gap_hours, "labels_separated_from_features": True}
    (output / f"{args.dataset}_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
