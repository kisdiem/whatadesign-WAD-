from __future__ import annotations

"""Audit AIT v2 raw JSONL timelines without consuming labels as features."""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


TIMESTAMP_KEYS = ("@timestamp", "timestamp", "event_time", "time")


def parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def find_timestamp(value: object) -> datetime | None:
    if isinstance(value, dict):
        for key in TIMESTAMP_KEYS:
            parsed = parse(value.get(key))
            if parsed:
                return parsed
        for nested in value.values():
            parsed = find_timestamp(nested)
            if parsed:
                return parsed
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--suffix", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = []
    for path in sorted(Path(args.raw_dir).glob(f"*_{args.suffix}.json")):
        count = parsed = 0
        minimum = maximum = None
        sources: Counter[str] = Counter()
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                count += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                stamp = find_timestamp(row)
                if stamp:
                    parsed += 1
                    minimum = stamp if minimum is None or stamp < minimum else minimum
                    maximum = stamp if maximum is None or stamp > maximum else maximum
                source = row.get("location") or row.get("source") or row.get("predecoder", {}).get("program_name")
                if source:
                    sources[str(source)] += 1
        result.append({"scenario": path.name.removesuffix(f"_{args.suffix}.json"), "kind": args.suffix, "records": count,
                       "parseable_timestamps": parsed, "start": minimum.isoformat() if minimum else None,
                       "end": maximum.isoformat() if maximum else None,
                       "span_seconds": (maximum - minimum).total_seconds() if minimum and maximum else None,
                       "top_sources": sources.most_common(10)})
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
