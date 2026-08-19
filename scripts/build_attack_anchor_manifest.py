"""Merge auditable ATT&CK supervision sources without losing provenance."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


REQUIRED = {"record_id", "technique_id", "provenance", "confidence"}


def build_manifest(inputs: list[Path], output: Path, summary_output: Path) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    source_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    for source in inputs:
        for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            missing = REQUIRED.difference(row)
            if missing:
                raise ValueError(f"{source}:{line_number} missing {sorted(missing)}")
            key = (str(row["record_id"]), str(row["technique_id"]))
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
            source_counts[source.name] += 1
            technique_counts[str(row["technique_id"])] += 1
    rows.sort(key=lambda row: (str(row["technique_id"]), str(row["record_id"])))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    summary: dict[str, object] = {
        "anchor_count": len(rows),
        "by_source": dict(sorted(source_counts.items())),
        "by_technique": dict(sorted(technique_counts.items())),
        "manifest": str(output),
    }
    summary_output.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_manifest(args.input, args.output, args.summary_output), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
