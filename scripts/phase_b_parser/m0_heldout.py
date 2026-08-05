from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.common.audit import append_operation
from src.common.schema import RawRecord
from src.parsers.m0_drain import M0DrainParser
from src.parsers.m0_metrics import evaluate_m0, timed_parse


def main() -> None:
    parser = argparse.ArgumentParser(description="Run M0 on a held-out JSONL fixture.")
    parser.add_argument("input", type=Path, help="JSONL with dataset_id, source_file, source_line, message, gold_template")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    for line_no, line in enumerate(args.input.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        rows.append((item, RawRecord(
            item.get("dataset_id", "heldout"), item.get("source_file", str(args.input)),
            int(item.get("source_line", line_no)), item.get("timestamp"), item["message"], M0DrainParser.VERSION,
        )))

    m0 = M0DrainParser()
    parsed, elapsed = timed_parse(m0, (record for _, record in rows))
    gold = [str(item["gold_template"]) for item, _ in rows]
    predicted = [str(result.fields["template"]) for result in parsed]
    metrics = evaluate_m0(gold, predicted, elapsed, len(rows))
    result = {
        "protocol": "m0_heldout",
        "split": "heldout",
        "rows": len(rows),
        "metrics": metrics.__dict__,
        "parser_version": M0DrainParser.VERSION,
        "ait_accessed": False,
        "input": str(args.input),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    append_operation(args.output.parents[2] / "logs/operations.jsonl", "m0_heldout", "completed", **result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
