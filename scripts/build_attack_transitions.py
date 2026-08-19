"""Build sparse M5 ATT&CK transition candidates from fact-only sidecars."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from _bootstrap import *  # noqa: F401,F403
from src.common.schema import EventFrame
from src.temporal.attack_transition import TransitionConfig, build_transition_candidates


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--eventframes", type=Path, required=True)
    parser.add_argument("--mappings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-gap-hours", type=float, default=24.0)
    parser.add_argument("--min-confidence", type=float, default=0.55)
    parser.add_argument("--max-predecessors", type=int, default=8)
    args = parser.parse_args()
    config = TransitionConfig(min_confidence=args.min_confidence, max_gap_seconds=int(args.max_gap_hours * 3600), max_predecessors_per_event=args.max_predecessors)
    transitions = build_transition_candidates((EventFrame.from_dict(row) for row in read_jsonl(args.eventframes)), read_jsonl(args.mappings), config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row.to_dict(), ensure_ascii=False) + "\n" for row in transitions), encoding="utf-8")
    print(json.dumps({"status": "COMPLETED", "transitions": len(transitions), "config": config.__dict__, "output": str(args.output)}))


if __name__ == "__main__": main()
