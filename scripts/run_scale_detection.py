from __future__ import annotations

import argparse
import json

import _bootstrap
from src.detection.engine import ScalableDetectionEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded-memory two-pass detection over heterogeneous log roots.")
    parser.add_argument("--root", action="append", required=True, help="Repeat for each source root.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-records", type=int, default=0, help="Per-pass cap; 0 scans all discovered logs.")
    parser.add_argument("--top-k", type=int, default=20_000)
    parser.add_argument("--sketch-width", type=int, default=1 << 16)
    parser.add_argument("--mode", choices=("online", "two-pass"), default="online")
    args = parser.parse_args()
    engine = ScalableDetectionEngine()
    method = engine.run_roots_online if args.mode == "online" else engine.run_roots
    result = method(args.root, args.output_dir, max_records=args.max_records,
                    top_k=args.top_k, sketch_width=args.sketch_width)
    print(json.dumps(result.manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
