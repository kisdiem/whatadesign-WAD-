from __future__ import annotations

import argparse
import json

import _bootstrap
from src.detection import DetectionEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="Run WAD detection on an unlabelled JSONL log file.")
    parser.add_argument("--input", required=True, help="Unlabelled JSONL. label/ground_truth fields are rejected.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--variant", choices=("full", "unsupervised_only", "weak_only", "without_entity_rarity"), default="full")
    parser.add_argument("--no-chain", action="store_true")
    args = parser.parse_args()
    result = DetectionEngine().run(args.input, args.output_dir, args.variant, not args.no_chain)
    print(json.dumps(result.manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
