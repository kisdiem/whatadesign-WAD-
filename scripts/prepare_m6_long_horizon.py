"""Build and validate the AIT-dominant M6 training contract.

This command never creates embeddings.  It combines an already-exported
FrozenFeatureRecord JSONL with an explicit split manifest and fails closed if
the upstream M1-M5 frozen export is missing or incomplete.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from _bootstrap import *  # noqa: F401,F403
from src.training.m6_data import M6Split, read_labels, read_records, validate_split, write_split


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-features", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--ait-train", type=Path, required=True)
    parser.add_argument("--ait2-train", type=Path, required=True)
    parser.add_argument("--ait2-validation", type=Path, required=True)
    parser.add_argument("--ait2-test", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    records = read_records(args.frozen_features)
    labels = read_labels(args.labels)
    groups = {
        "train": set(json.loads(args.ait_train.read_text(encoding="utf-8"))),
        "ait2_train": set(json.loads(args.ait2_train.read_text(encoding="utf-8"))),
        "validation": set(json.loads(args.ait2_validation.read_text(encoding="utf-8"))),
        "test": set(json.loads(args.ait2_test.read_text(encoding="utf-8"))),
    }
    split = M6Split(
        train=tuple(sorted(groups["train"] | groups["ait2_train"])),
        validation=tuple(sorted(groups["validation"])),
        test=tuple(sorted(groups["test"])),
    )
    validate_split(split, records, labels)
    write_split(args.output, split, {
        "frozen_features": str(args.frozen_features),
        "labels": str(args.labels),
        "ait_train_count": len(groups["train"]),
        "ait2_train_count": len(groups["ait2_train"]),
        "ait2_validation_count": len(groups["validation"]),
        "ait2_test_count": len(groups["test"]),
    })
    print(json.dumps({"status": "READY", "train": len(split.train), "validation": len(split.validation), "test": len(split.test)}))


if __name__ == "__main__":
    main()
