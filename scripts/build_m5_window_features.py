"""Aggregate real M4 current-event features into labeled M5 window inputs.

Labels are read only for the separate training-label output.  They never enter
the M1/M4 feature construction or the emitted FrozenFeatureRecord fields.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--m4-features", type=Path, required=True)
    p.add_argument("--windows", type=Path, required=True)
    p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    features = {}
    with args.m4_features.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                features[row["record_id"]] = row
    labels = {}
    with args.labels.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                labels[row["window_id"]] = int(row["label"])

    output_rows = []
    missing = defaultdict(int)
    with args.windows.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            window = json.loads(line)
            members = [features[record_id] for record_id in window["record_ids"] if record_id in features]
            if not members:
                missing["no_m4_members"] += 1
                continue
            dim = len(members[0]["event_embedding"])
            pooled = [sum(float(row["event_embedding"][i]) for row in members) / len(members) for i in range(dim)]
            output_rows.append({
                "record_id": window["window_id"],
                "dataset_id": window["dataset_id"],
                "timestamp": window["end"],
                "event_embedding": pooled,
                "raw_event_score": max(float(row["raw_event_score"]) for row in members),
                "micro_window_score": max(float(row["micro_window_score"]) for row in members),
                "macro_window_score": max(float(row["macro_window_score"]) for row in members),
                "source_record_ref": window["window_id"],
                "window_record_count": len(window["record_ids"]),
                "m4_member_count": len(members),
                "m5_score": None,
                "m5_status": "PENDING_TRAINED_M5",
            })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in output_rows), encoding="utf-8")
    label_path = args.output.with_name(args.output.stem + ".labels.jsonl")
    label_path.write_text("".join(json.dumps({"record_id": row["record_id"], "label": labels[row["record_id"]]}) + "\n" for row in output_rows if row["record_id"] in labels), encoding="utf-8")
    m4_hash = hashlib.sha256(args.m4_features.read_bytes()).hexdigest()
    manifest = {
        "status": "M5_INPUTS_READY_M5_TRAINING_PENDING",
        "count": len(output_rows),
        "labels_read_for_separate_file": True,
        "feature_labels_joined": sum(row["record_id"] in labels for row in output_rows),
        "m4_features_sha256": m4_hash,
        "m5_score": "not_generated",
        "missing": dict(missing),
    }
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
