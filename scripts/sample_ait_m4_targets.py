from __future__ import annotations

"""Select balanced, deterministic AIT v2 targets for supervised M4 training.

The full branch manifest remains the source of truth.  This script only makes
a smaller loss manifest for M4; feature rows still contain no labels.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def epoch(value: str) -> float:
    from datetime import datetime
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.timestamp()


def select_evenly(rows: list[dict], limit: int) -> list[dict]:
    if len(rows) <= limit:
        return rows
    stride = len(rows) / limit
    return [rows[min(len(rows) - 1, int(index * stride))] for index in range(limit)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--positive-per-scenario", type=int, default=400)
    parser.add_argument("--negative-per-scenario", type=int, default=400)
    args = parser.parse_args()
    source = Path(args.input_dir)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    intervals = defaultdict(list)
    for row in read_jsonl(source / "attack_intervals.jsonl"):
        intervals[row["scenario"]].append(row)
    summaries = []
    for scenario_dir in sorted(item for item in source.iterdir() if item.is_dir()):
        scenario = scenario_dir.name
        targets = list(read_jsonl(scenario_dir / "feature_targets.jsonl"))
        labels = {row["record_id"]: int(row["label"]) for row in read_jsonl(scenario_dir / "loss_labels.jsonl")}
        positive_by_attack = defaultdict(list)
        negatives = []
        for row in targets:
            stamp = epoch(row["timestamp"])
            active = [item["attack"] for item in intervals[scenario] if item["start_epoch"] <= stamp <= item["end_epoch"]]
            if active:
                positive_by_attack[sorted(set(active))[0]].append(row)
            else:
                negatives.append(row)
        attacks = sorted(positive_by_attack)
        per_attack = max(1, args.positive_per_scenario // max(1, len(attacks)))
        positives = []
        for attack in attacks:
            positives.extend(select_evenly(positive_by_attack[attack], per_attack))
        positives = select_evenly(sorted(positives, key=lambda row: (row["timestamp"], row["record_id"])), args.positive_per_scenario)
        negatives = select_evenly(sorted(negatives, key=lambda row: (row["timestamp"], row["record_id"])), args.negative_per_scenario)
        selected = sorted(positives + negatives, key=lambda row: (row["timestamp"], row["record_id"]))
        selected_ids = {row["record_id"] for row in selected}
        split = str(selected[0]["split"]) if selected else "unknown"
        out_dir = output / scenario
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "feature_targets.jsonl").open("w", encoding="utf-8") as handle:
            for row in selected:
                clean = {key: value for key, value in row.items() if key not in {"label", "attack", "attack_type"}}
                handle.write(json.dumps(clean, ensure_ascii=True) + "\n")
        with (out_dir / "loss_labels.jsonl").open("w", encoding="utf-8") as handle:
            for row in selected:
                handle.write(json.dumps({"dataset_id": row["dataset_id"], "record_id": row["record_id"], "label": labels[row["record_id"]]}, ensure_ascii=True) + "\n")
        summaries.append({"scenario": scenario, "split": split, "selected": len(selected), "positive": len(positives), "negative": len(negatives), "attack_types": attacks})
    manifest = {"schema_version": "ait-v2-m4-sample-v1", "source_manifest": str(source / "manifest.json"), "labels_separated_from_features": True, "summaries": summaries}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
