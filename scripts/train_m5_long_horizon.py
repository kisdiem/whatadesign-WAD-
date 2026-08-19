"""Train M5 from frozen M4 windows and export strict M6 inputs.

The available datasets provide window anomaly labels, not human annotated
window-to-window attack-chain links.  This script therefore uses a clearly
labelled weak target: two anomalous windows from the same source, separated by
the configured long-horizon interval, are positive pairs.  It is intended for
development only and records that provenance in every report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime
from pathlib import Path

import torch
from torch import nn

from _bootstrap import *  # noqa: F401,F403
from src.common.schema import FrozenFeatureRecord
from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def source_name(row: dict) -> str:
    return str(row["dataset_id"]).rsplit(":", 1)[-1]


def load_rows(inputs: list[Path], labels: list[Path], source_names: list[str]) -> list[dict]:
    if len(inputs) != len(labels) or len(inputs) != len(source_names):
        raise ValueError("inputs, labels, and source_names must have the same count")
    result = []
    for features_path, labels_path, input_source in zip(inputs, labels, source_names):
        label_by_id = {str(row["record_id"]): int(row["label"]) for row in read_jsonl(labels_path)}
        for row in read_jsonl(features_path):
            record_id = str(row["record_id"])
            if record_id not in label_by_id:
                raise ValueError(f"missing label for {record_id}")
            row["_label"] = label_by_id[record_id]
            # Dataset IDs are occasionally shared across independent source files.
            # The caller therefore supplies the audited source partition explicitly.
            row["_source"] = input_source
            row["_time"] = datetime.fromisoformat(str(row["timestamp"]))
            result.append(row)
    if len({len(row["event_embedding"]) for row in result}) != 1:
        raise ValueError("inconsistent event embedding dimensions")
    return result


def pairs(rows: list[dict], min_hours: float, max_hours: float, negative_ratio: int, seed: int):
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["_source"], []).append(row)
    positives, negatives = [], []
    for source_rows in grouped.values():
        source_rows.sort(key=lambda row: (row["_time"], row["record_id"]))
        for index, left in enumerate(source_rows):
            for right in source_rows[index + 1:]:
                hours = (right["_time"] - left["_time"]).total_seconds() / 3600
                if hours < min_hours:
                    continue
                if hours > max_hours:
                    break
                (positives if left["_label"] and right["_label"] else negatives).append((left, right, hours))
    rng = random.Random(seed)
    rng.shuffle(negatives)
    negatives = negatives[: max(len(positives) * negative_ratio, 1)]
    result = positives + negatives
    rng.shuffle(result)
    return result, len(positives), len(negatives)


def tensor_pairs(items, device):
    return (
        torch.tensor([x[0]["event_embedding"] for x in items], dtype=torch.float32, device=device),
        torch.tensor([x[1]["event_embedding"] for x in items], dtype=torch.float32, device=device),
        torch.tensor([x[2] * 3600 for x in items], dtype=torch.float32, device=device),
        torch.tensor([int(x[0]["_label"] and x[1]["_label"]) for x in items], dtype=torch.float32, device=device),
    )


def auc(labels, scores):
    positives = sum(labels); negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    ranked = sorted(zip(scores, labels), key=lambda row: row[0])
    rank_sum = sum(index + 1 for index, (_, label) in enumerate(ranked) if label)
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def metric(model, batch):
    with torch.no_grad():
        scores = torch.sigmoid(model(batch[0], batch[1], batch[2])).detach().cpu().tolist()
    labels = [int(value) for value in batch[3].detach().cpu().tolist()]
    return {"roc_auc": auc(labels, scores), "positive_pairs": sum(labels), "pairs": len(labels)}


def export_frozen(rows, model, checkpoint_hash, output: Path, device, min_hours, max_hours):
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["_source"], []).append(row)
    records = []
    for source_rows in grouped.values():
        source_rows.sort(key=lambda row: (row["_time"], row["record_id"]))
        for index, row in enumerate(source_rows):
            candidates = []
            for prior in source_rows[:index]:
                hours = (row["_time"] - prior["_time"]).total_seconds() / 3600
                if min_hours <= hours <= max_hours:
                    candidates.append((prior, hours))
            score = 0.0
            if candidates:
                left = torch.tensor([x[0]["event_embedding"] for x in candidates], dtype=torch.float32, device=device)
                right = torch.tensor([row["event_embedding"]] * len(candidates), dtype=torch.float32, device=device)
                delta = torch.tensor([x[1] * 3600 for x in candidates], dtype=torch.float32, device=device)
                with torch.no_grad(): score = float(torch.sigmoid(model(left, right, delta)).max().item())
            records.append(FrozenFeatureRecord(
                record_id=str(row["record_id"]), dataset_id=str(row["dataset_id"]), timestamp=str(row["timestamp"]),
                event_embedding=[float(v) for v in row["event_embedding"]], graph_score=0.0,
                raw_event_score=float(row.get("raw_event_score", 0.0)), micro_window_score=float(row.get("micro_window_score", 0.0)),
                macro_window_score=float(row.get("macro_window_score", 0.0)), long_horizon_score=score,
                queue_features={"m5_pair_target": "weak_window_anomaly_pair_v1", "candidate_count": len(candidates)},
                source_record_ref=str(row.get("source_record_ref", row["record_id"])),
                producer_checkpoint_hashes={"m4": "best_validation_m4_qformer", "m5": checkpoint_hash},
            ).to_dict())
    output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, nargs="+", required=True)
    parser.add_argument("--labels", type=Path, nargs="+", required=True)
    parser.add_argument("--source-names", nargs="+", required=True)
    parser.add_argument("--train-source", nargs="+", required=True)
    parser.add_argument("--validation-source", nargs="+", required=True)
    parser.add_argument("--test-source", nargs="+", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=40); parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--min-hours", type=float, default=6.0); parser.add_argument("--max-hours", type=float, default=24.0)
    parser.add_argument("--negative-ratio", type=int, default=4); parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(); torch.manual_seed(args.seed)
    rows = load_rows(args.inputs, args.labels, args.source_names); sources = {row["_source"] for row in rows}
    requested = set(args.train_source + args.validation_source + args.test_source)
    if requested != sources or set(args.train_source) & set(args.validation_source) or set(args.train_source) & set(args.test_source) or set(args.validation_source) & set(args.test_source):
        raise ValueError(f"sources must form an exact disjoint partition; available={sorted(sources)}")
    groups = {"train": [r for r in rows if r["_source"] in args.train_source], "validation": [r for r in rows if r["_source"] in args.validation_source], "test": [r for r in rows if r["_source"] in args.test_source]}
    built = {name: pairs(group, args.min_hours, args.max_hours, args.negative_ratio, args.seed) for name, group in groups.items()}
    empty_pair_splits = {name: {"positive_pairs": built[name][1], "pairs": len(built[name][0])} for name in built if built[name][1] == 0}
    if empty_pair_splits:
        raise ValueError(f"each split requires at least one weak positive long-horizon pair: {empty_pair_splits}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dim = len(rows[0]["event_embedding"]); model = M5LongHorizonLinker(M5Config(embedding_dim=dim, hidden_dim=dim)).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr); loss_fn = nn.BCEWithLogitsLoss()
    train = tensor_pairs(built["train"][0], device); validation = tensor_pairs(built["validation"][0], device); history = []; best = None
    for epoch in range(1, args.epochs + 1):
        model.train(); optimizer.zero_grad(set_to_none=True); loss = loss_fn(model(train[0], train[1], train[2]), train[3]); loss.backward(); optimizer.step()
        model.eval(); row = {"epoch": epoch, "train_loss": float(loss.detach().cpu()), "validation": metric(model, validation)}; history.append(row)
        key = row["validation"]["roc_auc"] if row["validation"]["roc_auc"] is not None else -1
        if best is None or key > best[0]: best = (key, epoch, {k: v.detach().cpu() for k, v in model.state_dict().items()})
    model.load_state_dict(best[2]); args.output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = args.output_dir / "m5_best.pt"; torch.save({"model": model.state_dict(), "epoch": best[1], "weak_target": "both_anomalous_same_source_within_long_horizon"}, checkpoint)
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest(); export_frozen(rows, model, digest, args.output_dir / "frozen_m1_m5.jsonl", device, args.min_hours, args.max_hours)
    labels_out = args.output_dir / "labels.jsonl"; labels_out.write_text("".join(json.dumps({"record_id": r["record_id"], "label": r["_label"]}) + "\n" for r in rows), encoding="utf-8")
    split = {"schema_version": "m6-split-v1", "policy": {"target": "source-held-out development split; no AIT target evaluation"}, "train": [r["record_id"] for r in groups["train"]], "validation": [r["record_id"] for r in groups["validation"]], "test": [r["record_id"] for r in groups["test"]], "provenance": {"m5_target": "weak_window_anomaly_pair_v1", "min_hours": args.min_hours, "max_hours": args.max_hours}}
    (args.output_dir / "m6_split.json").write_text(json.dumps(split, indent=2), encoding="utf-8")
    report = {"status": "COMPLETED", "weak_supervision": True, "sources": {name: {"windows": len(groups[name]), "positive_windows": sum(r["_label"] for r in groups[name]), "pairs": len(built[name][0]), "positive_pairs": built[name][1]} for name in groups}, "best_epoch": best[1], "validation": history[best[1] - 1]["validation"], "history": history, "checkpoint": str(checkpoint), "checkpoint_sha256": digest}
    (args.output_dir / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8"); print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__": main()
