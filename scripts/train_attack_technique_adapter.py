"""Train the frozen-M1 ATT&CK adapter on isolated source supervision."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import torch

from src.common.schema import EventFrame
from src.models.attack_technique_adapter import AttackTechniqueAdapter, AttackTechniqueAdapterConfig


def read_jsonl(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def stable_group_split(groups: dict[str, str], validation_fraction: float) -> tuple[set[str], set[str]]:
    """Split whole source files, never individual events from a source file."""
    unique_groups = sorted(set(groups.values()))
    validation_groups = {
        group for group in unique_groups
        if int(hashlib.sha256(group.encode()).hexdigest(), 16) % 10_000 < int(validation_fraction * 10_000)
    }
    if not validation_groups and len(unique_groups) > 1:
        validation_groups.add(unique_groups[-1])
    train_ids = {record_id for record_id, group in groups.items() if group not in validation_groups}
    validation_ids = {record_id for record_id, group in groups.items() if group in validation_groups}
    return train_ids, validation_ids


def metric(logits: torch.Tensor, targets: torch.Tensor) -> dict[str, float]:
    predicted = logits.argmax(dim=1)
    expected = targets.argmax(dim=1)
    recalls = []
    for class_index in range(targets.shape[1]):
        positives = expected == class_index
        if positives.any():
            recalls.append(float((predicted[positives] == class_index).float().mean().item()))
    return {
        "top1_accuracy": float((predicted == expected).float().mean().item()),
        "macro_recall": sum(recalls) / len(recalls) if recalls else 0.0,
        "examples": int(targets.shape[0]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-features", type=Path, required=True)
    parser.add_argument("--event-index", type=Path, required=True)
    parser.add_argument("--card-features", type=Path, required=True)
    parser.add_argument("--supervision", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--validation-fraction", type=float, default=0.2)
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = parser.parse_args()
    torch.manual_seed(7)

    events = {row["record_id"]: EventFrame.from_dict(row) for row in read_jsonl(args.event_features)}
    groups = {row["record_id"]: row["source_group"] for row in read_jsonl(args.event_index)}
    labels: dict[str, set[str]] = defaultdict(set)
    for row in read_jsonl(args.supervision):
        if row["record_id"] in events:
            labels[row["record_id"]].add(row["technique_id"])
    records = sorted(labels)
    if not records:
        raise ValueError("no supervision rows joined to real event features")
    card_vectors = {row["technique_id"]: row["semantic_embedding"] for row in read_jsonl(args.card_features)}
    technique_ids = sorted({technique for values in labels.values() for technique in values})
    if any(technique not in card_vectors for technique in technique_ids):
        raise ValueError("missing card embeddings for observed techniques")

    feature_matrix = torch.tensor([events[record].semantic_embedding for record in records], dtype=torch.float32)
    target_matrix = torch.tensor([[float(technique in labels[record]) for technique in technique_ids] for record in records], dtype=torch.float32)
    card_matrix = torch.tensor([card_vectors[technique] for technique in technique_ids], dtype=torch.float32)
    train_ids, validation_ids = stable_group_split({record: groups.get(record, "unknown") for record in records}, args.validation_fraction)
    train_indices = [index for index, record in enumerate(records) if record in train_ids]
    validation_indices = [index for index, record in enumerate(records) if record in validation_ids]
    if not train_indices or not validation_indices:
        raise ValueError("source-group split produced an empty train or validation partition")

    device = torch.device(args.device)
    model = AttackTechniqueAdapter(AttackTechniqueAdapterConfig(event_dim=feature_matrix.shape[1], card_dim=card_matrix.shape[1])).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    features, targets, cards = feature_matrix.to(device), target_matrix.to(device), card_matrix.to(device)
    train_index = torch.tensor(train_indices, device=device)
    validation_index = torch.tensor(validation_indices, device=device)
    positive_weight = float(len(technique_ids) - 1)
    history = []
    best: dict[str, object] | None = None
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for epoch in range(1, args.epochs + 1):
        model.train()
        output = model(features.index_select(0, train_index), cards)
        weights = torch.where(targets.index_select(0, train_index) > 0, positive_weight, 1.0)
        loss = model.loss(output, targets.index_select(0, train_index), weights)
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        optimizer.step()
        model.eval()
        with torch.inference_mode():
            validation_output = model(features.index_select(0, validation_index), cards)
            validation_metrics = metric(validation_output["logits"], targets.index_select(0, validation_index))
        row = {"epoch": epoch, "train_loss": float(loss.item()), "validation": validation_metrics}
        history.append(row)
        if best is None or validation_metrics["top1_accuracy"] > best["validation"]["top1_accuracy"]:
            best = row
            torch.save({"state_dict": model.state_dict(), "config": model.config.__dict__, "technique_ids": technique_ids, "best_epoch": epoch}, args.output_dir / "best.pt")
    summary = {
        "status": "completed",
        "event_count": len(records),
        "card_count_seen_in_training": len(technique_ids),
        "unmatched_supervision_rows": sum(1 for row in read_jsonl(args.supervision) if row["record_id"] not in events),
        "train_examples": len(train_indices),
        "validation_examples": len(validation_indices),
        "source_groups": len(set(groups.get(record, "unknown") for record in records)),
        "best": best,
        "warning": "This is source-only weak supervision over frozen M1 features; it is not target-AIT evaluation.",
    }
    (args.output_dir / "history.json").write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
