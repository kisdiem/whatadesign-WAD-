from __future__ import annotations

import hashlib
import json
from pathlib import Path

import torch

from src.common.schema import FrozenFeatureRecord
from src.fusion.m6_hierarchical import M6Config, M6HierarchicalFusion


def _hash(model) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(model.state_dict().items()):
        digest.update(name.encode())
        digest.update(value.detach().cpu().numpy().tobytes())
    return digest.hexdigest()


def _predict(model, records, labels, path):
    model.eval()
    with torch.no_grad():
        embedding = torch.tensor([row.event_embedding for row in records], dtype=torch.float32)
        graph = torch.tensor([row.graph_score for row in records], dtype=torch.float32)
        horizon = torch.tensor([row.long_horizon_score for row in records], dtype=torch.float32)
        scores = torch.sigmoid(model(embedding, graph, horizon)["fused_logit"]).tolist()
    with path.open("w", encoding="utf-8") as handle:
        for row, score in zip(records, scores):
            handle.write(json.dumps({"record_id": row.record_id, "score": float(score), "label": int(labels[row.record_id])}) + "\n")


def train_formal(records: list[FrozenFeatureRecord], labels: dict[str, int], split: dict[str, list[str]], output_dir: Path, seed: int = 42, epochs: int = 2):
    lookup = {row.record_id: row for row in records}
    train = [lookup[key] for key in split["train"] if key in lookup]
    validation = [lookup[key] for key in split["validation"] if key in lookup]
    test = [lookup[key] for key in split["test"] if key in lookup]
    if not train or not validation or not test:
        raise ValueError("formal source train/validation/test partitions must all be non-empty")
    torch.manual_seed(seed)
    dim = len(train[0].event_embedding)
    model = M6HierarchicalFusion(M6Config(embedding_dim=dim, hidden_dim=max(8, dim)))
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)
    before = _hash(model)
    history = []
    for epoch in range(1, epochs + 1):
        model.train(); optimizer.zero_grad(set_to_none=True)
        embedding = torch.tensor([row.event_embedding for row in train], dtype=torch.float32)
        graph = torch.tensor([row.graph_score for row in train], dtype=torch.float32)
        horizon = torch.tensor([row.long_horizon_score for row in train], dtype=torch.float32)
        target = torch.tensor([labels[row.record_id] for row in train], dtype=torch.float32)
        output = model(embedding, graph, horizon)
        loss = model.loss(output, target)["total"]
        loss.backward(); optimizer.step()
        model.eval()
        with torch.no_grad():
            ve = torch.tensor([row.event_embedding for row in validation], dtype=torch.float32)
            vg = torch.tensor([row.graph_score for row in validation], dtype=torch.float32)
            vh = torch.tensor([row.long_horizon_score for row in validation], dtype=torch.float32)
            validation_score = torch.sigmoid(model(ve, vg, vh)["fused_logit"])
        history.append({"epoch": epoch, "train_loss": float(loss.detach()), "train_count": len(train), "validation_count": len(validation), "validation_mean_score": float(validation_score.mean())})
    after = _hash(model); output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "train_history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
    _predict(model, validation, labels, output_dir / "validation_predictions.jsonl")
    _predict(model, test, labels, output_dir / "test_predictions.jsonl")
    checkpoint = output_dir / "formal_checkpoint.pt"
    torch.save({"artifact_type": "formal_source_checkpoint", "real_data_used": True, "synthetic_data": False, "release_eligible": False, "model": model.state_dict(), "parameter_hash_before": before, "parameter_hash_after": after, "train_count": len(train), "validation_count": len(validation), "test_count": len(test)}, checkpoint)
    return {"checkpoint": str(checkpoint), "parameter_hash_before": before, "parameter_hash_after": after, "train_count": len(train), "validation_count": len(validation), "test_count": len(test)}
