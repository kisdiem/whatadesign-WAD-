from __future__ import annotations

import hashlib
import json
from pathlib import Path
import torch
from src.common.schema import FrozenFeatureRecord
from src.fusion.m6_hierarchical import M6Config, M6HierarchicalFusion


def parameter_hash(model) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(model.state_dict().items()): digest.update(name.encode()); digest.update(value.detach().cpu().numpy().tobytes())
    return digest.hexdigest()


def train_development(records: list[FrozenFeatureRecord], labels: dict[str, int], output_dir: Path, seed: int = 42, epochs: int = 2):
    if len(records) < 2: raise ValueError("development training requires at least two records")
    torch.manual_seed(seed)
    dim = len(records[0].event_embedding); model = M6HierarchicalFusion(M6Config(embedding_dim=dim, hidden_dim=max(8, dim)))
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.01)
    before = parameter_hash(model); history = []
    order = sorted(records, key=lambda row: row.record_id); split = max(1, len(order) // 2); train, validation = order[:split], order[split:]
    for epoch in range(1, epochs + 1):
        model.train(); optimizer.zero_grad(set_to_none=True)
        batch = train; embedding = torch.tensor([row.event_embedding for row in batch], dtype=torch.float32)
        graph = torch.tensor([row.graph_score for row in batch]); horizon = torch.tensor([row.long_horizon_score for row in batch]); target = torch.tensor([labels[row.record_id] for row in batch])
        output = model(embedding, graph, horizon); loss = model.loss(output, target)["total"]; loss.backward(); optimizer.step()
        model.eval();
        with torch.no_grad():
            vb = torch.tensor([row.event_embedding for row in validation], dtype=torch.float32); vg = torch.tensor([row.graph_score for row in validation]); vh = torch.tensor([row.long_horizon_score for row in validation]); vo = model(vb, vg, vh)
        history.append({"epoch": epoch, "train_loss": float(loss.detach()), "validation_count": len(validation), "validation_mean_score": float(torch.sigmoid(vo["fused_logit"]).mean())})
    after = parameter_hash(model); output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "train_history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
    with (output_dir / "validation_predictions.jsonl").open("w", encoding="utf-8") as handle:
        for row in validation: handle.write(json.dumps({"record_id": row.record_id, "score": float(torch.sigmoid(vo["fused_logit"])[validation.index(row)])}) + "\n")
    checkpoint = output_dir / "development_checkpoint.pt"
    torch.save({"artifact_type": "development_checkpoint", "synthetic_data": True, "release_eligible": False, "not_for_scientific_reporting": True, "model": model.state_dict(), "parameter_hash_before": before, "parameter_hash_after": after}, checkpoint)
    return {"history": history, "parameter_hash_before": before, "parameter_hash_after": after, "checkpoint": str(checkpoint), "release_eligible": False}
