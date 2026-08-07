from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import torch
from torch import nn

from src.common.schema import FrozenFeatureRecord
from src.fusion.m6_hierarchical import M6Config, M6HierarchicalFusion


class M4DetectionHead(nn.Module):
    """Supervised adapter over the strict M4 event representation."""
    def __init__(self, dim: int) -> None:
        super().__init__()
        self.net = nn.Sequential(nn.LayerNorm(dim), nn.Linear(dim, dim), nn.GELU(), nn.Dropout(0.10), nn.Linear(dim, 1))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


class NormalEventAutoEncoder(nn.Module):
    """Benign-only reconstruction model used by the KAIROS-style branch."""
    def __init__(self, dim: int) -> None:
        super().__init__()
        hidden = max(8, dim // 2)
        self.encoder = nn.Sequential(nn.LayerNorm(dim), nn.Linear(dim, hidden), nn.GELU())
        self.decoder = nn.Linear(hidden, dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def _hash(models: dict[str, nn.Module]) -> str:
    digest = hashlib.sha256()
    for model_name, model in sorted(models.items()):
        for name, value in sorted(model.state_dict().items()):
            digest.update(f"{model_name}:{name}".encode())
            digest.update(value.detach().cpu().numpy().tobytes())
    return digest.hexdigest()


def _matrix(records: list[FrozenFeatureRecord]) -> torch.Tensor:
    return torch.tensor([row.event_embedding for row in records], dtype=torch.float32)


def _balanced_indices(labels: torch.Tensor, generator: torch.Generator) -> torch.Tensor:
    positive = torch.where(labels == 1)[0]
    negative = torch.where(labels == 0)[0]
    if not len(positive) or not len(negative):
        raise ValueError("formal training requires both positive and negative train records")
    # Draw a 1:1 batch every epoch so nine positives cannot collapse to "all normal".
    selected_negative = negative[torch.randint(len(negative), (len(positive),), generator=generator)]
    return torch.cat([positive, selected_negative])[torch.randperm(len(positive) + len(selected_negative), generator=generator)]


def _train_m4(embedding: torch.Tensor, labels: torch.Tensor, seed: int, epochs: int) -> M4DetectionHead:
    torch.manual_seed(seed)
    model = M4DetectionHead(embedding.shape[1])
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-3, weight_decay=1e-4)
    generator = torch.Generator().manual_seed(seed)
    for _ in range(max(40, epochs * 30)):
        index = _balanced_indices(labels, generator)
        loss = nn.functional.binary_cross_entropy_with_logits(model(embedding[index]), labels[index])
        optimizer.zero_grad(set_to_none=True); loss.backward(); optimizer.step()
    return model.eval()


def _train_normal_autoencoder(embedding: torch.Tensor, labels: torch.Tensor, seed: int, epochs: int) -> NormalEventAutoEncoder:
    torch.manual_seed(seed + 1)
    normal = embedding[labels == 0]
    if not len(normal):
        raise ValueError("KAIROS-style normal baseline requires negative train records")
    model = NormalEventAutoEncoder(embedding.shape[1])
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-3, weight_decay=1e-4)
    for _ in range(max(60, epochs * 40)):
        reconstruction = model(normal)
        loss = nn.functional.mse_loss(reconstruction, normal)
        optimizer.zero_grad(set_to_none=True); loss.backward(); optimizer.step()
    return model.eval()


def _window_and_queue_scores(records: list[FrozenFeatureRecord], errors: dict[str, float], sigma: float) -> tuple[dict[str, float], dict[str, float]]:
    windows: dict[tuple[str, datetime], list[str]] = defaultdict(list)
    for row in records:
        stamp = datetime.fromisoformat((row.timestamp or "2000-01-01T00:00:00Z").replace("Z", "+00:00"))
        if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
        start = stamp.replace(minute=(stamp.minute // 5) * 5, second=0, microsecond=0)
        windows[(row.dataset_id, start)].append(row.record_id)
    window_scores: dict[tuple[str, datetime], float] = {}
    for key, ids in windows.items():
        exceed = [errors[item] for item in ids if errors[item] > sigma]
        window_scores[key] = sum(exceed) / len(exceed) if exceed else 0.0
    queue_by_window: dict[tuple[str, datetime], float] = {}
    by_dataset: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    for (dataset, start), score in window_scores.items(): by_dataset[dataset].append((start, score))
    for dataset, entries in by_dataset.items():
        active: list[tuple[datetime, float]] = []
        def flush() -> None:
            if not active: return
            # KAIROS uses a product across anomalous windows; log1p keeps the
            # same monotonic aggregation without numerical underflow.
            value = sum(torch.log1p(torch.tensor(score)).item() for _, score in active)
            for start, _ in active: queue_by_window[(dataset, start)] = value
        for start, score in sorted(entries):
            if score <= 0:
                flush(); active = []; continue
            if active and start - active[-1][0] > timedelta(minutes=30):
                flush(); active = []
            active.append((start, score))
        flush()
    event_window, event_queue = {}, {}
    for key, ids in windows.items():
        for record_id in ids:
            event_window[record_id] = window_scores[key]
            event_queue[record_id] = queue_by_window.get(key, 0.0)
    return event_window, event_queue


def _augment(records: list[FrozenFeatureRecord], m4_scores: dict[str, float], errors: dict[str, float], windows: dict[str, float], queues: dict[str, float]) -> torch.Tensor:
    base = _matrix(records)
    extra = torch.tensor([[m4_scores[row.record_id], errors[row.record_id], windows[row.record_id], queues[row.record_id]] for row in records], dtype=torch.float32)
    return torch.cat([base, extra], dim=1)


def _train_m6(embedding: torch.Tensor, graph: torch.Tensor, horizon: torch.Tensor, labels: torch.Tensor, seed: int, epochs: int) -> M6HierarchicalFusion:
    torch.manual_seed(seed + 2)
    model = M6HierarchicalFusion(M6Config(embedding_dim=embedding.shape[1], hidden_dim=max(16, embedding.shape[1])))
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-3, weight_decay=1e-4)
    generator = torch.Generator().manual_seed(seed + 2)
    for _ in range(max(60, epochs * 40)):
        index = _balanced_indices(labels, generator)
        output = model(embedding[index], graph[index], horizon[index])
        loss = model.loss(output, labels[index])["total"]
        optimizer.zero_grad(set_to_none=True); loss.backward(); optimizer.step()
    return model.eval()


def _scores(model: M6HierarchicalFusion, embedding: torch.Tensor, graph: torch.Tensor, horizon: torch.Tensor) -> torch.Tensor:
    with torch.no_grad(): return torch.sigmoid(model(embedding, graph, horizon)["fused_logit"])


def _prediction_rows(records, labels, scores, m4_scores, errors, windows, queues):
    return [{"record_id": row.record_id, "score": float(score), "label": int(labels[row.record_id]), "m4_score": float(m4_scores[row.record_id]), "kairos_reconstruction_error": float(errors[row.record_id]), "kairos_window_score": float(windows[row.record_id]), "kairos_queue_log_score": float(queues[row.record_id])} for row, score in zip(records, scores.tolist())]


def train_formal(records: list[FrozenFeatureRecord], labels: dict[str, int], split: dict[str, list[str]], output_dir: Path, seed: int = 42, epochs: int = 2):
    lookup = {row.record_id: row for row in records}
    partitions = {name: [lookup[key] for key in split[name] if key in lookup] for name in ("train", "validation", "test")}
    train, validation, test = partitions["train"], partitions["validation"], partitions["test"]
    if not train or not validation or not test: raise ValueError("formal source train/validation/test partitions must all be non-empty")
    train_labels = torch.tensor([labels[row.record_id] for row in train], dtype=torch.float32)
    train_embedding = _matrix(train)
    m4 = _train_m4(train_embedding, train_labels, seed, epochs)
    autoencoder = _train_normal_autoencoder(train_embedding, train_labels, seed, epochs)
    all_embedding = _matrix(records)
    with torch.no_grad():
        all_m4 = torch.sigmoid(m4(all_embedding)).tolist()
        reconstruction = autoencoder(all_embedding)
        all_error = ((reconstruction - all_embedding) ** 2).mean(dim=1).tolist()
    m4_scores = {row.record_id: float(value) for row, value in zip(records, all_m4)}
    errors = {row.record_id: float(value) for row, value in zip(records, all_error)}
    sigma = float(torch.quantile(torch.tensor([errors[row.record_id] for row in train if labels[row.record_id] == 0]), 0.995))
    windows, queues = _window_and_queue_scores(records, errors, sigma)
    augmented_train = _augment(train, m4_scores, errors, windows, queues)
    graph_train = torch.tensor([row.graph_score for row in train], dtype=torch.float32)
    horizon_train = torch.tensor([row.long_horizon_score + queues[row.record_id] for row in train], dtype=torch.float32)
    # The M4 head and normal model have already been fitted. Capture the M6
    # initial state immediately before its supervised fusion training.
    torch.manual_seed(seed + 2)
    m6_initial = M6HierarchicalFusion(M6Config(embedding_dim=augmented_train.shape[1], hidden_dim=max(16, augmented_train.shape[1])))
    before = _hash({"m4": m4, "normal_autoencoder": autoencoder, "m6": m6_initial})
    m6 = _train_m6(augmented_train, graph_train, horizon_train, train_labels, seed, epochs)
    after = _hash({"m4": m4, "normal_autoencoder": autoencoder, "m6": m6})
    output_dir.mkdir(parents=True, exist_ok=True)
    history = {"epochs": max(60, epochs * 40), "train_count": len(train), "train_positive_count": int(train_labels.sum()), "m4_mode": "supervised_adapter_over_frozen_strict_m4_embeddings", "kairos_mode": "benign_reconstruction_event_window_temporal_queue", "kairos_edge_reconstruction_available": False, "normal_reconstruction_threshold_sigma": sigma, "m6_input_dim": int(augmented_train.shape[1])}
    (output_dir / "train_history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
    for name, rows in (("validation", validation), ("test", test)):
        features = _augment(rows, m4_scores, errors, windows, queues)
        graph = torch.tensor([row.graph_score for row in rows], dtype=torch.float32)
        horizon = torch.tensor([row.long_horizon_score + queues[row.record_id] for row in rows], dtype=torch.float32)
        predicted = _scores(m6, features, graph, horizon)
        payload = _prediction_rows(rows, labels, predicted, m4_scores, errors, windows, queues)
        (output_dir / f"{name}_predictions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in payload), encoding="utf-8")
    checkpoint = output_dir / "formal_checkpoint.pt"
    torch.save({"artifact_type": "formal_m4_kairos_m6_checkpoint", "real_data_used": True, "synthetic_data": False, "release_eligible": False, "m4": m4.state_dict(), "normal_autoencoder": autoencoder.state_dict(), "m6": m6.state_dict(), "parameter_hash_before": before, "parameter_hash_after": after, "normal_reconstruction_threshold_sigma": sigma, "train_count": len(train), "validation_count": len(validation), "test_count": len(test)}, checkpoint)
    return {"checkpoint": str(checkpoint), "parameter_hash_before": before, "parameter_hash_after": after, "train_count": len(train), "validation_count": len(validation), "test_count": len(test), "m4_integrated": True, "kairos_style_integrated": True, "kairos_edge_reconstruction_available": False, "normal_reconstruction_threshold_sigma": sigma}
