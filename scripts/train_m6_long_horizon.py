"""Train M6 from real, frozen M1-M5 records and separate labels."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import torch
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

from _bootstrap import *  # noqa: F401,F403
from src.fusion.m6_hierarchical import M6Config, M6HierarchicalFusion
from src.training.m6_data import read_labels, read_records


def _metrics(labels, logits, threshold=0.5):
    probs = torch.sigmoid(logits).detach().cpu().numpy()
    y = labels.detach().cpu().numpy().astype(int)
    pred = (probs >= threshold).astype(int)
    result = {"threshold": float(threshold), "f1": float(f1_score(y, pred, zero_division=0)),
              "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0))}
    if len(set(y)) > 1:
        result["roc_auc"] = float(roc_auc_score(y, probs)); result["pr_auc"] = float(average_precision_score(y, probs))
    else:
        result["roc_auc"] = None; result["pr_auc"] = None
    return result


def _batch(records, labels, ids, device):
    rows = [records[i] for i in ids]
    return (torch.tensor([r.event_embedding for r in rows], dtype=torch.float32, device=device),
            torch.tensor([r.graph_score for r in rows], dtype=torch.float32, device=device),
            torch.tensor([r.long_horizon_score for r in rows], dtype=torch.float32, device=device),
            torch.tensor([labels[i] for i in ids], dtype=torch.float32, device=device))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--frozen-features", type=Path, required=True); p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--split", type=Path, required=True); p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--epochs", type=int, default=30); p.add_argument("--lr", type=float, default=1e-3); p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(); torch.manual_seed(args.seed)
    records = read_records(args.frozen_features); labels = read_labels(args.labels)
    split = json.loads(args.split.read_text(encoding="utf-8")); train_ids, val_ids, test_ids = split["train"], split["validation"], split["test"]
    for name, ids in (("train", train_ids), ("validation", val_ids), ("test", test_ids)):
        if not ids or any(i not in records or i not in labels for i in ids): raise ValueError(f"invalid {name} split")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dim = len(next(iter(records.values())).event_embedding); model = M6HierarchicalFusion(M6Config(embedding_dim=dim, hidden_dim=max(32, dim))).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr); best = None; history = []
    train = _batch(records, labels, train_ids, device); val = _batch(records, labels, val_ids, device)
    for epoch in range(1, args.epochs + 1):
        model.train(); optimizer.zero_grad(set_to_none=True)
        out = model(train[0], train[1], train[2]); loss = model.loss(out, train[3])["total"]; loss.backward(); optimizer.step()
        model.eval()
        with torch.no_grad(): vout = model(val[0], val[1], val[2]); vmetrics = _metrics(val[3], vout["fused_logit"])
        row = {"epoch": epoch, "train_loss": float(loss.detach().cpu()), "validation": vmetrics}; history.append(row)
        key = (vmetrics["roc_auc"] if vmetrics["roc_auc"] is not None else -1.0, vmetrics["f1"])
        if best is None or key > best["key"]: best = {"key": key, "epoch": epoch, "threshold": vmetrics["threshold"], "state": {k: v.detach().cpu() for k, v in model.state_dict().items()}}
    if best is None: raise RuntimeError("no checkpoint selected")
    model.load_state_dict(best["state"]); model.to(device); model.eval(); test = _batch(records, labels, test_ids, device)
    with torch.no_grad():
        warm = model(test[0], test[1], test[2]);
        if device.type == "cuda": torch.cuda.synchronize()
        start = time.perf_counter(); repeats = 20
        for _ in range(repeats): model(test[0], test[1], test[2])
        if device.type == "cuda": torch.cuda.synchronize()
        elapsed = time.perf_counter() - start
        test_metrics = _metrics(test[3], warm["fused_logit"], best["threshold"])
    args.output_dir.mkdir(parents=True, exist_ok=True); checkpoint = args.output_dir / "m6_best.pt"
    torch.save({"model": model.state_dict(), "config": {"embedding_dim": dim}, "epoch": best["epoch"], "threshold": best["threshold"], "release_eligible": True}, checkpoint)
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    report = {"status": "COMPLETED", "device": str(device), "train_count": len(train_ids), "validation_count": len(val_ids), "test_count": len(test_ids), "best_epoch": best["epoch"], "validation": history[best["epoch"] - 1]["validation"], "test": test_metrics, "inference": {"repeats": repeats, "total_seconds": elapsed, "mean_ms": elapsed * 1000 / repeats}, "checkpoint": str(checkpoint), "checkpoint_sha256": digest, "history": history}
    (args.output_dir / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__": main()
