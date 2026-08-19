"""Train M5 with current-event query cross-attending to ATT&CK knowledge embeddings."""
from __future__ import annotations
import argparse, hashlib, json, random
from pathlib import Path
import torch
from torch import nn
import torch.nn.functional as F

from train_m5_progress import load_intervals, read_events

STAGE_POSITIONS = 4


def remap(items):
    return [(stamp, row, label, min(3, int(progress * 4)), progress)
            for stamp, row, label, _old, progress in items]


def tensors(items, device):
    x = torch.tensor([r[1]["semantic_embedding"] for r in items], dtype=torch.float32, device=device)
    y = torch.tensor([r[2] for r in items], dtype=torch.float32, device=device)
    p = torch.zeros((len(items), STAGE_POSITIONS), dtype=torch.float32, device=device)
    for i, row in enumerate(items):
        p[i, min(3, int(row[3]))] = 1.0
    return x, y, p


class AttackStepMLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(nn.LayerNorm(768), nn.Linear(768, 256), nn.GELU(), nn.Dropout(.1), nn.Linear(256, 1))

    def forward(self, x):
        return self.net(x).squeeze(-1)


class KnowledgeCrossAttention(nn.Module):
    def __init__(self, hidden=128):
        super().__init__()
        self.query = nn.Linear(768, hidden)
        self.key_value = nn.Linear(768, hidden)
        self.attn = nn.MultiheadAttention(hidden, 4, batch_first=True)
        self.norm = nn.LayerNorm(hidden)
        self.head = nn.Sequential(nn.Linear(hidden, hidden), nn.GELU(), nn.Linear(hidden, STAGE_POSITIONS))

    def forward(self, event, knowledge):
        q = self.query(event).unsqueeze(1)
        kv = self.key_value(knowledge).unsqueeze(0).expand(event.shape[0], -1, -1)
        context, weights = self.attn(q, kv, kv, need_weights=True)
        return self.head(self.norm(context[:, 0])), weights[:, 0]


@torch.no_grad()
def evaluate(step, stage, data, knowledge, device):
    x, y, p = tensors(data, device)
    score = torch.sigmoid(step(x))
    logits, _ = stage(x, knowledge)
    actual = y > .5
    predicted = score >= .5
    stage_hit = (logits.argmax(-1) == p.argmax(-1)) & actual
    return {
        "count": len(data),
        "positive": int(actual.sum()),
        "positive_recall_at_0.5": float((predicted & actual).sum()) / max(1, int(actual.sum())),
        "stage_hit_rate_on_positive": float(stage_hit.sum()) / max(1, int(actual.sum())),
        "joint_attack_stage_recall_pct": 100.0 * float((stage_hit & predicted).sum()) / max(1, int(actual.sum())),
    }


def load_knowledge(path: Path, device):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                emb = row.get("semantic_embedding")
                if isinstance(emb, list) and len(emb) == 768:
                    rows.append(emb)
    if not rows:
        raise RuntimeError("no 768-dimensional knowledge embeddings found")
    return torch.tensor(rows, dtype=torch.float32, device=device)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events-root", type=Path, required=True)
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--knowledge", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--negative-ratio", type=int, default=4)
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    torch.manual_seed(42); random.seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    knowledge = load_knowledge(a.knowledge, device)
    step = AttackStepMLP().to(device)
    stage = KnowledgeCrossAttention().to(device)
    if a.smoke:
        x = torch.randn(8, 768, device=device)
        logits, weights = stage(x, knowledge[: min(8, len(knowledge))])
        loss = step(x).square().mean() + logits.square().mean()
        loss.backward()
        print(json.dumps({"status": "SMOKE_COMPLETED", "device": str(device), "event_input": [8, 768], "knowledge_input": [min(8, len(knowledge)), 768], "stage_output": [8, 4], "attention_output": [8, min(8, len(knowledge))], "loss_finite": bool(torch.isfinite(loss).item()), "synthetic": True}))
        return
    intervals, phases = load_intervals(a.labels)
    names = sorted(p.name.removesuffix("_m1_m2") for p in a.events_root.glob("*_m1_m2"))
    paths = {n: a.events_root / f"{n}_m1_m2" / "m1_eventframes.jsonl" for n in names if (a.events_root / f"{n}_m1_m2" / "m1_eventframes.jsonl").exists()}
    data, groups = read_events(paths, intervals, phases, 4, a.negative_ratio, 42)
    train, val = remap(data["train"]), remap(data["validation"])
    tx, ty, tp = tensors(train, device)
    step_opt = torch.optim.AdamW(step.parameters(), lr=2e-4, weight_decay=1e-4)
    stage_opt = torch.optim.AdamW(stage.parameters(), lr=2e-4, weight_decay=1e-4)
    history, best = [], None
    for epoch in range(1, a.epochs + 1):
        step.train(); stage.train()
        total_step = total_stage = 0.0
        for idx in torch.arange(len(train), device=device).split(a.batch_size):
            mask = ty[idx] > .5
            step_opt.zero_grad(set_to_none=True)
            weight = ((ty[idx] == 0).sum().float() / ty[idx].sum().float().clamp_min(1)).clamp(1, 8)
            sl = F.binary_cross_entropy_with_logits(step(tx[idx]), ty[idx], pos_weight=weight)
            sl.backward(); step_opt.step(); total_step += float(sl.detach()) * len(idx)
            if mask.any():
                stage_opt.zero_grad(set_to_none=True)
                tl = F.cross_entropy(stage(tx[idx][mask], knowledge)[0], tp[idx][mask].argmax(-1))
                tl.backward(); stage_opt.step(); total_stage += float(tl.detach()) * int(mask.sum())
        metrics = evaluate(step, stage, val, knowledge, device)
        row = {"epoch": epoch, "step_loss": total_step / max(1, len(train)), "stage_loss": total_stage / max(1, int((ty > .5).sum())), "validation": metrics}
        history.append(row); print(json.dumps(row), flush=True)
        key = (metrics["positive_recall_at_0.5"], metrics["joint_attack_stage_recall_pct"], metrics["stage_hit_rate_on_positive"])
        if best is None or key > best[0]:
            best = (key, epoch, {"step": {k: v.detach().cpu() for k, v in step.state_dict().items()}, "stage": {k: v.detach().cpu() for k, v in stage.state_dict().items()}})
    a.output_dir.mkdir(parents=True, exist_ok=True)
    ckpt = a.output_dir / "m5_cross_attention_best.pt"
    torch.save({"models": best[2], "epoch": best[1], "stage_positions": 4, "knowledge_count": len(knowledge), "knowledge_path": str(a.knowledge), "weak_supervision": True}, ckpt)
    report = {"status": "COMPLETED", "model_version": "m5_cross_attention_v1", "device": str(device), "knowledge_count": len(knowledge), "selected": {"train": len(train), "validation": len(val)}, "objective": "current event query cross-attends to ATT&CK knowledge embeddings", "stage_definition": "0-25%, 25-50%, 50-75%, 75-100% of alert interval", "weak_supervision": True, "best_epoch": best[1], "validation": history[best[1] - 1]["validation"], "history": history, "checkpoint": str(ckpt), "checkpoint_sha256": hashlib.sha256(ckpt.read_bytes()).hexdigest()}
    (a.output_dir / "training_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
