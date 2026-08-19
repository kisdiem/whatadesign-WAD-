"""Train the M5 attack-step/progress heads with a causal time split.

This runner consumes frozen M1 EventFrame embeddings and AIT alert intervals.
The interval-derived event/stage/progress targets are weak supervision: they do
not claim that every event is a human-annotated ATT&CK step.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import torch
from torch import Tensor, nn
import torch.nn.functional as F


def ts(value: str | float | int) -> float:
    if isinstance(value, (float, int)):
        return float(value)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp()


def load_intervals(path: Path):
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({"scenario": row["scenario"], "start": float(row["start"]), "end": float(row["end"]), "phase": row.get("attack", "unknown")})
    for scenario in {r["scenario"] for r in rows}:
        ordered = sorted((r for r in rows if r["scenario"] == scenario), key=lambda r: (r["start"], r["end"]))
        train_count = max(1, int(len(ordered) * 0.7))
        for index, row in enumerate(ordered):
            row["interval_split"] = "train" if index < train_count else "validation"
    phases = {p: i for i, p in enumerate(dict.fromkeys(r["phase"] for r in sorted(rows, key=lambda x: (x["start"], x["phase"])) ))}
    return rows, phases


def label_for(scenario: str, stamp: float, intervals, phases, positions: int):
    hits = [r for r in intervals if r["scenario"] == scenario and r["start"] <= stamp <= max(r["end"], r["start"] + 1.0)]
    if not hits:
        return 0.0, 0, 0.0
    row = min(hits, key=lambda x: (x["end"] - x["start"], x["start"]))
    duration = max(row["end"] - row["start"], 1.0)
    progress = max(0.0, min(1.0, (stamp - row["start"]) / duration))
    position = min(positions - 1, int(phases.get(row["phase"], 0) * positions / max(len(phases), 1)))
    return 1.0, position, progress


def read_events(paths, intervals, phases, positions, negative_ratio, seed, max_positive_per_source=25000, max_negative_per_source=25000):
    rng = random.Random(seed)
    by_source = {}
    for source, path in paths.items():
        rows = []
        first_stamp = None
        last_stamp = None
        with path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                stamp = ts(row["timestamp"])
                first_stamp = stamp if first_stamp is None else first_stamp
                last_stamp = stamp
        if first_stamp is None or last_stamp is None:
            continue
        source_intervals = [r for r in intervals if r["scenario"] == source]
        validation_starts = [r["start"] for r in source_intervals if r.get("interval_split") == "validation"]
        # Split at the first validation alert interval. This preserves order
        # while ensuring the training side contains earlier attack examples.
        cut_stamp = min(validation_starts) if validation_starts else first_stamp + 0.8 * (last_stamp - first_stamp)
        train_pos, train_neg, val_pos, val_neg = [], [], [], []
        with path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line); stamp = ts(row["timestamp"])
                label, position, progress = label_for(source, stamp, intervals, phases, positions)
                item = (stamp, row, label, position, progress)
                target_pos = train_pos if stamp <= cut_stamp else val_pos
                target_neg = train_neg if stamp <= cut_stamp else val_neg
                if label > 0.5:
                    if len(target_pos) < max_positive_per_source: target_pos.append(item)
                elif len(target_neg) < max_negative_per_source:
                    target_neg.append(item)
        train_rows = train_pos + train_neg
        validation_rows = val_pos + val_neg
        train_rows.sort(key=lambda x: (x[0], str(x[1].get("record_id", ""))))
        validation_rows.sort(key=lambda x: (x[0], str(x[1].get("record_id", ""))))
        by_source[source] = {
            "train": train_rows,
            "validation": validation_rows,
            "total": sum(1 for _ in path.open(encoding="utf-8")),
            "first_timestamp": first_stamp,
            "last_timestamp": last_stamp,
        }
        print(json.dumps({"source": source, "events": by_source[source]["total"], "train_selected": len(train_rows), "validation_selected": len(validation_rows)}, ensure_ascii=False), flush=True)

    result = {}
    for split in ("train", "validation"):
        positives = []
        negatives = []
        for source, groups in by_source.items():
            for item in groups[split]:
                (positives if item[2] > 0.5 else negatives).append(item)
        rng.shuffle(negatives)
        negatives = negatives[: max(len(positives) * negative_ratio, 1)]
        selected = positives + negatives
        selected.sort(key=lambda x: (x[0], str(x[1].get("record_id", ""))))
        result[split] = selected
    return result, by_source


class M5ProgressModel(nn.Module):
    def __init__(self, input_dim: int, hidden: int, positions: int):
        super().__init__()
        self.input = nn.Linear(input_dim, hidden)
        self.norm = nn.LayerNorm(hidden)
        # M5 receives one current event embedding per sample here; a self-attention
        # block over sequence length one adds no information and is unstable on
        # some CUDA/PyTorch combinations. Cross-attention below remains active.
        self.encoder = nn.Sequential(nn.Linear(hidden, hidden * 2), nn.GELU(), nn.Linear(hidden * 2, hidden), nn.LayerNorm(hidden))
        self.knowledge_key = nn.Linear(hidden, hidden, bias=False)
        self.knowledge_value = nn.Linear(hidden, hidden, bias=False)
        self.cross = nn.MultiheadAttention(hidden, 4, batch_first=True)
        self.fuse = nn.Sequential(nn.Linear(hidden * 2, hidden), nn.GELU(), nn.LayerNorm(hidden))
        self.relevance = nn.Linear(hidden, 1)
        self.position = nn.Linear(hidden, positions)
        self.progress = nn.Linear(hidden, 1)

    def forward(self, x: Tensor, knowledge: Tensor):
        h = self.encoder(self.norm(self.input(x))).unsqueeze(1)
        k = self.knowledge_key(knowledge).unsqueeze(0).expand(h.shape[0], -1, -1)
        v = self.knowledge_value(knowledge).unsqueeze(0).expand(h.shape[0], -1, -1)
        cross, _ = self.cross(h, k, v, need_weights=False)
        z = self.fuse(torch.cat([h[:, 0], cross[:, 0]], dim=-1))
        return self.relevance(z).squeeze(-1), self.position(z), torch.sigmoid(self.progress(z).squeeze(-1)), z


def tensors(items, device):
    x = torch.tensor([r[1]["semantic_embedding"] for r in items], dtype=torch.float32, device=device)
    y = torch.tensor([r[2] for r in items], dtype=torch.float32, device=device)
    p = torch.zeros((len(items), 10), dtype=torch.float32, device=device)
    for i, row in enumerate(items):
        p[i, min(9, int(row[3]))] = 1.0
    q = torch.tensor([r[4] for r in items], dtype=torch.float32, device=device)
    return x, y, p, q


def metrics(y, score, position_logits, position_target, progress, progress_target):
    y = y.detach().cpu(); score = score.detach().cpu(); position_logits = position_logits.detach().cpu(); position_target = position_target.detach().cpu(); progress = progress.detach().cpu(); progress_target = progress_target.detach().cpu()
    actual = y > .5; predicted = score >= .5
    positive_recall = float((predicted & actual).sum()) / max(1, int(actual.sum()))
    positive_count = max(1, int(actual.sum()))
    stage_hit = (position_logits.argmax(-1) == position_target.argmax(-1)) & actual
    progress_hit = (torch.abs(progress - progress_target) <= .1) & actual
    joint_hit = stage_hit & progress_hit & predicted
    return {"count": len(y), "positive": int(actual.sum()), "positive_recall_at_0.5": positive_recall, "stage_hit_rate_on_positive": float(stage_hit.sum()) / positive_count, "progress_recall_pct_within_0.1": 100.0 * float(progress_hit.sum()) / positive_count, "joint_attack_progress_recall_pct": 100.0 * float(joint_hit.sum()) / positive_count}


@torch.no_grad()
def predict_batched(model, x, knowledge, batch_size):
    scores = []; positions = []; progresses = []
    for idx in torch.arange(x.shape[0], device=x.device).split(batch_size):
        rel, pos, prog, _ = model(x[idx], knowledge)
        scores.append(torch.sigmoid(rel).detach()); positions.append(pos.detach()); progresses.append(prog.detach())
    return torch.cat(scores, dim=0), torch.cat(positions, dim=0), torch.cat(progresses, dim=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events-root", type=Path, required=True)
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--batch-size", type=int, default=512)
    ap.add_argument("--negative-ratio", type=int, default=4)
    ap.add_argument("--max-sources", type=int, default=8)
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    torch.manual_seed(42); random.seed(42)
    if args.smoke:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = M5ProgressModel(768, 128, 10).to(device)
        x = torch.randn(8, 768, device=device)
        knowledge = torch.randn(10, 128, device=device)
        relevance, positions, progress, embedding = model(x, knowledge)
        loss = relevance.square().mean() + positions.square().mean() + progress.square().mean()
        loss.backward()
        args.output_dir.mkdir(parents=True, exist_ok=True)
        report = {"status": "SMOKE_COMPLETED", "device": str(device), "input_shape": list(x.shape), "knowledge_shape": list(knowledge.shape), "output_shapes": {"relevance": list(relevance.shape), "positions": list(positions.shape), "progress": list(progress.shape), "embedding": list(embedding.shape)}, "loss_finite": bool(torch.isfinite(loss).item()), "synthetic": True, "note": "implementation smoke only; no training metric or data result"}
        (args.output_dir / "training_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False), flush=True)
        return
    interval_rows, phases = load_intervals(args.labels)
    names = sorted(p.name.removesuffix("_m1_m2") for p in args.events_root.glob("*_m1_m2"))[:args.max_sources]
    paths = {n: args.events_root / f"{n}_m1_m2" / "m1_eventframes.jsonl" for n in names}
    paths = {n: p for n, p in paths.items() if p.exists()}
    if not paths: raise SystemExit("no M1 EventFrame inputs found")
    data, source_groups = read_events(paths, interval_rows, phases, 10, args.negative_ratio, 42)
    if not data["train"] or not data["validation"]: raise SystemExit("time split produced an empty split")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dim = len(data["train"][0][1]["semantic_embedding"])
    model = M5ProgressModel(dim, 128, 10).to(device)
    # Knowledge prototypes are fitted from train events only, then frozen as an index.
    proto = torch.zeros((10, dim), device=device); counts = torch.zeros(10, device=device)
    for row in data["train"]:
        if row[2] > .5: proto[row[3]] += torch.tensor(row[1]["semantic_embedding"], device=device); counts[row[3]] += 1
    fallback = torch.tensor([r[1]["semantic_embedding"] for r in data["train"]], device=device).mean(0)
    proto = torch.where(counts[:, None] > 0, proto / counts.clamp_min(1)[:, None], fallback[None, :])
    knowledge = model.input(proto).detach()
    opt = torch.optim.AdamW(model.parameters(), lr=2e-4, weight_decay=1e-4)
    train = tensors(data["train"], device); val = tensors(data["validation"], device)
    history=[]; best=(-math.inf, None)
    for epoch in range(1, args.epochs + 1):
        model.train(); order = torch.arange(train[0].shape[0], device=device)
        total=0.0
        for batch_idx in order.split(args.batch_size):
            opt.zero_grad(set_to_none=True); rel, pos, prog, _ = model(train[0][batch_idx], knowledge)
            mask=train[1][batch_idx] > .5
            positive_weight = (train[1][batch_idx] == 0).sum().float() / train[1][batch_idx].sum().float().clamp_min(1.0)
            positive_weight = positive_weight.clamp(1.0, 8.0)
            loss = F.binary_cross_entropy_with_logits(rel, train[1][batch_idx], pos_weight=positive_weight)
            # Stage position is undefined for negative events. Keep negatives
            # in relevance BCE, but exclude them from position/progress losses.
            if mask.any():
                loss = loss + .5 * F.cross_entropy(pos[mask], train[2][batch_idx][mask].argmax(-1))
                loss = loss + F.smooth_l1_loss(prog[mask], train[3][batch_idx][mask])
            loss.backward(); opt.step(); total += float(loss.detach()) * len(batch_idx)
        model.eval()
        validation_scores, validation_positions, validation_progress = predict_batched(model, val[0], knowledge, args.batch_size)
        row={"epoch":epoch,"train_loss":total/max(1,len(data["train"])),"validation":metrics(val[1],validation_scores,validation_positions,val[2],validation_progress,val[3])}
        history.append(row); print(json.dumps(row, ensure_ascii=False), flush=True)
        score=(row["validation"]["positive_recall_at_0.5"], row["validation"]["joint_attack_progress_recall_pct"], row["validation"]["stage_hit_rate_on_positive"])
        if best[1] is None or score > best[0]: best=(score, epoch, {k:v.detach().cpu() for k,v in model.state_dict().items()})
    args.output_dir.mkdir(parents=True, exist_ok=True)
    model.load_state_dict(best[2]); ckpt=args.output_dir/"m5_knowledge_progress_best.pt"
    torch.save({"model":model.state_dict(),"input_dim":dim,"hidden_dim":128,"positions":10,"weak_supervision":True,"time_split":"per_source_first_80_percent_train_last_20_percent_validation"},ckpt)
    digest=hashlib.sha256(ckpt.read_bytes()).hexdigest()
    report={"status":"SMOKE_COMPLETED" if args.smoke else "COMPLETED","model_version":"m5_knowledge_progress_v3_recall_first","device":str(device),"sources":{k:{"events":v["total"],"train":len(v["train"]),"validation":len(v["validation"])} for k,v in source_groups.items()},"selected":{"train":len(data["train"]),"validation":len(data["validation"])},"weak_supervision":True,"label_source":str(args.labels),"label_semantics":"AIT alert time intervals projected to event relevance, phase bucket, and within-interval progress; not exact event-level ATT&CK annotations","split_policy":"per-source attack intervals in chronological order: earliest 70 percent train, latest 30 percent validation; no test split","checkpoint_selection":"lexicographic positive recall, joint attack-progress recall percentage, stage hit rate; ROC-AUC not used","best_epoch":best[1],"validation":history[best[1]-1]["validation"],"history":history,"checkpoint":str(ckpt),"checkpoint_sha256":digest}
    (args.output_dir/"training_report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False), flush=True)

if __name__ == "__main__": main()
