"""AIT adapter for the public KAIROS TGN training design.

It keeps KAIROS's temporal memory, neighbor loader, TransformerConv and link
prediction objective, while adapting EventFrame JSONL to a modern PyG loop.
AIT alert intervals are never used as input features; they are reserved for
post-hoc reporting only.
"""
from __future__ import annotations

import argparse, hashlib, json, math, random
from datetime import datetime
from pathlib import Path
import torch
from torch import nn
import torch.nn.functional as F
from torch_geometric.nn import TransformerConv, TGNMemory
from torch_geometric.nn.models.tgn import LastNeighborLoader, IdentityMessage, LastAggregator


def stamp(v):
    return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1_000_000_000)


def node_id(value, table):
    value = str(value)
    if value not in table: table[value] = len(table)
    return table[value]


def relation_id(action):
    text = str(action).lower()
    keys = ("network", "execute", "process", "file", "auth", "login")
    return min(6, next((i for i, k in enumerate(keys) if k in text), 6))


def load_graph(path: Path, limit: int | None = None):
    table, edges = {}, []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f):
            if limit and line_no >= limit: break
            if not line.strip(): continue
            row = json.loads(line); mentions = row.get("entity_mentions") or []
            if not mentions: continue
            src = node_id(mentions[0].get("entity_id", mentions[0].get("value")), table)
            target = mentions[1] if len(mentions) > 1 else {"value": f"action:{row.get('action_family','unknown')}"}
            dst = node_id(target.get("entity_id", target.get("value")), table)
            embedding = row.get("semantic_embedding") or []
            msg = [float(v) for v in embedding[:16]]
            msg += [0.0] * (16 - len(msg))
            edges.append((stamp(row["timestamp"]), src, dst, relation_id(row.get("action_family")), msg))
    edges.sort(key=lambda x: x[0])
    return edges, table


class GraphEmbedding(nn.Module):
    def __init__(self, node_dim=64, edge_dim=64, msg_dim=16, time_dim=32):
        super().__init__(); self.time = nn.Sequential(nn.Linear(1, time_dim), nn.Tanh())
        self.conv1 = TransformerConv(node_dim, edge_dim, heads=2, edge_dim=msg_dim + time_dim)
        self.conv2 = TransformerConv(edge_dim * 2, edge_dim, heads=1, concat=False, edge_dim=msg_dim + time_dim)
    def forward(self, x, last_update, edge_index, t, msg):
        rel = (last_update[edge_index[0]] - t).float().unsqueeze(-1) / 1e9
        attr = torch.cat([self.time(rel), msg], dim=-1)
        x = F.relu(self.conv1(x, edge_index, attr)); return F.relu(self.conv2(x, edge_index, attr))


class LinkPredictor(nn.Module):
    def __init__(self, dim=64, classes=7):
        super().__init__(); self.net = nn.Sequential(nn.Linear(dim * 2, dim * 4), nn.ReLU(), nn.Dropout(.2), nn.Linear(dim * 4, classes))
    def forward(self, a, b): return self.net(torch.cat([a, b], dim=-1))


def run_epoch(edges, memory, gnn, predictor, optimizer, loader, assoc, device, batch_size, train=True):
    memory.train(train); gnn.train(train); predictor.train(train); loader.reset_state()
    if train: memory.reset_state()
    total = correct = count = 0
    for start in range(0, len(edges), batch_size):
        batch = edges[start:start + batch_size]
        src = torch.tensor([e[1] for e in batch], device=device, dtype=torch.long)
        dst = torch.tensor([e[2] for e in batch], device=device, dtype=torch.long)
        t = torch.tensor([e[0] for e in batch], device=device, dtype=torch.long)
        msg = torch.tensor([e[4] for e in batch], device=device, dtype=torch.float32)
        y = torch.tensor([e[3] for e in batch], device=device, dtype=torch.long)
        if train: optimizer.zero_grad(set_to_none=True)
        ids = torch.cat([src, dst]).unique(); n_id, edge_index, e_id = loader(ids)
        assoc[n_id] = torch.arange(n_id.numel(), device=device)
        z, last = memory(n_id); hist_t = torch.tensor([edges[int(i)][0] for i in e_id.cpu()], device=device, dtype=torch.long) if e_id.numel() else t[:0]
        hist_msg = torch.tensor([edges[int(i)][4] for i in e_id.cpu()], device=device, dtype=torch.float32) if e_id.numel() else msg[:0]
        if e_id.numel(): z = gnn(z, last, edge_index, hist_t, hist_msg)
        logits = predictor(z[assoc[src]], z[assoc[dst]]); loss = F.cross_entropy(logits, y)
        if train:
            memory.update_state(src, dst, t, msg); loader.insert(src, dst); loss.backward(); optimizer.step(); memory.detach()
        total += float(loss.detach()) * len(batch); correct += int((logits.argmax(-1) == y).sum()); count += len(batch)
    return total / max(1, count), correct / max(1, count)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--events", type=Path, required=True); ap.add_argument("--out", type=Path, required=True); ap.add_argument("--epochs", type=int, default=5); ap.add_argument("--batch-size", type=int, default=512); ap.add_argument("--limit", type=int); ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args(); torch.manual_seed(42); random.seed(42); device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if a.smoke:
        edges, table = load_graph(a.events, 2048); assert len(edges) > 8 and len(table) > 1
    else: edges, table = load_graph(a.events, a.limit)
    cut = max(1, int(len(edges) * .8)); train_edges, val_edges = edges[:cut], edges[cut:]
    n = len(table); memory = TGNMemory(n, 16, 64, 32, IdentityMessage(16, 64, 32), LastAggregator()).to(device); gnn = GraphEmbedding().to(device); predictor = LinkPredictor().to(device)
    loader = LastNeighborLoader(n, size=20, device=device); assoc = torch.empty(n, dtype=torch.long, device=device); opt = torch.optim.Adam(list(memory.parameters()) + list(gnn.parameters()) + list(predictor.parameters()), lr=5e-4, weight_decay=1e-4)
    history=[]
    for epoch in range(1, (1 if a.smoke else a.epochs) + 1):
        tr_loss, tr_acc = run_epoch(train_edges, memory, gnn, predictor, opt, loader, assoc, device, a.batch_size, True)
        va_loss, va_acc = run_epoch(val_edges, memory, gnn, predictor, opt, loader, assoc, device, a.batch_size, False)
        row={"epoch":epoch,"train_loss":tr_loss,"train_accuracy":tr_acc,"validation_loss":va_loss,"validation_accuracy":va_acc}; history.append(row); print(json.dumps(row), flush=True)
    a.out.mkdir(parents=True, exist_ok=True); ckpt=a.out/"kairos_ait_model.pt"; torch.save({"memory":memory.state_dict(),"gnn":gnn.state_dict(),"predictor":predictor.state_dict(),"node_count":n,"edge_count":len(edges),"time_split":"first_80_percent_train_last_20_percent_validation","ait_labels_used_as_features":False}, ckpt)
    report={"status":"SMOKE_COMPLETED" if a.smoke else "COMPLETED","device":str(device),"events":len(edges),"nodes":n,"train_events":len(train_edges),"validation_events":len(val_edges),"history":history,"checkpoint":str(ckpt),"checkpoint_sha256":hashlib.sha256(ckpt.read_bytes()).hexdigest(),"objective":"KAIROS-style temporal link relation prediction on adapted AIT EventFrames","label_note":"AIT alert intervals are not model input features and were not used in this link objective"}; (a.out/"training_report.json").write_text(json.dumps(report,indent=2),encoding="utf-8"); print(json.dumps(report),flush=True)

if __name__ == "__main__": main()
