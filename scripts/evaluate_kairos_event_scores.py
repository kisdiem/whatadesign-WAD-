"""Export event-level KAIROS relation loss and evaluate on the same temporal split."""
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime
from pathlib import Path
import numpy as np
import torch
from torch import nn
import torch.nn.functional as F
from torch_geometric.nn import TransformerConv, TGNMemory
from torch_geometric.nn.models.tgn import LastNeighborLoader, IdentityMessage, LastAggregator

def stamp(v): return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1_000_000_000)
def load_graph(path):
    table={}; edges=[]
    def nid(v):
        v=str(v)
        if v not in table: table[v]=len(table)
        return table[v]
    keys=("network","execute","process","file","auth","login")
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            r=json.loads(line); ms=r.get("entity_mentions") or []
            if not ms: continue
            src=nid(ms[0].get("entity_id",ms[0].get("value")))
            dst=nid(ms[1].get("entity_id",ms[1].get("value")) if len(ms)>1 else "action:"+str(r.get("action_family","unknown")))
            action=str(r.get("action_family","unknown")).lower(); rel=min(6,next((i for i,k in enumerate(keys) if k in action),6))
            msg=[float(v) for v in (r.get("semantic_embedding") or [])[:16]]; msg += [0.]*(16-len(msg))
            edges.append((stamp(r["timestamp"]),src,dst,rel,msg,str(r.get("record_id",""))))
    edges.sort(key=lambda x:x[0]); return edges,table
class GraphEmbedding(nn.Module):
    def __init__(self):
        super().__init__(); self.time=nn.Sequential(nn.Linear(1,32),nn.Tanh()); self.conv1=TransformerConv(64,64,heads=2,edge_dim=48); self.conv2=TransformerConv(128,64,heads=1,concat=False,edge_dim=48)
    def forward(self,x,last,ei,t,msg):
        rel=(last[ei[0]]-t).float().unsqueeze(-1)/1e9; a=torch.cat([self.time(rel),msg],-1); return F.relu(self.conv2(F.relu(self.conv1(x,ei,a)),ei,a))
class LinkPredictor(nn.Module):
    def __init__(self):
        super().__init__(); self.net=nn.Sequential(nn.Linear(128,256),nn.ReLU(),nn.Dropout(.2),nn.Linear(256,7))
    def forward(self,a,b): return self.net(torch.cat([a,b],-1))
def replay_or_score(edges, memory, gnn, pred, loader, assoc, device, score=False, batch_size=512):
    vals=[]; memory.eval(); gnn.eval(); pred.eval(); loader.reset_state()
    for start in range(0,len(edges),batch_size):
        batch=edges[start:start+batch_size]; src=torch.tensor([e[1] for e in batch],device=device); dst=torch.tensor([e[2] for e in batch],device=device); t=torch.tensor([e[0] for e in batch],device=device); msg=torch.tensor([e[4] for e in batch],device=device); y=torch.tensor([e[3] for e in batch],device=device)
        ids=torch.cat([src,dst]).unique(); n_id,ei,eid=loader(ids); assoc[n_id]=torch.arange(n_id.numel(),device=device); z,last=memory(n_id)
        if eid.numel():
            ht=torch.tensor([edges[int(i)][0] for i in eid.cpu()],device=device); hm=torch.tensor([edges[int(i)][4] for i in eid.cpu()],device=device); z=gnn(z,last,ei,ht,hm)
        logits=pred(z[assoc[src]],z[assoc[dst]])
        if score: vals.extend(F.cross_entropy(logits,y,reduction="none").detach().cpu().tolist())
        memory.update_state(src,dst,t,msg); loader.insert(src,dst); memory.detach()
    return vals
def ap(y,p):
    order=np.argsort(-np.asarray(p),kind="mergesort"); yy=np.asarray(y)[order]; pos=int(yy.sum())
    if pos==0 or pos==len(yy): return None
    tp=np.cumsum(yy); fp=np.cumsum(1-yy); precision=tp/np.maximum(tp+fp,1); recall=tp/pos; change=np.r_[True,yy[1:]!=yy[:-1]]
    return float(np.sum((recall[change]-np.r_[0.,recall[change][:-1]])*precision[change]))
def metrics(y,p,threshold):
    y=np.asarray(y); p=np.asarray(p); q=p>=threshold; tp=int((q&(y==1)).sum()); fp=int((q&(y==0)).sum()); fn=int((~q&(y==1)).sum()); prec=tp/max(tp+fp,1); rec=tp/max(tp+fn,1); return {"threshold":threshold,"precision":prec,"recall":rec,"f1":2*prec*rec/max(prec+rec,1e-12),"pr_auc":ap(y,p),"tp":tp,"fp":fp,"fn":fn}
def main():
    a=argparse.ArgumentParser(); a.add_argument("--events",type=Path,required=True); a.add_argument("--labels",type=Path,required=True); a.add_argument("--checkpoint",type=Path,required=True); a.add_argument("--output",type=Path,required=True); args=a.parse_args(); device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    edges,table=load_graph(args.events); labels={r["record_id"]:int(r["label"]) for r in (json.loads(x) for x in args.labels.read_text(encoding="utf-8").splitlines() if x.strip())}
    # The KAIROS graph adapter does not retain record_id in its edge tuple; use
    # the same temporal split and compare against the interval labels only
    # when the event stream has an aligned sidecar in the caller.
    cut=max(1,int(len(edges)*.8)); ck=torch.load(args.checkpoint,map_location=device); n=int(ck["node_count"]); memory=TGNMemory(n,16,64,32,IdentityMessage(16,64,32),LastAggregator()).to(device); gnn=GraphEmbedding().to(device); pred=LinkPredictor().to(device); memory.load_state_dict(ck["memory"]); gnn.load_state_dict(ck["gnn"]); pred.load_state_dict(ck["predictor"]); loader=LastNeighborLoader(n,size=20,device=device); assoc=torch.empty(n,dtype=torch.long,device=device)
    replay_or_score(edges[:cut],memory,gnn,pred,loader,assoc,device,False); scores=replay_or_score(edges[cut:],memory,gnn,pred,loader,assoc,device,True)
    test_edges=edges[cut:]
    pairs=[(e[5],s) for e,s in zip(test_edges,scores) if e[5] in labels]
    unmatched=len(test_edges)-len(pairs)
    if not pairs:
        raise SystemExit("no KAIROS event ids matched the label sidecar; refusing positional labeling")
    y=[labels[r] for r,_ in pairs]; p=[s for _,s in pairs]
    # Threshold is selected only from the training side, using the same model
    # and temporal replay.  A fresh model is reconstructed before test scoring.
    def build():
        m=TGNMemory(n,16,64,32,IdentityMessage(16,64,32),LastAggregator()).to(device); g=GraphEmbedding().to(device); q=LinkPredictor().to(device); m.load_state_dict(ck["memory"]); g.load_state_dict(ck["gnn"]); q.load_state_dict(ck["predictor"]); return m,g,q,LastNeighborLoader(n,size=20,device=device),torch.empty(n,dtype=torch.long,device=device)
    m,g,q,l,ac=build(); train_scores=replay_or_score(edges[:cut],m,g,q,l,ac,device,True); train_pairs=[(e[5],s) for e,s in zip(edges[:cut],train_scores) if e[5] in labels]; ty=[labels[r] for r,_ in train_pairs]; tp=[s for _,s in train_pairs]
    thresholds=np.linspace(float(min(tp)),float(max(tp)),101); selected=max(thresholds,key=lambda t:metrics(ty,tp,float(t))["f1"]); result={"status":"COMPLETED","dataset":"fox","split":"chronological_80_20","events":len(edges),"train_events":cut,"test_events":len(test_edges),"matched_test_events":len(pairs),"unmatched_test_events":unmatched,"threshold":float(selected),"threshold_source":"training_80_percent","test":metrics(y,p,float(selected)),"score_definition":"per-edge cross-entropy relation loss","checkpoint":str(args.checkpoint),"labels_used_as_features":False,"label_source":"AIT interval sidecar"}
    args.output.parent.mkdir(parents=True,exist_ok=True); (args.output.with_suffix(".scores.jsonl")).write_text("\n".join(json.dumps({"record_id":r,"score":s,"label":labels[r]}) for r,s in pairs)+"\n",encoding="utf-8"); args.output.write_text(json.dumps(result,indent=2),encoding="utf-8"); print(json.dumps(result))
if __name__=="__main__": main()
