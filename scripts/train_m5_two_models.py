"""Train independent M5 attack-step and attack-stage models."""
from __future__ import annotations
import argparse, hashlib, json, random, math
from pathlib import Path
import torch
from torch import nn
import torch.nn.functional as F

from train_m5_progress import load_intervals, read_events, tensors


class AttackStepMLP(nn.Module):
    def __init__(self, input_dim=768, hidden=256):
        super().__init__()
        self.net = nn.Sequential(nn.LayerNorm(input_dim), nn.Linear(input_dim, hidden), nn.GELU(), nn.Dropout(.1), nn.Linear(hidden, 1))
    def forward(self, x): return self.net(x).squeeze(-1)


class AttackStageTransformer(nn.Module):
    def __init__(self, input_dim=768, hidden=128, positions=10):
        super().__init__(); self.proj = nn.Linear(input_dim, hidden); self.query = nn.Parameter(torch.zeros(1, 1, hidden)); nn.init.normal_(self.query, std=.02)
        layer = nn.TransformerEncoderLayer(hidden, 4, hidden * 2, batch_first=True, norm_first=True)
        self.encoder = nn.TransformerEncoder(layer, 2, norm=nn.LayerNorm(hidden), enable_nested_tensor=False)
        self.head = nn.Sequential(nn.LayerNorm(hidden), nn.Linear(hidden, hidden), nn.GELU(), nn.Linear(hidden, positions))
    def forward(self, x):
        event = self.proj(x).unsqueeze(1); query = self.query.expand(x.shape[0], -1, -1)
        return self.head(self.encoder(torch.cat([query, event], dim=1))[:, 0])


@torch.no_grad()
def evaluate(step, stage, data, device, batch_size=256):
    x, y, pos, _ = tensors(data, device); step.eval(); stage.eval(); scores=[]; stages=[]
    for idx in torch.arange(len(data), device=device).split(batch_size):
        scores.append(torch.sigmoid(step(x[idx])).cpu()); stages.append(stage(x[idx]).cpu())
    score=torch.cat(scores); stage_logits=torch.cat(stages); actual=y.cpu() > .5; predicted=score >= .5
    recall=float((predicted & actual).sum())/max(1,int(actual.sum())); stage_hit=(stage_logits.argmax(-1)==pos.cpu().argmax(-1)) & actual
    joint=stage_hit & predicted
    return {"count":len(data),"positive":int(actual.sum()),"positive_recall_at_0.5":recall,"stage_hit_rate_on_positive":float(stage_hit.sum())/max(1,int(actual.sum())),"joint_attack_stage_recall_pct":100.0*float(joint.sum())/max(1,int(actual.sum()))}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--events-root",type=Path,required=True); ap.add_argument("--labels",type=Path,required=True); ap.add_argument("--output-dir",type=Path,required=True); ap.add_argument("--epochs",type=int,default=8); ap.add_argument("--batch-size",type=int,default=256); ap.add_argument("--negative-ratio",type=int,default=4); ap.add_argument("--max-sources",type=int,default=8); ap.add_argument("--smoke",action="store_true")
    a=ap.parse_args(); torch.manual_seed(42); random.seed(42); device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if a.smoke:
        step=AttackStepMLP().to(device); stage=AttackStageTransformer().to(device); x=torch.randn(8,768,device=device); loss=step(x).square().mean()+stage(x).square().mean(); loss.backward(); print(json.dumps({"status":"SMOKE_COMPLETED","device":str(device),"step_output":[8],"stage_output":[8,10],"loss_finite":bool(torch.isfinite(loss).item()),"synthetic":True})); return
    intervals, phases=load_intervals(a.labels); names=sorted(p.name.removesuffix("_m1_m2") for p in a.events_root.glob("*_m1_m2"))[:a.max_sources]; paths={n:a.events_root/f"{n}_m1_m2"/"m1_eventframes.jsonl" for n in names if (a.events_root/f"{n}_m1_m2"/"m1_eventframes.jsonl").exists()}; data, groups=read_events(paths,intervals,phases,10,a.negative_ratio,42)
    train=data["train"]; val=data["validation"]; device=torch.device("cuda" if torch.cuda.is_available() else "cpu"); tx,ty,tp,_=tensors(train,device); vx,vy,vp,_=tensors(val,device)
    step=AttackStepMLP().to(device); stage=AttackStageTransformer().to(device); step_opt=torch.optim.AdamW(step.parameters(),lr=2e-4,weight_decay=1e-4); stage_opt=torch.optim.AdamW(stage.parameters(),lr=2e-4,weight_decay=1e-4); history=[]; best=None
    for epoch in range(1,a.epochs+1):
        step.train(); stage.train(); total_step=total_stage=0.0
        for idx in torch.arange(len(train),device=device).split(a.batch_size):
            mask=ty[idx]>.5; step_opt.zero_grad(set_to_none=True); weight=((ty[idx]==0).sum().float()/ty[idx].sum().float().clamp_min(1)).clamp(1,8); sl=F.binary_cross_entropy_with_logits(step(tx[idx]),ty[idx],pos_weight=weight); sl.backward(); step_opt.step(); total_step+=float(sl.detach())*len(idx)
            if mask.any():
                stage_opt.zero_grad(set_to_none=True); tl=F.cross_entropy(stage(tx[idx][mask]),tp[idx][mask].argmax(-1)); tl.backward(); stage_opt.step(); total_stage+=float(tl.detach())*int(mask.sum())
        metrics=evaluate(step,stage,val,device,a.batch_size); row={"epoch":epoch,"step_loss":total_step/max(1,len(train)),"stage_loss":total_stage/max(1,int((ty>.5).sum())),"validation":metrics}; history.append(row); print(json.dumps(row),flush=True)
        key=(metrics["positive_recall_at_0.5"],metrics["joint_attack_stage_recall_pct"],metrics["stage_hit_rate_on_positive"])
        if best is None or key>best[0]: best=(key,epoch,{"step":{k:v.detach().cpu() for k,v in step.state_dict().items()},"stage":{k:v.detach().cpu() for k,v in stage.state_dict().items()}})
    a.output_dir.mkdir(parents=True,exist_ok=True); ckpt=a.output_dir/"m5_two_models_best.pt"; torch.save({"models":best[2],"epoch":best[1],"time_split":"per-source chronological attack-interval split, no test split","weak_supervision":True},ckpt); report={"status":"COMPLETED","model_version":"m5_two_models_v1","device":str(device),"sources":{k:{"events":v["total"],"train":len(v["train"]),"validation":len(v["validation"])} for k,v in groups.items()},"selected":{"train":len(train),"validation":len(val)},"objective":"independent MLP attack-step detection and Transformer attack-stage classification","stage_loss_positive_only":True,"checkpoint_selection":"positive recall, joint stage recall, stage hit rate; no ROC-AUC","weak_supervision":True,"label_semantics":"AIT alert intervals projected to event relevance and phase bucket; not event-level ATT&CK ground truth","best_epoch":best[1],"validation":history[best[1]-1]["validation"],"history":history,"checkpoint":str(ckpt),"checkpoint_sha256":hashlib.sha256(ckpt.read_bytes()).hexdigest()}; (a.output_dir/"training_report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(json.dumps(report,ensure_ascii=False),flush=True)

if __name__=="__main__": main()
