"""M5 with a frozen DeBERTa attack-stage knowledge encoder."""
from __future__ import annotations
import argparse, hashlib, json, random
from pathlib import Path
import torch
from torch import nn
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer
from train_m5_progress import load_intervals, read_events, tensors
from train_m5_two_models import AttackStepMLP

STAGES = [
    "初始访问：攻击者通过远程服务、有效账号、扫描或外部入口获得初始访问。",
    "执行：攻击者执行命令、脚本、解释器或恶意进程。",
    "持久化：攻击者建立计划任务、启动项、服务或其他长期驻留机制。",
    "权限提升：攻击者通过 sudo、漏洞利用或权限配置获得更高权限。",
    "防御规避：攻击者隐藏文件、清除痕迹、关闭安全工具或绕过检测。",
    "凭据访问：攻击者读取、窃取、猜测或滥用账号和认证材料。",
    "发现：攻击者枚举主机、用户、进程、网络、文件和系统配置。",
    "横向移动：攻击者使用远程服务、共享、凭据或网络连接访问其他主机。",
    "收集与命令控制：攻击者收集数据并通过网络通道维持控制或传输信息。",
    "影响与收尾：攻击者破坏、加密、删除、停止服务或完成攻击目标。",
]


def encode_stage_knowledge(model_path, device):
    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, use_fast=False)
    encoder = AutoModel.from_pretrained(model_path, local_files_only=True).to(device).eval()
    for p in encoder.parameters(): p.requires_grad_(False)
    encoded = tokenizer(STAGES, padding=True, truncation=True, max_length=128, return_tensors="pt")
    encoded = {k: v.to(device) for k, v in encoded.items()}
    with torch.no_grad():
        out = encoder(**encoded).last_hidden_state
        mask = encoded["attention_mask"].unsqueeze(-1).to(out.dtype)
        return (out * mask).sum(1) / mask.sum(1).clamp_min(1.0)


class TextConditionedStageTransformer(nn.Module):
    def __init__(self, event_dim=768, knowledge_dim=768, hidden=256, positions=10):
        super().__init__(); self.event_proj=nn.Linear(event_dim,hidden); self.knowledge_proj=nn.Linear(knowledge_dim,hidden)
        layer=nn.TransformerEncoderLayer(hidden,8,hidden*2,batch_first=True,norm_first=True)
        self.encoder=nn.TransformerEncoder(layer,2,norm=nn.LayerNorm(hidden),enable_nested_tensor=False)
        self.head=nn.Sequential(nn.LayerNorm(hidden),nn.Linear(hidden,hidden),nn.GELU(),nn.Linear(hidden,positions))
    def forward(self,event,knowledge):
        q=self.event_proj(event).unsqueeze(1); k=self.knowledge_proj(knowledge).unsqueeze(0).expand(event.size(0),-1,-1)
        return self.head(self.encoder(torch.cat([q,k],1))[:,0])


@torch.no_grad()
def evaluate(step, stage, data, knowledge, device, batch_size):
    x,y,pos,_=tensors(data,device); step.eval(); stage.eval(); scores=[]; logits=[]
    for idx in torch.arange(len(data),device=device).split(batch_size): scores.append(torch.sigmoid(step(x[idx])).cpu()); logits.append(stage(x[idx],knowledge).cpu())
    score=torch.cat(scores); logit=torch.cat(logits); actual=y.cpu()>.5; pred=score>=.5; hit=(logit.argmax(-1)==pos.cpu().argmax(-1))&actual; joint=hit&pred
    return {"count":len(data),"positive":int(actual.sum()),"positive_recall_at_0.5":float((pred&actual).sum())/max(1,int(actual.sum())),"stage_hit_rate_on_positive":float(hit.sum())/max(1,int(actual.sum())),"joint_attack_stage_recall_pct":100*float(joint.sum())/max(1,int(actual.sum()))}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--events-root",type=Path,required=True); ap.add_argument("--labels",type=Path,required=True); ap.add_argument("--deberta",type=Path,required=True); ap.add_argument("--output-dir",type=Path,required=True); ap.add_argument("--epochs",type=int,default=8); ap.add_argument("--batch-size",type=int,default=256); ap.add_argument("--negative-ratio",type=int,default=4); ap.add_argument("--max-sources",type=int,default=8); ap.add_argument("--smoke",action="store_true")
    a=ap.parse_args(); torch.manual_seed(42); random.seed(42); device=torch.device("cuda" if torch.cuda.is_available() else "cpu"); knowledge=encode_stage_knowledge(a.deberta,device)
    if a.smoke:
        stage=TextConditionedStageTransformer().to(device); step=AttackStepMLP().to(device); x=torch.randn(8,768,device=device); loss=stage(x,knowledge).square().mean()+step(x).square().mean(); loss.backward(); print(json.dumps({"status":"SMOKE_COMPLETED","device":str(device),"deberta_hidden":list(knowledge.shape),"stage_output":[8,10],"loss_finite":bool(torch.isfinite(loss).item()),"deberta_frozen":True,"synthetic":True})); return
    intervals,phases=load_intervals(a.labels); names=sorted(p.name.removesuffix("_m1_m2") for p in a.events_root.glob("*_m1_m2"))[:a.max_sources]; paths={n:a.events_root/f"{n}_m1_m2"/"m1_eventframes.jsonl" for n in names if (a.events_root/f"{n}_m1_m2"/"m1_eventframes.jsonl").exists()}; data,groups=read_events(paths,intervals,phases,10,a.negative_ratio,42); train,val=data["train"],data["validation"]; tx,ty,tp,_=tensors(train,device); step=AttackStepMLP().to(device); stage=TextConditionedStageTransformer().to(device); so=torch.optim.AdamW(step.parameters(),lr=2e-4,weight_decay=1e-4); to=torch.optim.AdamW(stage.parameters(),lr=2e-4,weight_decay=1e-4); history=[]; best=None
    for epoch in range(1,a.epochs+1):
        step.train(); stage.train(); sl_total=tl_total=0.0
        for idx in torch.arange(len(train),device=device).split(a.batch_size):
            mask=ty[idx]>.5; so.zero_grad(set_to_none=True); pw=((ty[idx]==0).sum().float()/ty[idx].sum().float().clamp_min(1)).clamp(1,8); sl=F.binary_cross_entropy_with_logits(step(tx[idx]),ty[idx],pos_weight=pw); sl.backward(); so.step(); sl_total+=float(sl.detach())*len(idx)
            if mask.any(): to.zero_grad(set_to_none=True); tl=F.cross_entropy(stage(tx[idx][mask],knowledge),tp[idx][mask].argmax(-1)); tl.backward(); to.step(); tl_total+=float(tl.detach())*int(mask.sum())
        metrics=evaluate(step,stage,val,knowledge,device,a.batch_size); row={"epoch":epoch,"step_loss":sl_total/max(1,len(train)),"stage_loss":tl_total/max(1,int((ty>.5).sum())),"validation":metrics}; history.append(row); print(json.dumps(row),flush=True); key=(metrics["positive_recall_at_0.5"],metrics["joint_attack_stage_recall_pct"],metrics["stage_hit_rate_on_positive"])
        if best is None or key>best[0]: best=(key,epoch,{"step":{k:v.detach().cpu() for k,v in step.state_dict().items()},"stage":{k:v.detach().cpu() for k,v in stage.state_dict().items()},"knowledge":knowledge.detach().cpu()})
    a.output_dir.mkdir(parents=True,exist_ok=True); ckpt=a.output_dir/"m5_text_stage_best.pt"; torch.save({"models":best[2],"epoch":best[1],"deberta":str(a.deberta),"deberta_frozen":True,"stage_texts":STAGES,"weak_supervision":True},ckpt); report={"status":"COMPLETED","model_version":"m5_text_conditioned_stage_v1","device":str(device),"deberta":str(a.deberta),"deberta_frozen":True,"sources":{k:{"events":v["total"],"train":len(v["train"]),"validation":len(v["validation"])} for k,v in groups.items()},"selected":{"train":len(train),"validation":len(val)},"objective":"MLP attack-step detection plus DeBERTa-knowledge-conditioned Transformer stage classification","stage_loss_positive_only":True,"stage_knowledge_encoder":"frozen DeBERTa masked-mean stage descriptions","checkpoint_selection":"positive recall, joint stage recall, stage hit rate; no ROC-AUC","weak_supervision":True,"label_semantics":"AIT alert intervals projected to event relevance and phase bucket; not event-level ATT&CK ground truth","best_epoch":best[1],"validation":history[best[1]-1]["validation"],"history":history,"checkpoint":str(ckpt),"checkpoint_sha256":hashlib.sha256(ckpt.read_bytes()).hexdigest()}; (a.output_dir/"training_report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8"); print(json.dumps(report,ensure_ascii=False),flush=True)

if __name__=="__main__": main()
