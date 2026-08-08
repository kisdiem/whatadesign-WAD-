from __future__ import annotations
import argparse, csv, json, random
from pathlib import Path
import torch
from transformers import AutoModel, AutoModelForMaskedLM, AutoTokenizer
import _bootstrap
from src.semantic.deberta_security import DebertaSecurityEncoder
from src.semantic.security_log_text import security_log_text

def json_rows(roots):
    paths=[path for root in roots for path in Path(root).rglob('raw_records.jsonl')]
    handles=[path.open(encoding='utf-8') for path in paths]
    try:
        while handles:
            for handle in handles[:]:
                line=handle.readline()
                if not line: handles.remove(handle); handle.close(); continue
                try:
                    row=json.loads(line); yield security_log_text(row.get('dataset_id','unknown'),row.get('features',row.get('payload',row)))
                except (json.JSONDecodeError,TypeError): continue
    finally:
        for handle in handles: handle.close()

def label_of(value):
    text=str(value).strip().lower()
    return 0 if text in {'','0','false','normal','benign'} or 'background' in text else 1

def labeled_rows(roots, per_class):
    pools={0:[],1:[]}
    for root in roots:
        for path in list(Path(root).rglob('*.binetflow'))+list(Path(root).rglob('*.csv')):
            with path.open(encoding='utf-8',errors='replace',newline='') as f:
                for row in csv.DictReader(f):
                    label=label_of(row.get('Label',row.get('label',row.get('Class',''))))
                    if len(pools[label])<per_class: pools[label].append(security_log_text('ctu13' if path.suffix=='.binetflow' else 'sandworm',row))
                    if all(len(v)>=per_class for v in pools.values()): break
    if not pools[0] or not pools[1]: raise RuntimeError('adapter stage requires both normal and anomalous labels')
    return pools

def mask_batch(tokenizer, texts, device, field_probability):
    batch=tokenizer(texts,return_tensors='pt',padding=True,truncation=True,max_length=192).to(device)
    labels=batch.input_ids.clone(); probability=torch.full(labels.shape,.15,device=device)
    special=torch.tensor([tokenizer.get_special_tokens_mask(row,already_has_special_tokens=True) for row in labels.tolist()],device=device,dtype=torch.bool)
    probability.masked_fill_(special,0)
    probability.masked_fill_(batch.attention_mask.eq(0),0)
    marker=tokenizer.convert_tokens_to_ids('[VALUE]')
    if marker != tokenizer.unk_token_id:
        field_next=torch.zeros_like(labels,dtype=torch.bool); field_next[:,1:]=labels[:,:-1].eq(marker); probability.masked_fill_(field_next,field_probability)
    chosen=torch.bernoulli(probability).bool(); labels[~chosen]=-100
    # A batch with no target tokens makes Hugging Face MLM loss undefined.
    for row in range(chosen.shape[0]):
        if not chosen[row].any():
            valid=torch.where(probability[row] > 0)[0]
            if not len(valid): raise RuntimeError('MLM batch contains no maskable tokens')
            chosen[row,valid[0]]=True; labels[row,valid[0]]=batch.input_ids[row,valid[0]]
    replace=torch.bernoulli(torch.full(labels.shape,.8,device=device)).bool() & chosen; batch.input_ids[replace]=tokenizer.mask_token_id
    random_mask=torch.bernoulli(torch.full(labels.shape,.5,device=device)).bool() & chosen & ~replace; batch.input_ids[random_mask]=torch.randint(len(tokenizer),labels.shape,device=device)[random_mask]
    batch['labels']=labels; return batch

def train_mlm(args):
    out=Path(args.output)/'mlm'; out.mkdir(parents=True,exist_ok=True); device=torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    tokenizer=AutoTokenizer.from_pretrained(args.model,local_files_only=True); tokenizer.add_special_tokens({'additional_special_tokens':['[DATASET]','[FIELD]','[VALUE]','[MESSAGE]']})
    model=AutoModelForMaskedLM.from_pretrained(args.model,local_files_only=True).float().to(device); model.resize_token_embeddings(len(tokenizer)); opt=torch.optim.AdamW(model.parameters(),lr=args.mlm_lr)
    stream=json_rows(args.mlm_roots); history=[]
    for step in range(1,args.mlm_steps+1):
        texts=[]
        while len(texts)<args.batch_size:
            try: texts.append(next(stream))
            except StopIteration: stream=json_rows(args.mlm_roots); texts.append(next(stream))
        batch=mask_batch(tokenizer,texts,device,args.field_mask_probability); loss=model(**batch).loss
        if not torch.isfinite(loss): raise RuntimeError(f'non-finite MLM loss at step {step}')
        opt.zero_grad(); loss.backward(); opt.step()
        if step%args.save_every==0 or step==args.mlm_steps:
            model.save_pretrained(out); tokenizer.save_pretrained(out); history.append({'step':step,'mlm_loss':float(loss.detach())}); (out/'history.json').write_text(json.dumps(history,indent=2))
    return out

def train_adapter(args, mlm_dir):
    out=Path(args.output)/'adapter'; out.mkdir(parents=True,exist_ok=True); device=torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    tokenizer=AutoTokenizer.from_pretrained(mlm_dir,local_files_only=True); backbone=AutoModel.from_pretrained(mlm_dir,local_files_only=True).to(device); model=DebertaSecurityEncoder(backbone,hidden_size=backbone.config.hidden_size,bottleneck_dim=args.adapter_dim).to(device); model.freeze_backbone(); opt=torch.optim.AdamW(list(model.adapter.parameters())+list(model.classifier.parameters()),lr=args.adapter_lr)
    pools=labeled_rows(args.label_roots,args.adapter_per_class); history=[]
    for step in range(1,args.adapter_steps+1):
        texts=[]; labels=[]
        for _ in range(args.batch_size//2):
            for label in (0,1): texts.append(random.choice(pools[label])); labels.append(label)
        batch=tokenizer(texts,return_tensors='pt',padding=True,truncation=True,max_length=192).to(device); target=torch.tensor(labels,dtype=torch.float32,device=device); loss=torch.nn.functional.binary_cross_entropy_with_logits(model(batch.input_ids,batch.attention_mask),target); opt.zero_grad(); loss.backward(); opt.step()
        if step%args.save_every==0 or step==args.adapter_steps:
            history.append({'step':step,'adapter_loss':float(loss.detach())}); (out/'history.json').write_text(json.dumps(history,indent=2)); torch.save(model.export_embedding_state(),out/'deberta_security_encoder_adapter.pt'); tokenizer.save_pretrained(out)
    return out

def main():
 p=argparse.ArgumentParser(); p.add_argument('--model',required=True); p.add_argument('--output',required=True); p.add_argument('--mlm-roots',nargs='+',required=True); p.add_argument('--label-roots',nargs='+',required=True); p.add_argument('--mlm-steps',type=int,default=200000); p.add_argument('--adapter-steps',type=int,default=20000); p.add_argument('--batch-size',type=int,default=16); p.add_argument('--save-every',type=int,default=1000); p.add_argument('--field-mask-probability',type=float,default=.20); p.add_argument('--mlm-lr',type=float,default=5e-5); p.add_argument('--adapter-lr',type=float,default=1e-3); p.add_argument('--adapter-dim',type=int,default=96); p.add_argument('--adapter-per-class',type=int,default=50000); p.add_argument('--stage',choices=['mlm','adapter','all'],default='all'); a=p.parse_args(); mlm=Path(a.output)/'mlm' if a.stage=='adapter' else train_mlm(a); train_adapter(a,mlm) if a.stage in {'adapter','all'} else None
if __name__=='__main__': main()
