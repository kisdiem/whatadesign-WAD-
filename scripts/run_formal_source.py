from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path
import _bootstrap
from src.common.schema import FrozenFeatureRecord
from src.training.m6_formal import train_formal

def jsonl(path): return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()

def main():
    p=argparse.ArgumentParser(); p.add_argument("--config",required=True); p.add_argument("--work-dir",required=True); p.add_argument("--max-records-per-source",type=int,default=500); p.add_argument("--epochs-per-module",type=int,default=2); p.add_argument("--seed",type=int,default=42); p.add_argument("--device",default="cuda"); p.add_argument("--skip-pipeline",action="store_true"); a=p.parse_args()
    root=Path(a.work_dir); root.mkdir(parents=True,exist_ok=True)
    if not a.skip_pipeline:
        subprocess.run([".venv/bin/python","scripts/run_source_v3_pipeline.py","--config",a.config,"--mode","train","--work-dir",str(root),"--max-records-per-source",str(a.max_records_per_source),"--epochs-per-module",str(a.epochs_per_module),"--seed",str(a.seed),"--device",a.device],check=True)
    split=json.loads((root/"splits.json").read_text(encoding="utf-8")); labels={r["record_id"]:int(r.get("label",0)) for r in jsonl(root/"labels.jsonl")}; frozen=[]
    for row in jsonl(root/"frozen_features.jsonl"):
        row.pop("schema_version", None)
        frozen.append(FrozenFeatureRecord(**row))
    formal=root/"m6_formal"; training=train_formal(frozen,labels,split,formal,a.seed,max(1,a.epochs_per_module)); validation=jsonl(formal/"validation_predictions.jsonl"); test=jsonl(formal/"test_predictions.jsonl")
    candidates=sorted({float(r["score"]) for r in validation}) or [.5]
    def validation_key(threshold):
        tp=sum(int(r["label"]) and float(r["score"])>=threshold for r in validation); fp=sum((not int(r["label"])) and float(r["score"])>=threshold for r in validation); fn=sum(int(r["label"]) and float(r["score"])<threshold for r in validation)
        precision=tp/max(tp+fp,1); recall=tp/max(tp+fn,1); return (2*precision*recall/max(precision+recall,1e-12), precision, recall, threshold)
    threshold=max(candidates,key=validation_key)
    calibration={"status":"FORMAL","source":"source_validation","checkpoint_mode":"train","checkpoint":training["checkpoint"],"record_count":len(validation),"positive_count":sum(int(r["label"]) for r in validation),"negative_count":sum(1-int(r["label"]) for r in validation),"threshold":float(threshold),"threshold_selection":"validation_max_f1","test_used_for_calibration":False,"ait_accessed":False,"m4_integrated":training.get("m4_integrated",False),"kairos_style_integrated":training.get("kairos_style_integrated",False)}
    tp=fp=fn=0
    for r in test:
        label=int(r["label"]); pred=float(r["score"])>=threshold; tp+=int(pred and label); fp+=int(pred and not label); fn+=int((not pred) and label)
    precision=tp/max(tp+fp,1); recall=tp/max(tp+fn,1); evaluation={"status":"FORMAL","split":"test","record_count":len(test),"positive_count":sum(int(r["label"]) for r in test),"negative_count":sum(1-int(r["label"]) for r in test),"threshold":float(threshold),"precision":precision,"recall":recall,"f1":2*precision*recall/max(precision+recall,1e-12),"threshold_source":"source_validation","test_used_for_calibration":False,"ait_accessed":False,"m4_integrated":training.get("m4_integrated",False),"kairos_style_integrated":training.get("kairos_style_integrated",False)}
    def score_metrics(rows, field, value):
        tp=sum(int(r["label"]) and float(r[field])>=value for r in rows); fp=sum((not int(r["label"])) and float(r[field])>=value for r in rows); fn=sum(int(r["label"]) and float(r[field])<value for r in rows); p=tp/max(tp+fp,1); r=tp/max(tp+fn,1); return {"threshold":float(value),"precision":p,"recall":r,"f1":2*p*r/max(p+r,1e-12),"true_positive":tp,"false_positive":fp,"false_negative":fn}
    ablation={}
    for field in ("m4_score","kairos_reconstruction_error","kairos_window_score","kairos_queue_log_score","score"):
        values=sorted({float(row[field]) for row in validation}) or [0.0]
        selected=max(values,key=lambda value:(score_metrics(validation,field,value)["f1"],score_metrics(validation,field,value)["precision"],score_metrics(validation,field,value)["recall"],value))
        ablation[field]={"validation":score_metrics(validation,field,selected),"test":score_metrics(test,field,selected),"selection_split":"validation"}
    contract={"contract_version":"v3-formal-2","status":"COMPLETED","mode":"train","stages":["ingest","split","m0_fit_transform","m1_semantic","m2_resolve","m3_causal","m4_train_infer","m4_supervised_adapter","kairos_style_anomaly","m5_build","frozen_export","m6_formal","calibration_validation_only","held_out_test","release_preflight"],"split_contract":{"train_ids":len(split["train"]),"validation_ids":len(split["validation"]),"test_ids":len(split["test"]),"test_used_for_calibration":False},"m0_m1_protocol":{"fit_scope":"all_available_unlabeled_records","test_labels_used":False,"evaluation_mode":"transductive_unlabeled_template_adaptation"},"formal_training":training,"ait_accessed":False,"real_data_used":True,"synthetic_data":False}
    metrics=root/"formal_metrics"; metrics.mkdir(exist_ok=True); (root/"formal_stage_contract.json").write_text(json.dumps(contract,indent=2),encoding="utf-8"); (metrics/"source_calibration.json").write_text(json.dumps(calibration,indent=2),encoding="utf-8"); (metrics/"source_evaluation.json").write_text(json.dumps(evaluation,indent=2),encoding="utf-8"); (metrics/"m4_kairos_ablation.json").write_text(json.dumps(ablation,indent=2),encoding="utf-8")
    release_reasons=[]
    if not test: release_reasons.append("held-out test is empty")
    if sum(int(r["label"]) for r in test) == 0: release_reasons.append("held-out test contains no positive examples; metrics are non-discriminative")
    if sum(int(r["label"]) for r in test) < 5: release_reasons.append("held-out test has fewer than five positive examples; release evidence is insufficient")
    if evaluation["recall"] <= 0 or evaluation["f1"] <= 0: release_reasons.append("held-out test has zero recall or F1; model has not detected any positive test record")
    release={"status":"RELEASE_READY" if not release_reasons else "RELEASE_REJECTED","reasons":release_reasons,"formal_metrics":not bool(release_reasons),"ait_accessed":False}; (metrics/"release_preflight.json").write_text(json.dumps(release,indent=2),encoding="utf-8")
    manifest=json.loads((root/"run_manifest.json").read_text(encoding="utf-8")) if (root/"run_manifest.json").is_file() else {}; manifest.update({"mode":"train","formal_metrics":True,"real_training_completed":True,"release_eligible":release["status"]=="RELEASE_READY","ait_accessed":False,"formal_checkpoint":training["checkpoint"],"formal_stage_contract":str(root/"formal_stage_contract.json")}); manifest["artifact_hashes"]={str(x.relative_to(root)):sha256(x) for x in root.rglob("*") if x.is_file() and x.name!="run_manifest.json"}; (root/"run_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    print(json.dumps({"stage_contract":contract,"calibration":calibration,"evaluation":evaluation,"release_preflight":release},indent=2))
if __name__=="__main__": main()
