import _bootstrap
import argparse
from src.pipeline.stage_runtime import run_stage

def transform(row):
    history = row.get("history_events", [])
    current = row.get("current_event")
    if not isinstance(current, dict) or not current.get("record_id"): raise ValueError("strict batch requires current_event")
    if any(item.get("record_id") == current["record_id"] for item in history): raise ValueError("current event leaked into history")
    return {"record_id": current["record_id"], "dataset_id": current.get("dataset_id", row.get("dataset_id", "")), "history_events": history,
            "current_event": current, "graph_before_current_event": row.get("graph_before_current_event", {}), "strict_mode": True,
            "source_record_ref": current.get("source_record_ref", "")}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',required=True); p.add_argument('--manifest',required=True); args=p.parse_args(); run_stage("build_causal_m4_batches", args.input, args.output, transform, args.manifest)
if __name__ == '__main__': main()
