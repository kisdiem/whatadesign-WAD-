import _bootstrap
import argparse
from src.pipeline.stage_runtime import run_stage

def transform(row):
    timestamp = row.get("timestamp")
    if timestamp is None: raise ValueError("window input requires timestamp")
    # Timestamps remain source strings here; a downstream configured parser owns timezone semantics.
    return {"record_id": row.get("record_id", ""), "dataset_id": row.get("dataset_id", ""), "timestamp": timestamp,
            "micro_window_minutes": 5, "macro_window_minutes": 30, "event": row}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',required=True); p.add_argument('--manifest',required=True); args=p.parse_args(); run_stage("build_windows", args.input, args.output, transform, args.manifest)
if __name__ == '__main__': main()
