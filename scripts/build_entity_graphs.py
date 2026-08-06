import _bootstrap
import argparse
from src.pipeline.stage_runtime import run_stage

def transform(row):
    if "record_id" not in row: raise ValueError("graph input requires record_id")
    nodes = [{"node_id": row["record_id"], "node_type": "event", "action_family": row.get("action_family", "unknown"), "outcome": row.get("outcome", "unknown")}]
    for item in row.get("entity_mentions", []):
        if not isinstance(item, dict) or not item.get("entity_id"): continue
        nodes.append({"node_id": item["entity_id"], "node_type": item.get("entity_type", "unknown")})
    return {"graph_id": "graph:" + row["record_id"], "dataset_id": row.get("dataset_id", ""), "current_record_id": row["record_id"], "nodes": nodes, "edges": []}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',required=True); p.add_argument('--manifest',required=True); args=p.parse_args(); run_stage("build_entity_graphs", args.input, args.output, transform, args.manifest)
if __name__ == '__main__': main()
