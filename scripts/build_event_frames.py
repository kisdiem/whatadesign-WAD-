import _bootstrap
import argparse
from src.pipeline.stage_runtime import run_stage

def transform(row):
    record_id = row.get("record_id") or row.get("raw_record_id")
    if not record_id or "dataset_id" not in row:
        raise ValueError("event-frame input requires record_id/raw_record_id and dataset_id")
    return {"dataset_id": row["dataset_id"], "record_id": record_id, "timestamp": row.get("timestamp", row.get("raw_timestamp")),
            "record_kind": row.get("record_kind", "unknown"), "relation_type": row.get("relation_type", "unknown"),
            "action_family": row.get("action_family", "unknown"), "action_leaf": row.get("action_leaf", "unknown"),
            "roles": row.get("roles", {}), "outcome": row.get("outcome", "unknown"),
            "key_attributes": row.get("key_attributes", {}), "entity_mentions": row.get("entity_mentions", []),
            "semantic_confidence": row.get("semantic_confidence", 0.0), "unknown_score": row.get("unknown_score", 1.0),
            "source_record_ref": row.get("source_record_ref", ""), "semantic_version": row.get("semantic_version", "mock")}

def main():
    p=argparse.ArgumentParser(); p.add_argument("--input", required=True); p.add_argument("--output", required=True); p.add_argument("--manifest", required=True); args=p.parse_args()
    run_stage("build_event_frames", args.input, args.output, transform, args.manifest)
if __name__ == '__main__': main()
