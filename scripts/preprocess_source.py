"""Strict stage entry point: source bytes -> traceable RawRecord JSONL."""
import _bootstrap
import argparse, hashlib, json, re
from pathlib import Path
from src.common.manifest import StageManifest, current_commit, hash_inputs
from src.pipeline.stage_runtime import write_jsonl

def main():
    p = argparse.ArgumentParser(); p.add_argument("--input", required=True); p.add_argument("--dataset-id", required=True); p.add_argument("--output", required=True); p.add_argument("--manifest", required=True); args = p.parse_args()
    source = Path(args.input)
    rows = []
    for line_no, line in enumerate(source.read_text(errors="replace").splitlines(), 1):
        timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?", line)
        rows.append({"dataset_id": args.dataset_id, "source_file": str(source), "source_line": line_no,
                     "raw_timestamp": timestamp_match.group(0) if timestamp_match else None, "raw_payload": line, "adapter_version": "file-1",
                     "parser_version": "unparsed", "raw_record_id": hashlib.sha256(f"{args.dataset_id}|{source}|{line_no}".encode()).hexdigest(),
                     "source_hash": hashlib.sha256(line.encode()).hexdigest(), "ingestion_metadata": {}})
    output = write_jsonl(args.output, rows)
    StageManifest("preprocess_source", "COMPLETED", current_commit("."), input_hashes=hash_inputs([source]), output_hashes=hash_inputs([output]), real_data_used=True).write(args.manifest)
if __name__ == "__main__": main()
