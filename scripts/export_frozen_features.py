import _bootstrap
import argparse, json
from pathlib import Path
from src.pipeline.stage_runtime import read_jsonl, write_jsonl
from src.common.manifest import StageManifest, current_commit, hash_inputs
def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',required=True); p.add_argument('--manifest',required=True); p.add_argument('--producer-hash',action='append',required=True); args=p.parse_args()
    rows=read_jsonl(args.input)
    hashes={item.split('=',1)[0]: item.split('=',1)[1] for item in args.producer_hash if '=' in item}
    if len(hashes) < 1: raise ValueError('--producer-hash must be MODULE=SHA256')
    frozen=[]
    for row in rows:
        for key in ('record_id','dataset_id'):
            if key not in row: raise ValueError(f'frozen feature missing {key}')
        item=dict(row); item['producer_checkpoint_hashes']=hashes; item['feature_schema_version']=row.get('feature_schema_version','v3-contract-1'); frozen.append(item)
    output=write_jsonl(args.output,frozen)
    StageManifest('export_frozen_features','COMPLETED',current_commit('.'),input_hashes=hash_inputs([args.input]),output_hashes=hash_inputs([output]),real_data_used=True).write(args.manifest)
if __name__ == '__main__': main()
