import _bootstrap
import argparse
from pathlib import Path
from src.pipeline.stage_runtime import read_jsonl
def main():
    p=argparse.ArgumentParser(); p.add_argument('--input',required=True); p.add_argument('--output',required=True); args=p.parse_args(); rows=read_jsonl(args.input)
    if not rows: raise ValueError('M6 training requires non-empty FrozenFeatureRecord input')
    if any(not row.get('producer_checkpoint_hashes') for row in rows): raise ValueError('M6 requires producer checkpoint hashes')
    raise RuntimeError('real M6 optimization requires an explicit model configuration and labeled source split; no training is silently performed by this preflight entry point')
if __name__ == '__main__': main()
