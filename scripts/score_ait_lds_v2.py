import _bootstrap
import argparse, json
from pathlib import Path
from src.protocol.ait_scorer import AitScorer
def main():
    p=argparse.ArgumentParser(); p.add_argument('--sealed',required=True); p.add_argument('--labels',required=True); p.add_argument('--output',required=True); args=p.parse_args(); result=AitScorer().score(args.sealed, args.labels, predictions_sealed=True); Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf-8')
if __name__ == '__main__': main()
