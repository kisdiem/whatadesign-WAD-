"""Strict stage entry point: source adapter -> RawRecord manifest only."""
import argparse, json
from pathlib import Path

def main():
    p = argparse.ArgumentParser(); p.add_argument("--output", required=True); p.add_argument("--commit", required=True); args = p.parse_args()
    Path(args.output).write_text(json.dumps({"stage":"preprocess_source","status":"contract_only","commit":args.commit,"records":0}, indent=2), encoding="utf-8")
if __name__ == "__main__": main()
