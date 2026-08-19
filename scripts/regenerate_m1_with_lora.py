"""Regenerate M1 EventFrame embeddings with a completed PEFT LoRA adapter."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModel, AutoTokenizer

from train_deberta_lora_security import safe_event_text, discover_eventframes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--adapter", type=Path, required=True)
    ap.add_argument("--input-root", type=Path, required=True)
    ap.add_argument("--output-root", type=Path, required=True)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--max-length", type=int, default=96)
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(args.model, local_files_only=True, use_fast=False)
    base = AutoModel.from_pretrained(args.model, local_files_only=True)
    model = PeftModel.from_pretrained(base, args.adapter, local_files_only=True).to(device).eval()
    for parameter in model.parameters():
        parameter.requires_grad_(False)
    paths = discover_eventframes(args.input_root)
    if not paths:
        raise FileNotFoundError(f"no EventFrame JSONL under {args.input_root}")
    total = 0
    source_counts = {}
    for path in paths:
        source = path.parent.name.split("_m1", 1)[0]
        out_dir = args.output_root / f"{source}_m1_m2"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "m1_eventframes.jsonl"
        rows = []
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                if not raw.strip():
                    continue
                row = json.loads(raw)
                rows.append(row)
                if args.smoke and len(rows) >= 8:
                    break
        with out_path.open("w", encoding="utf-8") as sink:
            for start in range(0, len(rows), args.batch_size):
                batch = rows[start:start + args.batch_size]
                texts = [safe_event_text(row) for row in batch]
                encoded = tokenizer(texts, padding=True, truncation=True, max_length=args.max_length, return_tensors="pt")
                encoded = {key: value.to(device) for key, value in encoded.items()}
                with torch.no_grad():
                    hidden = model(**encoded).last_hidden_state
                    mask = encoded["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                    embeddings = (hidden * mask).sum(1) / mask.sum(1).clamp_min(1.0)
                for row, embedding in zip(batch, embeddings.cpu().tolist()):
                    row["semantic_embedding"] = [float(value) for value in embedding]
                    row["semantic_version"] = "deberta_security_lora_v1"
                    sink.write(json.dumps(row, ensure_ascii=False) + "\n")
                sink.flush()
        total += len(rows)
        source_counts[source] = len(rows)
    manifest = {"status": "M1_REGENERATED", "device": str(device), "sources": source_counts,
                "total_events": total, "adapter": str(args.adapter), "base_model": str(args.model),
                "smoke": args.smoke, "labels_used": False}
    (args.output_root / ("m1_smoke_manifest.json" if args.smoke else "m1_manifest.json")).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
