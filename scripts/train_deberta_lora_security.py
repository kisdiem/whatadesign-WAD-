"""LoRA domain adaptation for DeBERTa on security-event text.

This script is deliberately separate from the supervised M5 scripts.  It uses
only event facts and optional ATT&CK technique descriptions.  Labels, split
metadata, and post-hoc detection results are rejected before tokenization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime
from pathlib import Path

import torch
from torch.utils.data import DataLoader, Dataset
from transformers import AutoTokenizer, DebertaV2ForMaskedLM, DataCollatorForLanguageModeling
from peft import LoraConfig, PeftModel, TaskType, get_peft_model


FORBIDDEN = {
    "target_label", "attack_label", "anomaly_label", "is_attack", "split",
    "ground_truth", "scenario_truth", "post_hoc_score", "final_score",
}
EVENT_KEYS = (
    "record_kind", "relation_type", "action_family", "action_leaf", "outcome",
    "entity_types", "roles", "source_record_ref", "timestamp", "template",
    "normalized_text", "semantic_text", "message", "command", "process",
)
TECHNIQUE_TEXT = (
    "Initial Access: remote service, valid account, external public-facing application.",
    "Execution: command and scripting interpreter, shell, process execution.",
    "Persistence: scheduled task, service, startup item, account manipulation.",
    "Privilege Escalation: sudo, exploitation, permission or token manipulation.",
    "Defense Evasion: clear traces, hidden files, disable tools, masquerading.",
    "Credential Access: credential files, password stores, account discovery.",
    "Discovery: host, process, account, network, file and system discovery.",
    "Lateral Movement: remote service, shared resources, valid account.",
    "Collection and Command and Control: collect files, stage data, network channel.",
    "Impact: data destruction, encryption, service stop, inhibit recovery.",
)


def safe_event_text(row: dict) -> str:
    """Serialize facts only; reject any record carrying label-like fields."""
    lower = {str(k).lower() for k in row}
    leaked = sorted(lower & FORBIDDEN)
    if leaked:
        raise ValueError(f"forbidden model-input fields: {leaked}")
    parts = []
    for key in EVENT_KEYS:
        value = row.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        parts.append(f"{key}={str(value)[:500]}")
    return "security_event " + " ".join(parts) if parts else "security_event unknown_event"


def read_corpus(paths: list[Path], max_events: int, seed: int) -> list[str]:
    lines: list[str] = []
    per_source = max(1, max_events // max(1, len(paths)))
    for path in paths:
        source_lines: list[str] = []
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                if len(source_lines) >= per_source:
                    break
                try:
                    row = json.loads(raw)
                    if isinstance(row, dict):
                        source_lines.append(safe_event_text(row))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
        lines.extend(source_lines)
    if len(lines) > max_events:
        lines = lines[:max_events]
    lines.extend("attack_technique " + item for item in TECHNIQUE_TEXT)
    random.Random(seed).shuffle(lines)
    return lines


def read_temporal_corpus(paths: list[Path], max_events: int, validation_ratio: float, smoke: bool = False) -> tuple[list[str], list[str], dict[str, int]]:
    """Hold out the latest timestamp interval from every source."""
    per_source = max(1, max_events // max(1, len(paths)))
    train, validation, counts = [], [], {}
    for path in paths:
        rows = []
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                if len(rows) >= (8 if smoke else per_source):
                    break
                try:
                    row = json.loads(raw)
                    if not isinstance(row, dict):
                        continue
                    stamp = str(row.get("timestamp", ""))
                    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else datetime.min
                    rows.append((parsed, safe_event_text(row)))
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    continue
        rows.sort(key=lambda item: item[0])
        cut = max(1, int(len(rows) * (1.0 - validation_ratio)))
        source = path.parent.name.split("_m1", 1)[0]
        train.extend(text for _, text in rows[:cut])
        validation.extend(text for _, text in rows[cut:])
        counts[source] = len(rows)
    train.extend("attack_technique " + item for item in TECHNIQUE_TEXT)
    return train, validation, counts


def read_external_text(paths: list[Path], max_lines: int) -> list[str]:
    lines: list[str] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(path)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                text = raw.strip()
                if text:
                    lines.append(f"external_log source={path.name} message={text[:800]}")
                if len(lines) >= max_lines:
                    break
    return lines


def discover_eventframes(root: Path) -> list[Path]:
    """Prefer the newest prepared variant when a source has multiple caches."""
    grouped: dict[str, list[Path]] = {}
    for path in root.rglob("m1_eventframes.jsonl"):
        name = path.parent.name
        source = name.split("_m1", 1)[0]
        grouped.setdefault(source, []).append(path)
    return [sorted(items, key=lambda item: str(item.parent))[-1] for _, items in sorted(grouped.items())]


class TextDataset(Dataset):
    def __init__(self, texts: list[str], tokenizer, max_length: int):
        self.items = tokenizer(texts, padding=False, truncation=True, max_length=max_length)

    def __len__(self):
        return len(self.items["input_ids"])

    def __getitem__(self, index):
        return {key: value[index] for key, value in self.items.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--events-root", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--max-events", type=int, default=200_000)
    ap.add_argument("--extra-text", type=Path, action="append", default=[])
    ap.add_argument("--extra-max-lines", type=int, default=50_000)
    ap.add_argument("--validation-ratio", type=float, default=0.1)
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--grad-accum", type=int, default=1)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--rank", type=int, default=8)
    ap.add_argument("--init-adapter", type=Path, default=None)
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    torch.manual_seed(42)
    random.seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    paths = discover_eventframes(args.events_root)
    if not paths:
        raise FileNotFoundError(f"no eventframes under {args.events_root}")
    if not 0.0 < args.validation_ratio < 0.5:
        raise ValueError("validation-ratio must be between 0 and 0.5")
    train_texts, validation_texts, source_counts = read_temporal_corpus(
        paths, 8 if args.smoke else args.max_events, args.validation_ratio, args.smoke
    )
    if not args.smoke and args.extra_text:
        train_texts.extend(read_external_text(args.extra_text, args.extra_max_lines))
    texts = train_texts + validation_texts
    tokenizer = AutoTokenizer.from_pretrained(args.model, local_files_only=True, use_fast=False)
    base = DebertaV2ForMaskedLM.from_pretrained(args.model, local_files_only=True)
    config = LoraConfig(
        task_type=TaskType.FEATURE_EXTRACTION,
        r=args.rank,
        lora_alpha=args.rank * 2,
        lora_dropout=0.05,
        target_modules=["query_proj", "key_proj", "value_proj"],
        bias="none",
    )
    if args.init_adapter:
        model = PeftModel.from_pretrained(base, args.init_adapter, is_trainable=True)
    else:
        model = get_peft_model(base, config)
    model = model.to(device)
    model.print_trainable_parameters()
    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=True, mlm_probability=0.15)
    dataset = TextDataset(train_texts, tokenizer, args.max_length)
    validation_dataset = TextDataset(validation_texts, tokenizer, args.max_length)
    loader = DataLoader(dataset, batch_size=args.batch_size, shuffle=True, collate_fn=collator)
    validation_loader = DataLoader(validation_dataset, batch_size=args.batch_size, shuffle=False, collate_fn=collator)
    if args.smoke:
        batch = {key: value.to(device) for key, value in next(iter(loader)).items()}
        out = model(**batch)
        out.loss.backward()
        print(json.dumps({"status": "SMOKE_COMPLETED", "device": str(device),
                          "base_model": "DeBERTa-v3-base-compatible-deberta-v2",
                          "records": len(texts), "train_records": len(train_texts), "validation_records": len(validation_texts), "trainable_lora": True,
                          "loss_finite": bool(torch.isfinite(out.loss).item()),
                          "labels_used": False, "synthetic": False}))
        return

    model.train()
    optimizer = torch.optim.AdamW((p for p in model.parameters() if p.requires_grad), lr=2e-4)
    history = []
    best_validation = float("inf")
    best_dir = args.output_dir / "best_adapter"
    for epoch in range(1, args.epochs + 1):
        total = 0.0
        optimizer.zero_grad(set_to_none=True)
        for batch_index, batch in enumerate(loader):
            batch = {key: value.to(device) for key, value in batch.items()}
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=device.type == "cuda"):
                loss = model(**batch).loss
            if not torch.isfinite(loss):
                raise FloatingPointError(f"non-finite loss at epoch {epoch}")
            (loss / args.grad_accum).backward()
            if (batch_index + 1) % args.grad_accum == 0 or batch_index + 1 == len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                optimizer.zero_grad(set_to_none=True)
            total += float(loss.detach())
        model.eval()
        validation_total = 0.0
        with torch.no_grad():
            for batch in validation_loader:
                batch = {key: value.to(device) for key, value in batch.items()}
                with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=device.type == "cuda"):
                    validation_total += float(model(**batch).loss.detach())
        validation_loss = validation_total / max(1, len(validation_loader))
        row = {"epoch": epoch, "mean_batch_mlm_loss": total / max(1, len(loader)), "validation_mlm_loss": validation_loss, "batches": len(loader), "batch_size": args.batch_size, "grad_accum": args.grad_accum}
        history.append(row)
        print(json.dumps(row), flush=True)
        if validation_loss < best_validation:
            best_validation = validation_loss
            model.save_pretrained(best_dir)
            tokenizer.save_pretrained(best_dir)
        model.train()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    report = {
        "status": "COMPLETED", "model_version": "deberta_security_lora_extended_v1" if args.init_adapter else "deberta_security_lora_v1",
        "device": str(device), "source_files": [str(p) for p in paths], "extra_text_files": [str(p) for p in args.extra_text],
        "records": len(texts), "train_records": len(train_texts), "validation_records": len(validation_texts), "epochs": args.epochs, "batch_size": args.batch_size,
        "objective": "MLM domain adaptation on security event facts plus technique descriptions",
        "base_checkpoint_kind": "encoder_checkpoint_reused_as_deberta_v2",
        "continued_from_adapter": str(args.init_adapter) if args.init_adapter else None,
        "mlm_head_randomly_initialized": True,
        "mlm_head_warning": "The cached M1 checkpoint has encoder weights only; the MLM head is newly initialized.",
        "labels_used": False, "forbidden_fields": sorted(FORBIDDEN), "split_strategy": "per-source chronological latest interval validation", "source_counts": source_counts, "validation_mlm_loss_best": best_validation, "best_adapter": str(best_dir), "history": history,
        "checkpoint": str(args.output_dir),
    }
    (args.output_dir / "training_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
