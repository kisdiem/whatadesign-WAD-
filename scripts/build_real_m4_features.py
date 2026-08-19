"""Run the real frozen Qwen + trained multiscale M4 path on M1 EventFrames."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import torch

import _bootstrap  # noqa: F401
from src.common.schema import EventFrame
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.models.m4_qformer import M4Config, M4QFormerDecoder
from src.temporal.window_builder import WindowBuilder


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--eventframes", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--qwen-model", type=Path, required=True)
    p.add_argument("--m4-checkpoint", type=Path, required=True)
    p.add_argument("--limit", type=int, default=128)
    p.add_argument("--target-record-ids", type=Path, default=None)
    p.add_argument("--macro-windows", type=Path, default=None,
                   help="authoritative M3 macro-window JSONL; preserves one M4 row per macro window")
    args = p.parse_args()
    root = args.eventframes.parent
    frames = [EventFrame.from_dict(json.loads(line)) for line in args.eventframes.read_text(encoding="utf-8").splitlines() if line.strip()]
    frames = frames[: args.limit]
    if not frames:
        raise ValueError("no EventFrame input")
    qwen = QwenBackboneAdapter(name=str(args.qwen_model), mode="frozen", local_files_only=True)
    checkpoint = torch.load(args.m4_checkpoint, map_location="cpu")
    model = M4QFormerDecoder(M4Config(input_dim=768, hidden_dim=128, qwen_hidden_dim=2048, heads=4, layers=1))
    model.load_state_dict(checkpoint["model"], strict=True)
    model.eval()
    target_ids = None
    if args.target_record_ids is not None and args.macro_windows is not None:
        raise ValueError("use either --target-record-ids or --macro-windows, not both")
    if args.target_record_ids is not None:
        target_ids = {line.strip() for line in args.target_record_ids.read_text(encoding="utf-8").splitlines() if line.strip()}
        if not target_ids:
            raise ValueError("target-record-ids file is empty")
    frames_by_id = {frame.record_id: frame for frame in frames}
    if args.macro_windows is not None:
        macro_rows = [json.loads(line) for line in args.macro_windows.read_text(encoding="utf-8").splitlines() if line.strip()]
        work_items = [
            (str(item["window_id"]), frames_by_id.get(str(item["current_record_id"])))
            for item in macro_rows
        ]
        missing_macro_currents = sum(current is None for _, current in work_items)
        work_items = [(window_id, current) for window_id, current in work_items if current is not None]
    else:
        current_frames = [frame for frame in frames if target_ids is None or frame.record_id in target_ids]
        work_items = [(None, frame) for frame in current_frames]
        missing_macro_currents = 0
    rows = []
    skipped_without_history = 0
    for macro_source_window_id, current in work_items:
        windows = WindowBuilder().build_micro_windows(frames, current.timestamp, current.record_id)
        if not windows:
            skipped_without_history += 1
            continue
        event_lists = [[frames[i] for i in window.event_indices] for window in windows]
        # Encode each micro window independently.  Batch-padding several dense
        # windows can create an avoidable GPU peak; chunked encoding preserves
        # every EventFrame and pools chunk representations by event count.
        qwen_outputs = [qwen.encode_window_chunked(items, device="cuda") for items in event_lists]
        qwen_embeddings = torch.stack([item["embedding"].detach().cpu() for item in qwen_outputs])
        max_events = max((len(items) for items in event_lists), default=1)
        event_tensor = torch.zeros(1, len(windows), max_events, 768)
        event_mask = torch.zeros(1, len(windows), max_events, dtype=torch.bool)
        for wi, items in enumerate(event_lists):
            for ei, frame in enumerate(items):
                event_tensor[0, wi, ei] = torch.tensor(frame.semantic_embedding, dtype=torch.float32)
                event_mask[0, wi, ei] = True
        with torch.no_grad():
            output = model.forward_micro_windows(
                event_tensor, qwen_embeddings.unsqueeze(0),
                torch.tensor(current.semantic_embedding, dtype=torch.float32).reshape(1, 768),
                event_valid_mask=event_mask,
                micro_window_mask=torch.ones(1, len(windows), dtype=torch.bool),
            )
        rows.append({
            "record_id": current.record_id, "dataset_id": current.dataset_id, "timestamp": current.timestamp,
            "macro_source_window_id": macro_source_window_id,
            "window_ids": [window.window_id for window in windows],
            "window_record_ids": [list(window.record_ids) for window in windows],
            "micro_window_score": float(output["micro_window_scores"].max().cpu()),
            "macro_window_score": float(output["macro_window_score"].reshape(-1)[0].cpu()),
            "event_embedding": output["event_embedding"].reshape(-1).cpu().tolist(),
            "raw_event_score": float(output["raw_event_logit"].reshape(-1)[0].cpu()),
            "qwen_window_embeddings": qwen_embeddings.tolist(),
            "qwen_mode": qwen_outputs[0]["mode"], "qwen_is_mock": qwen_outputs[0]["is_mock"],
            "source_record_ref": current.source_record_ref,
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")
    manifest = {
        "status": "M4_FEATURES_READY_M5_PENDING", "count": len(rows), "labels_read": False,
        "qwen_manifest": qwen.export_backbone_manifest(),
        "qwen_model_sha256": hashlib.sha256((args.qwen_model / "model.safetensors").read_bytes()).hexdigest(),
        "m4_checkpoint_sha256": hashlib.sha256(args.m4_checkpoint.read_bytes()).hexdigest(),
        "m4_checkpoint_epoch": checkpoint.get("epoch"), "target_count": len(work_items),
        "macro_window_mode": args.macro_windows is not None,
        "missing_macro_currents": missing_macro_currents,
        "skipped_without_history": skipped_without_history,
        "m5_score": "not_generated",
    }
    manifest_path = args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
