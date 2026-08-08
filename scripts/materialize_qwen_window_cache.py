from __future__ import annotations

"""Materialize label-free Qwen embeddings for M4 micro windows.

This tool never reads the separate loss-label file.  It uses only target
identity/timestamps to plan history and EventFrame fields to run Qwen.
"""

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import _bootstrap
from src.common.schema import EventFrame
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.temporal.window_builder import WindowConfig
from src.training.m4_window_cache import parse_utc, plan_micro_windows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize Qwen M4 micro-window cache")
    parser.add_argument("--targets", required=True, help="Unlabelled M4 target selection JSONL")
    parser.add_argument("--source", action="append", required=True,
                        help="Structured EventFrame JSONL; repeat for each source dataset")
    parser.add_argument("--output", required=True)
    parser.add_argument("--mapping-output", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--chunk-batch-size", type=int, default=8)
    parser.add_argument("--alignment", choices=("current", "stride"), default="current")
    parser.add_argument("--max-targets", type=int, default=None)
    args = parser.parse_args()

    config = WindowConfig()
    targets = list(jsonl(Path(args.targets)))
    if args.max_targets is not None:
        targets = targets[:args.max_targets]
    required = {str(row["dataset_id"]) for row in targets}
    frames_by_dataset: dict[str, list[EventFrame]] = defaultdict(list)
    for source in args.source:
        for row in jsonl(Path(source)):
            frame = EventFrame.from_dict(row)
            if frame.dataset_id in required:
                frames_by_dataset[frame.dataset_id].append(frame)
    missing = required - set(frames_by_dataset)
    if missing:
        raise ValueError(f"no EventFrames supplied for target datasets: {sorted(missing)}")
    for frames in frames_by_dataset.values():
        frames.sort(key=lambda item: (parse_utc(item.timestamp or ""), item.record_id))

    planned: dict[str, object] = {}
    target_windows: list[dict[str, object]] = []
    for target in targets:
        record_id = str(target["record_id"])
        windows = plan_micro_windows(
            dataset_id=str(target["dataset_id"]), current_timestamp=str(target["timestamp"]),
            current_record_id=record_id, config=config, alignment=args.alignment,
        )
        for window in windows:
            planned.setdefault(window.window_id, window)
        target_windows.append({
            "record_id": record_id,
            "dataset_id": target["dataset_id"],
            "timestamp": target["timestamp"],
            "window_ids": [window.window_id for window in windows],
        })

    output = Path(args.output)
    mapping = Path(args.mapping_output)
    output.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if output.exists():
        existing = {str(row["window_id"]) for row in jsonl(output)}
    mapping.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in target_windows), encoding="utf-8")

    qwen = QwenBackboneAdapter(args.model, mode="frozen", local_files_only=True)
    completed = len(existing)
    with output.open("a", encoding="utf-8") as handle:
        for number, window in enumerate(planned.values(), start=1):
            if window.window_id in existing:
                continue
            frames = [frame for frame in frames_by_dataset[window.dataset_id]
                      if frame.record_id != window.current_record_id and frame.timestamp is not None
                      and window.start <= parse_utc(frame.timestamp) < window.end]
            encoded = qwen.encode_window_chunked(
                frames, max_tokens=args.max_tokens, chunk_batch_size=args.chunk_batch_size,
                device=args.device,
            )
            # No labels, target split, ground truth, or raw prompt text is
            # persisted.  The cache is an M4 feature artifact only.
            row = {
                "window_id": window.window_id, "dataset_id": window.dataset_id,
                "start": window.start.isoformat(), "end": window.end.isoformat(),
                "alignment": window.alignment, "event_count": len(frames),
                "event_record_ids": [frame.record_id for frame in frames],
                "chunk_event_counts": encoded["chunk_event_counts"],
                "chunk_count": encoded["chunk_count"],
                "qwen_embedding": encoded["embedding"].detach().cpu().tolist(),
                "qwen_manifest": qwen.export_backbone_manifest(),
                "is_mock": bool(encoded["is_mock"]),
            }
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")
            handle.flush()
            completed += 1
            print(json.dumps({"completed": completed, "planned": len(planned), "last_window": window.window_id}, ensure_ascii=True), flush=True)
    manifest = {
        "status": "COMPLETED", "cache": str(output), "cache_sha256": sha256(output),
        "mapping": str(mapping), "mapping_sha256": sha256(mapping),
        "targets": len(targets), "unique_windows": len(planned), "alignment": args.alignment,
        "strict_current_aligned": args.alignment == "current",
        "temporal_config": {"macro_seconds": config.macro_seconds, "micro_seconds": config.micro_seconds, "stride_seconds": config.stride_seconds},
        "qwen": qwen.export_backbone_manifest(), "labels_read": False,
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
