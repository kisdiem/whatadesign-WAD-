from __future__ import annotations

"""Run source-only, frozen-backbone Q-Former supervision.

This runner intentionally has no AIT inputs.  It reads labels only after a
strict causal M4 sample is built, and selects a checkpoint using validation
loss only.  Exact Qwen feature construction is resumable at epoch boundaries;
feature artifact caching is a separate required scale-out step.
"""

import argparse
import hashlib
import json
from pathlib import Path

import torch

import _bootstrap
from src.common.schema import EventFrame
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.models.m4_qformer import M4Config, M4QFormerDecoder
from src.training.m4_multiscale_builder import StrictM4BatchBuilder
from src.training.m4_source_dataset import StrictM4SourceDataset
from src.training.m4_supervised_runner import M4SupervisedRunner


def read_frames(paths: list[str]) -> dict[str, list[EventFrame]]:
    result: dict[str, list[EventFrame]] = {}
    for source in paths:
        for line in Path(source).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            frame = EventFrame.from_dict(json.loads(line))
            result.setdefault(frame.dataset_id, []).append(frame)
    for rows in result.values():
        rows.sort(key=lambda row: (row.timestamp or "", row.record_id))
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Strict source-only M4 Q-Former training")
    parser.add_argument("--targets", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--events", action="append", required=True)
    parser.add_argument("--qwen-model", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--learning-rate", type=float, default=1e-4)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--max-train", type=int, default=None)
    parser.add_argument("--max-validation", type=int, default=None)
    parser.add_argument("--max-test", type=int, default=None)
    args = parser.parse_args()

    dataset = StrictM4SourceDataset(args.targets, args.labels)
    frames = read_frames(args.events)
    qwen = QwenBackboneAdapter(args.qwen_model, mode="frozen", local_files_only=True)
    builder = StrictM4BatchBuilder(qwen, qwen_device=args.device)
    model = M4QFormerDecoder(M4Config(input_dim=768, hidden_dim=128, qwen_hidden_dim=qwen.hidden_size, heads=4, layers=1))
    runner = M4SupervisedRunner(model, device=args.device, learning_rate=args.learning_rate)
    output = Path(args.output_dir); output.mkdir(parents=True, exist_ok=True)

    def run_split(name: str, limit: int | None, training: bool) -> dict[str, float]:
        targets = dataset.split_targets(name)
        if limit is not None:
            targets = targets[:limit]
        losses, scores = [], []
        for target in targets:
            rows = frames.get(target.dataset_id)
            if rows is None:
                raise ValueError(f"no EventFrames for dataset {target.dataset_id}")
            sample = builder.build_one(rows, target.record_id)
            batch = StrictM4BatchBuilder.collate([sample])
            label = dataset.loss_label(target)  # Only supervision read in this runner.
            if training:
                losses.append(runner.train_one(batch, loss_label=label))
            else:
                loss, score = runner.evaluate_one(batch, loss_label=label); losses.append(loss); scores.append(score)
        return {"count": len(targets), "mean_loss": sum(losses) / max(len(losses), 1), "mean_score": sum(scores) / max(len(scores), 1)}

    best = float("inf"); history = []
    for epoch in range(1, args.epochs + 1):
        train = run_split("train", args.max_train, True)
        validation = run_split("validation", args.max_validation, False)
        row = {"epoch": epoch, "train": train, "validation": validation}; history.append(row)
        if validation["mean_loss"] < best:
            best = validation["mean_loss"]
            checkpoint = output / "best_validation_m4_qformer.pt"
            torch.save({"epoch": epoch, "model": model.state_dict(), "optimizer": runner.optimizer.state_dict(), "validation": validation}, checkpoint)
            row["checkpoint"] = str(checkpoint)
    test = run_split("test", args.max_test, False)
    report = {"status": "COMPLETED", "protocol": "source_only_strict_m4", "ait_accessed": False,
              "labels_used_only_for_loss": True, "qwen": qwen.export_backbone_manifest(), "history": history, "held_out_test": test,
              "input_hashes": {str(Path(path)): sha256(Path(path)) for path in [args.targets, args.labels, *args.events]}}
    (output / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
