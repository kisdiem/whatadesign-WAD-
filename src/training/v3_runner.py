from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import torch
from torch import Tensor

from src.fusion.m6_hierarchical import M6HierarchicalFusion
from src.models.m4_qformer import M4QFormerDecoder
from src.temporal.m5_long_horizon import M5LongHorizonLinker


@dataclass(frozen=True)
class TrainBatch:
    sequence: Tensor
    graph_score: Tensor
    source_embedding: Tensor
    target_embedding: Tensor
    delta_seconds: Tensor
    event_label: Tensor
    link_label: Tensor
    micro_label: Tensor
    macro_label: Tensor
    padding_mask: Tensor | None = None
    # Strict M4 path. These are source-derived features only; labels remain
    # separate loss inputs above and cannot be serialized into Qwen windows.
    micro_event_embeddings: Tensor | None = None
    qwen_window_embeddings: Tensor | None = None
    current_event_embedding: Tensor | None = None
    micro_event_valid_mask: Tensor | None = None
    micro_window_mask: Tensor | None = None
    micro_graph_embeddings: Tensor | None = None


@dataclass(frozen=True)
class RunnerConfig:
    epochs: int = 1
    learning_rate: float = 1e-3
    checkpoint_dir: str = "outputs/checkpoints"
    version: str = "v3_m4_m6_runner_v1"


class V3Runner:
    """Train/evaluate M4-M6 while keeping source and target data contracts external."""

    def __init__(self, m4: M4QFormerDecoder, m5: M5LongHorizonLinker,
                 m6: M6HierarchicalFusion, config: RunnerConfig | None = None) -> None:
        self.m4, self.m5, self.m6 = m4, m5, m6
        self.config = config or RunnerConfig()
        self.optimizer = torch.optim.AdamW(self.parameters(), lr=self.config.learning_rate)
        self.loss = torch.nn.BCEWithLogitsLoss()

    def parameters(self):
        return list(self.m4.parameters()) + list(self.m5.parameters()) + list(self.m6.parameters())

    def _forward_loss(self, batch: TrainBatch) -> tuple[Tensor, dict[str, float]]:
        strict_fields = (batch.micro_event_embeddings, batch.qwen_window_embeddings, batch.current_event_embedding)
        if any(value is not None for value in strict_fields):
            if not all(value is not None for value in strict_fields):
                raise ValueError("strict M4 batch requires event, Qwen, and current-event embeddings together")
            m4_out = self.m4.forward_micro_windows(
                batch.micro_event_embeddings,
                batch.qwen_window_embeddings,
                batch.current_event_embedding,
                event_valid_mask=batch.micro_event_valid_mask,
                micro_window_mask=batch.micro_window_mask,
                graph_embeddings=batch.micro_graph_embeddings,
            )
        else:
            # Legacy/synthetic runner compatibility only. Formal source jobs
            # must supply the strict multiscale fields above.
            m4_out = self.m4(batch.sequence, batch.padding_mask)
        link_logit = self.m5(batch.source_embedding, batch.target_embedding, batch.delta_seconds)
        m6_out = self.m6(m4_out["embedding"], batch.graph_score, link_logit)
        losses = {
            "event": self.loss(m4_out["score_logit"], batch.event_label.float()),
            "link": self.loss(link_logit, batch.link_label.float()),
            "micro": self.loss(m6_out["micro_logit"], batch.micro_label.float()),
            "macro": self.loss(m6_out["macro_logit"], batch.macro_label.float()),
            "fused": self.loss(m6_out["fused_logit"], batch.macro_label.float()),
        }
        total = sum(losses.values())
        return total, {name: float(value.detach().cpu()) for name, value in losses.items()} | {"total": float(total.detach().cpu())}

    def train_epoch(self, batches: list[TrainBatch]) -> dict[str, float]:
        self.m4.train(); self.m5.train(); self.m6.train()
        totals: dict[str, float] = {}
        for batch in batches:
            self.optimizer.zero_grad(set_to_none=True)
            loss, metrics = self._forward_loss(batch)
            loss.backward()
            self.optimizer.step()
            for name, value in metrics.items():
                totals[name] = totals.get(name, 0.0) + value
        count = max(len(batches), 1)
        return {name: value / count for name, value in totals.items()}

    @torch.no_grad()
    def evaluate(self, batches: list[TrainBatch]) -> dict[str, float]:
        self.m4.eval(); self.m5.eval(); self.m6.eval()
        totals: dict[str, float] = {}
        for batch in batches:
            _, metrics = self._forward_loss(batch)
            for name, value in metrics.items():
                totals[name] = totals.get(name, 0.0) + value
        count = max(len(batches), 1)
        return {name: value / count for name, value in totals.items()}

    @torch.no_grad()
    def inference_timing(self, batch: TrainBatch, repeats: int = 20) -> dict[str, float]:
        self.m4.eval(); self.m5.eval(); self.m6.eval()
        for _ in range(3):
            self._forward_loss(batch)
        start = time.perf_counter()
        for _ in range(repeats):
            self._forward_loss(batch)
        elapsed = time.perf_counter() - start
        return {"repeats": float(repeats), "total_seconds": elapsed, "mean_ms": elapsed * 1000 / repeats}

    def save_checkpoint(self, epoch: int, metrics: dict[str, float]) -> Path:
        directory = Path(self.config.checkpoint_dir)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"v3_epoch_{epoch:03d}.pt"
        torch.save({"version": self.config.version, "epoch": epoch,
                    "m4": self.m4.state_dict(), "m5": self.m5.state_dict(),
                    "m6": self.m6.state_dict(), "optimizer": self.optimizer.state_dict(),
                    "metrics": metrics}, path)
        path.with_suffix(".json").write_text(json.dumps({"version": self.config.version, "epoch": epoch, "metrics": metrics}, indent=2), encoding="utf-8")
        return path

    def fit(self, train_batches: list[TrainBatch], validation_batches: list[TrainBatch]) -> list[dict[str, object]]:
        history: list[dict[str, object]] = []
        for epoch in range(1, self.config.epochs + 1):
            train_metrics = self.train_epoch(train_batches)
            validation_metrics = self.evaluate(validation_batches)
            metrics = {"train": train_metrics, "validation": validation_metrics}
            self.save_checkpoint(epoch, {f"train.{k}": v for k, v in train_metrics.items()} | {f"validation.{k}": v for k, v in validation_metrics.items()})
            history.append({"epoch": epoch, **metrics})
        return history
