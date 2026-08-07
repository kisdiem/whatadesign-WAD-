from dataclasses import replace

import torch

from src.fusion.m6_hierarchical import M6Config, M6HierarchicalFusion
from src.models.m4_qformer import M4Config, M4QFormerDecoder
from src.temporal.m5_long_horizon import M5Config, M5LongHorizonLinker
from src.training.v3_runner import RunnerConfig, TrainBatch, V3Runner


def _batch() -> TrainBatch:
    return TrainBatch(
        sequence=torch.randn(2, 4, 8), graph_score=torch.zeros(2),
        source_embedding=torch.randn(2, 8), target_embedding=torch.randn(2, 8),
        delta_seconds=torch.tensor([1800.0, 86400.0]),
        event_label=torch.tensor([0, 1]), link_label=torch.tensor([0, 1]),
        micro_label=torch.tensor([0, 1]), macro_label=torch.tensor([0, 1]),
    )


def test_runner_trains_saves_and_times(tmp_path):
    m4 = M4QFormerDecoder(M4Config(input_dim=8, hidden_dim=8, heads=2, layers=1))
    m5 = M5LongHorizonLinker(M5Config(embedding_dim=8, hidden_dim=8))
    m6 = M6HierarchicalFusion(M6Config(embedding_dim=8, hidden_dim=8))
    runner = V3Runner(m4, m5, m6, RunnerConfig(checkpoint_dir=str(tmp_path)))
    history = runner.fit([_batch()], [_batch()])
    assert history[0]["validation"]["total"] > 0
    assert list(tmp_path.glob("*.pt"))
    assert runner.inference_timing(_batch(), repeats=2)["mean_ms"] >= 0


def test_runner_accepts_strict_multiscale_m4_batch(tmp_path):
    m4 = M4QFormerDecoder(M4Config(input_dim=8, hidden_dim=8, qwen_hidden_dim=6, heads=2, layers=1, dropout=0.0))
    m5 = M5LongHorizonLinker(M5Config(embedding_dim=8, hidden_dim=8))
    m6 = M6HierarchicalFusion(M6Config(embedding_dim=8, hidden_dim=8))
    runner = V3Runner(m4, m5, m6, RunnerConfig(checkpoint_dir=str(tmp_path)))
    batch = _batch()
    strict = replace(
        batch,
        micro_event_embeddings=torch.randn(2, 3, 2, 8),
        qwen_window_embeddings=torch.randn(2, 3, 6),
        current_event_embedding=torch.randn(2, 8),
        micro_event_valid_mask=torch.ones(2, 3, 2, dtype=torch.bool),
        micro_window_mask=torch.ones(2, 3, dtype=torch.bool),
    )
    assert runner.evaluate([strict])["total"] > 0
