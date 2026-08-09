import torch

from src.models.m4_qformer import M4Config, M4QFormerDecoder
from src.training.m4_supervised_runner import M4SupervisedRunner


def test_supervised_runner_uses_label_only_for_loss():
    model = M4QFormerDecoder(M4Config(input_dim=4, hidden_dim=4, qwen_hidden_dim=6, heads=2, layers=1, dropout=0.0))
    runner = M4SupervisedRunner(model, device="cpu")
    batch = {
        "micro_event_embeddings": torch.ones(1, 1, 2, 4),
        "qwen_window_embeddings": torch.ones(1, 1, 6),
        "current_event_embedding": torch.ones(1, 4),
        "micro_event_valid_mask": torch.ones(1, 1, 2, dtype=torch.bool),
        "micro_window_mask": torch.ones(1, 1, dtype=torch.bool),
    }
    assert runner.train_one(batch, loss_label=1) >= 0
    loss, score = runner.evaluate_one(batch, loss_label=0)
    assert loss >= 0 and 0 <= score <= 1


def test_supervised_runner_optimizes_source_fact_contrastive_triplet():
    torch.manual_seed(7)
    model = M4QFormerDecoder(M4Config(input_dim=4, hidden_dim=4, qwen_hidden_dim=6, heads=2, layers=1, dropout=0.0))
    runner = M4SupervisedRunner(model, device="cpu")

    def batch(value: float) -> dict[str, torch.Tensor]:
        return {
            "micro_event_embeddings": torch.full((1, 1, 2, 4), value),
            "qwen_window_embeddings": torch.full((1, 1, 6), value),
            "current_event_embedding": torch.full((1, 4), value),
            "micro_event_valid_mask": torch.ones(1, 1, 2, dtype=torch.bool),
            "micro_window_mask": torch.ones(1, 1, dtype=torch.bool),
        }

    result = runner.train_triplet(
        batch(1.0), batch(0.9), batch(-1.0),
        anchor_label=1, positive_label=1, negative_label=0,
        contrastive_weight=0.1, temperature=0.2,
    )

    assert result["loss"] >= 0
    assert result["bce_loss"] >= 0
    assert result["contrastive_loss"] >= 0
