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
