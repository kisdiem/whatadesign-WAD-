from datetime import datetime

import torch

from src.temporal.m5_progress_adapter import progress_event_from_model_output


def test_progress_adapter_builds_cpu_persistent_event():
    output = {
        "semantic_embedding": torch.randn(2, 8),
        "relevance_probability": torch.tensor([0.7, 0.9]),
        "progress_score": torch.tensor([0.2, 0.6]),
        "position_probabilities": torch.rand(2, 6),
    }
    event = progress_event_from_model_output(
        event_id="evt-2",
        timestamp=datetime(2026, 8, 1, 12, 0),
        entities={"host": frozenset({"host-a"})},
        output=output,
        batch_index=1,
    )

    assert event.event_id == "evt-2"
    assert event.embedding.shape == (8,)
    assert event.embedding.device.type == "cpu"
    assert event.position_probabilities.shape == (6,)
    assert abs(event.relevance_probability - 0.9) < 1e-5
    assert abs(event.progress_score - 0.6) < 1e-5
