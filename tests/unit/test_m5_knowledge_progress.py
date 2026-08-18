import torch

from src.temporal.m5_knowledge_progress import (
    AttackKnowledgeIndex,
    M5KnowledgeConfig,
    M5KnowledgeProgressTransformer,
    multilabel_position_target,
    progress_target_from_attack_step,
)
from src.training.m5_progress_runner import M5ProgressRunner, M5TrainBatch


def _knowledge(count=32, d_model=16, num_positions=6):
    torch.manual_seed(7)
    embeddings = torch.randn(count, d_model)
    positions = torch.zeros(count, num_positions)
    progress = torch.linspace(0.05, 0.95, count)
    for index in range(count):
        positions[index, index % num_positions] = 1.0
        if index % 5 == 0:
            positions[index, (index + 1) % num_positions] = 1.0
    return AttackKnowledgeIndex(
        embeddings,
        positions,
        progress,
        tuple(f"k{index}" for index in range(count)),
    )


def _model(top_k=8):
    return M5KnowledgeProgressTransformer(
        M5KnowledgeConfig(
            vocab_size=128,
            max_seq_len=16,
            d_model=16,
            num_heads=4,
            encoder_layers=1,
            feedforward_dim=32,
            dropout=0.0,
            num_positions=6,
            knowledge_top_k=top_k,
            knowledge_candidate_cap=64,
            broad_attack_threshold=0.35,
        )
    )


def test_m5_outputs_joint_relevance_positions_and_progress():
    model = _model()
    knowledge = _knowledge()
    token_ids = torch.tensor([[1, 2, 3, 4, 0], [5, 6, 7, 0, 0]])
    mask = torch.tensor([[1, 1, 1, 1, 0], [1, 1, 1, 0, 0]])
    output = model(token_ids, mask, knowledge)
    assert output["relevance_probability"].shape == (2,)
    assert output["position_probabilities"].shape == (2, 6)
    assert output["progress_score"].shape == (2,)
    assert torch.all((output["progress_score"] >= 0) & (output["progress_score"] <= 1))
    assert output["attack_candidate"].dtype == torch.bool


def test_m5_retrieval_caps_cross_attention_to_top_k():
    model = _model(top_k=4)
    output = model(
        torch.tensor([[1, 2, 3]]),
        torch.ones(1, 3, dtype=torch.long),
        _knowledge(count=50),
    )
    assert output["retrieved_indices"].shape == (1, 4)
    assert output["retrieved_scores"].shape == (1, 4)


def test_m5_allowed_mask_can_exclude_target_scenario_knowledge():
    model = _model(top_k=5)
    knowledge = _knowledge(count=12)
    allowed = torch.ones(1, 12, dtype=torch.bool)
    allowed[:, :7] = False
    output = model(
        torch.tensor([[1, 2, 3]]),
        torch.ones(1, 3, dtype=torch.long),
        knowledge,
        allowed_knowledge_mask=allowed,
    )
    assert torch.all(output["retrieved_indices"] >= 7)


def test_m5_labels_support_continuous_progress_and_multiple_positions():
    assert progress_target_from_attack_step(3, 8) == 0.375
    target = multilabel_position_target([1, 3, 4], 6)
    assert target.tolist() == [0.0, 1.0, 0.0, 1.0, 1.0, 0.0]


def test_m5_train_step_smoke_has_finite_loss_and_updates_parameters():
    torch.manual_seed(11)
    model = _model(top_k=4)
    runner = M5ProgressRunner(model)
    knowledge = _knowledge(count=16)
    batch = M5TrainBatch(
        token_ids=torch.tensor([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 0]]),
        attention_mask=torch.tensor([[1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 1, 0]]),
        attack_targets=torch.tensor([1.0, 1.0, 0.0]),
        position_targets=torch.stack(
            [
                multilabel_position_target([1, 2], 6),
                multilabel_position_target([3, 4], 6),
                multilabel_position_target([], 6),
            ]
        ),
        progress_targets=torch.tensor([0.25, 0.75, 0.0]),
        progress_mask=torch.tensor([True, True, False]),
        ranking_pairs=torch.tensor([[0, 1]]),
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    before = model.progress_head[-1].weight.detach().clone()
    losses = runner.train_step(batch, knowledge, optimizer)
    after = model.progress_head[-1].weight.detach()
    assert all(torch.isfinite(torch.tensor(value)) for value in losses.values())
    assert losses["loss"] > 0
    assert not torch.equal(before, after)


def test_m5_rejects_unbounded_full_database_input():
    model = _model(top_k=8)
    too_large = _knowledge(count=65)
    try:
        model(
            torch.tensor([[1, 2, 3]]),
            torch.ones(1, 3, dtype=torch.long),
            too_large,
        )
    except ValueError as exc:
        assert "prefilter" in str(exc)
    else:
        raise AssertionError("M5 must require external candidate prefiltering")
