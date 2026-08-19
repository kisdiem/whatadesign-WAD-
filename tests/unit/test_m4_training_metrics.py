from src.training.m4_metrics import binary_metrics, select_f1_threshold


def test_binary_metrics_reports_pr_auc_for_ranked_scores() -> None:
    metrics = binary_metrics([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1])

    assert metrics["roc_auc"] == 0.75
    assert metrics["pr_auc"] == (1.0 + (2 / 3)) / 2
    assert metrics["f1"] > 0


def test_binary_metrics_handles_single_class_without_roc_auc() -> None:
    metrics = binary_metrics([1, 1], [0.8, 0.7])

    assert metrics["roc_auc"] is None
    assert metrics["pr_auc"] == 1.0


def test_f1_threshold_is_selected_from_validation_scores() -> None:
    threshold, metrics = select_f1_threshold([0, 0, 1, 1], [0.10, 0.35, 0.55, 0.90])

    assert 0.35 < threshold <= 0.55
    assert metrics["f1"] == 1.0
