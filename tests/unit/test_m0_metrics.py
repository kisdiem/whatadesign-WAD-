from src.parsers.m0_metrics import evaluate_m0


def test_m0_metrics_reports_eps_and_template_f1():
    result = evaluate_m0(["a", "b"], ["a", "b"], 2.0, 2)
    assert result.grouping_accuracy == 1.0
    assert result.template_f1 == 1.0
    assert result.eps == 1.0
