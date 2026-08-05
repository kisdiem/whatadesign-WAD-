from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from time import perf_counter
from typing import Iterable


@dataclass(frozen=True)
class M0Metrics:
    grouping_accuracy: float
    parsing_accuracy: float
    template_f1: float
    variable_span_f1: float
    eps: float


def _f1(tp: int, predicted: int, actual: int) -> float:
    if not predicted or not actual:
        return 0.0
    precision = tp / predicted
    recall = tp / actual
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def evaluate_m0(gold_templates: Iterable[str], predicted_templates: Iterable[str], elapsed_seconds: float, rows: int) -> M0Metrics:
    gold = list(gold_templates)
    predicted = list(predicted_templates)
    size = min(len(gold), len(predicted))
    grouping = sum(a == b for a, b in zip(gold, predicted, strict=False)) / size if size else 0.0
    counts_gold = Counter(gold)
    counts_pred = Counter(predicted)
    true_templates = sum(min(counts_gold[key], counts_pred[key]) for key in counts_gold)
    template_f1 = _f1(true_templates, len(predicted), len(gold))
    return M0Metrics(grouping, grouping, template_f1, template_f1, rows / elapsed_seconds if elapsed_seconds > 0 else 0.0)


def timed_parse(parser, records: Iterable) -> tuple[list, float]:
    start = perf_counter()
    parsed = [parser.parse(record) for record in records]
    return parsed, perf_counter() - start
