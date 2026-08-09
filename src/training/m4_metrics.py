from __future__ import annotations

"""Evaluation metrics used by strict source-only M4 training."""


def binary_metrics(labels: list[int], scores: list[float], threshold: float = 0.5) -> dict[str, float | int | None]:
    """Threshold metrics plus dependency-free ROC-AUC and PR-AUC."""
    predictions = [int(score >= threshold) for score in scores]
    tp = sum(p == 1 and y == 1 for p, y in zip(predictions, labels))
    fp = sum(p == 1 and y == 0 for p, y in zip(predictions, labels))
    tn = sum(p == 0 and y == 0 for p, y in zip(predictions, labels))
    fn = sum(p == 0 and y == 1 for p, y in zip(predictions, labels))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    positives, negatives = sum(labels), len(labels) - sum(labels)
    roc_auc = None
    if positives and negatives:
        wins = ties = 0
        for score, label in zip(scores, labels):
            if label:
                for other, other_label in zip(scores, labels):
                    if not other_label:
                        wins += score > other
                        ties += score == other
        roc_auc = (wins + 0.5 * ties) / (positives * negatives)
    pr_auc = None
    if positives:
        ranked = sorted(zip(scores, labels), key=lambda row: row[0], reverse=True)
        true_positives = 0
        precision_sum = 0.0
        for rank, (_, label) in enumerate(ranked, start=1):
            if label:
                true_positives += 1
                precision_sum += true_positives / rank
        pr_auc = precision_sum / positives
    return {"threshold": threshold, "roc_auc": roc_auc, "pr_auc": pr_auc, "f1": f1, "precision": precision,
            "recall": recall, "tp": tp, "fp": fp, "tn": tn, "fn": fn}
