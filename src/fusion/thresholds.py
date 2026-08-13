from __future__ import annotations

def fit_threshold(scores, labels, source: str) -> float:
    if "ait" in source.lower(): raise ValueError("AIT cannot fit thresholds")
    pairs = sorted(zip(scores, labels), reverse=True)
    positives = [s for s, y in pairs if y]
    return float(min(positives)) if positives else 1.0
