import json
from pathlib import Path

root = Path("outputs/source/formal_source_stratified_v2/m6_formal")
threshold = 0.3088289499282837
for name in ("validation_predictions.jsonl", "test_predictions.jsonl"):
    rows = [json.loads(line) for line in (root / name).read_text(encoding="utf-8").splitlines() if line]
    positives = [row["score"] for row in rows if row["label"]]
    negatives = [row["score"] for row in rows if not row["label"]]
    print(name, json.dumps({
        "records": len(rows), "positive": len(positives),
        "predicted_positive": sum(row["score"] >= threshold for row in rows),
        "true_positive": sum(row["label"] and row["score"] >= threshold for row in rows),
        "positive_score_range": [min(positives), max(positives)] if positives else None,
        "negative_score_range": [min(negatives), max(negatives)] if negatives else None,
    }))
