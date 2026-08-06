from __future__ import annotations

import json
from pathlib import Path
from src.evaluation.protocol_gates import require_sealed_predictions


class AitScorer:
    """Post-seal scorer; labels enter only here, never through the target adapter."""
    def score(self, prediction_manifest: str | Path, label_path: str | Path, *, predictions_sealed: bool = False):
        manifest = Path(prediction_manifest)
        if not predictions_sealed:
            raise PermissionError("predictions must be sealed before label scoring")
        require_sealed_predictions(manifest)
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        predictions = {}
        for item in payload["predictions"]:
            for line in Path(item["path"]).read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line); predictions[str(row["record_id"])] = float(row.get("score", row.get("fused_score", 0.0)))
        labels = {}
        for line in Path(label_path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line); labels[str(row["record_id"])] = int(row["label"])
        common = sorted(set(predictions) & set(labels))
        if not common: raise ValueError("no record_id overlap between sealed predictions and labels")
        correct = sum((predictions[key] >= 0.5) == bool(labels[key]) for key in common)
        positives = sum(labels[key] for key in common)
        return {"records_scored": len(common), "accuracy_at_0_5": correct / len(common), "positive_labels": positives, "labels_source": str(Path(label_path).resolve())}
