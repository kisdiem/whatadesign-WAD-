from __future__ import annotations

class AitScorer:
    def score(self, prediction_path, label_path, *, predictions_sealed: bool):
        if not predictions_sealed: raise PermissionError("predictions must be sealed before label scoring")
        raise NotImplementedError("AIT scoring requires separately supplied labels; none are bundled")
