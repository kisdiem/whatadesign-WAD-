from __future__ import annotations

class TargetAccessGuard:
    def assert_unlabeled(self, record) -> None:
        if any(hasattr(record, name) for name in ("label", "ground_truth", "attack_stage", "evaluation_result")):
            raise ValueError("target adapter returned labels or evaluation fields")
