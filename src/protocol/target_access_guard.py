from __future__ import annotations

class TargetAccessGuard:
    def assert_unlabeled(self, record) -> None:
        forbidden = ("label", "ground_truth", "attack_stage", "evaluation_result", "scenario")
        if any(hasattr(record, name) for name in forbidden):
            raise ValueError("target adapter returned labels or evaluation fields")

        if isinstance(record, dict) and any(name in record for name in forbidden):
            raise ValueError("target adapter returned labels or evaluation fields")
