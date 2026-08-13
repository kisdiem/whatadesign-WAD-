from __future__ import annotations

from enum import StrEnum


class ProtocolState(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    SOURCE_FROZEN = "SOURCE_FROZEN"
    RELEASE_LOCKED = "RELEASE_LOCKED"
    TARGET_INFERENCE_STARTED = "TARGET_INFERENCE_STARTED"
    PREDICTIONS_SEALED = "PREDICTIONS_SEALED"
    LABEL_SCORING_ALLOWED = "LABEL_SCORING_ALLOWED"


_TRANSITIONS = {
    ProtocolState.DEVELOPMENT: {ProtocolState.SOURCE_FROZEN},
    ProtocolState.SOURCE_FROZEN: {ProtocolState.RELEASE_LOCKED},
    ProtocolState.RELEASE_LOCKED: {ProtocolState.TARGET_INFERENCE_STARTED},
    ProtocolState.TARGET_INFERENCE_STARTED: {ProtocolState.PREDICTIONS_SEALED},
    ProtocolState.PREDICTIONS_SEALED: {ProtocolState.LABEL_SCORING_ALLOWED},
}


class ProtocolStateMachine:
    def __init__(self, state: ProtocolState = ProtocolState.DEVELOPMENT):
        self.state = ProtocolState(state)

    def transition(self, target: ProtocolState) -> ProtocolState:
        target = ProtocolState(target)
        if target not in _TRANSITIONS.get(self.state, set()):
            raise ValueError(f"invalid protocol transition: {self.state} -> {target}")
        self.state = target
        return self.state

    def require(self, expected: ProtocolState) -> None:
        if self.state != ProtocolState(expected):
            raise PermissionError(f"required state {expected}, current state {self.state}")
