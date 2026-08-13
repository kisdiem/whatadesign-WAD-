from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class WindowConfig:
    micro_minutes: int = 5
    macro_minutes: int = 30

class WindowBuilder:
    def __init__(self, config: WindowConfig | None = None): self.config = config or WindowConfig()
    def assign(self, timestamp_seconds: float) -> tuple[int, int]:
        return (int(timestamp_seconds // (self.config.micro_minutes * 60)), int(timestamp_seconds // (self.config.macro_minutes * 60)))
