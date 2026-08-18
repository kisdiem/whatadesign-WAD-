from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WindowConfig:
    micro_minutes: int = 5
    macro_minutes: int = 15

    def __post_init__(self) -> None:
        if self.micro_minutes <= 0 or self.macro_minutes <= 0:
            raise ValueError("window sizes must be positive")
        if self.macro_minutes < self.micro_minutes:
            raise ValueError("macro window cannot be shorter than micro window")


class WindowBuilder:
    def __init__(self, config: WindowConfig | None = None) -> None:
        self.config = config or WindowConfig()

    def assign(self, timestamp_seconds: float) -> tuple[int, int]:
        return (
            int(timestamp_seconds // (self.config.micro_minutes * 60)),
            int(timestamp_seconds // (self.config.macro_minutes * 60)),
        )
