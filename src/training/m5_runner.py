from __future__ import annotations
from src.temporal.window_builder import WindowBuilder, WindowConfig

class M5Runner:
    def __init__(self, config=None): self.window_builder = WindowBuilder(config or WindowConfig())
    def build(self, windows):
        return [{**row, "window_ids": self.window_builder.assign(float(row["timestamp_seconds"]))} for row in windows]
