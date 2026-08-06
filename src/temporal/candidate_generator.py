from __future__ import annotations
from src.temporal.m5_long_horizon import M5Linker

class CandidateGenerator:
    def __init__(self, linker: M5Linker): self.linker = linker
    def generate(self, source, target): return self.linker.evidence_features(source, target)
