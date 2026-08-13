from src.temporal.m5_long_horizon import M5Linker

class M5PairScorer:
    def __init__(self, linker: M5Linker): self.linker = linker
    def score(self, source, target): return self.linker(source, target)
