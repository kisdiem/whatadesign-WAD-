from __future__ import annotations
import random

class HardNegativeSampler:
    def __init__(self, seed: int = 0): self.random = random.Random(seed)
    def sample(self, candidates, count: int): return self.random.sample(list(candidates), min(count, len(candidates)))
