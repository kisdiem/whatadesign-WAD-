from __future__ import annotations
from src.common.schema import FrozenFeatureRecord

class FrozenFeatureExporter:
    def __init__(self, producers):
        self.producers = tuple(producers)
        for producer in self.producers:
            if any(p.requires_grad for p in producer.parameters()):
                raise ValueError("M0-M5 producers must be frozen before export")

    def export(self, record: FrozenFeatureRecord) -> FrozenFeatureRecord:
        if not record.producer_checkpoint_hashes: raise ValueError("producer checkpoint hashes are required")
        return record
