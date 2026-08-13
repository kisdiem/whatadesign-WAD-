from __future__ import annotations

import math
import re
import statistics
import zlib
from array import array
from collections import Counter
from dataclasses import dataclass

from .schema import LogEvent, parse_timestamp


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


def _template(event: LogEvent) -> str:
    text = event.message.lower()
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)
    text = re.sub(r"\b\d+\b", "<num>", text)
    return " ".join(TOKEN_RE.findall(text))[:240]


class CountMinSketch:
    """Fixed-memory approximate frequency table."""

    def __init__(self, width: int = 1 << 16, depth: int = 4) -> None:
        self.width = width
        self.depth = depth
        self.tables = [array("I", [0]) * width for _ in range(depth)]

    def _indices(self, value: str) -> tuple[int, ...]:
        encoded = value.encode("utf-8", errors="replace")
        return tuple(zlib.crc32(encoded, 0x9E3779B1 * (seed + 1)) % self.width for seed in range(self.depth))

    def add(self, value: str) -> None:
        for table, index in zip(self.tables, self._indices(value)):
            if table[index] < 0xFFFFFFFF:
                table[index] += 1

    def estimate(self, value: str) -> int:
        return min(table[index] for table, index in zip(self.tables, self._indices(value)))

    @property
    def bytes_allocated(self) -> int:
        return sum(len(table) * table.itemsize for table in self.tables)


class StreamingFrequencyBaseline:
    """Two-pass, bounded-memory baseline for datasets larger than RAM."""

    def __init__(self, sketch_width: int = 1 << 16) -> None:
        self.templates = CountMinSketch(sketch_width)
        self.entities = CountMinSketch(sketch_width)
        self.sources = CountMinSketch(max(1024, sketch_width // 16))
        self.total = 0
        self.length_mean = 0.0
        self.length_m2 = 0.0

    def update(self, event: LogEvent) -> None:
        self.total += 1
        length = float(len(event.message))
        delta = length - self.length_mean
        self.length_mean += delta / self.total
        self.length_m2 += delta * (length - self.length_mean)
        self.templates.add(_template(event))
        self.sources.add(event.source_type)
        for entity in event.entities:
            self.entities.add(entity)

    @property
    def fixed_state_bytes(self) -> int:
        return self.templates.bytes_allocated + self.entities.bytes_allocated + self.sources.bytes_allocated

    def score(self, event: LogEvent) -> BaselineScore:
        template_rarity = 1.0 / math.sqrt(self.templates.estimate(_template(event)) + 1)
        entity_rarity = max((1.0 / math.sqrt(self.entities.estimate(value) + 1) for value in event.entities), default=0.35)
        source_rarity = 1.0 / math.sqrt(self.sources.estimate(event.source_type) + 1)
        variance = self.length_m2 / max(self.total - 1, 1)
        length_z = min(abs(len(event.message) - self.length_mean) / max(4.0 * math.sqrt(variance), 1.0), 1.0)
        hour = parse_timestamp(event.timestamp).hour
        off_hours = 1.0 if hour < 5 else 0.0
        components = {"template_rarity": template_rarity, "entity_rarity": entity_rarity, "source_rarity": source_rarity, "length_deviation": length_z, "off_hours": off_hours}
        score = min(1.0, 0.40 * template_rarity + 0.27 * entity_rarity + 0.08 * source_rarity + 0.15 * length_z + 0.10 * off_hours)
        return BaselineScore(score, components, tuple(name for name, value in components.items() if value >= 0.7))


@dataclass(frozen=True)
class BaselineScore:
    score: float
    components: dict[str, float]
    reasons: tuple[str, ...]


class FrequencyIsolationBaseline:
    """Label-free robust rarity baseline suitable for streaming pre-fit statistics."""

    def __init__(self) -> None:
        self.template_counts: Counter[str] = Counter()
        self.entity_counts: Counter[str] = Counter()
        self.source_counts: Counter[str] = Counter()
        self.length_median = 0.0
        self.length_mad = 1.0
        self.total = 0

    def fit(self, events: list[LogEvent]) -> "FrequencyIsolationBaseline":
        if not events:
            raise ValueError("baseline fit requires events")
        self.total = len(events)
        lengths = [len(event.message) for event in events]
        self.length_median = statistics.median(lengths)
        deviations = [abs(value - self.length_median) for value in lengths]
        self.length_mad = max(statistics.median(deviations), 1.0)
        for event in events:
            self.template_counts[_template(event)] += 1
            self.source_counts[event.source_type] += 1
            self.entity_counts.update(event.entities)
        return self

    def score(self, event: LogEvent) -> BaselineScore:
        template_rarity = 1.0 / math.sqrt(self.template_counts[_template(event)] + 1)
        entity_rarity = max((1.0 / math.sqrt(self.entity_counts[value] + 1) for value in event.entities), default=0.35)
        source_rarity = 1.0 / math.sqrt(self.source_counts[event.source_type] + 1)
        length_z = min(abs(len(event.message) - self.length_median) / (6.0 * self.length_mad), 1.0)
        hour = parse_timestamp(event.timestamp).hour
        off_hours = 1.0 if hour < 5 else 0.0
        components = {
            "template_rarity": template_rarity,
            "entity_rarity": entity_rarity,
            "source_rarity": source_rarity,
            "length_deviation": length_z,
            "off_hours": off_hours,
        }
        score = min(1.0, 0.40 * template_rarity + 0.27 * entity_rarity + 0.08 * source_rarity + 0.15 * length_z + 0.10 * off_hours)
        reasons = tuple(name for name, value in components.items() if value >= 0.7)
        return BaselineScore(score=score, components=components, reasons=reasons)
