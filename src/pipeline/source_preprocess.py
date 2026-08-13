from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.common.schema import EventFrame, SyntaxParse
from src.data.adapters import AdapterResult, adapter_for
from src.entities.m2_resolver import M2EntityResolver, ResolvedEntity
from src.graph.m3_graph import EventGraph, M3EventGraphBuilder
from src.parsers.m0_drain import M0DrainParser
from src.semantic.m1_normalizer import M1SemanticNormalizer


@dataclass(frozen=True)
class PreprocessResult:
    dataset_id: str
    raw_records: int
    parsed_records: int
    frames: tuple[EventFrame, ...]
    entities: tuple[tuple[ResolvedEntity, ...], ...]
    graph: EventGraph | None
    status: str
    errors: tuple[str, ...] = ()


def run_source_preprocess(dataset_id: str, path: Path, limit: int = 0) -> PreprocessResult:
    adapter_result: AdapterResult = adapter_for(dataset_id).read(path, limit=limit)
    if adapter_result.status != "ok":
        return PreprocessResult(dataset_id, 0, 0, (), (), None, adapter_result.status, adapter_result.errors)
    parser = M0DrainParser()
    normalizer = M1SemanticNormalizer()
    resolver = M2EntityResolver()
    frames: list[EventFrame] = []
    entities: list[tuple[ResolvedEntity, ...]] = []
    for raw in adapter_result.records:
        payload = raw.raw_payload if isinstance(raw.raw_payload, str) else str(raw.raw_payload)
        parsed = parser.parse(raw.__class__(raw.dataset_id, raw.source_file, raw.source_line, raw.raw_timestamp, payload, "m0_drain_v1"))
        frame = normalizer.normalize(parsed)
        resolved = tuple(resolver.resolve(frame))
        frames.append(frame)
        entities.append(resolved)
    graph = M3EventGraphBuilder().build(zip(frames, entities)) if frames else None
    return PreprocessResult(dataset_id, len(adapter_result.records), len(frames), tuple(frames), tuple(entities), graph, "ok")
