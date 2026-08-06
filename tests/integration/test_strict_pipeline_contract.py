from __future__ import annotations

import pytest
from src.common.schema import EventFrame, FrozenFeatureRecord, RawRecord
from src.entities.m2_rule_resolver import M2RuleResolver
from src.graph.event_graph_builder import EventGraphBuilder
from src.graph.history_graph_builder import CausalGraphBuilder
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.parsers.m0_parser import M0Parser
from src.protocol.target_access_guard import TargetAccessGuard


@pytest.mark.parametrize("case", range(10))
def test_synthetic_strict_pipeline_contract(case):
    raw = RawRecord("source", "fixture.log", case + 1, f"2026-01-01T00:0{case}:00", {"message": "read file"}, "m0", "fixture")
    syntax = M0Parser().parse(raw)
    assert not syntax.quarantined
    entity = M2RuleResolver().resolve(dataset_id="source", entity_type="file", raw_value=f"/tmp/{case}", source_record_ref=syntax.source_record_ref, platform="linux")
    event = EventFrame(dataset_id="source", record_id=syntax.record_id, timestamp=syntax.timestamp, action_family="read", entity_mentions=[{"entity_id": entity.entity_id, "entity_type": "file"}], source_record_ref=syntax.source_record_ref)
    graph = EventGraphBuilder().build(event)
    causal = CausalGraphBuilder().build_causal_graph_before([event], event)
    assert graph.current_record_id == event.record_id and len(causal.node_records) == 0
    assert QwenBackboneAdapter(mode="mock").model_loaded is False
    TargetAccessGuard().assert_unlabeled(raw)
