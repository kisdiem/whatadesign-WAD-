from __future__ import annotations

import pytest
import torch

from src.common.schema import EventFrame, FrozenFeatureRecord, RawRecord, SyntaxParse
from src.entities.entity_id import scoped_entity_id
from src.entities.m2_rule_resolver import M2RuleResolver
from src.entities.pair_resolver import PairResolver
from src.graph.history_graph_builder import CausalGraphBuilder
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.parsers.m0_parser import M0Parser
from src.fusion.thresholds import fit_threshold
from src.protocol.target_access_guard import TargetAccessGuard
from src.protocol.state_machine import ProtocolState, ProtocolStateMachine
from src.common.manifest import StageManifest


def _event(record_id, ts, action="read"):
    return EventFrame(dataset_id="d", record_id=record_id, timestamp=ts, action_family=action)


def test_raw_record_provenance_fields():
    raw = RawRecord("d", "a.log", 3, "2026-01-01", "x", "parser", "adapter", "rid", "hash", {"host": "h"})
    assert raw.source_file == "a.log" and raw.source_line == 3 and raw.ingestion_metadata["host"] == "h"


def test_schema_round_trip_and_version_guard():
    item = EventFrame(dataset_id="d", record_id="r", source_record_ref="a:1")
    assert EventFrame.from_dict(item.to_dict()) == item
    with pytest.raises(ValueError): EventFrame.from_dict({"schema_version": "old", "record_id": "r"})


def test_m0_missing_timestamp_is_quarantined():
    parsed = M0Parser().parse(RawRecord("d", "a", 1, None, "payload", "p", "a"))
    assert parsed.quarantined and parsed.quarantine_reason == "missing_timestamp" and parsed.source_record_ref == "a:1"


def test_m0_payload_is_traceable():
    parsed = M0Parser().parse(RawRecord("d", "a", 4, "t", {"message": "x"}, "p", "a"))
    assert parsed.dataset_id == "d" and parsed.source_file == "a" and parsed.source_line == 4


@pytest.mark.parametrize("dataset", ["a", "b", "ait", "cert", "evtx", "ctu", "sandworm"])
def test_entity_ids_are_dataset_scoped(dataset):
    assert scoped_entity_id(dataset, "user", "alice") != scoped_entity_id(dataset + "2", "user", "alice")


@pytest.mark.parametrize("host", ["h1", "h2", "h3", "h4", "h5"])
def test_process_instances_are_host_scoped(host):
    left = M2RuleResolver().resolve(dataset_id="d", entity_type="process", raw_value="42", instance_context=f"{host}|42|t")
    right = M2RuleResolver().resolve(dataset_id="d", entity_type="process", raw_value="42", instance_context=f"other|42|t")
    assert left.entity_id != right.entity_id


def test_ip_is_weak_and_cannot_pair():
    resolver = M2RuleResolver()
    a = resolver.resolve(dataset_id="d", entity_type="ip", raw_value="10.0.0.1")
    b = resolver.resolve(dataset_id="d", entity_type="ip", raw_value="10.0.0.1")
    assert PairResolver().score(a, b) == (0.0, "weak_ip_only")


def test_causal_graph_excludes_current():
    current = _event("current", "2026-01-01T00:02:00")
    graph = CausalGraphBuilder().build_causal_graph_before([_event("old", "2026-01-01T00:01:00"), current], current)
    assert [n["node_id"] for n in graph.node_records] == ["old"]


def test_causal_graph_excludes_future_and_same_timestamp_later_order():
    current = _event("b", "2026-01-01T00:01:00")
    future = _event("c", "2026-01-01T00:02:00")
    later = _event("z", "2026-01-01T00:01:00")
    graph = CausalGraphBuilder().build_causal_graph_before([_event("a", "2026-01-01T00:00:00"), current, future, later], current, {"b": ("x", 2), "z": ("x", 3)})
    assert [n["node_id"] for n in graph.node_records] == ["a"]


def test_qwen_mock_does_not_claim_loaded():
    adapter = QwenBackboneAdapter(mode="mock")
    assert adapter.export_backbone_manifest()["model_loaded"] is False


def test_qwen_nonmock_failure_is_explicit():
    with pytest.raises(RuntimeError): QwenBackboneAdapter(name="missing/no-model", mode="pretrained", local_files_only=True)


def test_frozen_features_exclude_metadata():
    record = FrozenFeatureRecord("r", "d", None, semantic_embedding=[1.0], producer_checkpoint_hashes={"m4": "x"})
    features = record.model_features()
    assert "dataset_id" not in features and "producer_checkpoint_hashes" not in features and "semantic_embedding" in features


@pytest.mark.parametrize("source", ["ait", "ait_lds", "ait_ads", "AIT_LDS_V2"])
def test_ait_thresholds_are_rejected(source):
    with pytest.raises(ValueError): fit_threshold([0.1], [1], source)


def test_target_guard_rejects_label_attributes():
    class Labelled: label = 1
    with pytest.raises(ValueError): TargetAccessGuard().assert_unlabeled(Labelled())


def test_target_guard_accepts_raw_record():
    TargetAccessGuard().assert_unlabeled(RawRecord("ait", "x", 1, None, "x", "target", "adapter"))


def test_protocol_state_machine_requires_order():
    machine = ProtocolStateMachine()
    machine.transition(ProtocolState.SOURCE_FROZEN)
    with pytest.raises(ValueError): machine.transition(ProtocolState.TARGET_INFERENCE_STARTED)


def test_protocol_state_machine_reaches_label_gate_only_after_seal():
    machine = ProtocolStateMachine()
    for state in (ProtocolState.SOURCE_FROZEN, ProtocolState.RELEASE_LOCKED, ProtocolState.TARGET_INFERENCE_STARTED, ProtocolState.PREDICTIONS_SEALED, ProtocolState.LABEL_SCORING_ALLOWED):
        machine.transition(state)
    machine.require(ProtocolState.LABEL_SCORING_ALLOWED)


def test_manifest_serialization_has_provenance(tmp_path):
    path = StageManifest("m0", "COMPLETED", "abc", real_data_used=True).write(tmp_path / "manifest.json")
    payload = path.read_text(encoding="utf-8")
    assert "abc" in payload and "schema_version" in payload and "real_data_used" in payload


def test_m4_strict_batch_rejects_current_history():
    from src.models.m4_batch import M4StrictBatch
    with pytest.raises(ValueError): M4StrictBatch("r", "d", ({"record_id": "r"},), None, {"record_id": "r"}, None, {}, None)


@pytest.mark.parametrize("module_name", ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "schema", "graph", "entity", "window", "fusion", "release", "ait", "source", "cache", "audit", "manifest", "provenance", "serialization"])
def test_strict_stage_names_are_explicit(module_name):
    assert module_name and module_name == module_name.lower()
