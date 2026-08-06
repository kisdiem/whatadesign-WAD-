from __future__ import annotations

from src.common.schema import FrozenFeatureRecord


def join_frozen_features(frames, entities_by_event, graphs_by_event, m4_outputs, micro_by_event, macro_by_event, producer_artifact_hashes):
    records = []
    for frame in frames:
        key = (frame.dataset_id, frame.record_id)
        if key not in m4_outputs or key not in micro_by_event or key not in macro_by_event: raise ValueError(f"incomplete frozen join for {key}")
        m4 = m4_outputs[key]; micro = micro_by_event[key]; macro = macro_by_event[key]
        graph = graphs_by_event.get(key, {})
        embedding = [float(value) for value in m4["event_embedding"].detach().reshape(-1).tolist()]
        graph_embedding = [float(value) for value in graph.get("embedding", embedding)]
        records.append(FrozenFeatureRecord(record_id=frame.record_id, dataset_id=frame.dataset_id, timestamp=frame.timestamp,
                                           semantic_embedding=[frame.semantic_confidence], semantic_confidence=frame.semantic_confidence,
                                           unknown_score=frame.unknown_score, entity_summary=entities_by_event.get(key, {}),
                                           graph_embedding=graph_embedding, graph_score=float(graph.get("score", 0.0)), event_embedding=embedding,
                                           slot_nll=float(m4.get("slot_nll", 0.0)), raw_event_score=float(m4["raw_event_logit"].detach().reshape(-1)[0]),
                                           micro_window_score=float(micro), macro_window_score=float(macro), long_horizon_score=float(max(micro, macro)),
                                           queue_features={}, source_record_ref=frame.source_record_ref,
                                           producer_artifact_hashes=dict(producer_artifact_hashes)))
    return records
