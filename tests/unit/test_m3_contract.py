from src.common.schema import EventFrame
from src.entities.m2_resolver import M2EntityResolver
from src.graph.m3_graph import M3EventGraphBuilder
from src.graph.m3_encoder import GraphTensor, M3GraphSAGEEncoder


def test_m3_builds_typed_event_graph():
    frame = EventFrame("r1", action="authenticate", outcome="failure", entities=["10.0.0.1"])
    graph = M3EventGraphBuilder().build([(frame, M2EntityResolver().resolve(frame))])
    assert graph.schema_version == "m3_event_graph_v1"
    assert any(node.node_type == "event" for node in graph.nodes)
    assert any(edge.relation == "participates" for edge in graph.edges)


def test_m3_is_deterministic_for_same_input():
    frame = EventFrame("r1", action="read", entities=["/tmp/a"])
    resolver = M2EntityResolver()
    builder = M3EventGraphBuilder()
    first = builder.build([(frame, resolver.resolve(frame))])
    second = builder.build([(frame, resolver.resolve(frame))])
    assert first == second


def test_m3_history_excludes_current_event_and_encoder_runs():
    resolver = M2EntityResolver()
    first = EventFrame("r1", action="read", entities=["/tmp/a"])
    current = EventFrame("r2", action="write", entities=["/tmp/b"])
    graph = M3EventGraphBuilder().build_before_current_event(
        [(first, resolver.resolve(first)), (current, resolver.resolve(current))], "r2"
    )
    assert all(node.node_id != "event:r2" for node in graph.nodes)
    tensor = GraphTensor.from_event_graph(graph, feature_dim=8)
    output = M3GraphSAGEEncoder(input_dim=8, hidden_dim=8)(tensor)
    assert output["node_embedding"].shape[-1] == 8
