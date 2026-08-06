"""Feature extraction boundary for causal graph statistics."""

def graph_features(graph):
    return {"node_count": len(graph.node_records), "edge_count": len(graph.edge_records)}
