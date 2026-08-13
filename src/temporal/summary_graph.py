def build_summary_graph(queue):
    return {"queue_id": queue.queue_id, "window_ids": list(queue.window_ids), "evidence": list(queue.evidence)}
