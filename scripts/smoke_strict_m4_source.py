from __future__ import annotations

"""Exercise the real source EventFrame -> M4 causal feature path once.

This is a contract smoke only. It does not load labels, calculate a loss, or
claim a trained Q-Former checkpoint.
"""

import argparse
import json
from pathlib import Path

import _bootstrap
from src.common.schema import EventFrame
from src.models.m4_backbone_adapter import QwenBackboneAdapter
from src.models.m4_qformer import M4Config, M4QFormerDecoder
from src.training.m4_multiscale_builder import StrictM4BatchBuilder


def main() -> None:
    parser = argparse.ArgumentParser(description="Strict real-Qwen M4 source smoke")
    parser.add_argument("--events", required=True, help="M1 embedded EventFrame JSONL")
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--qwen-model", required=True)
    parser.add_argument("--device", default="cuda")
    args = parser.parse_args()

    frames = [EventFrame.from_dict(json.loads(line)) for line in Path(args.events).read_text(encoding="utf-8").splitlines() if line.strip()]
    qwen = QwenBackboneAdapter(args.qwen_model, mode="frozen", local_files_only=True)
    sample = StrictM4BatchBuilder(qwen).build_one(frames, args.record_id)
    batch = StrictM4BatchBuilder.collate([sample])
    m4 = M4QFormerDecoder(M4Config(input_dim=768, hidden_dim=128, qwen_hidden_dim=qwen.hidden_size, heads=4, layers=1)).eval()
    output = m4.forward_micro_windows(**batch)
    # All history membership has been established by WindowBuilder before Qwen
    # receives its structured EventFrames.  Assert the current event cannot
    # appear in any returned causal micro window.
    assert all(args.record_id not in window.record_ids for window in sample.windows)
    print(json.dumps({
        "status": "PASSED", "mode": "strict_source_contract_smoke", "labels_read": False,
        "record_id": args.record_id, "dataset_id": frames[0].dataset_id,
        "micro_window_count": len(sample.windows),
        "micro_event_shape": list(batch["micro_event_embeddings"].shape),
        "qwen_shape": list(batch["qwen_window_embeddings"].shape),
        "m4_event_embedding_shape": list(output["event_embedding"].shape),
        "score_logit_shape": list(output["score_logit"].shape),
        "qwen": sample.qwen_manifest,
    }, indent=2))


if __name__ == "__main__":
    main()
