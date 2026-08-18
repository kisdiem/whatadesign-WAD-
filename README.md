# Cross-Domain Semantic Graph APT Detection V3

This repository contains the current code architecture for a multi-source APT/log detection system.

## Pipeline

`M0` parsing -> `M1` semantic normalization -> `M2` entity resolution -> `M3` temporal event graph -> `M4` current-event-conditioned Q-Former -> `M5` long-horizon window linking -> `M6` frozen-feature hierarchical fusion.

### M4 training contract

M4 is a source-only current-event anomaly head. It consumes strict causal
batches containing frozen M1 EventFrame embeddings and M3 context, plus either
the frozen Qwen window representation or an exact hash-keyed Qwen cache. The
Qwen backbone is not updated by the M4 head. Labels enter only the loss and
are never serialized into EventFrame, graph, Qwen, or frozen-feature inputs.

The supervised objective is binary loss on `score_logit`. When source-fact
triplets are available, an InfoNCE relation term is added. Pair construction
preserves the causal time boundary. Checkpoints are selected using only the
time/source-held-out validation split and its validation-fitted threshold;
held-out test data is scored afterward. AIT remains target-only for the strict
V3 release path. Any AIT-supervised run is a separately named upper-bound
experiment and is not zero-shot cross-domain evidence.

The formal entry point is `scripts/train_m4_source_supervised.py`. It records
the selected checkpoint, threshold, split manifest, loss history, and
provenance. Smoke/cache tests verify interfaces only, not model quality.

## Current status

The repository contains implementation contracts, smoke/unit tests, source-held-out and leakage-audit utilities, release protocol gates, and reduced M3-M6 model components. It does not contain real training data, model checkpoints, final source-domain metrics, or AIT predictions.

The latest verified server test result is `34 passed` with commit `f2bb562`.

The current data fallback route is CERT long-term behavior, EVTX endpoint/entity relationships, CTU-13 network continuity, and Sandworm attack-window validation. LANL is not part of the current training route.

## Protocol boundaries

- AIT is a target evaluation domain, not a training source for P1.
- AIT labels may only be read after predictions are sealed.
- A locked release requires real checkpoints, thresholds, calibration and model hashes.
- Generated data, virtual environments, logs and temporary outputs are intentionally excluded.

See `docs/v3_compliance_audit.md`, `docs/data_deviation_v3.md`, and `outputs/audit/` for the strict audit status.
