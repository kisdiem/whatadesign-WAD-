# Cross-Domain Semantic Graph APT Detection V3

This repository contains the current code architecture for a multi-source APT/log detection system.

## Pipeline

`M0` parsing -> `M1` semantic normalization -> `M2` entity resolution -> `M3` temporal event graph -> `M4` current-event-conditioned Q-Former -> `M5` long-horizon window linking -> `M6` frozen-feature hierarchical fusion.

## M5 long-horizon design

M5 now separates local attack-stage estimation from actual long-horizon linking:

1. `M5KnowledgeProgressTransformer` performs token-level semantic encoding plus Top-K external ATT&CK/attack-chain knowledge cross-attention. It outputs broad attack relevance, multi-label attack-chain position probabilities and a continuous progress prior.
2. `PersistentEntityMemory` records where stable and weak entities appeared over time and uses the index to retrieve a sparse set of historical candidate events instead of comparing every event pair.
3. `M5EntityProgressLinker` only permits edges from an earlier event to a later event. Observation time is therefore a hard ordering constraint.
4. Attack progress and attack-chain position are soft ordering constraints. Small backwards movement is tolerated because these values are predicted and real APT campaigns can revisit earlier tactics; large backwards movement is strongly penalized.
5. Entity continuity, semantic similarity, progress consistency, position consistency, long-horizon time decay, graph similarity and attack relevance are fused into the final link score. IP-only continuity is weak by default and is insufficient to create a link.
6. `M5AttackChainAssembler` incrementally creates a directed acyclic attack-chain graph by retrieving historical candidates, scoring `past -> current` edges, then storing the current event in persistent memory.

This keeps Transformer context length independent from the total campaign duration: raw multi-day logs are not concatenated into one Transformer context. Long-range recall is provided by entity memory and sparse candidate retrieval.

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
