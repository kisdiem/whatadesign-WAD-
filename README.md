# Cross-Domain Semantic Graph APT Detection V3

This repository contains the current code architecture for a multi-source APT/log detection system.

## Pipeline

`M0` parsing -> `M1` semantic normalization -> `M2` entity resolution -> `M3` temporal event graph -> `M4` current-event-conditioned Q-Former (15-minute local association) -> `M5` long-horizon attack-chain linking -> `M6` frozen-feature hierarchical fusion.

## Local/long-horizon boundary

The local association window is fixed at **15 minutes** by default. `WindowConfig.macro_minutes=15`, and `WindowAggregator.aggregate(..., minutes=15)` uses the same default. M4 handles dense local reasoning inside these windows; M5 does not extend Transformer context across days of raw logs. Instead, M5 retrieves sparse historical candidates from persistent entity memory and connects local windows/events across longer time spans.

## M5 long-horizon design

M5 is split into explicit stages:

1. `M5KnowledgeProgressTransformer` performs token-level semantic encoding plus Top-K external ATT&CK/attack-chain knowledge cross-attention. It outputs broad attack relevance, multi-label attack-chain position probabilities, continuous progress prior, and the fused semantic embedding used downstream.
2. `PersistentEntityMemory` records where entities appeared over time and uses those indices to retrieve historical candidates instead of comparing every event pair. Stable entities carry more weight; IP/account continuity is weak and cannot create a long-horizon edge by itself under the default threshold.
3. `M5EntityProgressLinker` applies the hard temporal rule `past -> current`. Observation time is the hard direction constraint; predicted progress is only a soft constraint, so small regressions are tolerated and large regressions are penalized rather than forbidden.
4. `AttackTransitionCompatibility` replaces scalar expected-position ordering with a full ATT&CK-stage transition compatibility matrix. Same-stage, forward, short backward revisit and large backward transitions receive different priors. The matrix is learnable, so source-domain supervision can calibrate it rather than enforcing a fixed linear tactic sequence.
5. `M5LearnedLinkScorer` replaces the final fixed weighted sum. Entity continuity, semantic similarity, progress consistency, ATT&CK transition compatibility, long-horizon time consistency and graph similarity are fused with trainable feature weights plus a nonlinear residual MLP. It is initialized to reproduce the previous interpretable weighting, then can be optimized with labeled positive/negative candidate pairs through `supervised_link_loss` or `M5LinkTrainingRunner`.
6. `M5AttackChainManager` is chain-aware. It groups incoming event links by the attack chain of their source event, combines event-link support with the chain state prototype, and assigns the current event to at most one existing chain. If evidence is weak or two chains are too close, it opens a new chain instead of implicitly merging existing chains.
7. Each `AttackChainState` maintains event IDs, accumulated entity profile, semantic prototype, ATT&CK-position prototype, latest progress/time and mean relevance. This lets M5 ask “which existing attack chain does this event belong to?” instead of only “which historical event is most similar?”.

The resulting flow is:

`15-min M4 local window -> knowledge/progress estimation -> persistent entity retrieval -> learned event-link scoring -> chain-aware assignment -> attack-chain DAG`.

This keeps Transformer context length independent from total campaign duration while retaining interpretable evidence for every long-horizon edge and chain assignment.

## Current status

The repository contains implementation contracts, smoke/unit tests, source-held-out and leakage-audit utilities, release protocol gates, and reduced M3-M6 model components. It does not contain real training data, model checkpoints, final source-domain metrics, or AIT predictions.

The last previously recorded server-wide test result is `34 passed` at commit `f2bb562`. This branch adds new M5 architecture tests for 15-minute windows, learned link scoring, transition compatibility and chain-aware assignment; a fresh server-wide CI result has not yet been recorded here.

The current data fallback route is CERT long-term behavior, EVTX endpoint/entity relationships, CTU-13 network continuity, and Sandworm attack-window validation. LANL is not part of the current training route.

## Protocol boundaries

- AIT is a target evaluation domain, not a training source for P1.
- AIT labels may only be read after predictions are sealed.
- A locked release requires real checkpoints, thresholds, calibration and model hashes.
- Generated data, virtual environments, logs and temporary outputs are intentionally excluded.

See `docs/v3_compliance_audit.md`, `docs/data_deviation_v3.md`, and `outputs/audit/` for the strict audit status.
