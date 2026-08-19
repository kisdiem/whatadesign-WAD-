# Cross-Domain Semantic Graph APT Detection V3

This repository contains the current code architecture for a multi-source APT/log detection system.

## Pipeline

`M0` parsing -> `M1` single-event semantic normalization -> `M2` entity resolution -> `M3` causal 30-minute event graph -> `M4` multi-scale current-event-conditioned anomaly detection -> `M5` long-horizon linking -> `M6` frozen-feature hierarchical fusion.

### M4 temporal boundary

M4 performs `single-event -> 5min -> 30min`, while M5 performs only
cross-30-minute/hour-level linking. For a current event at `t`, M3 and M4
accept only history satisfying `t-30min <= event_time < t` and exclude the
current record ID. The default 5-minute micro windows stride by 2.5 minutes;
a complete 30-minute history produces 11 windows, but the count is calculated
from configuration and partial history yields fewer complete windows.

Each micro window combines parallel inputs: M1/DeBERTa EventFrame semantic
embeddings for individual events, and a Qwen3 embedding of time-ordered,
normalized EventFrame fields. The current event conditions Q-Former query
tokens before cross-attention. A masked temporal transformer then aggregates
micro-context embeddings without summing overlapping window scores. Qwen
serialization excludes labels, split information, ground truth, and post-hoc
results by construction.

### M4 training contract

M4 is trained as a source-only current-event anomaly head. The training runner
receives strict causal M4 batches built from frozen M1 EventFrame embeddings,
M3 graph context, and either the frozen Qwen window representation or an
exact, hash-keyed Qwen cache. The Qwen backbone is not updated by the M4 head.
Labels are read only at loss time and are never serialized into EventFrame,
graph, Qwen, or frozen-feature inputs.

The supervised objective is binary anomaly loss on `score_logit`. When source
triplets are available, an InfoNCE relation term is added between source-fact
positive and negative events; pair construction uses factual EventFrame
relations and preserves the causal time boundary. The validation split is
time/source held out and selects the checkpoint by validation loss and its
validation-fitted threshold. Held-out test data is scored only after checkpoint
selection. AIT remains target-only for the strict V3 release path; any
AIT-supervised run is a separately named upper-bound experiment and must not be
reported as zero-shot cross-domain performance.

The formal entry point is `scripts/train_m4_source_supervised.py`. It writes
the selected checkpoint, validation threshold, split manifest, loss history,
and provenance report. A smoke test or cache test is an interface check only,
not a claim of real M4 training quality.

## Storage architecture

Formal storage uses **PostgreSQL as the system of record**. The former SQLite
`FeatureRepository` prototype is retired. PostgreSQL stores normalized events,
dynamically updated entity state plus append-only entity observations,
event/entity and explicit event/event relations, model-versioned detection
results, attack chains, and audit/provenance metadata.

Raw logs, large embedding batches, tensors, checkpoints, and model weights stay
as immutable file artifacts. PostgreSQL references them through URI, SHA-256,
size, schema version, and lineage instead of duplicating large payloads in the
database.

Core business tables:

- `entities`
- `entity_aliases`
- `entity_observations`
- `events`
- `event_entities`
- `event_relations`
- `context_windows`
- `window_events`
- `detection_results`
- `window_detection_results`
- `window_links`
- `attack_chains`
- `attack_chain_windows`
- `attack_chain_events`

Engineering audit tables:

- `pipeline_runs`
- `artifacts`
- `lineage`
- `operation_logs`
- `schema_migrations`

There is intentionally no generic `stage_records(payload_json)` fact table in
the formal schema. See `docs/storage_architecture.md` and
`migrations/postgres/`.

## Current status

The repository contains implementation contracts, smoke/unit tests, source-held-out and leakage-audit utilities, release protocol gates, and reduced M3-M6 model components. It does not contain real training data, model checkpoints, final source-domain metrics, or AIT predictions.

The latest verified server test result is `34 passed` with commit `f2bb562`.

The current data fallback route is CERT long-term behavior, EVTX endpoint/entity relationships, CTU-13 network continuity, and Sandworm attack-window validation. LANL is not part of the current training route.

## Protocol boundaries

- AIT is a target evaluation domain, not a training source for P1.
- AIT labels may only be read after predictions are sealed.
- A locked release requires real checkpoints, thresholds, calibration and model hashes.
- Generated data, virtual environments, logs and temporary outputs are intentionally excluded.
- Security business tables reject label/split fields and keep source-training labels outside model-queryable facts.

See `docs/v3_compliance_audit.md`, `docs/data_deviation_v3.md`, `docs/storage_architecture.md`, and `outputs/audit/` for the strict audit status.
