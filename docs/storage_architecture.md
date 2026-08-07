# Storage Architecture

## Decision

The formal V3 storage layer uses **PostgreSQL as the system of record**. The earlier SQLite `FeatureRepository` prototype is retired. Raw logs, embedding batches, model checkpoints, tensors, and other large immutable outputs remain in the existing file/ArtifactStore path; PostgreSQL stores their identity, hashes, lineage, queryable security facts, model judgements, and attack-chain membership.

This is deliberately not a polyglot-database design. Neo4j, Redis, Kafka, and ClickHouse are not required for the current system. A graph database may later be introduced as a read-only derived projection if multi-hop graph queries become a measured bottleneck, but PostgreSQL remains authoritative.

## Why PostgreSQL

The system needs to store more than a graph. It has time-ordered security events, evolving entity state, many-to-many event/entity membership, model-versioned anomaly results, attack-chain ordering, transactions, foreign keys, audit records, and JSON-shaped attributes. PostgreSQL supports these requirements in one consistent store while preserving relational integrity.

## Storage boundaries

### File / ArtifactStore

Keep large or immutable payloads outside PostgreSQL:

- raw log files;
- large JSONL/Parquet batches;
- DeBERTa/Qwen embeddings in bulk;
- tensors;
- checkpoints and model weights;
- generated intermediate artifacts.

`artifacts` stores only URI, SHA-256, byte size, schema version, producer run, and metadata.

### PostgreSQL

PostgreSQL contains two conceptual layers.

#### 1. Basic security facts

- `entities`: stable entity identity and latest known state;
- `entity_aliases`: queryable aliases/identifiers (IP, hostname, raw process/file value, etc.) with scoped first/last-seen state;
- `entity_observations`: append-only history of how an entity was observed over time;
- `events`: normalized EventFrame facts;
- `event_entities`: event-to-entity roles;
- `event_relations`: event-to-event causal/temporal/behavioral relations emitted by M3;
- `context_windows`: explicit 5-minute / 30-minute / long-horizon temporal windows;
- `window_events`: event membership inside each window, including overlapping membership.

#### 2. Detection and association results

- `detection_results`: event-level M4/M6 model-versioned anomaly results;
- `window_detection_results`: per-window anomaly results, so overlapping 5-minute windows are not collapsed into one event field;
- `window_links`: M5 long-horizon window-to-window evidence and scores;
- `attack_chains`: M5/M6 candidate/confirmed/dismissed attack processes;
- `attack_chain_windows`: ordered suspicious windows that support an attack chain;
- `attack_chain_events`: ordered event membership and evidence for each attack chain.

Engineering audit/provenance remains separate:

- `pipeline_runs`;
- `artifacts`;
- `lineage`;
- `operation_logs`;
- `schema_migrations`.

There is intentionally **no generic `stage_records(payload_json)` fact table** in the formal design. It would create a second source of truth beside the normalized business tables.

## Dynamic entity updates

`entities`, `entity_aliases`, and `entity_observations` have different semantics:

- `entities` answers **what stable entity the system currently believes exists**;
- `entity_aliases` answers **which observed identifiers currently/previously point to that entity and in which scope**;
- `entity_observations` answers **what evidence changed over time**.

When a new event observes an existing entity, the repository performs an UPSERT:

- `first_seen` can only move earlier;
- `last_seen` can only move later;
- confidence keeps the strongest known value;
- current attributes may be updated;
- an immutable/deduplicated observation row is appended for the new evidence.

This design is important for temporary IPs, host aliases, process instances, banners, and other identifiers whose observed attributes change. Alias lookup is indexed by `(dataset_id, alias_type, alias_value, scope)`. Weak IP identities remain scoped by the existing M2 `dataset_id`, `host_scope`, and `instance_key` logic rather than being merged globally by address text alone. An alias row is an identity clue, not permission to merge two stable entities without M2 evidence.

## Facts vs model judgement

`events` and `entities` are factual records produced by A/M1-M3. M4-M6 may read them but must not rewrite them because an event appears suspicious.

Model output goes only into `detection_results`, `attack_chains`, and `attack_chain_events`.

This preserves the boundary:

```text
A data processing -> facts -> PostgreSQL <- history query <- C detection
                                     ^
                                     |
                         detections / attack chains
```

A can write facts. C can write judgements. C cannot turn a model score into a changed historical fact.

## Event relations vs attack chains

`event_relations` means only that two events are related by a supported relation, such as a causal, shared-entity, or temporal relation.

`context_windows` / `window_events` preserve the actual temporal hierarchy. An event may belong to two adjacent 5-minute windows when the strict M4 stride is 2.5 minutes; the event itself is stored once in `events`, and overlap exists only as membership rows. This prevents accidental duplication of the underlying event.

`window_detection_results` keeps each micro/macro window score separately. It is therefore possible to inspect all 11 complete 5-minute windows inside a full 30-minute context instead of flattening them into a single `micro_window_score` column on the event.

`window_links` stores M5's cross-window link evidence. `attack_chains` means the detection system has judged a set of linked evidence to belong to one suspicious/attack process.

These concepts are intentionally separate. The current `StrictGraphBuilder` mainly emits entity-to-event participation edges; the import bridge therefore persists them as `event_entities` and **does not fabricate event-to-event rows**. `event_relations` should be populated only when M3 emits an explicit event-to-event relation.

## ER diagram

```mermaid
erDiagram
    PIPELINE_RUNS ||--o{ ARTIFACTS : produces
    PIPELINE_RUNS ||--o{ OPERATION_LOGS : records

    ENTITIES ||--o{ ENTITY_ALIASES : has_alias
    ENTITIES ||--o{ ENTITY_OBSERVATIONS : has_history
    EVENTS ||--o{ ENTITY_OBSERVATIONS : observed_in
    EVENTS ||--o{ EVENT_ENTITIES : contains
    ENTITIES ||--o{ EVENT_ENTITIES : participates
    EVENTS ||--o{ EVENT_RELATIONS : source
    EVENTS ||--o{ EVENT_RELATIONS : target

    EVENTS ||--o{ CONTEXT_WINDOWS : anchors
    CONTEXT_WINDOWS ||--o{ WINDOW_EVENTS : contains
    EVENTS ||--o{ WINDOW_EVENTS : participates
    EVENTS ||--o{ DETECTION_RESULTS : evaluated_by
    CONTEXT_WINDOWS ||--o{ WINDOW_DETECTION_RESULTS : evaluated_by
    CONTEXT_WINDOWS ||--o{ WINDOW_LINKS : source
    CONTEXT_WINDOWS ||--o{ WINDOW_LINKS : target
    ATTACK_CHAINS ||--o{ ATTACK_CHAIN_WINDOWS : contains
    CONTEXT_WINDOWS ||--o{ ATTACK_CHAIN_WINDOWS : supports
    ATTACK_CHAINS ||--o{ ATTACK_CHAIN_EVENTS : contains
    EVENTS ||--o{ ATTACK_CHAIN_EVENTS : participates
```

## Stage ownership

| Stage | Writes | Reads |
|---|---|---|
| M1 | `events` | source artifacts |
| M2 | `entities`, `entity_aliases`, `entity_observations`, `event_entities` | `events`, prior entity/alias state |
| M3 | `event_relations` when explicit event-event edges exist | `events`, `event_entities` |
| M4 | `context_windows`, `window_events`, `window_detection_results`, event-level `detection_results` | recent `events`, entity/graph context |
| M5 | `window_links`, `attack_chains`, `attack_chain_windows`, `attack_chain_events` | macro/window detections and event/entity relations |
| M6 | new versioned `detection_results` / `window_detection_results`; may update chain judgement through a new result version | frozen model features and existing evidence |

## Leakage boundary

Business write APIs reject fields named `target_label`, `attack_label`, `anomaly_label`, `ground_truth`, `is_attack`, `malicious`, `split`, or `ait_label`, including nested payloads.

Source training labels and split manifests stay outside model-queryable business tables. AIT labels remain subject to the existing sealed-prediction protocol.

## Migrations

The production schema is versioned under `migrations/postgres/`:

1. `001_core_audit.sql`
2. `002_security_facts.sql`
3. `003_temporal_detection.sql`
4. `004_attack_chains.sql`

The migration runner stores file checksums in `schema_migrations`; editing an already-applied migration is treated as an error.

Apply migrations with:

```bash
export DATABASE_URL='postgresql://user:password@host:5432/wad'
python scripts/migrate_postgres.py
```

Run the source pipeline and persist it in one command with:

```bash
python scripts/run_source_v3_with_storage.py --config configs/v3/source_training.yaml --work-dir outputs/source_run
```

Or persist an already completed work directory with:

```bash
python scripts/persist_source_outputs.py --work-dir outputs/source_run
```

`labels.jsonl` and `splits.json` are deliberately not imported into the security business tables.

## Frontend query mapping

- alert list/detail: `detection_results` / `window_detection_results` + `events` / `context_windows`;
- event timeline: `events` + `event_relations` + `window_events`;
- entity detail/history: `entities` + `entity_aliases` + `entity_observations` + `event_entities`;
- attack chain: `attack_chains` + `attack_chain_windows` + `attack_chain_events` + `context_windows` + `events`;
- graph view: `event_entities`, explicit `event_relations`, and optional window-link overlay from `window_links`;
- raw evidence trace: `events.source_record_ref` -> `artifacts` / file store plus `lineage`.
