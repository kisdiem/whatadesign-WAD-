# PostgreSQL storage refactor

This branch intentionally retires the SQLite `stage_records(payload_json)` prototype.

## Formal database

PostgreSQL is the only formal business database. The schema contains:

- `schema_migrations`
- `pipeline_runs`
- `artifacts`
- `lineage`
- `operation_logs`
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

## Key invariants

- events are immutable facts and use a fact hash to reject same-ID/different-content rewrites;
- entity current state and scoped alias first/last-seen state are updated by UPSERT while observation history is append-only/deduplicated;
- facts and model judgements are separate tables;
- overlapping 5-minute windows are first-class rows with event membership instead of duplicated event records;
- explicit M3 relations, M4 window scores, M5 window links, and M5/M6 attack judgements are separate concepts;
- source labels/split metadata are rejected from business payloads;
- raw logs, large embeddings and checkpoints remain file artifacts referenced by URI + SHA-256;
- schema migrations are versioned and checksum-protected.

## Run

```bash
pip install -r requirements-storage.txt
export DATABASE_URL='postgresql://user:password@host:5432/wad'
python scripts/migrate_postgres.py
python scripts/run_source_v3_with_storage.py --config configs/v3/source_training.yaml --work-dir outputs/source_run
```

PostgreSQL integration tests run only when `TEST_DATABASE_URL` is set.
