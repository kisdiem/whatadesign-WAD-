CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pipeline_runs (
    run_id TEXT PRIMARY KEY,
    stage TEXT NOT NULL,
    mode TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    stage TEXT NOT NULL,
    uri TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    bytes BIGINT CHECK (bytes IS NULL OR bytes >= 0),
    schema_version TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (uri, sha256)
);

CREATE TABLE lineage (
    output_kind TEXT NOT NULL,
    output_id TEXT NOT NULL,
    input_kind TEXT NOT NULL,
    input_id TEXT NOT NULL,
    relation TEXT NOT NULL DEFAULT 'derived_from',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (output_kind, output_id, input_kind, input_id, relation)
);

CREATE TABLE operation_logs (
    sequence BIGSERIAL PRIMARY KEY,
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    operation TEXT NOT NULL,
    status TEXT NOT NULL,
    run_id TEXT REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX artifacts_run_stage_idx ON artifacts(run_id, stage);
CREATE INDEX lineage_input_idx ON lineage(input_kind, input_id);
CREATE INDEX operation_logs_run_time_idx ON operation_logs(run_id, timestamp_utc);
