CREATE TABLE attack_chains (
    chain_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    risk_score DOUBLE PRECISION,
    status TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate','confirmed','dismissed')),
    model_version TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL DEFAULT '',
    producer_run_id TEXT REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (start_time IS NULL OR end_time IS NULL OR end_time >= start_time)
);

CREATE TABLE attack_chain_windows (
    chain_id TEXT NOT NULL REFERENCES attack_chains(chain_id) ON DELETE CASCADE,
    window_id TEXT NOT NULL REFERENCES context_windows(window_id) ON DELETE CASCADE,
    sequence_no INTEGER NOT NULL CHECK (sequence_no >= 0),
    evidence_score DOUBLE PRECISION,
    relation_reason TEXT NOT NULL DEFAULT '',
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, window_id),
    UNIQUE (chain_id, sequence_no)
);

CREATE TABLE attack_chain_events (
    chain_id TEXT NOT NULL REFERENCES attack_chains(chain_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    sequence_no INTEGER NOT NULL CHECK (sequence_no >= 0),
    evidence_score DOUBLE PRECISION,
    relation_reason TEXT NOT NULL DEFAULT '',
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, event_id),
    UNIQUE (chain_id, sequence_no)
);

CREATE INDEX attack_chains_run_idx ON attack_chains(producer_run_id);
CREATE INDEX attack_chains_time_idx ON attack_chains(start_time, end_time);
CREATE INDEX attack_chain_windows_chain_seq_idx ON attack_chain_windows(chain_id, sequence_no);
CREATE INDEX attack_chain_windows_window_idx ON attack_chain_windows(window_id);
CREATE INDEX attack_chain_events_chain_seq_idx ON attack_chain_events(chain_id, sequence_no);
CREATE INDEX attack_chain_events_event_idx ON attack_chain_events(event_id);
