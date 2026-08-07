CREATE TABLE context_windows (
    window_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    anchor_event_id TEXT REFERENCES events(event_id) ON DELETE CASCADE,
    window_kind TEXT NOT NULL CHECK (window_kind IN ('micro','macro','long_horizon')),
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    stride_seconds INTEGER CHECK (stride_seconds IS NULL OR stride_seconds > 0),
    window_index INTEGER CHECK (window_index IS NULL OR window_index >= 0),
    config_hash TEXT NOT NULL DEFAULT '',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    window_hash TEXT NOT NULL CHECK (length(window_hash) = 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (end_time > start_time),
    UNIQUE (dataset_id, anchor_event_id, window_kind, start_time, end_time)
);

CREATE TABLE window_events (
    window_id TEXT NOT NULL REFERENCES context_windows(window_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (window_id, event_id),
    UNIQUE (window_id, position)
);

CREATE TABLE detection_results (
    detection_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    model_version TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL DEFAULT '',
    producer_run_id TEXT REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    event_score DOUBLE PRECISION,
    final_score DOUBLE PRECISION,
    alert_level TEXT NOT NULL DEFAULT 'unscored' CHECK (alert_level IN (
        'unscored','info','low','medium','high','critical'
    )),
    score_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, model_version, checkpoint_hash)
);

CREATE TABLE window_detection_results (
    window_detection_id TEXT PRIMARY KEY,
    window_id TEXT NOT NULL REFERENCES context_windows(window_id) ON DELETE CASCADE,
    model_version TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL DEFAULT '',
    producer_run_id TEXT REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    raw_score DOUBLE PRECISION,
    calibrated_score DOUBLE PRECISION,
    alert_level TEXT NOT NULL DEFAULT 'unscored' CHECK (alert_level IN (
        'unscored','info','low','medium','high','critical'
    )),
    score_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (window_id, model_version, checkpoint_hash)
);

CREATE TABLE window_links (
    source_window_id TEXT NOT NULL REFERENCES context_windows(window_id) ON DELETE CASCADE,
    target_window_id TEXT NOT NULL REFERENCES context_windows(window_id) ON DELETE CASCADE,
    link_type TEXT NOT NULL DEFAULT 'long_horizon',
    score DOUBLE PRECISION,
    delta_seconds DOUBLE PRECISION CHECK (delta_seconds IS NULL OR delta_seconds >= 0),
    anchor_strength TEXT NOT NULL DEFAULT '',
    anchors JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    producer_run_id TEXT REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source_window_id, target_window_id, link_type),
    CHECK (source_window_id <> target_window_id)
);

CREATE INDEX context_windows_anchor_time_idx ON context_windows(anchor_event_id, start_time, end_time);
CREATE INDEX context_windows_dataset_kind_time_idx ON context_windows(dataset_id, window_kind, start_time);
CREATE INDEX window_events_event_idx ON window_events(event_id, window_id);
CREATE INDEX detection_results_run_idx ON detection_results(producer_run_id);
CREATE INDEX detection_results_event_time_idx ON detection_results(event_id, created_at DESC);
CREATE INDEX detection_results_final_score_idx ON detection_results(final_score DESC);
CREATE INDEX window_detection_results_window_time_idx ON window_detection_results(window_id, created_at DESC);
CREATE INDEX window_detection_results_score_idx ON window_detection_results(calibrated_score DESC);
CREATE INDEX window_links_target_idx ON window_links(target_window_id);
CREATE INDEX window_links_run_idx ON window_links(producer_run_id);
