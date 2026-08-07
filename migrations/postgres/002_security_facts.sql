CREATE TABLE entities (
    entity_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK (entity_type IN (
        'user','host','process','ip','file','domain','service','session','container','cloud_resource','unknown'
    )),
    canonical_value TEXT NOT NULL,
    instance_key TEXT NOT NULL DEFAULT '',
    host_scope TEXT NOT NULL DEFAULT '',
    parent_entity_id TEXT REFERENCES entities(entity_id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    current_status TEXT NOT NULL DEFAULT 'observed',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    resolution_method TEXT NOT NULL DEFAULT 'unknown',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (first_seen IS NULL OR last_seen IS NULL OR last_seen >= first_seen),
    UNIQUE (dataset_id, entity_type, canonical_value, instance_key, host_scope)
);

CREATE TABLE entity_aliases (
    alias_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    dataset_id TEXT NOT NULL,
    alias_type TEXT NOT NULL,
    alias_value TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_record_ref TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (first_seen IS NULL OR last_seen IS NULL OR last_seen >= first_seen),
    UNIQUE (entity_id, alias_type, alias_value, scope)
);

CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ,
    record_kind TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    action_family TEXT NOT NULL,
    action_leaf TEXT NOT NULL,
    outcome TEXT NOT NULL,
    roles JSONB NOT NULL DEFAULT '{}'::jsonb,
    key_attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    entity_mentions JSONB NOT NULL DEFAULT '[]'::jsonb,
    semantic_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    unknown_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    source_record_ref TEXT NOT NULL DEFAULT '',
    semantic_version TEXT NOT NULL DEFAULT 'unknown',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    fact_hash TEXT NOT NULL CHECK (length(fact_hash) = 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_entities (
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL REFERENCES entities(entity_id) ON DELETE RESTRICT,
    role TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, entity_id, role)
);

CREATE TABLE entity_observations (
    observation_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    event_id TEXT REFERENCES events(event_id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ,
    attribute_name TEXT NOT NULL,
    observed_value JSONB NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    source_record_ref TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_relations (
    source_event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    target_event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    time_delta_seconds DOUBLE PRECISION,
    graph_id TEXT,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source_event_id, target_event_id, relation_type),
    CHECK (source_event_id <> target_event_id)
);

CREATE INDEX events_dataset_time_idx ON events(dataset_id, timestamp);
CREATE INDEX entities_identity_idx ON entities(dataset_id, entity_type, canonical_value, host_scope);
CREATE INDEX entities_last_seen_idx ON entities(last_seen);
CREATE INDEX entity_aliases_lookup_idx ON entity_aliases(dataset_id, alias_type, alias_value, scope);
CREATE INDEX entity_aliases_entity_time_idx ON entity_aliases(entity_id, last_seen);
CREATE INDEX entity_observations_entity_time_idx ON entity_observations(entity_id, timestamp);
CREATE INDEX event_entities_entity_idx ON event_entities(entity_id, event_id);
CREATE INDEX event_relations_source_idx ON event_relations(source_event_id);
CREATE INDEX event_relations_target_idx ON event_relations(target_event_id);
