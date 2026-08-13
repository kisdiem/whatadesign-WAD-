# V3 Strict Reproduction and Code Refactor Plan

## 0. Scope and non-negotiable rules

This is a separate experiment line. It must not overwrite the existing AIT-GARNET experiment or reuse its trained AIT M6 result as the V3 P1 result.

The V3 claim is only valid when source-domain data trains/fits M0-M6, all source checkpoints are frozen, a locked release is created, and AIT is used only for target inference and post-seal scoring.

Three result tracks remain separate:

- P1: strict zero-shot target inference. No AIT labels before prediction sealing.
- P2: unlabeled target adaptation. Independent checkpoint and independent report.
- P3: AIT supervised upper bound. Never presented as zero-shot.

Every stage must write an input manifest, resolved configuration, output manifest, code version, dependency hash, and operation record. A failed stage cannot be silently skipped.

## 1. Repository and data boundaries

Server code root: `/root/semantic-graph-apt`
Server data root: `/root/autodl-tmp/semantic-graph-apt`
Server persistent release root: `/root/autodl-fs/semantic-graph-apt`

Required directories:

```text
configs/data
configs/taxonomy
configs/model
configs/experiments
data/manifests
data/source_domains
data/target_ait_sealed
data/normalized
data/semantic_frames
data/graphs
data/windows
data/feature_store
src/common
src/registry
src/parsers
src/semantics
src/entity_resolution
src/graph
src/short_term
src/long_horizon
src/fusion
src/calibration
src/target_adapters
src/evaluation
src/reporting
scripts/phase_a_data
scripts/phase_b_parser
scripts/phase_c_semantics
scripts/phase_d_graph
scripts/phase_e_short_term
scripts/phase_f_long_horizon
scripts/phase_g_fusion
scripts/phase_h_release
scripts/phase_i_ait
tests/unit
tests/integration
tests/leakage
tests/fixtures
outputs/source_validation
outputs/locked_release
outputs/ait_p1_zero_shot
outputs/ait_p2_unsupervised_adapt
outputs/ait_p3_supervised_upper
run_state
logs
```

Raw data, normalized data, feature stores, checkpoints, source code and target sealed data must never share one undifferentiated directory.

## 2. Common data contracts

Implement Pydantic schemas before model code:

- `RawRecord`: dataset_id, source_file, source_line, raw_timestamp, raw_payload, parser_version.
- `SyntaxParse`: format, timestamp, host, source, fields, template_id, parse_confidence, raw_record_ref.
- `EventFrame`: actor, action, object, location, outcome, entities, attributes, semantic_confidence, source_record_ref.
- `Entity`: entity_id, entity_type, canonical_value, raw_value, namespace, resolution_confidence.
- `GraphEvent`: event_id, timestamp, nodes, typed_edges, source_record_ref.
- `Window`: window_id, start, end, event_ids, entity_ids, graph_refs, label_source.
- `FeatureRecord`: raw M0-M5 scores, graph scores, long-horizon scores, M6 fields and release_id.

Every output row must retain a source record reference. No parser may silently discard malformed rows; malformed rows go to a quarantine file with reason and checksum.

## 3. Data registry and acquisition

Complete the registry before downloading more data. Each entry must have official URL, version/commit, license, expected files, expected size, checksum, role, allowed label usage and status.

Current known status:

- LogHub-2.0: verified, available for M0 and sequence smoke tests.
- OCSF schema: verified, available for taxonomy.
- HDFS/BGL: available, system anomaly only, not APT labels.
- Splunk Attack Data: unavailable until official selective clone is complete.
- OTRF Security-Datasets: unavailable until official source is verified.
- LANL: unavailable until official files and license are verified.
- DARPA TC: unavailable until official selected files and entity definitions are verified.
- AIT-LDSv2.0 and AIT-ADS: target only, not accessed by V3 before locked release.

Do not mark unavailable data as ready and do not silently substitute mirrors.

## 4. M0 parser and template stage

Implement two baselines and one main path:

1. Raw exact fingerprint baseline.
2. Drain3 baseline with stable masking rules.
3. M0 main parser with explicit constant-token allowlist, variable spans, cache save/load and parser version.

Required tests:

- security constants are not masked;
- allow/deny actions remain distinct;
- success/failure remain distinct;
- PID reuse does not collapse unrelated events;
- cache reload produces identical template IDs;
- held-out source file is not used to fit parser thresholds;
- malformed rows are quarantined, not dropped.

M0 outputs: template catalog, per-row parse output, template metrics, throughput, cache statistics and hashes.

## 5. M1 semantic encoder

The minimal V3 path is a role-aware semantic encoder. It must not be replaced by a single source-family rule dictionary.

Training data:

- OCSF schema and examples;
- selected Splunk/OTRF event metadata when available;
- LANL/DARPA structured fields when available;
- external weak labels plus a manually reviewed queue of 2,000-5,000 records.

Outputs must include actor, action, object, outcome, roles, relation signature, OOD score and semantic confidence.

Baselines: rule-only mapping, nearest prototype embedding, single-label classifier. Main model is evaluated source-held-out before freeze.

## 6. M2 entity resolution

Start with deterministic normalization as a baseline, then add a pair resolver only after source data is available.

Rules:

- host and namespace are part of identity;
- PID reuse must be time-scoped;
- IP is a weak anchor;
- path normalization is idempotent;
- source and destination roles cannot be reversed;
- entity IDs must not contain target-specific labels.

Output entity registry, resolution decisions, confidence, unresolved queue and source-held-out metrics.

## 7. M3 graph encoder

Use the fixed first-version entity-event bipartite graph. Do not silently change to a hypergraph.

Graph windows must preserve event time, source references, typed roles, observed versus inferred edge origin, counts and graph version.

Baselines: observed graph statistics, GraphSAGE reconstruction and HGT only after the baseline is valid. Current 5-minute local windows are a feature, not the full long-horizon chain.

Tests must verify that current events do not enter their own history graph and that aggregation counts are deterministic.

## 8. M4 short-term sequence model

Use HDFS/BGL for general sequence pretraining only. Their anomaly labels are not APT labels.

Implement in this order:

1. Frequency/IDF baseline.
2. Next-event Transformer baseline.
3. Graph/text context baseline.
4. Current-event-conditioned Q-Former + small Decoder.

Use 5-minute micro-windows. Output event NLL, slot NLL, graph reconstruction score and top abnormal slots. Do not use a full-window mean as the only anomaly score.

## 9. M5 long-horizon association

This is required for attacks whose events are separated by hours or days.

Use a persistent campaign state store with:

- stable entities and confidence;
- observed and inferred edges separated;
- ATT&CK stage state;
- first_seen and last_seen;
- evidence references;
- time-decay score;
- queue/campaign ID;
- merge and split decisions.

Use multiple scales:

- local 5-minute event window;
- 30-minute short association;
- macro windows made from six 5-minute slots;
- 1-hour, 6-hour and 24-hour decay for long campaigns.

Never link two events only because they share a weak IP. Require stable-entity evidence plus compatible action/stage progression or multiple independent anchors. Long gaps remain visible in the final chain.

Baselines: time adjacency, any entity overlap, stable-entity overlap. Main M5 is a learned/validated link model only after hard negative pairs are available.

## 10. M6 source-domain fusion head

Freeze M0-M5 before generating source features. Train separate event, window and campaign heads where labels permit.

Baselines: weighted sum, logistic regression, LightGBM. Main hierarchical head must not receive dataset_id or target labels. Calibrate only on source validation data.

Thresholds come from source validation only. Every threshold must include protocol, split, seed and calibration source.

## 11. Source validation and release lock

Before AIT access:

- source-domain holdout passes;
- input/output manifests exist;
- all checkpoint hashes are recorded;
- code commit and dependency lock are recorded;
- leakage tests pass;
- prediction schema is frozen;
- release manifest is signed by hash;
- `RELEASE_LOCKED` marker is created.

No AIT target mount or label path may be used before this gate.

## 12. AIT P1/P2/P3 execution

P1:

1. Mount only sealed target records.
2. Run generic parsers and frozen source checkpoints.
3. Save predictions without labels.
4. Hash and mark predictions sealed.
5. Load labels only for scoring.

P2 runs separately with an independent checkpoint and never changes the P1 result.

P3 may use AIT labels but is reported only as a supervised upper bound.

## 13. Required tests and reports

Minimum gates:

- 80 unit tests;
- 10 integration tests;
- leakage tests for labels, dataset ID, target paths and target-specific constants;
- source-held-out test;
- cache determinism test;
- long-gap chain test;
- malformed input test;
- release manifest test.

Reports must include event, window and campaign metrics; attack recall at fixed alert budget; detection delay; false alerts/hour; graph edge recall; stage order accuracy; throughput; GPU memory; CPU memory; disk footprint; cache hit rate; model calls per million records; and confidence intervals.

## 14. Execution order

```text
A00 environment
A01 registry
A02 taxonomy
B01-B04 M0 and held-out validation
C01-C09 M1 and semantic held-out validation
D01-D06 M2/M3 and graph held-out validation
E01-E06 M4 short-term validation
F01-F04 M5 long-horizon validation
G01-G08 freeze and source-domain M6
H01-H08 locked release and AIT P1
I01-I05 optional P2/P3/ablation/efficiency
```

No phase may be skipped because a later phase appears easier. If a required dataset is unavailable, write a failure report and use only the explicitly approved fallback; do not silently change the scientific claim.
