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
