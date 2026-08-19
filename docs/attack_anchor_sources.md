# ATT&CK Anchor Sources

This project uses event-level ATT&CK supervision only when a source event and
an auditable rule or source annotation directly support the technique.  The
anchor is stored separately from `EventFrame`; training labels are passed only
to the adapter loss and never to M1, M3, M4, M5, or target evaluation features.

## Current sources

| Source | What is used | What is not inferred |
| --- | --- | --- |
| EVTX-ATTACK-SAMPLES | Raw EVTX records satisfying a named content rule | Technique from a directory or file name |
| Existing source rules | High-confidence source-rule matches with rule provenance | AIT target labels or test split fields |
| MITRE ATT&CK STIX | Technique-card descriptions for contrastive text/label representations | An event-level observation |

## Detection scope

The training objective is not complete ATT&CK coverage.  It is coverage of
behavior that can be evidenced by logs from the defended environment.  The
authoritative scope is `configs/data/log_observable_attack_scope.json`.

Resource development is excluded because it normally occurs before an actor
interacts with the defended environment.  Reconnaissance is only included when
boundary DNS, proxy, firewall, or web-access logs are actually present.  C2,
exfiltration, collection, impact, and initial access require their matching
network, web, identity, file, or cloud telemetry; endpoint EVTX alone cannot
label them honestly.

## Selected external supplement

Splunk Attack Data is the next external log source.  It provides curated raw
attack logs under ATT&CK technique directories and metadata describing the
recording environment.  It must be fetched selectively, split by source
scenario/file before training, and ingested only after its log format and
per-event applicability are audited.  Directory-level technique metadata is
provenance, not a feature supplied to a model.

`configs/data/splunk_attack_anchor_subset.json` selects a deliberately small
cross-tactic subset.  `scripts/fetch_splunk_attack_data_subset.py` downloads
only metadata by default, writes a SHA-256 manifest, preserves failed-download
records, and refuses to ingest Git LFS pointers as if they were raw logs.

Atomic Red Team is not ingested as a raw-log corpus.  Its technique-specific
test procedures may enrich the technique-card text and rule review checklist,
but test commands are not fabricated telemetry.

## Quality gates

1. Preserve raw record reference, parser version, rule/source annotation, and
   stable record ID for every anchor.
2. Exclude ambiguous generic activity, such as ordinary PowerShell, DNS, or
   logon events.  Explicit command-interpreter and discovery commands may be
   retained at a lower confidence only when the command itself identifies the
   ATT&CK technique.
3. Group train/validation/test splits by source scenario or source file to
   prevent near-duplicate records crossing splits.
4. Keep AIT target data out of anchor construction and adapter source training.
