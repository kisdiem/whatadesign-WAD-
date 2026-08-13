# V3 Deviation Request: P1-S-reduced / V3-fallback

## Reason

The original V3 specification requires Splunk Attack Data, OTRF Security-Datasets, LANL and DARPA Transparent Computing for different module roles. At the audit commit `ba814236102f02dde4d4fc7d0182e33033a7ac09`, Splunk, OTRF, LANL and DARPA are unavailable. AIT is a target test dataset and has not been accessed.

## Current fallback

- LogHub-2.0 and HDFS/BGL: template, sequence and baseline development.
- OCSF schema: taxonomy reference.
- EVTX ATTACK SAMPLES: Windows semantic/entity source.
- Sandworm flow CSV: external network-window validation only.
- CTU-13: planned network continuity source; download is incomplete.
- CERT: planned long-term behavior source; official download is blocked.

## Compensated capability

- EVTX provides Windows event/entity structure.
- CTU-13 can provide network-flow continuity after verified download.
- CERT can provide long-horizon synthetic user behavior if obtained from the official source.
- Sandworm provides a separate labeled attack-window check.

## Uncompensated capability

- LANL unified enterprise auth/process/DNS/flow identity space.
- DARPA Transparent Computing provenance graph semantics and attack timelines.
- Original Splunk/OTRF semantic coverage.
- Full V3 M3/M5 source-domain training evidence.

## Impact

M1, M3, M4 and M5 cannot be reported as full original V3 implementations. Any result must be labeled `P1-S-reduced` or `V3-fallback`. AIT P1 remains `TARGET_EVALUATION_PENDING` until a locked release and verified AIT input exist.

## Approval required

This deviation must be accepted before using fallback data for a final paper-style claim. It does not authorize AIT label use in training or threshold selection.
