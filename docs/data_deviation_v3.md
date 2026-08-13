# V3 Data Deviation Record

Current protocol remains `P1-S-reduced-development`. This code-only round did not download or read datasets and did not train models.

The planned source route is the replacement combination already agreed for the current project: CERT long-term behavior, existing EVTX entity relations, CTU-13 network continuity, and Sandworm attack-window validation. AIT LDS v2 remains target-only and is excluded from training, threshold selection, calibration, feature selection, model selection, and ablation selection.

LANL is not part of the current training route. Any LANL adapter retained in the repository is historical compatibility code only and must not be interpreted as current training evidence.

No dataset deviation is being silently promoted to a result: the data status remains `BLOCKED_BY_DATA` until manifests, licenses, checksums, source-held-out splits, and real records are supplied.
