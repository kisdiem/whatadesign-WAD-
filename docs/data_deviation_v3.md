# V3 Data Deviation Record

| Original source | Status | Current substitute/status | Compensated capability | Uncompensated capability | Impact |
|---|---|---|---|---|---|
| Splunk Attack Data | unavailable | EVTX ATTACK SAMPLES | Windows event semantics | Splunk sourcetype/attack metadata diversity | M1 reduced |
| OTRF Security-Datasets | unavailable | LogHub/EVTX/Sandworm where applicable | Basic event-source coverage | Original OTRF provenance and metadata | M1/M3 reduced |
| LANL Comprehensive | unavailable | CERT planned; LANL adapter only | Long-horizon behavior may be partially covered by CERT | Unified enterprise auth/proc/DNS/flow identity space | M2/M5 reduced |
| DARPA Transparent Computing | unavailable | CTU-13 planned plus EVTX/Sandworm | Network continuity and endpoint events | Provenance graph and DARPA attack timeline semantics | M3/M5 reduced |
| AIT LDS/ADS | not accessed | none; remains target | none yet | Target evaluation unavailable | P1 blocked by data |

The release must be named `P1-S-reduced` or `V3-fallback`, never full V3 source release.
