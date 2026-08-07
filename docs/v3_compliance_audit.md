# V3 Compliance Audit

Audit sources: `1.txt` and `跨域语义图APT检测_完整Codex执行报告_V3.txt`.

Audit commit: pending (strict execution round)  
Test command: `.venv/bin/python -m pytest -q`  
Result: `97 passed, 4 warnings` (`87` unit, `10` integration).

## Current truth

This change completes the requested code contracts, module boundaries, strict protocol interfaces, and synthetic tests. It does **not** complete real training, real checkpoint production, source-domain metrics, or AIT evaluation. No fake checkpoint, metric, prediction, or AIT result was generated.

`current_protocol=P1-S-reduced-development`  
`complete_v3=false`  
`real_training_completed=false`  
`real_checkpoints_available=false`  
`locked_release_available=false`  
`ait_status=TARGET_EVALUATION_PENDING`

## Key implementation changes

- Versioned `RawRecord`, `SyntaxParse`, `EventFrame`, `EntityRecord`, `GraphRecord`, and `FrozenFeatureRecord` contracts with provenance and compatibility aliases.
- M0 adapter/parser/cache/quarantine interfaces; parsing failures are explicit and traceable.
- M1 DeBERTa adapter and multitask-head boundary; mock mode is explicit and never claims a loaded model.
- Dataset-scoped M2 IDs, typed normalization, pair resolver, and entity memory.
- Global graph vocabularies and causal history builder ordered by timestamp, source file, source line, and record ID.
- Qwen3 adapter boundary with explicit mock/pretrained/frozen/lora modes and hard load failures.
- M4 multi-scale causal path: M1 event embeddings and Qwen3 5-minute window embeddings are parallel inputs to a current-event-conditioned Q-Former; a masked macro temporal aggregator models 5min-to-30min development without overlap-score summation.
- Strict history construction rejects current, future, out-of-window, and malformed-timestamp records. M3 event nodes preserve M1 semantic embeddings; UTF-8 byte features remain an explicit legacy fallback for unresolved entity/action nodes.
- Frozen M4 outputs now populate the existing semantic, graph, event, raw, micro, and macro fields. M5 receives the M4 event representation for longer-horizon linking and does not repeat M4 aggregation.
- M5 stage boundaries for windows, candidates, evidence, hard negatives, queue management, and exports.
- M6 frozen-feature exporter, feature validation, source-only calibration/threshold interfaces, and M6-only runner.
- Independent stage scripts and target-only AIT adapter/guard/scorer interfaces.
- Directly executable stage scripts with input/output hashes and manifests; missing prerequisites fail explicitly.
- 87 unit and 10 integration tests covering the strict synthetic path and protocol failures.

## Remaining blocked work

Real source data, dependency weights, training batches, source-held-out metrics, calibration/threshold artifacts, real checkpoints, locked release, and post-seal AIT inference/scoring remain blocked until data and model training are intentionally supplied.
