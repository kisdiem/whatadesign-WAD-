# V3 Compliance Audit

Audit sources: `1.txt` and `跨域语义图APT检测_完整Codex执行报告_V3.txt`.

Audit commit: `601f374`  
Test command: `.venv/bin/python -m pytest -q`  
Result: `93 passed, 4 warnings` (`83` unit, `10` integration).

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
- M5 stage boundaries for windows, candidates, evidence, hard negatives, queue management, and exports.
- M6 frozen-feature exporter, feature validation, source-only calibration/threshold interfaces, and M6-only runner.
- Independent stage scripts and target-only AIT adapter/guard/scorer interfaces.
- 83 unit and 10 integration tests covering the strict synthetic path and protocol failures.

## Remaining blocked work

Real source data, dependency weights, training batches, source-held-out metrics, calibration/threshold artifacts, real checkpoints, locked release, and post-seal AIT inference/scoring remain blocked until data and model training are intentionally supplied.
