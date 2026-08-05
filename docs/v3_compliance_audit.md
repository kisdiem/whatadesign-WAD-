# V3 Compliance Audit

Audit source: `C:\Users\sixth\Desktop\跨域语义图APT检测_完整Codex执行报告_V3.txt`  
Audit instruction: `C:\Users\sixth\Desktop\1.txt`  
Commit: `5219dee`  
Command: `.venv/bin/python -m pytest -q`  
Result: `26 passed, 3 warnings`

## Executive finding

The repository contains contract-level M0-M6 modules, source splitting, leakage checks, data adapters, a generic M4-M6 runner, and a partially strengthened M0 parser with masking/fingerprint/cache primitives. It does not contain the original V3 trained system, real M0-M6 checkpoints, source-domain metrics, AIT predictions, locked release gates, baseline results or ablations.

The detailed ten-field evidence for every required item is in `outputs/audit/v3_compliance_matrix.json`. The implementation inventory is in `outputs/audit/implementation_inventory.json`.

## Status summary

| Area | Status |
|---|---|
| M0 | PARTIAL |
| M1 | DEVIATED |
| M2 | PARTIAL |
| Graph construction | PARTIAL |
| M3 graph training | INTERFACE_ONLY |
| M4 | DEVIATED |
| M5 | PARTIAL |
| M6 | PARTIAL |
| Data | DEVIATED |
| source-held-out | IMPLEMENTED_AND_TESTED |
| leakage | PARTIAL |
| threshold/calibration | MISSING |
| locked release | PARTIAL |
| AIT P1 | BLOCKED_BY_DATA |
| baselines | MISSING |
| ablations | MISSING |
| metrics | MISSING |
| unit tests | IMPLEMENTED_NOT_TESTED |
| integration tests | MISSING |
| output files | PARTIAL |
| raw evidence traceability | PARTIAL |

## Evidence limits

- No real checkpoint files were found.
- No train, validation or test metric files were found.
- No AIT data or labels were accessed; `run_state/completed_steps.json` records `ait_accessed=false`.
- Existing strict/enhanced manifests are not locked releases.
- The 26 passing tests are contract/smoke tests, not the required 80-unit/10-integration V3 suite.

The current project report must therefore say: “核心模块接口和 smoke/contract 测试已建立；真实 M0-M6 训练、锁定发布和 AIT 评估尚未完成。”
