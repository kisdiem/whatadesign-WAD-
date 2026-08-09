#!/usr/bin/env bash
set -euo pipefail

# Resumable, source-only M4 V2 execution.  Qwen cache entries are append-only
# by window_id, so rerunning this script resumes an interrupted materializer.
ROOT="${ROOT:-/root/semantic-graph-apt}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-/root/autodl-tmp/semantic-graph-apt-artifacts}"
V1_CACHE="$ARTIFACT_ROOT/qwen_m4_cache/expanded_balanced_v1/merged"
V2_ROOT="$ARTIFACT_ROOT/qwen_m4_cache/expanded_balanced_v2"
NEW_CACHE="$V2_ROOT/new_train_20"
TRAIN_ROOT="$ARTIFACT_ROOT/m4_training/expanded_balanced_v2"
MODEL="${QWEN_MODEL:-/root/autodl-tmp/semantic-graph-apt/model_cache/m4}"
CTU_STRUCTURED="$ROOT/outputs/deberta_security_formal_v2/source_ctu13_eventframes_structured_utc.jsonl"
SANDWORM_STRUCTURED="$ROOT/outputs/deberta_security_formal_v2/source_sandworm_eventframes_structured_utc.jsonl"
CTU_EMBEDDED="$ROOT/outputs/deberta_security_formal_v2/source_ctu13_eventframes_structured_embedded.jsonl"
SANDWORM_EMBEDDED="$ROOT/outputs/deberta_security_formal_v2/source_sandworm_eventframes_structured_embedded.jsonl"

cd "$ROOT"
mkdir -p "$NEW_CACHE" "$V2_ROOT/merged" "$TRAIN_ROOT/run_contrastive_v2"

.venv/bin/python scripts/materialize_qwen_window_cache.py \
  --targets "$TRAIN_ROOT/new_train_targets_20.jsonl" \
  --source "$CTU_STRUCTURED" --source "$SANDWORM_STRUCTURED" \
  --output "$NEW_CACHE/exact_current.jsonl" \
  --mapping-output "$NEW_CACHE/exact_current_mapping.jsonl" \
  --model "$MODEL" --device cuda --max-tokens 2048 --chunk-batch-size 8 \
  --alignment current --member-provenance reconstruct

# Keep only cache/mapping entries required by the current V2 selection.  The
# old V1 cache has extra targets after the V2 split changed; they must not be
# used accidentally by the new run.
ROOT="$ROOT" ARTIFACT_ROOT="$ARTIFACT_ROOT" .venv/bin/python - <<'PY'
import json
import os
from pathlib import Path

artifacts = Path(os.environ["ARTIFACT_ROOT"])
train = artifacts / "m4_training" / "expanded_balanced_v2"
v1 = artifacts / "qwen_m4_cache" / "expanded_balanced_v1" / "merged"
new = artifacts / "qwen_m4_cache" / "expanded_balanced_v2" / "new_train_20"
merged = artifacts / "qwen_m4_cache" / "expanded_balanced_v2" / "merged"
selected = {(row["dataset_id"], row["record_id"]) for row in map(json.loads, train.joinpath("targets.jsonl").read_text().splitlines()) if row}

def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]

windows = {}
for path in (v1 / "exact_current.jsonl", new / "exact_current.jsonl"):
    for row in rows(path):
        windows[row["window_id"]] = row
mappings = {}
for path in (v1 / "exact_current_mapping.jsonl", new / "exact_current_mapping.jsonl"):
    for row in rows(path):
        key = (row["dataset_id"], row["record_id"])
        if key in selected:
            mappings[key] = row
if set(mappings) != selected:
    raise SystemExit(f"incomplete V2 mapping: missing={len(selected - set(mappings))}")
needed = {window_id for row in mappings.values() for window_id in row["window_ids"]}
if needed - set(windows):
    raise SystemExit(f"incomplete V2 cache: missing={len(needed - set(windows))}")
merged.mkdir(parents=True, exist_ok=True)
(merged / "exact_current.jsonl").write_text("".join(json.dumps(windows[item], ensure_ascii=True) + "\n" for item in sorted(needed)))
(merged / "exact_current_mapping.jsonl").write_text("".join(json.dumps(mappings[item], ensure_ascii=True) + "\n" for item in sorted(mappings)))
print(json.dumps({"status": "V2_CACHE_READY", "targets": len(selected), "windows": len(needed)}))
PY

.venv/bin/python scripts/train_m4_source_supervised.py \
  --targets "$TRAIN_ROOT/targets.jsonl" --labels "$TRAIN_ROOT/labels_loss_only.jsonl" \
  --events "$CTU_EMBEDDED" --events "$SANDWORM_EMBEDDED" \
  --qwen-model "$MODEL" \
  --qwen-cache "$V2_ROOT/merged/exact_current.jsonl" \
  --qwen-cache-mapping "$V2_ROOT/merged/exact_current_mapping.jsonl" \
  --output-dir "$TRAIN_ROOT/run_contrastive_v2" \
  --epochs 20 --early-stopping-patience 4 --learning-rate 0.0001 \
  --contrastive-weight 0.10 --contrastive-temperature 0.20 --device cuda
