#!/usr/bin/env bash
set -euo pipefail
ROOT="${ROOT:-/root/semantic-graph-apt}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-/root/autodl-tmp/semantic-graph-apt-artifacts}"
V2="$ARTIFACT_ROOT/qwen_m4_cache/expanded_balanced_v2/merged"
V3="$ARTIFACT_ROOT/qwen_m4_cache/expanded_balanced_v3_plus100"
TRAIN="$ARTIFACT_ROOT/m4_training/expanded_balanced_v3_plus100"
MODEL="${QWEN_MODEL:-/root/autodl-tmp/semantic-graph-apt/model_cache/m4}"
cd "$ROOT"
ARTIFACT_ROOT="$ARTIFACT_ROOT" .venv/bin/python - <<'PY'
import json, os
from pathlib import Path
root=Path(os.environ['ARTIFACT_ROOT'])
train=root/'m4_training'/'expanded_balanced_v3_plus100'
v2=root/'qwen_m4_cache'/'expanded_balanced_v2'/'merged'
new=root/'qwen_m4_cache'/'expanded_balanced_v3_plus100'/'new_100'
out=root/'qwen_m4_cache'/'expanded_balanced_v3_plus100'/'merged'
def rows(path): return [json.loads(x) for x in path.read_text().splitlines() if x]
selected={(x['dataset_id'],x['record_id']) for x in rows(train/'targets.jsonl')}
windows={}; mappings={}
for base in (v2,new):
    for row in rows(base/'exact_current.jsonl'): windows[row['window_id']]=row
    for row in rows(base/'exact_current_mapping.jsonl'):
        key=(row['dataset_id'],row['record_id'])
        if key in selected: mappings[key]=row
if set(mappings)!=selected: raise SystemExit(f'mapping incomplete: {len(selected-set(mappings))}')
needed={wid for row in mappings.values() for wid in row['window_ids']}
if needed-set(windows): raise SystemExit(f'cache incomplete: {len(needed-set(windows))}')
out.mkdir(parents=True,exist_ok=True)
(out/'exact_current.jsonl').write_text(''.join(json.dumps(windows[x])+'\n' for x in sorted(needed)))
(out/'exact_current_mapping.jsonl').write_text(''.join(json.dumps(mappings[x])+'\n' for x in sorted(mappings)))
print(json.dumps({'status':'V3_CACHE_READY','targets':len(selected),'windows':len(needed)}))
PY
.venv/bin/python scripts/train_m4_source_supervised.py \
 --targets "$TRAIN/targets.jsonl" --labels "$TRAIN/labels_loss_only.jsonl" \
 --events "$ROOT/outputs/deberta_security_formal_v2/source_ctu13_eventframes_structured_embedded.jsonl" \
 --events "$ROOT/outputs/deberta_security_formal_v2/source_sandworm_eventframes_structured_embedded.jsonl" \
 --qwen-model "$MODEL" --qwen-cache "$V3/merged/exact_current.jsonl" --qwen-cache-mapping "$V3/merged/exact_current_mapping.jsonl" \
 --output-dir "$TRAIN/run_contrastive_v3" --epochs 20 --early-stopping-patience 4 \
 --learning-rate 0.0001 --contrastive-weight 0.10 --contrastive-temperature 0.20 --device cuda
