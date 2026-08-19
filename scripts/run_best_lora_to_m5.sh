#!/usr/bin/env bash
set -euo pipefail
PY=/root/miniconda3/bin/python3.12
ROOT=/root/autodl-tmp/semantic-graph-apt
ART=/root/autodl-tmp/semantic-graph-apt-artifacts/m5_knowledge_progress
INPUT=/root/autodl-tmp/semantic-graph-apt-artifacts/m6_long_horizon/20260814/ait_train_long_horizon
MODEL=$ROOT/model_cache/m1
ADAPTER=$ART/deberta_security_lora_ait_temporal_v1/best_adapter
WORK=$ART/lora_best_m5_pipeline_v1
mkdir -p "$WORK"
echo "START $(date -Is)" >> "$WORK/pipeline.log"
$PY "$ROOT/scripts/regenerate_m1_with_lora.py" --model "$MODEL" --adapter "$ADAPTER" --input-root "$INPUT" --output-root "$WORK/m1_smoke" --smoke >> "$WORK/pipeline.log" 2>&1
test -s "$WORK/m1_smoke/m1_smoke_manifest.json"
$PY "$ROOT/scripts/regenerate_m1_with_lora.py" --model "$MODEL" --adapter "$ADAPTER" --input-root "$INPUT" --output-root "$WORK/m1_lora" >> "$WORK/pipeline.log" 2>&1
test -s "$WORK/m1_lora/m1_manifest.json"
$PY "$ROOT/scripts/train_m5_two_models.py" --events-root "$WORK/m1_lora" --labels /root/autodl-tmp/ait-garnet-demo/data/raw/labels.csv --output-dir "$WORK/m5_smoke" --smoke >> "$WORK/pipeline.log" 2>&1
$PY "$ROOT/scripts/train_m5_two_models.py" --events-root "$WORK/m1_lora" --labels /root/autodl-tmp/ait-garnet-demo/data/raw/labels.csv --output-dir "$WORK/m5_final" --epochs 8 >> "$WORK/pipeline.log" 2>&1
echo "COMPLETED $(date -Is)" >> "$WORK/pipeline.log"
