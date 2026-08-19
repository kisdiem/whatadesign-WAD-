#!/usr/bin/env bash
set -e
time /root/miniconda3/bin/python3.12 /root/autodl-tmp/kairos_work/kairos/DARPA/CADETS_E3/evaluate_kairos_event_scores.py \
  --events /root/autodl-tmp/wad_transfer_ait/ait_train/fox/outputs/m4_lite_v9/event_frames.jsonl \
  --labels /root/autodl-tmp/wad_transfer_ait/ait_train/fox/outputs/m4_lite_v9/labels_v2/event_labels.jsonl \
  --checkpoint /root/autodl-tmp/kairos_work/ait_full/kairos_ait_model.pt \
  --output /root/autodl-tmp/kairos_work/ait_full/kairos_speed_eval.json
