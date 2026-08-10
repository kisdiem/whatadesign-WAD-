#!/usr/bin/env bash
set -euo pipefail

# This waiter never writes the cache.  It is safe to run while a single Qwen
# materializer owns the append-only cache artifact.
CACHE="${CACHE:-/root/autodl-tmp/semantic-graph-apt-artifacts/qwen_m4_cache/expanded_balanced_v2/new_train_20/exact_current.jsonl}"
EXPECTED_WINDOWS="${EXPECTED_WINDOWS:-220}"
ROOT="${ROOT:-/root/semantic-graph-apt}"

while true; do
  completed="$(wc -l < "$CACHE" 2>/dev/null || printf 0)"
  if [ "$completed" -ge "$EXPECTED_WINDOWS" ]; then
    exec bash "$ROOT/scripts/run_m4_v2_auto.sh"
  fi
  sleep 60
done
