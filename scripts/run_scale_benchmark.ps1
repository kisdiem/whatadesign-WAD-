$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

python scripts/run_parallel_scale.py `
  --root D:\CODE\santos `
  --root D:\CODE\russellmitchell `
  --root D:\CODE\EVTX-ATTACK-SAMPLES-master `
  --root D:\CODE\ait_ads `
  --output-dir outputs\scale_parallel `
  --workers 4 `
  --max-records-per-worker 200000 `
  --top-k-per-worker 5000 `
  --aggregate-top-k 10000 `
  --sketch-width 65536

python scripts/build_log_index.py `
  --root D:\CODE\santos `
  --root D:\CODE\russellmitchell `
  --root D:\CODE\EVTX-ATTACK-SAMPLES-master `
  --root D:\CODE\ait_ads `
  --database outputs\scale_parallel\all_logs.sqlite `
  --max-records-per-root 200000

Write-Host "Scale report: outputs\scale_parallel\scale_report.json"
Write-Host "Paginated log index: outputs\scale_parallel\all_logs.sqlite"
