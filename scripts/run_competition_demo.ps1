$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

python scripts/run_real_detection.py `
  --input data/demo/real_logs.jsonl `
  --output-dir outputs/demo_state

python scripts/evaluate_detection.py `
  --input data/demo/real_logs.jsonl `
  --labels data/demo/evaluation_labels.json `
  --output-dir outputs/evaluation

Write-Host "Artifacts ready. Start API with: uvicorn agent_service.app:app --host 127.0.0.1 --port 8000"
Write-Host "Start UI with: cd frontend; npm install; npm run dev"
