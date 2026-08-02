# Pull the Ollama model used by Sentinel AI agents / action recommender.
# Run from repo root or infra/:  powershell -File infra/setup_ollama.ps1

$ErrorActionPreference = "Stop"
$Model = if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "llama3.2:3b" }
$InfraDir = $PSScriptRoot

Write-Host "==> Starting Ollama container..."
Push-Location $InfraDir
try {
    docker compose up -d ollama
    Write-Host "==> Pulling model: $Model (this can take several minutes)"
    docker compose exec ollama ollama pull $Model
    Write-Host "==> Installed models:"
    docker compose exec ollama ollama list
    Write-Host "==> Smoke test (one short generation)..."
    docker compose exec ollama ollama run $Model "Reply with the single word: pong"
    Write-Host "==> Done. Compose services should use OLLAMA_URL=http://ollama:11434"
} finally {
    Pop-Location
}
