# run.ps1
# Run from the microservices/ directory:  .\run.ps1

param(
    [switch]$SkipBuild  # pass -SkipBuild to skip image rebuilds (faster restart)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Step($n, $total, $msg) {
    Write-Host "`n[$n/$total] $msg" -ForegroundColor Cyan
}
function Ok($msg)   { Write-Host "  OK  $msg" -ForegroundColor Green  }
function Err($msg)  { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

Write-Host "Starting Pentest Framework..." -ForegroundColor Green

# ── Network ───────────────────────────────────────────────────────────────────
Write-Host "`nEnsuring pentest-net exists..."
docker network inspect pentest-net 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    docker network create pentest-net
    if ($LASTEXITCODE -ne 0) { Err "Failed to create pentest-net" }
    Ok "Network pentest-net created"
} else {
    Ok "Network pentest-net already exists"
}

# ── 1. Infrastructure — pgvector + MLflow (persistent) ───────────────────────
Step 1 5 "Infrastructure (pgvector + MLflow)"
if ($SkipBuild) {
    docker compose -f infrastructure/docker-compose.yml up -d
} else {
    docker compose -f infrastructure/docker-compose.yml up -d --build
}
if ($LASTEXITCODE -ne 0) { Err "Infrastructure failed to start" }
Ok "pgvector  -> localhost:6000"
Ok "MLflow    -> http://localhost:5000"

# ── 2. Target applications — DVWA, Juice Shop, WebGoat (persistent) ──────────
Step 2 5 "Target applications (DVWA / Juice Shop / WebGoat)"
if ($SkipBuild) {
    docker compose -f target/docker-compose.yml up -d
} else {
    docker compose -f target/docker-compose.yml up -d --build
}
if ($LASTEXITCODE -ne 0) { Err "Target failed to start" }
Ok "DVWA       -> http://localhost:8081"
Ok "Juice Shop -> http://localhost:8082"
Ok "WebGoat    -> http://localhost:8083"

# ── 3. Pentester toolbox (persistent, exec'd into by plan_agent) ──────────────
Step 3 5 "Pentester toolbox"
if ($SkipBuild) {
    docker compose -f pentester/docker-compose.yml up -d
} else {
    docker compose -f pentester/docker-compose.yml up -d --build
}
if ($LASTEXITCODE -ne 0) { Err "Pentester failed to start" }
Ok "pentest-tools container running on pentest-net"

# ── 4. Browser Recon image (one-shot — only built here, not started) ──────────
Step 4 5 "Browser Recon image (build only)"
docker compose -f browser-recon/docker-compose.yml build
if ($LASTEXITCODE -ne 0) { Err "Browser Recon image build failed" }
Ok "browser-recon:latest ready"

# ── 5. HTTP Probe image (one-shot — only built here, not started) ─────────────
Step 5 5 "HTTP Probe image (build only)"
docker compose -f http-probe/docker-compose.yml build
if ($LASTEXITCODE -ne 0) { Err "HTTP Probe image build failed" }
Ok "http-probe:latest ready"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "All services ready." -ForegroundColor Green
Write-Host ""
Write-Host "Persistent services:" -ForegroundColor Yellow
Write-Host "  pgvector         localhost:6000"
Write-Host "  MLflow           http://localhost:5000"
Write-Host "  DVWA             http://localhost:8081"
Write-Host "  Juice Shop       http://localhost:8082"
Write-Host "  WebGoat          http://localhost:8083"
Write-Host "  pentest-tools    (exec target on pentest-net)"
Write-Host ""
Write-Host "One-shot images (launched by the pipeline per task):" -ForegroundColor Yellow
Write-Host "  browser-recon:latest   (Browser Recon phase)"
Write-Host "  http-probe:latest      (Browser Probe phase)"
Write-Host ""
Write-Host "Next step: cd .. && python -m uvicorn server.main:app --reload" -ForegroundColor Cyan
