# stop.ps1

Write-Host "Stopping Pentest Framework..." -ForegroundColor Red

# Stop persistent services
docker compose -f pentester/docker-compose.yml down
docker compose -f target/docker-compose.yml down
docker compose -f infrastructure/docker-compose.yml down

# Stop and clean up one-shot images if running
docker compose -f browser-recon/docker-compose.yml down 2>$null | Out-Null
docker compose -f http-probe/docker-compose.yml down 2>$null | Out-Null

Write-Host "✅ All services stopped."