#!/usr/bin/env bash
set -euo pipefail

echo "=== FortiGate Agent Container Smoke Test ==="

# Ensure environment file exists or create a test one
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
  fi
fi

echo "[1/5] Building container image..."
docker compose build app

echo "[2/5] Starting services via docker compose..."
docker compose up -d

echo "[3/5] Waiting for service readiness..."
READY=0
for i in $(seq 1 30); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health/ready || echo "000")
  if [ "$STATUS" = "200" ]; then
    READY=1
    echo "Service reported healthy (HTTP ${STATUS})!"
    break
  fi
  sleep 1
done

if [ "$READY" -ne 1 ]; then
  echo "ERROR: Service failed to report ready on /health/ready within 30s"
  docker compose logs app
  docker compose down
  exit 1
fi

echo "[4/5] Verifying database schema migrations..."
MIGRATION_CHECK=$(docker compose exec -T postgres psql -U "${POSTGRES_USER:-forti_intel}" -d "${POSTGRES_DB:-forti_intelligence}" -t -A -c "SELECT version FROM schema_migrations ORDER BY applied_at ASC;" 2>/dev/null || echo "NONE")
echo "Applied migrations:"
echo "${MIGRATION_CHECK}"

if ! echo "${MIGRATION_CHECK}" | grep -q "006_agent_audit"; then
  echo "ERROR: 006_agent_audit migration missing from schema_migrations"
  docker compose down
  exit 1
fi

echo "[5/5] Testing graceful SIGTERM shutdown (exit code 0 within 10s)..."
docker compose stop -t 10 app
CONTAINER_ID=$(docker compose ps -q app)
EXIT_CODE=$(docker inspect --format='{{.State.ExitCode}}' "${CONTAINER_ID}")
echo "Container stop exit code: ${EXIT_CODE}"

docker compose down

if [ "${EXIT_CODE}" -ne 0 ]; then
  echo "ERROR: Container exited with non-zero exit code: ${EXIT_CODE}"
  exit 1
fi

echo "=== Container Smoke Test PASSED ==="
