#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker/docker-compose.test.yml"

cleanup() {
    echo "Tearing down Juice Shop..."
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}

trap cleanup EXIT

echo "Starting Juice Shop..."
docker compose -f "$COMPOSE_FILE" up -d juiceshop

echo "Waiting for Juice Shop to be healthy..."
timeout=120
elapsed=0
until curl -sf http://localhost:3000 > /dev/null 2>&1; do
    if [ "$elapsed" -ge "$timeout" ]; then
        echo "ERROR: Juice Shop did not start within ${timeout}s"
        docker compose -f "$COMPOSE_FILE" logs juiceshop
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
    echo "  Waiting... (${elapsed}s)"
done

echo "Juice Shop is ready on http://localhost:3000"
echo ""
echo "Running integration tests..."
cd "$PROJECT_DIR"
uv run pytest tests/integration/ -m integration -v "$@"

echo ""
echo "Integration tests complete!"
