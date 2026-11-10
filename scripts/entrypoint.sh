#!/usr/bin/env bash
set -e

echo "=============================================================================="
echo "          AMANA SHIELD — Container Startup & Deployment Initialisation         "
echo "=============================================================================="

# 1. Wait for PostgreSQL readiness
echo "[1/4] Verifying database connectivity..."
python scripts/wait_for_db.py

# 2. Apply database migrations
echo "[2/4] Applying database schema migrations (Alembic)..."
alembic upgrade head

# 3. Seed initial curated registry data if empty
echo "[3/4] Ensuring curated domain registries and evidence sources are seeded..."
python scripts/seed_initial_data.py

# 4. Start Uvicorn ASGI server
PORT="${PORT:-8000}"
WORKERS="${UVICORN_WORKERS:-2}"
echo "[4/4] Starting FastAPI production server on 0.0.0.0:${PORT} (${WORKERS} worker(s))..."

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "${PORT}" \
    --workers "${WORKERS}" \
    --proxy-headers \
    --forwarded-allow-ips="*" \
    --no-server-header \
    --timeout-keep-alive 65
