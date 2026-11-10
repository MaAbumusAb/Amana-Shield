#!/usr/bin/env bash
# ==============================================================================
# AMANA SHIELD — Automated Database Backup Script
# Creates a compressed, timestamped pg_dump of the PostgreSQL database,
# verifies backup integrity, locks permissions to 0600, and prunes old archives.
# Recommended cron schedule: Run daily at 02:00 UTC
#   0 2 * * * /path/to/AI4Election/scripts/backup_db.sh >> /var/log/amana_backup.log 2>&1
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

BACKUP_DIR="${BACKUP_DIR:-${PROJECT_ROOT}/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%S")"
BACKUP_FILE="${BACKUP_DIR}/amana_shield_backup_${TIMESTAMP}.sql.gz"

# Source environment variables if .env exists
if [ -f .env ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' .env | xargs -0) 2>/dev/null || true
fi

DB_USER="${POSTGRES_USER:-amana_user}"
DB_NAME="${POSTGRES_DB:-amana_shield}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Starting database backup for '${DB_NAME}'..."

# Dump PostgreSQL via Docker Compose container
if docker compose ps db >/dev/null 2>&1; then
    docker compose exec -T db pg_dump -U "$DB_USER" -d "$DB_NAME" \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges | gzip -9 > "$BACKUP_FILE"
else
    echo "ERROR: 'db' container is not running under Docker Compose. Aborting." >&2
    exit 1
fi

# Verify non-empty backup file
if [ -s "$BACKUP_FILE" ]; then
    BACKUP_SIZE="$(du -h "$BACKUP_FILE" | cut -f1)"
    chmod 600 "$BACKUP_FILE"
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] SUCCESS: Backup created: ${BACKUP_FILE} (${BACKUP_SIZE})"
else
    echo "ERROR: Backup file ${BACKUP_FILE} is empty or failed to write!" >&2
    rm -f "$BACKUP_FILE"
    exit 1
fi

# Retention pruning: Remove backups older than RETENTION_DAYS
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Pruning backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -type f -name "amana_shield_backup_*.sql.gz" -mtime +"$RETENTION_DAYS" -print -delete

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Backup maintenance cycle complete."
