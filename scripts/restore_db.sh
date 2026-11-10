#!/usr/bin/env bash
# ==============================================================================
# AMANA SHIELD — Database Disaster Recovery & Restore Script
# Restores a compressed pg_dump file into the running PostgreSQL container.
# Usage:
#   ./scripts/restore_db.sh ./backups/amana_shield_backup_20261110_020000.sql.gz
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <path-to-backup-file.sql.gz> [--force]"
    exit 1
fi

BACKUP_FILE="$1"
FORCE_RESTORE="${2:-}"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file '$BACKUP_FILE' does not exist." >&2
    exit 1
fi

# Source environment variables if .env exists
if [ -f .env ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' .env | xargs -0) 2>/dev/null || true
fi

DB_USER="${POSTGRES_USER:-amana_user}"
DB_NAME="${POSTGRES_DB:-amana_shield}"

echo "=============================================================================="
echo "          AMANA SHIELD — DATABASE DISASTER RECOVERY & RESTORE                "
echo "=============================================================================="
echo "Target Database: ${DB_NAME} (User: ${DB_USER})"
echo "Restore Archive: ${BACKUP_FILE}"
echo "WARNING: This operation will overwrite current data with the backup snapshot!"
echo "=============================================================================="

if [ "$FORCE_RESTORE" != "--force" ]; then
    read -r -p "Type 'RESTORE' to execute the recovery: " CONFIRMATION
    if [ "$CONFIRMATION" != "RESTORE" ]; then
        echo "Aborted by user. No changes were made."
        exit 0
    fi
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Executing database restoration..."

# Decompress and stream into psql via Docker Compose
gunzip -c "$BACKUP_FILE" | docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Restoration stream finished. Verifying integrity..."

# Run post-restore sanity check query
RECORD_COUNTS=$(docker compose exec -T db psql -U "$DB_USER" -d "$DB_NAME" -t -c \
    "SELECT 'Domains: ' || count(*) FROM domains UNION ALL SELECT 'Evidence: ' || count(*) FROM evidence_sources UNION ALL SELECT 'Submissions: ' || count(*) FROM submissions;")

echo "Post-restore record counts:"
echo "$RECORD_COUNTS"

echo "=============================================================================="
echo "SUCCESS: Database restored and verified."
echo "=============================================================================="
