#!/usr/bin/env python3
"""Database Pre-flight Connectivity Checker.

Polls the configured database until it responds successfully to a SELECT 1 query
or until max timeout is reached. Used by container entrypoint before executing
Alembic migrations.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings
from app.core.database import dispose_engine, get_db_session, verify_database_connectivity

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("wait_for_db")


async def wait_for_database(max_attempts: int = 30, interval_seconds: float = 1.5) -> bool:
    """Poll database connectivity with exponential backoff up to max_attempts."""
    settings = get_settings()
    # Mask password for safe logging
    db_url_masked = settings.DATABASE_URL
    if "@" in db_url_masked and "://" in db_url_masked:
        scheme_user, host_db = db_url_masked.split("@", 1)
        scheme = scheme_user.split("://")[0]
        db_url_masked = f"{scheme}://***:***@{host_db}"

    logger.info("Checking database connectivity to %s...", db_url_masked)

    for attempt in range(1, max_attempts + 1):
        try:
            async for session in get_db_session():
                is_connected, detail = await verify_database_connectivity(session)
                if is_connected:
                    logger.info("Database is READY and accepting queries (attempt %d/%d).", attempt, max_attempts)
                    await dispose_engine()
                    return True
                else:
                    logger.warning("Database responded with status '%s' (attempt %d/%d). Retrying...", detail, attempt, max_attempts)
        except Exception as exc:
            logger.warning(
                "Database not ready yet (attempt %d/%d): %s. Waiting %.1fs...",
                attempt,
                max_attempts,
                exc.__class__.__name__,
                interval_seconds,
            )

        await asyncio.sleep(interval_seconds)

    logger.error("Database connection FAILED after %d attempts. Exiting.", max_attempts)
    await dispose_engine()
    return False


def main() -> None:
    success = asyncio.run(wait_for_database())
    if not success:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
