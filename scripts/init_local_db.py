#!/usr/bin/env python3
"""Local Database Bootstrapper.

Creates tables and seeds curated initial official domains, evidence debunking records,
and threat indicators into the local database (SQLite or PostgreSQL).
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
from app.core.database import dispose_engine, get_engine
from app.models import Base
from scripts.seed_initial_data import seed_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("init_local_db")


async def init_and_seed() -> None:
    settings = get_settings()
    logger.info("Initializing database schema for: %s", settings.DATABASE_URL)

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database schema initialized. Now seeding initial curated data...")
    await seed_database()
    logger.info("Local database bootstrap COMPLETE! You can now run the app.")


if __name__ == "__main__":
    asyncio.run(init_and_seed())
