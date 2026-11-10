"""SQLAlchemy 2.x async engine, session factory, and connectivity health check."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings

logger = logging.getLogger("amana_shield.database")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def build_async_engine(settings: Settings | None = None) -> AsyncEngine:
    """Create a configured SQLAlchemy 2.x AsyncEngine."""
    cfg = settings or get_settings()
    url = cfg.DATABASE_URL
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)

    engine_kwargs: dict[str, Any] = {
        "echo": cfg.DB_ECHO,
        "pool_pre_ping": True,
    }

    if url.startswith("sqlite+aiosqlite://"):
        if ":memory:" in url:
            engine_kwargs["poolclass"] = StaticPool
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        engine_kwargs["pool_size"] = cfg.DB_POOL_SIZE
        engine_kwargs["max_overflow"] = cfg.DB_MAX_OVERFLOW

    engine = create_async_engine(url, **engine_kwargs)

    if url.startswith("sqlite+aiosqlite://"):
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_fks(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def get_engine() -> AsyncEngine:
    """Return singleton AsyncEngine, initialising if needed."""
    global _engine
    if _engine is None:
        _engine = build_async_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return singleton async_sessionmaker bound to the application engine."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


def override_database_engine(engine: AsyncEngine) -> None:
    """Override global engine and session factory (used in isolated tests)."""
    global _engine, _session_factory
    _engine = engine
    _session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def dispose_engine() -> None:
    """Cleanly dispose the database connection pool on shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a managed AsyncSession with automatic rollback on error."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def verify_database_connectivity(session: AsyncSession) -> tuple[bool, str]:
    """Execute a lightweight SELECT 1 query to verify live database readiness."""
    try:
        result = await session.execute(text("SELECT 1"))
        val = result.scalar_one_or_none()
        if val == 1:
            return True, "connected"
        return False, "unexpected_response"
    except Exception as exc:
        logger.warning("Database readiness check failed: %s", exc.__class__.__name__)
        return False, "unreachable"
