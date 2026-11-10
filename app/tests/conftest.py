"""Pytest fixtures for isolated async database sessions and HTTP test client."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.main import create_app
from app.models import Base


@pytest.fixture
def test_settings() -> Settings:
    """Return isolated test settings."""
    return Settings(
        APP_NAME="AMANA SHIELD TEST",
        APP_ENV="testing",
        APP_DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        MAX_REQUEST_BODY_BYTES=8192,
    )


@pytest.fixture
async def db_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Create an isolated in-memory async database engine with foreign keys enforced."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession bound to the isolated test engine."""
    session_maker = async_sessionmaker(
        bind=db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with session_maker() as session:
        yield session


@pytest.fixture
async def async_client(
    test_settings: Settings,
    db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:
    """Yield an HTTPX AsyncClient wired to the FastAPI app with overridden DB session."""
    app = create_app(settings_override=test_settings)

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db_session] = _override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
