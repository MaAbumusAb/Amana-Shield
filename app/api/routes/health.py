"""Health and database readiness probe endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db_session, verify_database_connectivity
from app.schemas.common import HealthCheckResponse

router = APIRouter(tags=["System Health"])


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    summary="Application and database health check",
    description=(
        "Verifies application liveness and executes a parameterised connectivity check "
        "against the configured database session."
    ),
)
async def health_check(
    response: Response,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> HealthCheckResponse:
    """Return service health and database connectivity status."""
    db_ok, db_status = await verify_database_connectivity(session)
    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthCheckResponse(
        status="healthy" if db_ok else "degraded",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database=db_status,  # type: ignore[arg-type]
        timestamp=datetime.now(timezone.utc),
    )
