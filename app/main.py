"""FastAPI application entrypoint, security middleware, and lifespan management."""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import (
    ai_analysis,
    analyst,
    evidence,
    fusion,
    health,
    submissions,
    triage,
    whatsapp,
)
from app.core.config import Settings, get_settings
from app.core.database import dispose_engine, get_engine
from app.core.exceptions import build_error_Envelope, register_exception_handlers
from app.core.logging import configure_logging, request_id_ctx_var
from app.models import Base

logger = logging.getLogger("amana_shield.main")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage startup logging and clean database connection pool disposal on shutdown."""
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL)
    logger.info(
        "Starting %s v%s in %s mode",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.APP_ENV,
    )
    if settings.DATABASE_URL.startswith("sqlite"):
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Local SQLite database schema initialized successfully")
    yield
    logger.info("Shutting down %s and disposing database connections", settings.APP_NAME)
    await dispose_engine()


def create_app(settings_override: Settings | None = None) -> FastAPI:
    """Application factory creating the configured FastAPI modular monolith."""
    settings = settings_override or get_settings()
    configure_logging(settings.LOG_LEVEL)

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "AMANA SHIELD — AI-powered electoral and government scam detection "
            "and protection system for AI4Elections 2026."
        ),
        docs_url=f"{settings.API_V1_PREFIX}/docs",
        redoc_url=f"{settings.API_V1_PREFIX}/redoc",
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_and_correlation_middleware(
        request: Request, call_next
    ) -> Response:
        """Assign request correlation ID, enforce max body size, and set security headers."""
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_ctx_var.set(req_id)
        try:
            content_length = request.headers.get("content-length")
            if content_length and content_length.isdigit():
                if int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content=build_error_Envelope(
                            code="PAYLOAD_TOO_LARGE",
                            message=(
                                f"Request payload exceeds maximum allowed size of "
                                f"{settings.MAX_REQUEST_BODY_BYTES} bytes."
                            ),
                        ),
                    )

            response: Response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
            return response
        finally:
            request_id_ctx_var.reset(token)

    register_exception_handlers(app)

    app.include_router(health.router, prefix=settings.API_V1_PREFIX)
    app.include_router(submissions.router, prefix=settings.API_V1_PREFIX)
    app.include_router(triage.router, prefix=settings.API_V1_PREFIX)
    app.include_router(ai_analysis.router, prefix=settings.API_V1_PREFIX)
    app.include_router(evidence.router, prefix=settings.API_V1_PREFIX)
    app.include_router(fusion.router, prefix=settings.API_V1_PREFIX)
    app.include_router(whatsapp.router, prefix=settings.API_V1_PREFIX)
    app.include_router(analyst.router, prefix=settings.API_V1_PREFIX)

    # Static UI serving for Public Verification and Analyst Workspace
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/", include_in_schema=False, response_class=FileResponse)
        async def serve_public_portal() -> FileResponse:
            return FileResponse(static_dir / "index.html")

        @app.get("/analyst", include_in_schema=False, response_class=FileResponse)
        async def serve_analyst_dashboard() -> FileResponse:
            return FileResponse(static_dir / "analyst.html")

    return app


app = create_app()
