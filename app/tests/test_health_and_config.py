"""Tests for application entrypoint, health check, OpenAPI docs, and security middleware."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.core.logging import redact_sensitive_text


@pytest.mark.asyncio
async def test_health_check_endpoint_returns_healthy(async_client: AsyncClient) -> None:
    """GET /api/v1/health must return 200 OK, database connected, and security headers."""
    response = await async_client.get(
        "/api/v1/health",
        headers={"X-Request-ID": "test-corr-id-001"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["environment"] == "testing"
    assert response.headers["X-Request-ID"] == "test-corr-id-001"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


@pytest.mark.asyncio
async def test_openapi_documentation_endpoints_available(
    async_client: AsyncClient,
) -> None:
    """OpenAPI schema and Swagger UI endpoints must be served under /api/v1."""
    openapi_resp = await async_client.get("/api/v1/openapi.json")
    assert openapi_resp.status_code == 200
    schema = openapi_resp.json()
    assert "/api/v1/health" in schema["paths"]
    assert "/api/v1/submissions" in schema["paths"]

    docs_resp = await async_client.get("/api/v1/docs")
    assert docs_resp.status_code == 200


@pytest.mark.asyncio
async def test_payload_too_large_rejected_by_middleware(
    async_client: AsyncClient,
) -> None:
    """Requests exceeding MAX_REQUEST_BODY_BYTES must be rejected with HTTP 413."""
    oversized_body = "A" * 9000  # test_settings sets MAX_REQUEST_BODY_BYTES = 8192
    response = await async_client.post(
        "/api/v1/submissions",
        content=oversized_body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    body = response.json()
    assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_production_settings_reject_placeholder_secrets() -> None:
    """Settings validator must block placeholder secrets or debug mode in production."""
    with pytest.raises(ValidationError):
        Settings(
            APP_ENV="production",
            APP_DEBUG=False,
            DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/amana",
            SECRET_KEY=SecretStr("CHANGE_ME_PLACEHOLDER_SECRET_KEY_VALUE_12345"),
        )


def test_logging_redacts_nigerian_phone_numbers_and_bearer_tokens() -> None:
    """Log redaction helper must scrub Nigerian mobile numbers and Bearer tokens."""
    raw_log = "Incoming message from +2348031234567 and 08098765432 with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    redacted = redact_sensitive_text(raw_log)
    assert "+2348031234567" not in redacted
    assert "08098765432" not in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "[REDACTED_TOKEN]" in redacted
