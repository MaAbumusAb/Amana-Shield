"""Tests for submission intake, validation, URL extraction, and idempotency."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_and_retrieve_submission(async_client: AsyncClient) -> None:
    """POST /api/v1/submissions normalises text, extracts defanged URLs, and creates baseline assessment."""
    payload = {
        "channel": "WHATSAPP",
        "external_message_id": "wamid.HBgLMjM0FoundationTest01",
        "sender_identifier": "+2348030001111",
        "raw_text": "URGENT\u200b: Claim N50,000 INEC voter grant at hxxps://inec-gov-empowerment[.]com.ng/verify now!",
    }
    create_resp = await async_client.post("/api/v1/submissions", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()

    assert created["external_message_id"] == "wamid.HBgLMjM0FoundationTest01"
    assert "\u200b" not in created["normalised_text"]
    assert created["extracted_urls"] == ["https://inec-gov-empowerment.com.ng/verify"]
    assert created["assessment"]["public_verdict"] == "SUSPICIOUS"
    assert created["assessment"]["internal_status"] == "UNDER_REVIEW"
    assert created["assessment"]["url_risk"] == "SUSPICIOUS"
    assert "TR-INSTITUTIONAL-LOOKALIKE-DOMAIN" in created["assessment"]["triggered_rules"]

    # Fetch by ID
    sub_id = created["id"]
    get_resp = await async_client.get(f"/api/v1/submissions/{sub_id}")
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert fetched["id"] == sub_id
    assert fetched["content_sha256"] == created["content_sha256"]


@pytest.mark.asyncio
async def test_duplicate_external_message_id_returns_409_conflict(
    async_client: AsyncClient,
) -> None:
    """Replaying the same external_message_id must return HTTP 409 DUPLICATE_SUBMISSION."""
    payload = {
        "channel": "WHATSAPP",
        "external_message_id": "wamid.HBgLMjM0ReplayLock99",
        "sender_identifier": "+2348030002222",
        "raw_text": "Check official portal https://inecnigeria.org",
    }
    first_resp = await async_client.post("/api/v1/submissions", json=payload)
    assert first_resp.status_code == 201

    second_resp = await async_client.post("/api/v1/submissions", json=payload)
    assert second_resp.status_code == 409
    err = second_resp.json()
    assert err["error"]["code"] == "DUPLICATE_SUBMISSION"


@pytest.mark.asyncio
async def test_invalid_submission_payload_returns_422_validation_error(
    async_client: AsyncClient,
) -> None:
    """Blank raw_text or unknown extra fields must be rejected with HTTP 422."""
    bad_payload = {
        "channel": "WEB",
        "external_message_id": "web-msg-001",
        "sender_identifier": "user-123",
        "raw_text": "   ",
        "unexpected_field": "malicious_injection",
    }
    resp = await async_client.post("/api/v1/submissions", json=bad_payload)
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_get_nonexistent_submission_returns_404(
    async_client: AsyncClient,
) -> None:
    """Requesting an unknown submission UUID must return HTTP 404 RESOURCE_NOT_FOUND."""
    random_id = uuid.uuid4()
    resp = await async_client.get(f"/api/v1/submissions/{random_id}")
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["code"] == "RESOURCE_NOT_FOUND"
