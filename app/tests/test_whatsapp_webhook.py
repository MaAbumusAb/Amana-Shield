"""Comprehensive automated tests for Meta WhatsApp Cloud API integration."""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.integrations.whatsapp_client import WhatsAppApiError, WhatsAppCloudApiClient
from app.models.entities import (
    ClaimVerificationStatus,
    ConfidenceLevel,
    InternalStatus,
    MessageRisk,
    PublicVerdict,
    UrlRisk,
)
from app.schemas.fusion import (
    LocalizedExplanation,
    RiskFusionEvaluation,
    SupportedLanguage,
)
from app.services.whatsapp_formatter import (
    format_unsupported_media_reply,
    format_whatsapp_reply,
)


def _compute_meta_signature(raw_body: bytes, secret: str) -> str:
    """Helper to compute valid Meta X-Hub-Signature-256 header value."""
    digest = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


# =========================================================================
# 1. Webhook GET Verification Tests
# =========================================================================

@pytest.mark.asyncio
async def test_webhook_get_verification_success(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify Meta challenge echo when verify token is valid."""
    verify_token = test_settings.WHATSAPP_VERIFY_TOKEN.get_secret_value()
    response = await async_client.get(
        "/api/v1/webhooks/whatsapp",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": verify_token,
            "hub.challenge": "1158201444",
        },
    )
    assert response.status_code == 200
    assert response.text == "1158201444"


@pytest.mark.asyncio
async def test_webhook_get_verification_invalid_token(
    async_client: AsyncClient,
) -> None:
    """Reject verification if token does not match."""
    response = await async_client.get(
        "/api/v1/webhooks/whatsapp",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "wrong-token",
            "hub.challenge": "1158201444",
        },
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_webhook_get_verification_invalid_mode(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Reject verification if mode is not subscribe."""
    verify_token = test_settings.WHATSAPP_VERIFY_TOKEN.get_secret_value()
    response = await async_client.get(
        "/api/v1/webhooks/whatsapp",
        params={
            "hub.mode": "publish",
            "hub.verify_token": verify_token,
            "hub.challenge": "1158201444",
        },
    )
    assert response.status_code == 403


# =========================================================================
# 2. Webhook POST Signature Security Tests
# =========================================================================

@pytest.mark.asyncio
async def test_webhook_post_missing_signature_rejected(
    async_client: AsyncClient,
) -> None:
    """Reject POST request if X-Hub-Signature-256 header is missing."""
    payload = {"object": "whatsapp_business_account", "entry": []}
    response = await async_client.post(
        "/api/v1/webhooks/whatsapp",
        json=payload,
    )
    assert response.status_code == 403
    assert "Invalid webhook signature" in response.text


@pytest.mark.asyncio
async def test_webhook_post_invalid_signature_rejected(
    async_client: AsyncClient,
) -> None:
    """Reject POST request if signature header does not match HMAC."""
    payload = {"object": "whatsapp_business_account", "entry": []}
    headers = {"X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000"}
    response = await async_client.post(
        "/api/v1/webhooks/whatsapp",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 403


# =========================================================================
# 3. Webhook POST Incoming Message & Idempotency Tests
# =========================================================================

@pytest.mark.asyncio
async def test_webhook_post_valid_incoming_text_message(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify incoming text message is triaged, evaluated, persisted, and replied to."""
    app_secret = test_settings.WHATSAPP_APP_SECRET.get_secret_value()
    wamid = "wamid.HBgLMjM0ODAxMjM0NTY3OAAA"
    sender_phone = "2348012345678"

    payload_dict = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "2348000000000",
                                "phone_number_id": "100000000000",
                            },
                            "contacts": [{"wa_id": sender_phone}],
                            "messages": [
                                {
                                    "from": sender_phone,
                                    "id": wamid,
                                    "timestamp": "1710000000",
                                    "type": "text",
                                    "text": {
                                        "body": "Federal Government grants 50,000 to all citizens! Check https://inecnigeria.gov.ng"
                                    },
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    raw_body = json.dumps(payload_dict).encode("utf-8")
    sig = _compute_meta_signature(raw_body, app_secret)

    with patch.object(
        WhatsAppCloudApiClient,
        "send_text_message",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = {"messages": [{"id": "wamid.OUTBOUND_123"}]}

        response = await async_client.post(
            "/api/v1/webhooks/whatsapp",
            content=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": sig,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["processed"] == 1

        mock_send.assert_awaited_once()
        call_args = mock_send.await_args
        assert call_args.kwargs["to_phone"] == sender_phone
        reply_body = call_args.kwargs["message_body"]
        assert "AMANA SHIELD" in reply_body


@pytest.mark.asyncio
async def test_webhook_post_duplicate_wamid_is_idempotent(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify replaying the same wamid is ignored without sending redundant replies."""
    app_secret = test_settings.WHATSAPP_APP_SECRET.get_secret_value()
    wamid = "wamid.HBgLMjM0ODAxMjM0NTY3OUJCOQAA"
    sender_phone = "2348098765432"

    payload_dict = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [
                                {
                                    "from": sender_phone,
                                    "id": wamid,
                                    "timestamp": "1710000000",
                                    "type": "text",
                                    "text": {"body": "Test duplicate message verification"},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    raw_body = json.dumps(payload_dict).encode("utf-8")
    sig = _compute_meta_signature(raw_body, app_secret)

    with patch.object(
        WhatsAppCloudApiClient,
        "send_text_message",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = {"messages": [{"id": "wamid.OUTBOUND_1"}]}

        # First delivery: should process
        resp1 = await async_client.post(
            "/api/v1/webhooks/whatsapp",
            content=raw_body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
        )
        assert resp1.status_code == 200
        assert resp1.json()["processed"] == 1
        assert mock_send.await_count == 1

        # Second delivery (replay with same wamid): must be skipped idempotently
        resp2 = await async_client.post(
            "/api/v1/webhooks/whatsapp",
            content=raw_body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
        )
        assert resp2.status_code == 200
        assert resp2.json()["processed"] == 0
        # No extra outbound reply dispatched
        assert mock_send.await_count == 1


# =========================================================================
# 4. Webhook POST Media & Delivery Edge Cases
# =========================================================================

@pytest.mark.asyncio
async def test_webhook_post_unsupported_media_message(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify unsupported media messages (e.g. image) receive copy-paste guidance."""
    app_secret = test_settings.WHATSAPP_APP_SECRET.get_secret_value()
    wamid = "wamid.HBgLMjM0ODAxMjM0NTY3ME1FREIA"
    sender_phone = "2348055555555"

    payload_dict = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [
                                {
                                    "from": sender_phone,
                                    "id": wamid,
                                    "timestamp": "1710000000",
                                    "type": "image",
                                    "image": {"id": "12345678", "mime_type": "image/jpeg"},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    raw_body = json.dumps(payload_dict).encode("utf-8")
    sig = _compute_meta_signature(raw_body, app_secret)

    with patch.object(
        WhatsAppCloudApiClient,
        "send_text_message",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = {"messages": [{"id": "wamid.OUTBOUND_MEDIA"}]}

        response = await async_client.post(
            "/api/v1/webhooks/whatsapp",
            content=raw_body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
        )

        assert response.status_code == 200
        assert response.json()["processed"] == 1
        mock_send.assert_awaited_once()
        sent_body = mock_send.await_args.kwargs["message_body"]
        assert "analyses *text messages and website links*" in sent_body
        assert "rubutun sako da adireshin yanar gizo" in sent_body


@pytest.mark.asyncio
async def test_webhook_post_status_update_ignored_gracefully(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify receipt status events (delivered, read) return 200 without creating submissions."""
    app_secret = test_settings.WHATSAPP_APP_SECRET.get_secret_value()

    payload_dict = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "statuses": [
                                {
                                    "id": "wamid.HBgLSTATUS123",
                                    "status": "delivered",
                                    "timestamp": "1710000005",
                                    "recipient_id": "2348012345678",
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    raw_body = json.dumps(payload_dict).encode("utf-8")
    sig = _compute_meta_signature(raw_body, app_secret)

    response = await async_client.post(
        "/api/v1/webhooks/whatsapp",
        content=raw_body,
        headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
    )
    assert response.status_code == 200
    assert response.json()["processed"] == 0


@pytest.mark.asyncio
async def test_webhook_post_delivery_failure_resilience(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify outbound delivery failure is logged and webhook returns 200 to prevent retry storms."""
    app_secret = test_settings.WHATSAPP_APP_SECRET.get_secret_value()
    wamid = "wamid.HBgLFAIL123"
    sender_phone = "2348099999999"

    payload_dict = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [
                                {
                                    "from": sender_phone,
                                    "id": wamid,
                                    "timestamp": "1710000000",
                                    "type": "text",
                                    "text": {"body": "Check this out"},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    raw_body = json.dumps(payload_dict).encode("utf-8")
    sig = _compute_meta_signature(raw_body, app_secret)

    with patch.object(
        WhatsAppCloudApiClient,
        "send_text_message",
        side_effect=WhatsAppApiError("Meta Graph API internal error", status_code=500),
    ):
        response = await async_client.post(
            "/api/v1/webhooks/whatsapp",
            content=raw_body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
        )
        # Must still return 200 OK so Meta doesn't enter infinite retry loops
        assert response.status_code == 200


# =========================================================================
# 5. Outbound WhatsApp Client Unit Tests
# =========================================================================

@pytest.mark.asyncio
async def test_whatsapp_cloud_api_client_success(test_settings: Settings) -> None:
    """Test successful outbound message transmission via MockTransport."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert "Bearer " in request.headers.get("Authorization", "")
        body = json.loads(request.content)
        assert body["messaging_product"] == "whatsapp"
        assert body["to"] == "2348012345678"
        return httpx.Response(
            status_code=200,
            json={"messages": [{"id": "wamid.OUTBOUND_TEST"}]},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = WhatsAppCloudApiClient(settings=test_settings, http_client=http_client)
        resp = await client.send_text_message(
            to_phone="+2348012345678",
            message_body="Test message from AMANA SHIELD",
        )
        assert resp["messages"][0]["id"] == "wamid.OUTBOUND_TEST"


@pytest.mark.asyncio
async def test_whatsapp_cloud_api_client_retry_and_succeed(test_settings: Settings) -> None:
    """Test transient 500 error triggers retry and succeeds on 2nd attempt."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(status_code=500, json={"error": "transient failure"})
        return httpx.Response(status_code=200, json={"messages": [{"id": "wamid.RETRY_OK"}]})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = WhatsAppCloudApiClient(settings=test_settings, http_client=http_client)
        resp = await client.send_text_message(
            to_phone="2348012345678",
            message_body="Test retry message",
        )
        assert calls == 2
        assert resp["messages"][0]["id"] == "wamid.RETRY_OK"


@pytest.mark.asyncio
async def test_whatsapp_cloud_api_client_permanent_failure(test_settings: Settings) -> None:
    """Test permanent 400 error raises WhatsAppApiError immediately."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=400,
            json={"error": {"message": "Invalid recipient phone number"}},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = WhatsAppCloudApiClient(settings=test_settings, http_client=http_client)
        with pytest.raises(WhatsAppApiError) as exc_info:
            await client.send_text_message(
                to_phone="1234",
                message_body="Test invalid phone",
            )
        assert exc_info.value.status_code == 400


# =========================================================================
# 6. Response Formatter Tests
# =========================================================================

def test_whatsapp_formatter_malicious_output() -> None:
    """Verify malicious evaluation formatting matches user guidelines."""
    from datetime import datetime, timezone

    eval_obj = RiskFusionEvaluation(
        message_risk=MessageRisk.CRITICAL,
        url_risk=UrlRisk.MALICIOUS,
        claim_verification_status=ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL,
        verdict=PublicVerdict.MALICIOUS,
        review_status=InternalStatus.CONFIRMED,
        reasons=["Confirmed phishing domain", "Requests BVN and OTP"],
        primary_explanation=LocalizedExplanation(
            language=SupportedLanguage.ENGLISH,
            verdict_badge="🚨 DANGER",
            summary="This message is a confirmed scam imitating an official government agency.",
            reasons=["Confirmed phishing domain", "Requests sensitive personal credentials"],
            recommended_action="Do not open the link. Do not submit your personal details.",
            evidence_points=["Official INEC warning published on official portal"],
        ),
        recommended_action="Do not open the link. Do not submit your personal details.",
        assessment_timestamp=datetime.now(timezone.utc),
    )

    formatted = format_whatsapp_reply(eval_obj)
    assert "🚨 *DANGER: MALICIOUS CONTENT DETECTED*" in formatted
    assert "*TARIHI: BABBAN HADARI*" in formatted
    assert "Confirmed phishing domain" in formatted
    assert "Official INEC warning" in formatted
    assert "🛡️ *Recommended Action" in formatted
    assert "AMANA SHIELD" in formatted


def test_unsupported_media_formatter_output() -> None:
    """Verify unsupported media reply gives clear English and Hausa advice."""
    msg = format_unsupported_media_reply()
    assert "*text messages and website links*" in msg
    assert "*rubutun sako da adireshin yanar gizo*" in msg
    assert "copy and paste" in msg
