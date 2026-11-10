"""Meta WhatsApp Cloud API Webhook routes.

Handles:
- GET webhook verification (hub.challenge response)
- POST incoming webhook events with X-Hub-Signature-256 validation
- Duplicate replay prevention (wamid idempotency)
- Unsupported media guidance (no arbitrary binary execution)
- Deterministic and AI scam evaluation pipeline execution
- Automated WhatsApp outbound reply dispatch
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.core.exceptions import DuplicateSubmissionError
from app.integrations.whatsapp_client import WhatsAppCloudApiClient
from app.models.entities import SubmissionChannel
from app.repositories.submissions import SubmissionRepository
from app.schemas.common import SubmissionCreateRequest
from app.schemas.whatsapp import WhatsAppWebhookPayload
from app.services.submission_service import SubmissionService
from app.services.whatsapp_formatter import format_unsupported_media_reply, format_whatsapp_reply

logger = logging.getLogger("amana_shield.api.whatsapp")

router = APIRouter(prefix="/webhooks/whatsapp", tags=["WhatsApp Webhook"])

# In-memory sliding window rate-limiter per sender phone to prevent abuse
# Tracks timestamps of recent submissions per sender
_SENDER_RATE_LIMIT_TIMESTAMPS: dict[str, list[float]] = defaultdict(list)
_MAX_MESSAGES_PER_MINUTE = 15


def _is_rate_limited(sender_phone: str) -> bool:
    """Simple sliding-window rate limit check per sender."""
    now = datetime.now(timezone.utc).timestamp()
    cutoff = now - 60.0
    timestamps = [t for t in _SENDER_RATE_LIMIT_TIMESTAMPS[sender_phone] if t > cutoff]
    if len(timestamps) >= _MAX_MESSAGES_PER_MINUTE:
        _SENDER_RATE_LIMIT_TIMESTAMPS[sender_phone] = timestamps
        return True
    timestamps.append(now)
    _SENDER_RATE_LIMIT_TIMESTAMPS[sender_phone] = timestamps
    return False


def verify_meta_signature(raw_body: bytes, signature_header: Optional[str], app_secret: str) -> bool:
    """Verify X-Hub-Signature-256 header using constant-time HMAC comparison."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    received_sig = signature_header.split("sha256=", 1)[1].strip()
    expected_sig = hmac.new(
        key=app_secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(received_sig, expected_sig)


@router.get(
    "",
    summary="Meta Webhook Verification Endpoint",
    description="Responds to Meta's GET challenge when configuring webhook in the Meta App Dashboard.",
    response_class=PlainTextResponse,
)
async def verify_webhook(
    hub_mode: Optional[str] = Query(None, alias="hub.mode"),
    hub_verify_token: Optional[str] = Query(None, alias="hub.verify_token"),
    hub_challenge: Optional[str] = Query(None, alias="hub.challenge"),
    settings: Settings = Depends(get_settings),
) -> PlainTextResponse:
    """Verify webhook subscription challenge token sent by Meta."""
    expected_token = settings.WHATSAPP_VERIFY_TOKEN.get_secret_value()

    if hub_mode == "subscribe" and hub_verify_token == expected_token:
        logger.info("WhatsApp webhook challenge verified successfully")
        return PlainTextResponse(content=hub_challenge or "", status_code=status.HTTP_200_OK)

    logger.warning("WhatsApp webhook challenge verification failed (invalid token or mode)")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Verification token mismatch or invalid hub mode",
    )


@router.post(
    "",
    summary="Receive WhatsApp Webhook Events",
    description="Receives incoming messages and status events from Meta WhatsApp Cloud API.",
)
async def receive_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Handle incoming WhatsApp webhook payload securely and idempotently."""
    raw_body = await request.body()
    app_secret = settings.WHATSAPP_APP_SECRET.get_secret_value()

    # 1. Enforce Meta HMAC-SHA256 signature validation
    if not verify_meta_signature(raw_body, x_hub_signature_256, app_secret):
        logger.warning("Rejected WhatsApp webhook request: invalid or missing X-Hub-Signature-256")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook signature",
        )

    # 2. Parse payload using Pydantic
    try:
        data = await request.json()
        payload = WhatsAppWebhookPayload.model_validate(data)
    except Exception as exc:
        logger.error("Failed to parse WhatsApp webhook payload: %s", exc)
        # Return 200 to acknowledge Meta to avoid retry storms on malformed payloads
        return {"status": "ignored", "reason": "malformed_json"}

    submission_repo = SubmissionRepository(session)
    submission_service = SubmissionService(session)
    whatsapp_client = WhatsAppCloudApiClient(settings=settings)

    processed_count = 0

    for entry in payload.entry:
        for change in entry.changes:
            value = change.value

            # Acknowledge status receipts (sent, delivered, read) without processing
            if value.statuses:
                logger.debug("Received delivery status update for %d messages", len(value.statuses))
                continue

            if not value.messages:
                continue

            for message in value.messages:
                wamid = message.id
                sender_phone = message.from_

                # 3. Prevent duplicate replay processing (idempotency check)
                existing_submission = await submission_repo.get_by_external_message_id(wamid)
                if existing_submission is not None:
                    logger.info("Duplicate WhatsApp webhook received for wamid=%s. Ignoring.", wamid)
                    continue

                # 4. Check sender rate limiting
                if _is_rate_limited(sender_phone):
                    logger.warning("Rate limit exceeded for sender %s", sender_phone[:4] + "***")
                    continue

                # 5. Handle unsupported media gracefully without downloading untrusted files
                if message.type != "text":
                    logger.info(
                        "Received non-text WhatsApp message (type=%s) for wamid=%s",
                        message.type,
                        wamid,
                    )
                    unsupported_reply = format_unsupported_media_reply()
                    try:
                        await whatsapp_client.send_text_message(
                            to_phone=sender_phone,
                            message_body=unsupported_reply,
                        )
                    except Exception as exc:
                        logger.error("Error sending unsupported media guidance: %s", exc)
                    processed_count += 1
                    continue

                # 6. Process text message
                if not message.text or not message.text.body.strip():
                    logger.warning("Received empty text message body for wamid=%s", wamid)
                    continue

                text_content = message.text.body.strip()

                try:
                    submission = await submission_service.create_submission(
                        SubmissionCreateRequest(
                            channel=SubmissionChannel.WHATSAPP,
                            external_message_id=wamid,
                            sender_identifier=sender_phone,
                            raw_text=text_content,
                        )
                    )

                    # Extract the fusion evaluation attached during creation
                    fusion_eval = getattr(submission, "_fusion_evaluation", None)
                    if fusion_eval is not None:
                        reply_text = format_whatsapp_reply(fusion_eval)
                    else:
                        # Fallback from saved assessment if evaluation attribute is not present
                        from app.models.entities import PublicVerdict
                        from app.schemas.fusion import LocalizedExplanation, RiskFusionEvaluation, SupportedLanguage
                        fallback_eval = RiskFusionEvaluation(
                            submission_id=submission.id,
                            message_risk=submission.assessment.message_risk,
                            url_risk=submission.assessment.url_risk,
                            claim_verification_status=submission.assessment.claim_verification_status,
                            verdict=PublicVerdict(submission.assessment.public_verdict),
                            review_status=submission.assessment.internal_status,
                            triggered_rules=submission.assessment.triggered_rules,
                            reasons=[],
                            recommended_action=submission.assessment.recommended_action,
                            primary_explanation=LocalizedExplanation(
                                language=SupportedLanguage.ENGLISH,
                                verdict_badge=f"[{submission.assessment.public_verdict}]",
                                summary=submission.assessment.explanation_text,
                                recommended_action=submission.assessment.recommended_action,
                            ),
                            assessment_timestamp=submission.assessment.assessed_at,
                        )
                        reply_text = format_whatsapp_reply(fallback_eval)

                    # 7. Dispatch outbound WhatsApp response
                    await whatsapp_client.send_text_message(
                        to_phone=sender_phone,
                        message_body=reply_text,
                    )
                    processed_count += 1

                except DuplicateSubmissionError:
                    logger.info("Duplicate submission detected concurrently for wamid=%s", wamid)
                except Exception as exc:
                    logger.exception("Error processing WhatsApp submission for wamid=%s: %s", wamid, exc)
                    # We still return 200 OK to Meta to avoid infinite retry loops

    return {"status": "ok", "processed": processed_count}
