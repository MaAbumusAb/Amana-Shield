"""Pydantic v2 request and response schemas for AMANA SHIELD."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.entities import (
    ClaimVerificationStatus,
    InternalStatus,
    MessageRisk,
    ProcessingStatus,
    PublicVerdict,
    SubmissionChannel,
    UrlRisk,
)


class HealthCheckResponse(BaseModel):
    """Health and readiness probe response schema."""

    status: Literal["healthy", "degraded"]
    service: str
    version: str
    environment: str
    database: Literal["connected", "unreachable", "unexpected_response"]
    timestamp: datetime


class SubmissionCreateRequest(BaseModel):
    """Inbound submission payload for suspicious messages or URLs."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    channel: SubmissionChannel = Field(
        default=SubmissionChannel.WEB,
        description="Submission channel (WHATSAPP, WEB, ANDROID_SHARE)",
    )
    external_message_id: str = Field(
        min_length=4,
        max_length=128,
        description="Idempotency key or WhatsApp wamid to prevent duplicate replay processing",
    )
    sender_identifier: str = Field(
        min_length=2,
        max_length=128,
        description="Raw sender identifier (hashed with server pepper before storage; never stored raw)",
    )
    raw_text: str = Field(
        min_length=1,
        max_length=10000,
        description="Submitted suspicious message or URL text",
    )

    @field_validator("raw_text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("raw_text must contain non-whitespace characters.")
        return value


class AssessmentSummarySchema(BaseModel):
    """Structured risk assessment and deterministic verdict summary."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    message_risk: MessageRisk
    url_risk: UrlRisk
    claim_verification_status: ClaimVerificationStatus
    public_verdict: PublicVerdict
    internal_status: InternalStatus
    triggered_rules: list[str]
    explanation_text: str
    recommended_action: str
    is_degraded_mode: bool
    assessed_at: datetime


class SubmissionResponse(BaseModel):
    """Structured API response for a created or retrieved submission."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    channel: SubmissionChannel
    external_message_id: str
    normalised_text: str
    content_sha256: str
    extracted_urls: list[str]
    processing_status: ProcessingStatus
    submitted_at: datetime
    assessment: AssessmentSummarySchema | None = None


class ErrorDetailSchema(BaseModel):
    """Standardised API error envelope."""

    code: str
    message: str
    request_id: str
    details: Any | None = None


class ErrorEnvelopeResponse(BaseModel):
    """Top-level error response wrapper."""

    error: ErrorDetailSchema
