"""Pydantic v2 schemas for the AMANA SHIELD Analyst Dashboard."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.entities import (
    ClaimVerificationStatus,
    DomainClassification,
    IndicatorStatus,
    IndicatorType,
    InternalStatus,
    MessageRisk,
    PublicVerdict,
    SubmissionChannel,
    UrlRisk,
)


class AnalystOverviewMetrics(BaseModel):
    """High-level metrics for the analyst dashboard overview."""

    model_config = ConfigDict(extra="forbid")

    total_submissions: int
    malicious_count: int
    suspicious_count: int
    official_count: int
    unverified_count: int
    under_review_count: int
    confirmed_count: int
    dismissed_count: int
    active_campaigns_count: int
    malicious_domains_count: int
    channel_breakdown: dict[str, int]


class AnalystSubmissionListItem(BaseModel):
    """Compact summary of a submission for analyst queues."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    id: uuid.UUID
    channel: str
    external_message_id: str
    submitted_at: datetime
    raw_text_preview: str
    extracted_urls: list[str] = Field(default_factory=list)
    public_verdict: Optional[str] = None
    internal_status: Optional[str] = None
    message_risk: Optional[str] = None
    url_risk: Optional[str] = None
    claim_verification_status: Optional[str] = None


class AnalystSubmissionDetail(BaseModel):
    """Exhaustive submission details for analyst investigation."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    id: uuid.UUID
    channel: str
    external_message_id: str
    submitted_at: datetime
    raw_text: str
    normalised_text: str
    content_sha256: str
    extracted_urls: list[str] = Field(default_factory=list)
    processing_status: str

    # Assessment details
    assessment_id: Optional[uuid.UUID] = None
    public_verdict: Optional[str] = None
    internal_status: Optional[str] = None
    message_risk: Optional[str] = None
    url_risk: Optional[str] = None
    claim_verification_status: Optional[str] = None
    explanation_text: Optional[str] = None
    recommended_action: Optional[str] = None
    triggered_rules: list[str] = Field(default_factory=list)
    triage_findings: dict[str, Any] = Field(default_factory=dict)
    ai_heuristics: dict[str, Any] = Field(default_factory=dict)
    assessed_at: Optional[datetime] = None
    is_degraded_mode: bool = False

    # Linked claims
    extracted_claims: list[dict[str, Any]] = Field(default_factory=list)


class AnalystReviewActionRequest(BaseModel):
    """Analyst review and correction action payload."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: InternalStatus = Field(
        description="Target status: CONFIRMED, DISMISSED, or UNDER_REVIEW"
    )
    reviewer_notes: Optional[str] = Field(
        default=None, max_length=1000, description="Audit note describing review justification"
    )


class AnalystDomainClassificationRequest(BaseModel):
    """Analyst action to update a domain's classification."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    classification: DomainClassification
    official_institution: Optional[str] = Field(default=None, max_length=64)
    reason: Optional[str] = Field(default=None, max_length=512)


class AnalystThreatIndicatorCreateRequest(BaseModel):
    """Analyst action to create or confirm a threat indicator."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    indicator_type: IndicatorType
    indicator_value: str = Field(min_length=2, max_length=2048)
    threat_category: str = Field(min_length=2, max_length=64)
    status: IndicatorStatus = IndicatorStatus.CONFIRMED
    reason: Optional[str] = Field(default=None, max_length=512)
