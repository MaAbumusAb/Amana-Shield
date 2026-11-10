"""Pydantic v2 schemas for the AI-Powered Scam Message Analysis Service.

Enforces strict structured output validation on LLM responses and guarantees
that the AI never independently decides the final security verdict.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.entities import ConfidenceLevel, MessageRisk


class ScamPatternCategory(StrEnum):
    """Supported scam pattern categories detected in submitted messages."""

    FAKE_EMPOWERMENT_ANNOUNCEMENT = "FAKE_EMPOWERMENT_ANNOUNCEMENT"
    ELECTORAL_REGISTRATION_IMPERSONATION = "ELECTORAL_REGISTRATION_IMPERSONATION"
    FAKE_PVC_COLLECTION_CLAIM = "FAKE_PVC_COLLECTION_CLAIM"
    FALSE_FINANCIAL_REWARD = "FALSE_FINANCIAL_REWARD"
    ARTIFICIAL_URGENCY = "ARTIFICIAL_URGENCY"
    SENSITIVE_DATA_REQUEST = "SENSITIVE_DATA_REQUEST"
    REGISTRATION_OR_PROCESSING_FEE = "REGISTRATION_OR_PROCESSING_FEE"
    VIRAL_FORWARDING_SOLICITATION = "VIRAL_FORWARDING_SOLICITATION"
    INSTITUTIONAL_IMPERSONATION = "INSTITUTIONAL_IMPERSONATION"
    BEHAVIOURAL_MANIPULATION = "BEHAVIOURAL_MANIPULATION"


class RequestedActionType(StrEnum):
    """High-risk or notable user actions requested by a message."""

    CLICK_LINK = "CLICK_LINK"
    SUBMIT_NIN = "SUBMIT_NIN"
    SUBMIT_BVN = "SUBMIT_BVN"
    SUBMIT_OTP_OR_PIN = "SUBMIT_OTP_OR_PIN"
    SUBMIT_BANK_DETAILS = "SUBMIT_BANK_DETAILS"
    SUBMIT_PVC_OR_VOTER_ID = "SUBMIT_PVC_OR_VOTER_ID"
    PAY_REGISTRATION_OR_PROCESSING_FEE = "PAY_REGISTRATION_OR_PROCESSING_FEE"
    FORWARD_MESSAGE_TO_GROUPS = "FORWARD_MESSAGE_TO_GROUPS"
    CALL_OR_MESSAGE_PHONE_NUMBER = "CALL_OR_MESSAGE_PHONE_NUMBER"
    DIAL_USSD_CODE = "DIAL_USSD_CODE"
    VISIT_PHYSICAL_OFFICE = "VISIT_PHYSICAL_OFFICE"


class ExtractedClaimItem(BaseModel):
    """A factual or policy claim extracted from the submitted message."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    claim_text: str = Field(min_length=3, max_length=1000)
    claim_topic: Literal[
        "VOTER_REGISTRATION",
        "PVC_COLLECTION",
        "CASH_GRANT_OR_EMPOWERMENT",
        "ELECTION_SCHEDULE_OR_POLICY",
        "RECRUITMENT_OR_ADHOC_STAFF",
        "IDENTITY_VERIFICATION_NIN_BVN",
        "GENERAL_ANNOUNCEMENT",
    ] = "GENERAL_ANNOUNCEMENT"
    impersonated_entity: Optional[str] = Field(default=None, max_length=128)
    requires_external_verification: bool = True
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH


class RequestedActionItem(BaseModel):
    """An action the message instructs the recipient to perform."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action_type: RequestedActionType
    description: str = Field(min_length=3, max_length=500)
    is_sensitive_or_financial: bool = False
    evidence_excerpt: Optional[str] = Field(default=None, max_length=300)


class ScamIndicatorItem(BaseModel):
    """A specific scam or manipulation indicator identified in the message."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    category: ScamPatternCategory
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str = Field(min_length=3, max_length=500)
    evidence_excerpt: Optional[str] = Field(default=None, max_length=300)


class ImpersonationIndicatorItem(BaseModel):
    """Indicator showing how the message claims or mimics institutional authority."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    institution_name: str = Field(min_length=2, max_length=128)
    impersonation_method: str = Field(min_length=3, max_length=500)
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    evidence_excerpt: Optional[str] = Field(default=None, max_length=300)


class LLMStructuredOutputPayload(BaseModel):
    """Strict JSON schema contract expected from the LLM provider.

    Notice: There is NO `public_verdict` field here so the LLM cannot decide the final verdict.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    extracted_claims: list[ExtractedClaimItem] = Field(default_factory=list)
    mentioned_institutions: list[str] = Field(default_factory=list)
    requested_actions: list[RequestedActionItem] = Field(default_factory=list)
    scam_indicators: list[ScamIndicatorItem] = Field(default_factory=list)
    impersonation_indicators: list[ImpersonationIndicatorItem] = Field(
        default_factory=list
    )
    verification_requirements: list[str] = Field(default_factory=list)
    explanation: str = Field(min_length=10, max_length=2000)
    limitations: list[str] = Field(default_factory=list)


class AIAnalysisResult(BaseModel):
    """Validated output from the AMANA SHIELD AI Scam Message Analysis Service."""

    model_config = ConfigDict(extra="forbid")

    extracted_claims: list[ExtractedClaimItem] = Field(default_factory=list)
    mentioned_institutions: list[str] = Field(default_factory=list)
    requested_actions: list[RequestedActionItem] = Field(default_factory=list)
    scam_indicators: list[ScamIndicatorItem] = Field(default_factory=list)
    impersonation_indicators: list[ImpersonationIndicatorItem] = Field(
        default_factory=list
    )
    verification_requirements: list[str] = Field(default_factory=list)
    explanation: str
    limitations: list[str] = Field(default_factory=list)

    # Derived metadata & risk signal for downstream Risk Fusion Engine
    assessed_message_risk: MessageRisk = MessageRisk.LOW
    analysis_mode: Literal["LLM_PRIMARY", "FALLBACK_HEURISTIC"] = "LLM_PRIMARY"
    prompt_injection_detected: bool = False
    is_degraded: bool = False
    degraded_reason: Optional[str] = None
