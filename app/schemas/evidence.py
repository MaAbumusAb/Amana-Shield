"""Pydantic v2 schemas for Evidence Retrieval and Claim Verification."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.entities import ConfidenceLevel, EvidenceSourceType


class SourceCategory(StrEnum):
    """Categorisation of curated evidence sources according to source strategy priority."""

    INEC_OFFICIAL = "INEC_OFFICIAL"
    GOVERNMENT_INSTITUTION = "GOVERNMENT_INSTITUTION"
    GOVERNMENT_PROGRAMME_DOC = "GOVERNMENT_PROGRAMME_DOC"
    FACT_CHECKING_ORG = "FACT_CHECKING_ORG"
    CREDIBLE_PRIMARY = "CREDIBLE_PRIMARY"


class SourceVerificationStatus(StrEnum):
    """Validation status of the source registry entry itself."""

    VERIFIED_AUTHENTIC = "VERIFIED_AUTHENTIC"
    PROVISIONAL = "PROVISIONAL"
    DEPRECATED = "DEPRECATED"


class VerificationVerdict(StrEnum):
    """Standard public/analysis verification verdict for an individual factual claim."""

    VERIFIED = "VERIFIED"
    FALSE = "FALSE"
    MISLEADING = "MISLEADING"
    UNVERIFIED = "UNVERIFIED"


class EvidenceSourceRecordSchema(BaseModel):
    """Evidence source summary representation."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    institution_code: str
    title: str
    source_type: EvidenceSourceType
    summary_content: str
    official_url: str
    is_debunking_notice: bool
    published_at: datetime
    valid_until: Optional[datetime] = None
    is_active: bool
    source_category: SourceCategory = SourceCategory.GOVERNMENT_INSTITUTION
    verification_status: SourceVerificationStatus = SourceVerificationStatus.VERIFIED_AUTHENTIC
    last_checked_at: Optional[datetime] = None


class RetrievedEvidenceItem(BaseModel):
    """An evidence item retrieved for a specific claim with relevance score and attribution."""

    model_config = ConfigDict(extra="forbid")

    source_id: uuid.UUID
    title: str
    official_url: str
    institution_code: str
    source_category: SourceCategory
    published_at: datetime
    is_debunking_notice: bool
    relevant_excerpt: str
    relevance_score: float = Field(ge=0.0)


class ClaimVerificationEvaluation(BaseModel):
    """Verification analysis for a single extracted claim against retrieved evidence."""

    model_config = ConfigDict(extra="forbid")

    claim_text: str
    claim_topic: str
    impersonated_entity: Optional[str] = None
    verdict: VerificationVerdict
    confidence: ConfidenceLevel
    matched_source_id: Optional[uuid.UUID] = None
    matched_source_url: Optional[str] = None
    supporting_points: list[str] = Field(default_factory=list)
    contradicting_points: list[str] = Field(default_factory=list)
    uncertainty_explanation: Optional[str] = None
    publication_dates: list[datetime] = Field(default_factory=list)
    evidence_citations: list[str] = Field(default_factory=list)


class EvidenceVerificationResult(BaseModel):
    """Aggregate result from Evidence Verification Service for a message / submission."""

    model_config = ConfigDict(extra="forbid")

    evaluated_claims: list[ClaimVerificationEvaluation] = Field(default_factory=list)
    overall_claim_status: Literal[
        "NOT_APPLICABLE",
        "VERIFIED_OFFICIAL",
        "CONTRADICTED_BY_OFFICIAL",
        "OUTDATED_OR_EXPIRED",
        "UNVERIFIED",
    ] = "UNVERIFIED"
    has_contradicted_claims: bool = False
    has_verified_official_claims: bool = False
    has_misleading_claims: bool = False
    sources_consulted_count: int = 0
    explanation: str
    uncertainty_summary: Optional[str] = None


class EvidenceSourceUpsertRequest(BaseModel):
    """Request schema for creating or updating a curated evidence source record."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    institution_code: str = Field(min_length=2, max_length=32)
    title: str = Field(min_length=5, max_length=512)
    source_type: EvidenceSourceType
    summary_content: str = Field(min_length=10, max_length=10000)
    official_url: str = Field(min_length=5, max_length=2048)
    is_debunking_notice: bool = False
    published_at: datetime
    valid_until: Optional[datetime] = None
    is_active: bool = True
    source_category: SourceCategory = SourceCategory.GOVERNMENT_INSTITUTION
    verification_status: SourceVerificationStatus = SourceVerificationStatus.VERIFIED_AUTHENTIC
