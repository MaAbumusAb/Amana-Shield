"""SQLAlchemy 2.x relational models for AMANA SHIELD (PostgreSQL primary)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def default_expiry() -> datetime:
    """Return default 90-day retention expiration timestamp."""
    return datetime.now(timezone.utc) + timedelta(days=90)


# Cross-dialect JSONB (PostgreSQL JSONB in production, JSON fallback in local SQLite tests)
JSONBType = JSON().with_variant(JSONB(), "postgresql")
TSVectorType = Text().with_variant(TSVECTOR(), "postgresql")


class SubmissionChannel(StrEnum):
    WHATSAPP = "WHATSAPP"
    WEB = "WEB"
    ANDROID_SHARE = "ANDROID_SHARE"


class ProcessingStatus(StrEnum):
    RECEIVED = "RECEIVED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class DomainClassification(StrEnum):
    OFFICIAL = "OFFICIAL"
    BENIGN_KNOWN = "BENIGN_KNOWN"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class IndicatorType(StrEnum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    PHONE_NUMBER = "PHONE_NUMBER"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    TEXT_HASH = "TEXT_HASH"


class IndicatorStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    CONFIRMED = "CONFIRMED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceSourceType(StrEnum):
    PRESS_RELEASE = "PRESS_RELEASE"
    OFFICIAL_PORTAL = "OFFICIAL_PORTAL"
    DEBUNKING_NOTICE = "DEBUNKING_NOTICE"
    POLICY_RULE = "POLICY_RULE"


class MessageRisk(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UrlRisk(StrEnum):
    NO_URL = "NO_URL"
    VERIFIED_OFFICIAL = "VERIFIED_OFFICIAL"
    BENIGN_KNOWN = "BENIGN_KNOWN"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ClaimVerificationStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    VERIFIED_OFFICIAL = "VERIFIED_OFFICIAL"
    CONTRADICTED_BY_OFFICIAL = "CONTRADICTED_BY_OFFICIAL"
    OUTDATED_OR_EXPIRED = "OUTDATED_OR_EXPIRED"
    UNVERIFIED = "UNVERIFIED"


class PublicVerdict(StrEnum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    OFFICIAL = "OFFICIAL"
    UNVERIFIED = "UNVERIFIED"


class InternalStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    UNDER_REVIEW = "UNDER_REVIEW"
    DISMISSED = "DISMISSED"


class Base(DeclarativeBase):
    """Declarative base for all AMANA SHIELD models."""


class Domain(Base):
    """Normalised directory of canonical hosts/domains and official registries."""

    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    canonical_host: Mapped[str] = mapped_column(String(255), nullable=False)
    registered_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    tld_suffix: Mapped[str] = mapped_column(String(63), nullable=False)
    is_idn_punycode: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    classification: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=DomainClassification.UNKNOWN.value,
    )
    official_institution: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )
    source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="SYSTEM_DISCOVERED",
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    review_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reviewer: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    domain_registered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    domain_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    registrar_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dns_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    rdap_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    campaigns: Mapped[list["ScamCampaign"]] = relationship(
        back_populates="primary_domain"
    )
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="primary_domain"
    )
    threat_indicators: Mapped[list["ThreatIndicator"]] = relationship(
        back_populates="linked_domain"
    )

    __table_args__ = (
        UniqueConstraint("canonical_host", name="uq_domains_canonical_host"),
        CheckConstraint(
            "classification IN ('OFFICIAL', 'BENIGN_KNOWN', 'UNKNOWN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_domains_classification",
        ),
        CheckConstraint(
            "classification != 'OFFICIAL' OR official_institution IS NOT NULL",
            name="ck_domains_official_requires_institution",
        ),
        Index("ix_domains_registered_domain", "registered_domain"),
        Index("ix_domains_classification", "classification"),
    )


class ScamCampaign(Base):
    """Tracks clusters of related scam messages by shared domain or fingerprint."""

    __tablename__ = "scam_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    scam_category: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    primary_domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    sighting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    primary_domain: Mapped[Optional["Domain"]] = relationship(
        back_populates="campaigns"
    )
    submissions: Mapped[list["Submission"]] = relationship(back_populates="campaign")

    __table_args__ = (
        UniqueConstraint("slug", name="uq_scam_campaigns_slug"),
        UniqueConstraint("fingerprint_hash", name="uq_scam_campaigns_fingerprint_hash"),
        CheckConstraint("sighting_count >= 1", name="ck_scam_campaigns_sighting_positive"),
        CheckConstraint(
            "status IN ('ACTIVE', 'MONITORING', 'ARCHIVED')",
            name="ck_scam_campaigns_status",
        ),
        Index("ix_scam_campaigns_status_last_seen", "status", "last_seen_at"),
    )


class Submission(Base):
    """Immutable record of user-submitted content and replay-prevention lock."""

    __tablename__ = "submissions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    external_message_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sender_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    normalised_text: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    extracted_urls: Mapped[list[str]] = mapped_column(
        JSONBType, nullable=False, default=list
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scam_campaigns.id", ondelete="SET NULL"),
        nullable=True,
    )
    processing_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ProcessingStatus.RECEIVED.value,
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=default_expiry,
    )

    campaign: Mapped[Optional["ScamCampaign"]] = relationship(
        back_populates="submissions"
    )
    assessment: Mapped[Optional["Assessment"]] = relationship(
        back_populates="submission", uselist=False, cascade="all, delete-orphan"
    )
    discovered_indicators: Mapped[list["ThreatIndicator"]] = relationship(
        back_populates="first_seen_submission"
    )

    __table_args__ = (
        UniqueConstraint("external_message_id", name="uq_submissions_external_message_id"),
        CheckConstraint(
            "channel IN ('WHATSAPP', 'WEB', 'ANDROID_SHARE')",
            name="ck_submissions_channel",
        ),
        CheckConstraint(
            "processing_status IN ('RECEIVED', 'PROCESSING', 'COMPLETED', 'FAILED')",
            name="ck_submissions_processing_status",
        ),
        CheckConstraint(
            "length(raw_text) BETWEEN 1 AND 10000",
            name="ck_submissions_raw_text_len",
        ),
        Index("ix_submissions_sender_hash_submitted_at", "sender_hash", "submitted_at"),
        Index("ix_submissions_content_sha256", "content_sha256"),
        Index("ix_submissions_campaign_id", "campaign_id"),
    )


class ThreatIndicator(Base):
    """Curated and candidate indicators of compromise (domains, URLs, phones, accounts)."""

    __tablename__ = "threat_indicators"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    linked_domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
    )
    first_seen_submission_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("submissions.id", ondelete="SET NULL"),
        nullable=True,
    )
    threat_category: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence_level: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ConfidenceLevel.MEDIUM.value,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=IndicatorStatus.CANDIDATE.value,
    )
    source_origin: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewer: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    valid_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    linked_domain: Mapped[Optional["Domain"]] = relationship(
        back_populates="threat_indicators"
    )
    first_seen_submission: Mapped[Optional["Submission"]] = relationship(
        back_populates="discovered_indicators"
    )
    review_events: Mapped[list["ReviewEvent"]] = relationship(
        back_populates="threat_indicator"
    )

    __table_args__ = (
        UniqueConstraint(
            "indicator_type", "indicator_value", name="uq_threat_indicators_type_value"
        ),
        CheckConstraint(
            "indicator_type IN ('DOMAIN', 'URL', 'PHONE_NUMBER', 'BANK_ACCOUNT', 'TEXT_HASH')",
            name="ck_threat_indicators_type",
        ),
        CheckConstraint(
            "status IN ('CANDIDATE', 'CONFIRMED', 'REVOKED', 'EXPIRED')",
            name="ck_threat_indicators_status",
        ),
        CheckConstraint(
            "confidence_level IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_threat_indicators_confidence",
        ),
        Index(
            "ix_threat_indicators_active_lookup",
            "indicator_type",
            "indicator_value",
            "status",
        ),
    )


class EvidenceSource(Base):
    """Curated official statements, portal registries, and debunking notices."""

    __tablename__ = "evidence_sources"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    institution_code: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    summary_content: Mapped[str] = mapped_column(Text, nullable=False)
    official_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    is_debunking_notice: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    valid_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source_category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="GOVERNMENT_INSTITUTION",
    )
    verification_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="VERIFIED_AUTHENTIC",
    )
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    verified_claims: Mapped[list["ExtractedClaim"]] = relationship(
        back_populates="matched_evidence"
    )

    __table_args__ = (
        UniqueConstraint("official_url", name="uq_evidence_sources_official_url"),
        CheckConstraint(
            "source_type IN ('PRESS_RELEASE', 'OFFICIAL_PORTAL', 'DEBUNKING_NOTICE', 'POLICY_RULE')",
            name="ck_evidence_sources_source_type",
        ),
        Index(
            "ix_evidence_sources_institution_active",
            "institution_code",
            "is_active",
            "published_at",
        ),
    )


class Assessment(Base):
    """Derived risk assessment and deterministic verdict for a submission."""

    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("submissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    primary_domain_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
    )
    message_risk: Mapped[str] = mapped_column(String(32), nullable=False)
    url_risk: Mapped[str] = mapped_column(String(32), nullable=False)
    claim_verification_status: Mapped[str] = mapped_column(String(32), nullable=False)
    public_verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    internal_status: Mapped[str] = mapped_column(String(32), nullable=False)
    triggered_rules: Mapped[list[str]] = mapped_column(
        JSONBType, nullable=False, default=list
    )
    triage_findings: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    ai_heuristics: Mapped[dict[str, Any]] = mapped_column(
        JSONBType, nullable=False, default=dict
    )
    explanation_text: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    is_degraded_mode: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    submission: Mapped["Submission"] = relationship(back_populates="assessment")
    primary_domain: Mapped[Optional["Domain"]] = relationship(
        back_populates="assessments"
    )
    extracted_claims: Mapped[list["ExtractedClaim"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    review_events: Mapped[list["ReviewEvent"]] = relationship(
        back_populates="assessment"
    )

    __table_args__ = (
        UniqueConstraint("submission_id", name="uq_assessments_submission_id"),
        CheckConstraint(
            "message_risk IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_assessments_message_risk",
        ),
        CheckConstraint(
            "url_risk IN ('NO_URL', 'VERIFIED_OFFICIAL', 'BENIGN_KNOWN', 'UNKNOWN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_assessments_url_risk",
        ),
        CheckConstraint(
            "claim_verification_status IN ('NOT_APPLICABLE', 'VERIFIED_OFFICIAL', 'CONTRADICTED_BY_OFFICIAL', 'OUTDATED_OR_EXPIRED', 'UNVERIFIED')",
            name="ck_assessments_claim_status",
        ),
        CheckConstraint(
            "public_verdict IN ('MALICIOUS', 'SUSPICIOUS', 'OFFICIAL', 'UNVERIFIED')",
            name="ck_assessments_public_verdict",
        ),
        CheckConstraint(
            "internal_status IN ('CONFIRMED', 'UNDER_REVIEW', 'DISMISSED')",
            name="ck_assessments_internal_status",
        ),
        CheckConstraint(
            "NOT (is_degraded_mode = true AND public_verdict = 'OFFICIAL')",
            name="ck_assessments_no_official_when_degraded",
        ),
        Index(
            "ix_assessments_internal_status_assessed_at",
            "internal_status",
            "assessed_at",
        ),
        Index("ix_assessments_public_verdict", "public_verdict"),
    )


class ExtractedClaim(Base):
    """Factual claim extracted from a submission and linked to official evidence."""

    __tablename__ = "extracted_claims"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
    )
    claim_text: Mapped[str] = mapped_column(Text, nullable=False)
    impersonated_entity: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    claim_topic: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    matched_evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_sources.id", ondelete="SET NULL"),
        nullable=True,
    )
    confidence: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ConfidenceLevel.MEDIUM.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="extracted_claims")
    matched_evidence: Mapped[Optional["EvidenceSource"]] = relationship(
        back_populates="verified_claims"
    )

    __table_args__ = (
        CheckConstraint(
            "verification_outcome IN ('VERIFIED_OFFICIAL', 'CONTRADICTED_BY_OFFICIAL', 'OUTDATED_OR_EXPIRED', 'UNVERIFIED')",
            name="ck_extracted_claims_outcome",
        ),
        CheckConstraint(
            "verification_outcome NOT IN ('VERIFIED_OFFICIAL', 'CONTRADICTED_BY_OFFICIAL') "
            "OR matched_evidence_id IS NOT NULL",
            name="ck_extracted_claims_verified_requires_source",
        ),
        CheckConstraint(
            "confidence IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_extracted_claims_confidence",
        ),
        Index("ix_extracted_claims_assessment_id", "assessment_id"),
        Index("ix_extracted_claims_matched_evidence_id", "matched_evidence_id"),
    )


class ReviewEvent(Base):
    """Immutable append-only audit trail for analyst reviews and threat status changes."""

    __tablename__ = "review_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assessments.id", ondelete="RESTRICT"),
        nullable=True,
    )
    threat_indicator_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("threat_indicators.id", ondelete="RESTRICT"),
        nullable=True,
    )
    actor_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_status: Mapped[str] = mapped_column(String(64), nullable=False)
    new_status: Mapped[str] = mapped_column(String(64), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now()
    )

    assessment: Mapped[Optional["Assessment"]] = relationship(
        back_populates="review_events"
    )
    threat_indicator: Mapped[Optional["ThreatIndicator"]] = relationship(
        back_populates="review_events"
    )

    __table_args__ = (
        CheckConstraint(
            "target_type IN ('ASSESSMENT', 'THREAT_INDICATOR')",
            name="ck_review_events_target_type",
        ),
        CheckConstraint(
            "(target_type = 'ASSESSMENT' AND assessment_id IS NOT NULL) OR "
            "(target_type = 'THREAT_INDICATOR' AND threat_indicator_id IS NOT NULL)",
            name="ck_review_events_target_link",
        ),
        CheckConstraint(
            "length(trim(rationale)) >= 5",
            name="ck_review_events_rationale_nonempty",
        ),
        Index("ix_review_events_assessment_id", "assessment_id", "created_at"),
        Index(
            "ix_review_events_threat_indicator_id",
            "threat_indicator_id",
            "created_at",
        ),
    )
