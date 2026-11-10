"""Pydantic v2 schemas for the Deterministic URL and Domain Intelligence Engine."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.entities import (
    ConfidenceLevel,
    DomainClassification,
    IndicatorStatus,
    IndicatorType,
    UrlRisk,
)


class ExtractedUrlFinding(BaseModel):
    """Structured result of extracting and normalising a single URL candidate."""

    model_config = ConfigDict(extra="forbid")

    raw_url: str
    normalised_url: Optional[str] = None
    scheme: Optional[str] = None
    canonical_host: Optional[str] = None
    unicode_host: Optional[str] = None
    registered_domain: Optional[str] = None
    subdomain: str = ""
    tld_suffix: str = ""
    path: str = "/"
    was_defanged: bool = False
    is_idn_punycode: bool = False
    has_mixed_script_or_confusable: bool = False
    is_shortened_url: bool = False
    is_ip_literal: bool = False
    is_private_or_reserved_ip: bool = False
    is_malformed: bool = False
    malformed_reason: Optional[str] = None


class ThreatMatchFinding(BaseModel):
    """Match against a confirmed, candidate, or official registry indicator."""

    model_config = ConfigDict(extra="forbid")

    match_source: Literal["DOMAIN_REGISTRY", "THREAT_INDICATOR", "PRIOR_SUBMISSION"]
    indicator_type: str
    matched_value: str
    classification: str
    status: str
    confidence: str = "HIGH"
    source: str
    reason: Optional[str] = None
    official_institution: Optional[str] = None
    date_added: Optional[datetime] = None
    expiry_or_review_date: Optional[datetime] = None
    reviewer: Optional[str] = None


class RDAPRegistrationInfo(BaseModel):
    """Domain registration information retrieved via RDAP."""

    model_config = ConfigDict(extra="forbid")

    lookup_status: Literal[
        "SUCCESS", "CACHED", "SKIPPED", "UNAVAILABLE", "RATE_LIMITED"
    ]
    registered_domain: str
    registrar_name: Optional[str] = None
    registered_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    error_message: Optional[str] = None


class DNSFinding(BaseModel):
    """DNS resolution findings for a domain."""

    model_config = ConfigDict(extra="forbid")

    lookup_status: Literal["SUCCESS", "CACHED", "SKIPPED", "UNAVAILABLE", "NXDOMAIN"]
    canonical_host: str
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    has_private_or_reserved_ip: bool = False
    blocked_ips: list[str] = Field(default_factory=list)
    error_message: Optional[str] = None


class RedirectHopFinding(BaseModel):
    """Single hop in a controlled, SSRF-safe redirect inspection chain."""

    model_config = ConfigDict(extra="forbid")

    hop_number: int
    url: str
    resolved_ips: list[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    location_header: Optional[str] = None
    blocked_reason: Optional[str] = None


class RedirectAnalysisFinding(BaseModel):
    """Controlled redirect inspection summary for a submitted URL."""

    model_config = ConfigDict(extra="forbid")

    initial_url: str
    final_url: Optional[str] = None
    final_canonical_host: Optional[str] = None
    hops: list[RedirectHopFinding] = Field(default_factory=list)
    redirect_count: int = 0
    is_truncated_or_Incomplete: bool = False
    ssrf_or_rebinding_blocked: bool = False
    error_message: Optional[str] = None


class RiskIndicatorFinding(BaseModel):
    """Auditable deterministic risk signal."""

    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    weight_category: Literal[
        "CONCLUSIVE_THREAT", "STRONG_SIGNAL", "WEAK_SIGNAL", "OFFICIAL_SIGNAL"
    ]
    target: str
    description: str
    evidence: Optional[str] = None


class NormalisedDomainSummary(BaseModel):
    """Summary of a unique normalised domain analysed in the submission."""

    model_config = ConfigDict(extra="forbid")

    canonical_host: str
    unicode_host: str
    registered_domain: str
    subdomain: str
    tld_suffix: str
    classification: str = DomainClassification.UNKNOWN.value
    official_institution: Optional[str] = None
    is_idn_punycode: bool = False
    is_shortened_service: bool = False
    previously_reported_count: int = 0
    impersonation_target: Optional[str] = None


class DeterministicTriageResult(BaseModel):
    """Complete structured output from the Deterministic URL and Domain Intelligence Engine."""

    model_config = ConfigDict(extra="forbid")

    extracted_urls: list[ExtractedUrlFinding] = Field(default_factory=list)
    normalised_domains: list[NormalisedDomainSummary] = Field(default_factory=list)
    threat_matches: list[ThreatMatchFinding] = Field(default_factory=list)
    registration_info: list[RDAPRegistrationInfo] = Field(default_factory=list)
    dns_findings: list[DNSFinding] = Field(default_factory=list)
    redirect_findings: list[RedirectAnalysisFinding] = Field(default_factory=list)
    risk_indicators: list[RiskIndicatorFinding] = Field(default_factory=list)
    unavailable_checks: list[str] = Field(default_factory=list)
    aggregated_url_risk: UrlRisk = UrlRisk.NO_URL
    contains_verified_official_domain: bool = False
    trust_warning: Optional[str] = None


class DomainRegistryUpsertRequest(BaseModel):
    """Request schema to register or update an official, malicious, or suspicious domain."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    canonical_host: str = Field(min_length=3, max_length=255)
    classification: DomainClassification
    official_institution: Optional[str] = Field(default=None, max_length=128)
    source: str = Field(min_length=2, max_length=128)
    reason: str = Field(min_length=5, max_length=2000)
    status: Literal["ACTIVE", "UNDER_REVIEW", "EXPIRED", "REVOKED"] = "ACTIVE"
    review_date: Optional[datetime] = None
    domain_expires_at: Optional[datetime] = None
    reviewer: Optional[str] = Field(default=None, max_length=128)


class DomainRegistryResponse(BaseModel):
    """Response schema for a domain registry record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canonical_host: str
    registered_domain: str
    tld_suffix: str
    is_idn_punycode: bool
    classification: str
    official_institution: Optional[str]
    status: str
    source: str
    reason: Optional[str]
    created_at: datetime
    review_date: Optional[datetime]
    domain_expires_at: Optional[datetime]
    reviewer: Optional[str]


class ThreatIndicatorUpsertRequest(BaseModel):
    """Request schema to register a confirmed or candidate threat indicator."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    indicator_type: IndicatorType
    indicator_value: str = Field(min_length=3, max_length=2048)
    threat_category: str = Field(min_length=2, max_length=64)
    confidence_level: ConfidenceLevel = ConfidenceLevel.HIGH
    status: IndicatorStatus = IndicatorStatus.CONFIRMED
    source_origin: str = Field(min_length=2, max_length=128)
    reason: str = Field(min_length=5, max_length=2000)
    valid_until: Optional[datetime] = None
    reviewer: Optional[str] = Field(default=None, max_length=128)


class ThreatIndicatorResponse(BaseModel):
    """Response schema for a threat indicator record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    indicator_type: str
    indicator_value: str
    threat_category: str
    confidence_level: str
    status: str
    source_origin: str
    reason: Optional[str]
    valid_from: datetime
    valid_until: Optional[datetime]
    reviewer: Optional[str]
    created_at: datetime
