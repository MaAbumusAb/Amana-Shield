"""Analyst Dashboard protected routes for investigation, oversight, and corrections."""

from __future__ import annotations

import hmac
import logging
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.models.entities import (
    Assessment,
    Domain,
    EvidenceSource,
    ExtractedClaim,
    ReviewEvent,
    ScamCampaign,
    Submission,
    ThreatIndicator,
)
from app.schemas.analyst import (
    AnalystDomainClassificationRequest,
    AnalystOverviewMetrics,
    AnalystReviewActionRequest,
    AnalystSubmissionDetail,
    AnalystSubmissionListItem,
    AnalystThreatIndicatorCreateRequest,
)

logger = logging.getLogger("amana_shield.api.analyst")

router = APIRouter(prefix="/analyst", tags=["Analyst Dashboard"])


def verify_analyst_key(
    x_analyst_key: Optional[str] = Header(None, alias="X-Analyst-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    settings: Settings = Depends(get_settings),
) -> str:
    """Validate caller has provided the designated analyst API secret key."""
    provided_key: Optional[str] = x_analyst_key
    if not provided_key and authorization and authorization.startswith("Bearer "):
        provided_key = authorization.removeprefix("Bearer ").strip()

    expected_key = settings.ANALYST_API_KEY.get_secret_value()

    if not provided_key or not hmac.compare_digest(provided_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing analyst API credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return provided_key


@router.get(
    "/overview",
    response_model=AnalystOverviewMetrics,
    summary="Dashboard Summary Metrics",
    dependencies=[Depends(verify_analyst_key)],
)
async def get_dashboard_overview(
    session: AsyncSession = Depends(get_db_session),
) -> AnalystOverviewMetrics:
    """Retrieve aggregate statistics regarding submissions, verdicts, and indicators."""
    # Total submissions
    sub_count_res = await session.execute(select(func.count(Submission.id)))
    total_submissions = sub_count_res.scalar() or 0

    # Verdict counts from assessments
    verdict_rows = await session.execute(
        select(Assessment.public_verdict, func.count(Assessment.id)).group_by(Assessment.public_verdict)
    )
    verdict_map = {row[0]: row[1] for row in verdict_rows.all()}

    # Internal status counts
    status_rows = await session.execute(
        select(Assessment.internal_status, func.count(Assessment.id)).group_by(Assessment.internal_status)
    )
    status_map = {row[0]: row[1] for row in status_rows.all()}

    # Channel breakdown
    channel_rows = await session.execute(
        select(Submission.channel, func.count(Submission.id)).group_by(Submission.channel)
    )
    channel_map = {row[0]: row[1] for row in channel_rows.all()}

    # Active campaigns count
    camp_res = await session.execute(
        select(func.count(ScamCampaign.id)).where(ScamCampaign.status == "ACTIVE")
    )
    active_campaigns = camp_res.scalar() or 0

    # Malicious domains count
    dom_res = await session.execute(
        select(func.count(Domain.id)).where(Domain.classification == "MALICIOUS")
    )
    malicious_domains = dom_res.scalar() or 0

    return AnalystOverviewMetrics(
        total_submissions=total_submissions,
        malicious_count=verdict_map.get("MALICIOUS", 0),
        suspicious_count=verdict_map.get("SUSPICIOUS", 0),
        official_count=verdict_map.get("OFFICIAL", 0),
        unverified_count=verdict_map.get("UNVERIFIED", 0),
        under_review_count=status_map.get("UNDER_REVIEW", 0),
        confirmed_count=status_map.get("CONFIRMED", 0),
        dismissed_count=status_map.get("DISMISSED", 0),
        active_campaigns_count=active_campaigns,
        malicious_domains_count=malicious_domains,
        channel_breakdown=channel_map,
    )


@router.get(
    "/submissions",
    response_model=list[AnalystSubmissionListItem],
    summary="List Submissions Queue",
    dependencies=[Depends(verify_analyst_key)],
)
async def list_submissions(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    verdict: Optional[str] = Query(default=None),
    internal_status: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> list[AnalystSubmissionListItem]:
    """Retrieve filtered submissions list for queue monitoring."""
    stmt = (
        select(Submission)
        .options(selectinload(Submission.assessment))
        .order_by(Submission.submitted_at.desc())
    )

    if channel:
        stmt = stmt.where(Submission.channel == channel.upper())

    if verdict or internal_status:
        stmt = stmt.join(Submission.assessment)
        if verdict:
            stmt = stmt.where(Assessment.public_verdict == verdict.upper())
        if internal_status:
            stmt = stmt.where(Assessment.internal_status == internal_status.upper())

    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    submissions = result.scalars().all()

    items: list[AnalystSubmissionListItem] = []
    for sub in submissions:
        preview = sub.raw_text[:120] + "..." if len(sub.raw_text) > 120 else sub.raw_text
        ass = sub.assessment
        items.append(
            AnalystSubmissionListItem(
                id=sub.id,
                channel=sub.channel,
                external_message_id=sub.external_message_id,
                submitted_at=sub.submitted_at,
                raw_text_preview=preview,
                extracted_urls=sub.extracted_urls or [],
                public_verdict=ass.public_verdict if ass else None,
                internal_status=ass.internal_status if ass else None,
                message_risk=ass.message_risk if ass else None,
                url_risk=ass.url_risk if ass else None,
                claim_verification_status=ass.claim_verification_status if ass else None,
            )
        )
    return items


@router.get(
    "/submissions/{submission_id}",
    response_model=AnalystSubmissionDetail,
    summary="Get Single Submission Detail",
    dependencies=[Depends(verify_analyst_key)],
)
async def get_submission_detail(
    submission_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
) -> AnalystSubmissionDetail:
    """Retrieve full inspection metadata for a submission."""
    stmt = (
        select(Submission)
        .options(
            selectinload(Submission.assessment).selectinload(Assessment.extracted_claims)
        )
        .where(Submission.id == submission_id)
    )
    result = await session.execute(stmt)
    sub = result.scalar_one_or_none()
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Submission {submission_id} not found.",
        )

    ass = sub.assessment
    claims_list: list[dict[str, Any]] = []
    if ass and ass.extracted_claims:
        for c in ass.extracted_claims:
            claims_list.append(
                {
                    "id": str(c.id),
                    "claim_text": c.claim_text,
                    "impersonated_entity": c.impersonated_entity,
                    "claim_topic": c.claim_topic,
                    "verification_outcome": c.verification_outcome,
                    "confidence": c.confidence,
                    "matched_evidence_id": str(c.matched_evidence_id) if c.matched_evidence_id else None,
                }
            )

    return AnalystSubmissionDetail(
        id=sub.id,
        channel=sub.channel,
        external_message_id=sub.external_message_id,
        submitted_at=sub.submitted_at,
        raw_text=sub.raw_text,
        normalised_text=sub.normalised_text,
        content_sha256=sub.content_sha256,
        extracted_urls=sub.extracted_urls or [],
        processing_status=sub.processing_status,
        assessment_id=ass.id if ass else None,
        public_verdict=ass.public_verdict if ass else None,
        internal_status=ass.internal_status if ass else None,
        message_risk=ass.message_risk if ass else None,
        url_risk=ass.url_risk if ass else None,
        claim_verification_status=ass.claim_verification_status if ass else None,
        explanation_text=ass.explanation_text if ass else None,
        recommended_action=ass.recommended_action if ass else None,
        triggered_rules=ass.triggered_rules if ass else [],
        triage_findings=ass.triage_findings if ass else {},
        ai_heuristics=ass.ai_heuristics if ass else {},
        assessed_at=ass.assessed_at if ass else None,
        is_degraded_mode=ass.is_degraded_mode if ass else False,
        extracted_claims=claims_list,
    )


@router.post(
    "/submissions/{submission_id}/review",
    response_model=dict[str, Any],
    summary="Update Assessment Review Status",
    dependencies=[Depends(verify_analyst_key)],
)
async def review_submission_assessment(
    submission_id: uuid.UUID,
    payload: AnalystReviewActionRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Record an analyst review decision and log an immutable ReviewEvent audit entry."""
    stmt = (
        select(Assessment)
        .where(Assessment.submission_id == submission_id)
    )
    result = await session.execute(stmt)
    ass = result.scalar_one_or_none()
    if ass is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment for this submission was not found.",
        )

    previous_status = ass.internal_status
    ass.internal_status = payload.status.value

    # Record immutable audit event
    review_event = ReviewEvent(
        target_type="ASSESSMENT",
        assessment_id=ass.id,
        actor_identifier="analyst_authenticated",
        action_type="STATUS_CHANGE",
        previous_status=previous_status,
        new_status=payload.status.value,
        rationale=payload.reviewer_notes or "Manual review update by analyst",
    )
    session.add(review_event)
    await session.commit()
    await session.refresh(ass)

    logger.info(
        "Analyst updated assessment status for submission %s: %s -> %s",
        submission_id,
        previous_status,
        payload.status.value,
    )
    return {
        "status": "success",
        "submission_id": str(submission_id),
        "previous_status": previous_status,
        "new_status": ass.internal_status,
        "reviewed_at": review_event.created_at.isoformat(),
    }


@router.get(
    "/domains",
    summary="List Registered and Discovered Domains",
    dependencies=[Depends(verify_analyst_key)],
)
async def list_domains(
    classification: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    session: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """List domains in the threat and official directory."""
    stmt = select(Domain).order_by(Domain.created_at.desc()).limit(limit)
    if classification:
        stmt = stmt.where(Domain.classification == classification.upper())
    result = await session.execute(stmt)
    domains = result.scalars().all()
    return [
        {
            "id": str(d.id),
            "canonical_host": d.canonical_host,
            "registered_domain": d.registered_domain,
            "classification": d.classification,
            "official_institution": d.official_institution,
            "status": d.status,
            "source": d.source,
            "reason": d.reason,
            "created_at": d.created_at.isoformat(),
        }
        for d in domains
    ]


@router.post(
    "/domains/{domain_id}/classification",
    summary="Update Domain Classification",
    dependencies=[Depends(verify_analyst_key)],
)
async def update_domain_classification(
    domain_id: uuid.UUID,
    payload: AnalystDomainClassificationRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Reclassify a domain (e.g., mark as confirmed MALICIOUS or OFFICIAL)."""
    stmt = select(Domain).where(Domain.id == domain_id)
    result = await session.execute(stmt)
    domain = result.scalar_one_or_none()
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain {domain_id} not found.",
        )

    domain.classification = payload.classification.value
    if payload.official_institution:
        domain.official_institution = payload.official_institution
    if payload.reason:
        domain.reason = payload.reason

    await session.commit()
    await session.refresh(domain)
    return {
        "status": "success",
        "domain_id": str(domain.id),
        "canonical_host": domain.canonical_host,
        "classification": domain.classification,
    }


@router.get(
    "/claims",
    summary="List Extracted Claims Under Review",
    dependencies=[Depends(verify_analyst_key)],
)
async def list_extracted_claims(
    verification_outcome: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    session: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """List extracted claims across submissions."""
    stmt = (
        select(ExtractedClaim)
        .options(selectinload(ExtractedClaim.matched_evidence))
        .order_by(ExtractedClaim.created_at.desc())
        .limit(limit)
    )
    if verification_outcome:
        stmt = stmt.where(ExtractedClaim.verification_outcome == verification_outcome.upper())
    result = await session.execute(stmt)
    claims = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "assessment_id": str(c.assessment_id),
            "claim_text": c.claim_text,
            "impersonated_entity": c.impersonated_entity,
            "claim_topic": c.claim_topic,
            "verification_outcome": c.verification_outcome,
            "confidence": c.confidence,
            "matched_source_title": c.matched_evidence.title if c.matched_evidence else None,
            "matched_source_url": c.matched_evidence.official_url if c.matched_evidence else None,
            "created_at": c.created_at.isoformat(),
        }
        for c in claims
    ]


@router.get(
    "/campaigns",
    summary="List Known Scam Campaigns",
    dependencies=[Depends(verify_analyst_key)],
)
async def list_scam_campaigns(
    session: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """List grouped scam campaign clusters."""
    stmt = select(ScamCampaign).order_by(ScamCampaign.last_seen_at.desc())
    result = await session.execute(stmt)
    campaigns = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "slug": c.slug,
            "title": c.title,
            "scam_category": c.scam_category,
            "status": c.status,
            "sighting_count": c.sighting_count,
            "first_seen_at": c.first_seen_at.isoformat(),
            "last_seen_at": c.last_seen_at.isoformat(),
        }
        for c in campaigns
    ]


@router.get(
    "/evidence",
    summary="List Active Evidence Sources",
    dependencies=[Depends(verify_analyst_key)],
)
async def list_evidence_sources(
    session: AsyncSession = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """List official evidence registry entries."""
    stmt = (
        select(EvidenceSource)
        .order_by(EvidenceSource.published_at.desc())
        .limit(50)
    )
    result = await session.execute(stmt)
    sources = result.scalars().all()
    return [
        {
            "id": str(s.id),
            "institution_code": s.institution_code,
            "title": s.title,
            "source_type": s.source_type,
            "official_url": s.official_url,
            "is_debunking_notice": s.is_debunking_notice,
            "published_at": s.published_at.isoformat(),
            "is_active": s.is_active,
        }
        for s in sources
    ]


@router.post(
    "/threat-indicators",
    summary="Add Confirmed Threat Indicator",
    dependencies=[Depends(verify_analyst_key)],
)
async def create_threat_indicator(
    payload: AnalystThreatIndicatorCreateRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Add a threat indicator (malicious URL, domain, phone, bank account)."""
    indicator = ThreatIndicator(
        indicator_type=payload.indicator_type.value,
        indicator_value=payload.indicator_value,
        threat_category=payload.threat_category,
        confidence_level="HIGH",
        status=payload.status.value,
        source_origin="ANALYST_DASHBOARD",
        reason=payload.reason or "Analyst manual addition",
        reviewer="analyst_authenticated",
    )
    session.add(indicator)
    await session.commit()
    await session.refresh(indicator)
    return {
        "status": "success",
        "indicator_id": str(indicator.id),
        "indicator_type": indicator.indicator_type,
        "indicator_value": indicator.indicator_value,
    }
