"""Automated database integrity and constraint verification tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import (
    Assessment,
    Domain,
    ExtractedClaim,
    ReviewEvent,
    Submission,
    ThreatIndicator,
)


@pytest.mark.asyncio
async def test_webhook_replay_idempotency_constraint(
    db_session: AsyncSession,
) -> None:
    """Duplicate external_message_id (e.g. replayed WhatsApp wamid) must be rejected by DB."""
    sub1 = Submission(
        channel="WHATSAPP",
        external_message_id="wamid.HBgLMjM0TestReplay001",
        sender_hash="a" * 64,
        raw_text="Check https://inec-gov-empowerment.com.ng",
        normalised_text="Check https://inec-gov-empowerment.com.ng",
        content_sha256="b" * 64,
    )
    db_session.add(sub1)
    await db_session.commit()

    sub_duplicate = Submission(
        channel="WHATSAPP",
        external_message_id="wamid.HBgLMjM0TestReplay001",
        sender_hash="a" * 64,
        raw_text="Check https://inec-gov-empowerment.com.ng",
        normalised_text="Check https://inec-gov-empowerment.com.ng",
        content_sha256="b" * 64,
    )
    db_session.add(sub_duplicate)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_degraded_mode_cannot_produce_official_verdict(
    db_session: AsyncSession,
) -> None:
    """Database CHECK constraint must block public_verdict='OFFICIAL' when is_degraded_mode=True."""
    sub = Submission(
        channel="WEB",
        external_message_id=f"web-{uuid.uuid4()}",
        sender_hash="c" * 64,
        raw_text="Official notice",
        normalised_text="Official notice",
        content_sha256="d" * 64,
    )
    db_session.add(sub)
    await db_session.flush()

    bad_assessment = Assessment(
        submission_id=sub.id,
        message_risk="LOW",
        url_risk="VERIFIED_OFFICIAL",
        claim_verification_status="VERIFIED_OFFICIAL",
        public_verdict="OFFICIAL",
        internal_status="CONFIRMED",
        explanation_text="Should fail check constraint",
        recommended_action="None",
        is_degraded_mode=True,
    )
    db_session.add(bad_assessment)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_verified_claim_requires_evidence_source_fk(
    db_session: AsyncSession,
) -> None:
    """A claim cannot be marked VERIFIED_OFFICIAL or CONTRADICTED_BY_OFFICIAL without matched_evidence_id."""
    sub = Submission(
        channel="WEB",
        external_message_id=f"web-{uuid.uuid4()}",
        sender_hash="e" * 64,
        raw_text="INEC gives N50,000 grant",
        normalised_text="INEC gives N50,000 grant",
        content_sha256="f" * 64,
    )
    db_session.add(sub)
    await db_session.flush()

    assessment = Assessment(
        submission_id=sub.id,
        message_risk="HIGH",
        url_risk="NO_URL",
        claim_verification_status="CONTRADICTED_BY_OFFICIAL",
        public_verdict="SUSPICIOUS",
        internal_status="UNDER_REVIEW",
        explanation_text="Contradicted claim",
        recommended_action="Ignore",
    )
    db_session.add(assessment)
    await db_session.flush()

    unlinked_claim = ExtractedClaim(
        assessment_id=assessment.id,
        claim_text="INEC gives N50,000 grant",
        impersonated_entity="INEC",
        claim_topic="CASH_GRANT",
        verification_outcome="CONTRADICTED_BY_OFFICIAL",
        matched_evidence_id=None,
    )
    db_session.add(unlinked_claim)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_official_domain_requires_institution_name(
    db_session: AsyncSession,
) -> None:
    """Domain with classification='OFFICIAL' must specify official_institution."""
    invalid_official = Domain(
        canonical_host="unknown-portal.gov.ng",
        registered_domain="unknown-portal.gov.ng",
        tld_suffix="gov.ng",
        classification="OFFICIAL",
        official_institution=None,
    )
    db_session.add(invalid_official)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_review_event_requires_non_empty_rationale_and_target(
    db_session: AsyncSession,
) -> None:
    """Analyst review events must link to target entity and include a rationale >= 5 chars."""
    indicator = ThreatIndicator(
        indicator_type="DOMAIN",
        indicator_value="fake-inec.com.ng",
        threat_category="PHISHING",
        status="CANDIDATE",
        source_origin="USER_SUBMISSION",
    )
    db_session.add(indicator)
    await db_session.flush()

    bad_review = ReviewEvent(
        target_type="THREAT_INDICATOR",
        threat_indicator_id=indicator.id,
        actor_identifier="analyst_01",
        action_type="PROMOTE_INDICATOR",
        previous_status="CANDIDATE",
        new_status="CONFIRMED",
        rationale="ok",
    )
    db_session.add(bad_review)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
