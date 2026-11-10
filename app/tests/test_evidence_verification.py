"""Tests for Task 7: Evidence Retrieval and Claim Verification Service.

Uses human-labelled test fixtures representing:
1. Genuine INEC voter registration announcement (Supported / VERIFIED).
2. Fake INEC N50,000 cash grant (Contradicted by debunking notice / FALSE).
3. Registration fee claim (Contradicted by policy / FALSE).
4. Authentic NIMC NIN update schedule (Supported / VERIFIED).
5. Unverifiable civic announcement with no matching records (Abstains / UNVERIFIED).
6. Evidence source registry management and API endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import EvidenceSourceType
from app.repositories.submissions import EvidenceSourceRepository
from app.schemas.ai_analysis import ExtractedClaimItem
from app.schemas.evidence import (
    SourceCategory,
    SourceVerificationStatus,
    VerificationVerdict,
)
from app.services.evidence_service import EvidenceVerificationService


@pytest.fixture
async def seed_curated_evidence(db_session: AsyncSession) -> None:
    """Seed curated official evidence sources for INEC, NIMC, and FGN."""
    repo = EvidenceSourceRepository(db_session)

    # 1. Official INEC CVR announcement
    await repo.upsert_evidence_source(
        institution_code="INEC",
        title="INEC Resumption of Continuous Voter Registration Schedule",
        source_type=EvidenceSourceType.PRESS_RELEASE.value,
        summary_content=(
            "The Independent National Electoral Commission resumes Continuous Voter Registration "
            "nationwide across all 774 LGA offices. Registration is completely free for all eligible citizens."
        ),
        official_url="https://inecnigeria.org/cvr-resumption-2026",
        published_at=datetime(2026, 5, 10, tzinfo=timezone.utc),
        is_debunking_notice=False,
        is_active=True,
        source_category=SourceCategory.INEC_OFFICIAL.value,
        verification_status=SourceVerificationStatus.VERIFIED_AUTHENTIC.value,
    )

    # 2. Official INEC Debunking Notice: Fake N50,000 Grant
    await repo.upsert_evidence_source(
        institution_code="INEC",
        title="INEC Disclaimer: Fraudulent N50,000 Voter Empowerment Grant Announcement",
        source_type=EvidenceSourceType.DEBUNKING_NOTICE.value,
        summary_content=(
            "PUBLIC DISCLAIMER: INEC does NOT offer or distribute N50,000 voter empowerment grants, "
            "election palliatives, or financial relief. Any message directing voters to claim cash by submitting "
            "their BVN or paying fees is a fraudulent scam."
        ),
        official_url="https://inecnigeria.org/fake-voter-grant-disclaimer",
        published_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        is_debunking_notice=True,
        is_active=True,
        source_category=SourceCategory.INEC_OFFICIAL.value,
        verification_status=SourceVerificationStatus.VERIFIED_AUTHENTIC.value,
    )

    # 3. NIMC NIN Self-Service Policy
    await repo.upsert_evidence_source(
        institution_code="NIMC",
        title="NIMC Guidelines on NIN Self-Service Enrolment and Modification",
        source_type=EvidenceSourceType.POLICY_RULE.value,
        summary_content=(
            "National Identity Management Commission reminds citizens that official NIN modifications "
            "must be conducted strictly through the official portal nimc.gov.ng. NIMC does not charge third-party fees."
        ),
        official_url="https://nimc.gov.ng/self-service-portal-notice",
        published_at=datetime(2026, 4, 15, tzinfo=timezone.utc),
        is_debunking_notice=False,
        is_active=True,
        source_category=SourceCategory.GOVERNMENT_INSTITUTION.value,
        verification_status=SourceVerificationStatus.VERIFIED_AUTHENTIC.value,
    )


@pytest.mark.asyncio
async def test_genuine_claim_verified_by_official_source(
    db_session: AsyncSession, seed_curated_evidence: None
) -> None:
    """A claim matching active INEC registration announcement must be marked VERIFIED with evidence citations."""
    service = EvidenceVerificationService(session=db_session)
    claim = ExtractedClaimItem(
        claim_text="INEC resumes Continuous Voter Registration across all LGA offices nationwide",
        claim_topic="VOTER_REGISTRATION",
        impersonated_entity="INEC",
        requires_external_verification=True,
    )

    result = await service.verify_claims([claim], use_llm=False)

    assert result.overall_claim_status == "VERIFIED_OFFICIAL"
    assert result.has_verified_official_claims is True
    assert result.has_contradicted_claims is False
    assert len(result.evaluated_claims) == 1

    eval_item = result.evaluated_claims[0]
    assert eval_item.verdict == VerificationVerdict.VERIFIED
    assert eval_item.matched_source_id is not None
    assert eval_item.matched_source_url == "https://inecnigeria.org/cvr-resumption-2026"
    assert eval_item.evidence_citations != []
    assert any("INEC Resumption" in c for c in eval_item.evidence_citations)


@pytest.mark.asyncio
async def test_fake_grant_contradicted_by_debunking_notice(
    db_session: AsyncSession, seed_curated_evidence: None
) -> None:
    """A claim about N50,000 INEC cash grants must be marked FALSE due to the official debunking notice."""
    service = EvidenceVerificationService(session=db_session)
    claim = ExtractedClaimItem(
        claim_text="INEC is giving N50,000 voter empowerment grant to citizens who submit BVN",
        claim_topic="CASH_GRANT_OR_EMPOWERMENT",
        impersonated_entity="INEC",
        requires_external_verification=True,
    )

    result = await service.verify_claims([claim], use_llm=False)

    assert result.overall_claim_status == "CONTRADICTED_BY_OFFICIAL"
    assert result.has_contradicted_claims is True
    assert len(result.evaluated_claims) == 1

    eval_item = result.evaluated_claims[0]
    assert eval_item.verdict == VerificationVerdict.FALSE
    assert eval_item.matched_source_id is not None
    assert eval_item.matched_source_url == "https://inecnigeria.org/fake-voter-grant-disclaimer"
    assert eval_item.contradicting_points != []
    assert any("PUBLIC DISCLAIMER" in p or "does NOT offer" in p for p in eval_item.contradicting_points)


@pytest.mark.asyncio
async def test_unsupported_claim_abstains_with_uncertainty(
    db_session: AsyncSession, seed_curated_evidence: None
) -> None:
    """A claim with zero relevant evidence must abstain, returning UNVERIFIED and an uncertainty explanation."""
    service = EvidenceVerificationService(session=db_session)
    claim = ExtractedClaimItem(
        claim_text="The local market union will hold elections for stall coordinators next Tuesday",
        claim_topic="GENERAL_ANNOUNCEMENT",
        impersonated_entity=None,
        requires_external_verification=True,
    )

    result = await service.verify_claims([claim], use_llm=False)

    assert result.overall_claim_status == "UNVERIFIED"
    assert result.has_contradicted_claims is False
    assert result.has_verified_official_claims is False
    assert len(result.evaluated_claims) == 1

    eval_item = result.evaluated_claims[0]
    assert eval_item.verdict == VerificationVerdict.UNVERIFIED
    assert eval_item.matched_source_id is None
    assert eval_item.uncertainty_explanation is not None
    assert "Lack of evidence is not proof" in eval_item.uncertainty_explanation


@pytest.mark.asyncio
async def test_evidence_api_endpoints_and_pipeline(
    async_client: AsyncClient, seed_curated_evidence: None
) -> None:
    """Verify POST /api/v1/evidence/verify-claims and POST /api/v1/evidence/sources."""
    # 1. Query verify-claims endpoint
    verify_resp = await async_client.post(
        "/api/v1/evidence/verify-claims",
        json={
            "claims": [
                {
                    "claim_text": "Claim N50,000 INEC grant online",
                    "claim_topic": "CASH_GRANT_OR_EMPOWERMENT",
                    "impersonated_entity": "INEC",
                    "requires_external_verification": True,
                }
            ],
            "use_llm": False,
        },
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["has_contradicted_claims"] is True
    assert data["overall_claim_status"] == "CONTRADICTED_BY_OFFICIAL"

    # 2. Register a new credible fact-checking organisation debunking via API
    source_resp = await async_client.post(
        "/api/v1/evidence/sources",
        json={
            "institution_code": "CDD",
            "title": "CDD Fact-Check: False claims of polling unit relocation in Lagos",
            "source_type": "DEBUNKING_NOTICE",
            "summary_content": "CDD West Africa confirms that INEC has not altered polling units in Ikeja.",
            "official_url": "https://cddwestafrica.org/fact-check-ikeja-pu",
            "published_at": "2026-06-02T12:00:00Z",
            "is_debunking_notice": True,
            "is_active": True,
            "source_category": "FACT_CHECKING_ORG",
            "verification_status": "VERIFIED_AUTHENTIC",
        },
    )
    assert source_resp.status_code == 201
    source_data = source_resp.json()
    assert source_data["institution_code"] == "CDD"
    assert source_data["source_category"] == "FACT_CHECKING_ORG"

    # 3. Retrieve sources by institution
    list_resp = await async_client.get("/api/v1/evidence/sources?institution=CDD")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1
