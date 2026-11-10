"""Automated tests for Public Verification UI, Analyst Dashboard API, and authentication."""

from __future__ import annotations

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.entities import (
    Assessment,
    ClaimVerificationStatus,
    Domain,
    DomainClassification,
    IndicatorStatus,
    IndicatorType,
    InternalStatus,
    MessageRisk,
    PublicVerdict,
    Submission,
    SubmissionChannel,
    UrlRisk,
)
from app.repositories.submissions import SubmissionRepository


# =========================================================================
# 1. UI Static Endpoint Tests
# =========================================================================

@pytest.mark.asyncio
async def test_public_portal_serves_html(async_client: AsyncClient) -> None:
    """Verify GET / returns the Public Verification Portal."""
    response = await async_client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "AMANA SHIELD" in response.text
    assert "Citizen Protection" in response.text


@pytest.mark.asyncio
async def test_analyst_dashboard_serves_html(async_client: AsyncClient) -> None:
    """Verify GET /analyst returns the Analyst Portal UI."""
    response = await async_client.get("/analyst")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "Analyst" in response.text


# =========================================================================
# 2. Analyst API Authentication & Guardrails
# =========================================================================

@pytest.mark.asyncio
async def test_analyst_overview_requires_auth(async_client: AsyncClient) -> None:
    """Reject unauthenticated requests to analyst endpoints."""
    response = await async_client.get("/api/v1/analyst/overview")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_analyst_overview_rejects_invalid_key(async_client: AsyncClient) -> None:
    """Reject requests with wrong analyst key."""
    response = await async_client.get(
        "/api/v1/analyst/overview",
        headers={"X-Analyst-Key": "wrong-key-value"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_analyst_overview_accepts_valid_key(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Accept requests with correct X-Analyst-Key."""
    key = test_settings.ANALYST_API_KEY.get_secret_value()
    response = await async_client.get(
        "/api/v1/analyst/overview",
        headers={"X-Analyst-Key": key},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_submissions" in data
    assert "malicious_count" in data
    assert "suspicious_count" in data


@pytest.mark.asyncio
async def test_analyst_overview_bearer_auth(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Accept Authorization: Bearer <key> as alternative header format."""
    key = test_settings.ANALYST_API_KEY.get_secret_value()
    response = await async_client.get(
        "/api/v1/analyst/overview",
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 200


# =========================================================================
# 3. Analyst Submissions Queue, Detail, & Review Audit
# =========================================================================

@pytest.mark.asyncio
async def test_analyst_submissions_queue_and_detail(
    async_client: AsyncClient,
    test_settings: Settings,
    db_session: AsyncSession,
) -> None:
    """Verify queue listing, filtering, and deep detail inspection."""
    key = test_settings.ANALYST_API_KEY.get_secret_value()
    repo = SubmissionRepository(db_session)

    # Seed a test submission and assessment
    sub = Submission(
        channel=SubmissionChannel.WEB.value,
        external_message_id="web-test-queue-1",
        sender_hash="hash-123",
        raw_text="Urgent: Claim your 50,000 PVC support at http://fake-inec.net",
        normalised_text="Urgent: Claim your 50,000 PVC support at http://fake-inec.net",
        content_sha256="sha-12345",
        extracted_urls=["http://fake-inec.net"],
        processing_status="COMPLETED",
    )
    ass = Assessment(
        submission_id=sub.id,
        message_risk=MessageRisk.HIGH.value,
        url_risk=UrlRisk.MALICIOUS.value,
        claim_verification_status=ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL.value,
        public_verdict=PublicVerdict.MALICIOUS.value,
        internal_status=InternalStatus.UNDER_REVIEW.value,
        triggered_rules=["R1_CONFIRMED_MALICIOUS_DESTINATION"],
        triage_findings={"url_count": 1},
        ai_heuristics={"urgency": True},
        explanation_text="Confirmed phishing message impersonating INEC.",
        recommended_action="Do not open the link.",
    )
    await repo.create_submission_with_assessment(sub, ass)

    # List submissions queue
    res = await async_client.get(
        "/api/v1/analyst/submissions?verdict=MALICIOUS",
        headers={"X-Analyst-Key": key},
    )
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1
    target = next((item for item in items if item["id"] == str(sub.id)), None)
    assert target is not None
    assert target["public_verdict"] == "MALICIOUS"
    assert target["internal_status"] == "UNDER_REVIEW"

    # Inspect single submission detail
    detail_res = await async_client.get(
        f"/api/v1/analyst/submissions/{sub.id}",
        headers={"X-Analyst-Key": key},
    )
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["raw_text"] == sub.raw_text
    assert detail["public_verdict"] == "MALICIOUS"
    assert "R1_CONFIRMED_MALICIOUS_DESTINATION" in detail["triggered_rules"]

    # Analyst review action: update status to CONFIRMED
    review_res = await async_client.post(
        f"/api/v1/analyst/submissions/{sub.id}/review",
        headers={"X-Analyst-Key": key},
        json={
            "status": "CONFIRMED",
            "reviewer_notes": "Verified against INEC official press release. Phishing domain verified.",
        },
    )
    assert review_res.status_code == 200
    review_data = review_res.json()
    assert review_data["previous_status"] == "UNDER_REVIEW"
    assert review_data["new_status"] == "CONFIRMED"


# =========================================================================
# 4. Analyst Domain Reclassification & Threat Indicators
# =========================================================================

@pytest.mark.asyncio
async def test_analyst_domain_reclassification(
    async_client: AsyncClient,
    test_settings: Settings,
    db_session: AsyncSession,
) -> None:
    """Verify domain list and reclassification."""
    key = test_settings.ANALYST_API_KEY.get_secret_value()

    # Seed a domain
    dom = Domain(
        canonical_host="suspicious-voter-check.ng",
        registered_domain="suspicious-voter-check.ng",
        tld_suffix="ng",
        is_idn_punycode=False,
        classification=DomainClassification.SUSPICIOUS.value,
        status="ACTIVE",
    )
    db_session.add(dom)
    await db_session.commit()
    await db_session.refresh(dom)

    # List domains
    list_res = await async_client.get(
        "/api/v1/analyst/domains?classification=SUSPICIOUS",
        headers={"X-Analyst-Key": key},
    )
    assert list_res.status_code == 200
    assert any(d["id"] == str(dom.id) for d in list_res.json())

    # Reclassify to MALICIOUS
    reclass_res = await async_client.post(
        f"/api/v1/analyst/domains/{dom.id}/classification",
        headers={"X-Analyst-Key": key},
        json={
            "classification": "MALICIOUS",
            "reason": "Confirmed hosting phishing login form",
        },
    )
    assert reclass_res.status_code == 200
    assert reclass_res.json()["classification"] == "MALICIOUS"


@pytest.mark.asyncio
async def test_analyst_threat_indicator_creation(
    async_client: AsyncClient,
    test_settings: Settings,
) -> None:
    """Verify analyst can manually register confirmed threat indicators."""
    key = test_settings.ANALYST_API_KEY.get_secret_value()

    res = await async_client.post(
        "/api/v1/analyst/threat-indicators",
        headers={"X-Analyst-Key": key},
        json={
            "indicator_type": "URL",
            "indicator_value": "http://fraud-empowerment-portal.com/login",
            "threat_category": "CREDENTIAL_HARVESTING",
            "status": "CONFIRMED",
            "reason": "Harvesting NIN and bank account numbers",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["indicator_type"] == "URL"
