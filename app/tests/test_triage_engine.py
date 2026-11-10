"""Comprehensive tests for Task 5: Deterministic URL and Domain Intelligence Engine.

Uses controlled test fixtures and mock HTTP/DNS transports. Never contacts real malicious websites.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.integrations.domain_intel import RDAPIntelligenceClient
from app.integrations.safe_redirect import SafeRedirectInspector
from app.models.entities import (
    ConfidenceLevel,
    DomainClassification,
    IndicatorStatus,
    IndicatorType,
    UrlRisk,
)
from app.repositories.submissions import DomainRepository, ThreatIndicatorRepository
from app.schemas.triage import DomainRegistryUpsertRequest, ThreatIndicatorUpsertRequest
from app.services.triage_service import DeterministicTriageService
from app.utils.text import extract_urls_from_text, parse_and_normalise_url


def test_normal_and_multiple_url_extraction_and_normalisation() -> None:
    """Extract multiple URLs, strip tracking parameters, and extract subdomain/domain/suffix."""
    text = (
        "Visit the voter portal at https://CVR.Inecnigeria.org/login?utm_source=whatsapp&step=2 "
        "or check www.nimc.gov.ng/enrollment/ for details."
    )
    findings = extract_urls_from_text(text)
    assert len(findings) == 2

    first = findings[0]
    assert first.normalised_url == "https://cvr.inecnigeria.org/login?step=2"
    assert first.canonical_host == "cvr.inecnigeria.org"
    assert first.registered_domain == "inecnigeria.org"
    assert first.subdomain == "cvr"
    assert first.tld_suffix == "org"
    assert not first.is_malformed

    second = findings[1]
    assert second.normalised_url == "https://www.nimc.gov.ng/enrollment/"
    assert second.canonical_host == "www.nimc.gov.ng"
    assert second.registered_domain == "nimc.gov.ng"
    assert second.subdomain == "www"
    assert second.tld_suffix == "gov.ng"


def test_defanged_and_shortened_url_recognition() -> None:
    """Recognise defanged URLs (hxxps, [.], (dot)) and flag URL shorteners."""
    text = (
        "Claim grant at hxxps://inec-palliative[.]com[.]ng/claim or via https://bit.ly/3xYzTest"
    )
    findings = extract_urls_from_text(text)
    assert len(findings) == 2

    defanged = findings[0]
    assert defanged.was_defanged is True
    assert defanged.normalised_url == "https://inec-palliative.com.ng/claim"
    assert defanged.registered_domain == "inec-palliative.com.ng"
    assert defanged.tld_suffix == "com.ng"

    shortened = findings[1]
    assert shortened.is_shortened_url is True
    assert shortened.registered_domain == "bit.ly"


def test_idn_punycode_and_homograph_detection() -> None:
    """Detect Unicode IDN / punycode domains and mixed-script homographs."""
    # Cyrillic 'і' (\u0456) in 'іnecnigeria.org'
    idn_text = "Verify your PVC at https://\u0456necnigeria.org/verify"
    findings = extract_urls_from_text(idn_text)
    assert len(findings) == 1
    f = findings[0]
    assert f.is_idn_punycode is True
    assert f.has_mixed_script_or_confusable is True
    assert f.canonical_host == "xn--necnigeria-w2i.org"
    assert f.unicode_host == "\u0456necnigeria.org"


def test_malformed_url_handling() -> None:
    """Reject embedded authority credentials, invalid ports, and malformed hosts safely."""
    cred_url = parse_and_normalise_url(
        "https://inecnigeria.org:pass@evil-phish.example.com/login"
    )
    assert cred_url is not None
    assert cred_url.is_malformed is True
    assert "userinfo/credentials" in (cred_url.malformed_reason or "")

    bad_port_url = parse_and_normalise_url("https://example.com:99999/test")
    assert bad_port_url is not None
    assert bad_port_url.is_malformed is True
    assert "Invalid port" in (bad_port_url.malformed_reason or "")


@pytest.mark.asyncio
async def test_known_malicious_and_verified_official_domain_registry(
    db_session: AsyncSession,
) -> None:
    """Test domain registry metadata, confirmed malicious matches, and verified official domain handling."""
    domain_repo = DomainRepository(db_session)
    threat_repo = ThreatIndicatorRepository(db_session)

    review_dt = datetime.now(timezone.utc) + timedelta(days=30)

    # 1. Register verified official domain
    await domain_repo.upsert_domain_registry(
        DomainRegistryUpsertRequest(
            canonical_host="cvr.inecnigeria.org",
            classification=DomainClassification.OFFICIAL,
            official_institution="INEC",
            source="INEC_OFFICIAL_REGISTRY",
            reason="Official INEC Continuous Voter Registration portal",
            status="ACTIVE",
            review_date=review_dt,
            reviewer="lead_analyst",
        )
    )

    # 2. Register confirmed malicious domain in registry
    await domain_repo.upsert_domain_registry(
        DomainRegistryUpsertRequest(
            canonical_host="inec-cash-grant2026.com.ng",
            classification=DomainClassification.MALICIOUS,
            source="NGCERT_ADVISORY",
            reason="Confirmed BVN harvesting portal impersonating INEC",
            status="ACTIVE",
            review_date=review_dt,
            reviewer="sec_analyst_01",
        )
    )

    # 3. Register confirmed URL threat indicator
    await threat_repo.upsert_indicator(
        ThreatIndicatorUpsertRequest(
            indicator_type=IndicatorType.URL,
            indicator_value="https://scam-portal.example.org/bvn-form",
            threat_category="CREDENTIAL_HARVESTING",
            confidence_level=ConfidenceLevel.HIGH,
            status=IndicatorStatus.CONFIRMED,
            source_origin="ANALYST_CONFIRMED",
            reason="Confirmed phishing form path",
            reviewer="sec_analyst_01",
        )
    )

    service = DeterministicTriageService(session=db_session)

    # Case A: Known malicious domain
    mal_res = await service.analyse_text(
        "Click https://inec-cash-grant2026.com.ng/apply to claim."
    )
    assert mal_res.aggregated_url_risk == UrlRisk.MALICIOUS
    assert any(m.classification == "MALICIOUS" for m in mal_res.threat_matches)
    assert any(
        r.code == "TR-DOMAIN-REGISTRY-MALICIOUS" for r in mal_res.risk_indicators
    )

    # Case B: Verified official domain (must include trust_warning that message still requires verification)
    off_res = await service.analyse_text(
        "Register at https://cvr.inecnigeria.org/ today."
    )
    assert off_res.aggregated_url_risk == UrlRisk.VERIFIED_OFFICIAL
    assert off_res.contains_verified_official_domain is True
    assert off_res.trust_warning is not None
    assert "does not automatically make the surrounding message trustworthy" in off_res.trust_warning


@pytest.mark.asyncio
async def test_domain_age_is_weak_signal_never_conclusive_proof(
    db_session: AsyncSession,
) -> None:
    """A newly registered domain (e.g. 2 days old) with no malicious indicators must NOT be marked MALICIOUS."""

    async def _mock_rdap_handler(request: httpx.Request) -> httpx.Response:
        two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        return httpx.Response(
            status_code=200,
            json={
                "events": [{"eventAction": "registration", "eventDate": two_days_ago}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Registrar Ltd"]],
                        ],
                    }
                ],
            },
        )

    rdap_client = RDAPIntelligenceClient(
        http_transport=httpx.MockTransport(_mock_rdap_handler)
    )
    service = DeterministicTriageService(
        session=db_session,
        rdap_client=rdap_client,
    )

    res = await service.analyse_text(
        "Read our civic observer blog at https://civic-observers-forum.org/notes",
        run_rdap=True,
    )
    assert len(res.registration_info) == 1
    assert res.registration_info[0].domain_age_days is not None
    assert res.registration_info[0].domain_age_days <= 3
    # Verify weak signal is recorded
    age_indicators = [
        r for r in res.risk_indicators if r.code == "TR-NEWLY-REGISTERED-DOMAIN"
    ]
    assert len(age_indicators) == 1
    assert age_indicators[0].weight_category == "WEAK_SIGNAL"
    # Crucial invariant: domain age alone NEVER produces MALICIOUS or SUSPICIOUS url_risk
    assert res.aggregated_url_risk == UrlRisk.UNKNOWN


@pytest.mark.asyncio
async def test_private_ip_and_cloud_metadata_destinations_blocked(
    db_session: AsyncSession,
) -> None:
    """Private RFC1918, loopback, and cloud metadata IPs (169.254.169.254) must be flagged CRITICAL/MALICIOUS."""
    service = DeterministicTriageService(session=db_session)

    res = await service.analyse_text(
        "Check http://169.254.169.254/latest/meta-data/ and http://192.168.1.1/admin"
    )
    assert len(res.extracted_urls) == 2
    assert all(u.is_private_or_reserved_ip for u in res.extracted_urls)
    assert res.aggregated_url_risk == UrlRisk.MALICIOUS
    assert any(
        r.code == "TR-PRIVATE-OR-RESERVED-IP-URL" for r in res.risk_indicators
    )


@pytest.mark.asyncio
async def test_malicious_redirect_to_private_ip_and_dns_rebinding_blocked(
    db_session: AsyncSession,
) -> None:
    """SafeRedirectInspector must follow benign hops and immediately block redirects to loopback/private IPs or DNS rebinding."""
    # Scenario 1: Public shortener redirects to cloud metadata IP 169.254.169.254
    async def _mock_ip_resolver(hostname: str) -> list[str]:
        if hostname == "bit.ly":
            return ["67.199.248.10"]
        if hostname == "internal.evil.example":
            return ["10.0.0.42"]
        return ["93.184.216.34"]

    async def _mock_http_handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "bit.ly":
            return httpx.Response(
                status_code=302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            )
        return httpx.Response(status_code=200)

    inspector = SafeRedirectInspector(
        max_hops=3,
        ip_resolver=_mock_ip_resolver,
        http_transport=httpx.MockTransport(_mock_http_handler),
    )
    service = DeterministicTriageService(
        session=db_session,
        redirect_inspector=inspector,
    )

    result = await service.analyse_text(
        "Short link: https://bit.ly/evil-redirect",
        run_redirects=True,
    )
    assert len(result.redirect_findings) == 1
    rf = result.redirect_findings[0]
    assert rf.ssrf_or_rebinding_blocked is True
    assert "CLOUD_METADATA_OR_LINK_LOCAL_IP" in (rf.error_message or "")
    assert result.aggregated_url_risk == UrlRisk.MALICIOUS
    assert any(
        r.code == "TR-REDIRECT-SSRF-BLOCKED" for r in result.risk_indicators
    )

    # Scenario 2: DNS rebinding simulation (1st resolve returns public IP, 2nd resolve returns 127.0.0.1)
    call_counter = {"count": 0}

    async def _rebinding_resolver(hostname: str) -> list[str]:
        call_counter["count"] += 1
        if call_counter["count"] == 1:
            return ["93.184.216.34"]  # Public on first check
        return ["127.0.0.1"]  # Loopback on second check right before socket request

    rebinding_inspector = SafeRedirectInspector(
        max_hops=3,
        ip_resolver=_rebinding_resolver,
        http_transport=httpx.MockTransport(_mock_http_handler),
    )
    rebind_finding = await rebinding_inspector.inspect_url(
        "https://rebind-test.example.com/landing"
    )
    assert rebind_finding.ssrf_or_rebinding_blocked is True
    assert "DNS rebinding detected" in (rebind_finding.error_message or "")


@pytest.mark.asyncio
async def test_triage_api_endpoints(async_client: AsyncClient) -> None:
    """Verify POST /api/v1/triage/domains, POST /api/v1/triage/indicators, and POST /api/v1/triage/inspect."""
    # 1. Register an official domain via API
    dom_resp = await async_client.post(
        "/api/v1/triage/domains",
        json={
            "canonical_host": "inecnigeria.org",
            "classification": "OFFICIAL",
            "official_institution": "INEC",
            "source": "INEC_SEED",
            "reason": "Official INEC main domain",
            "status": "ACTIVE",
            "reviewer": "admin_01",
        },
    )
    assert dom_resp.status_code == 201
    dom_data = dom_resp.json()
    assert dom_data["canonical_host"] == "inecnigeria.org"
    assert dom_data["classification"] == "OFFICIAL"

    # 2. Inspect text containing both official domain and a lookalike phishing domain
    inspect_resp = await async_client.post(
        "/api/v1/triage/inspect",
        json={
            "text": (
                "Official site is https://inecnigeria.org but register for grant at "
                "hxxps://inec-voter-grant[.]com.ng/apply"
            )
        },
    )
    assert inspect_resp.status_code == 200
    body = inspect_resp.json()
    assert len(body["extracted_urls"]) == 2
    assert body["contains_verified_official_domain"] is True
    assert body["aggregated_url_risk"] == "SUSPICIOUS"
    assert body["trust_warning"] is not None
