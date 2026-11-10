"""Comprehensive decision-table tests for Task 8: AMANA SHIELD Risk Fusion Engine.

Covers exact decision-table matrix combinations:
1. Confirmed malicious URL -> MALICIOUS (Block recommendation).
2. Suspicious URL (Lookalike) -> SUSPICIOUS.
3. Verified official domain + unverified claims -> UNVERIFIED (Never auto-trusted).
4. Verified official domain + verified official claims -> OFFICIAL.
5. No URL + Critical scam indicators (BVN/Fee harvesting) -> MALICIOUS.
6. No URL + False claims contradicted by debunking notice -> SUSPICIOUS.
7. No URL + Unknown neutral claims -> UNVERIFIED (Abstains cleanly).
8. Young/new domain treated as weak signal -> UNVERIFIED (Never malicious solely due to age).
9. AI provider failure/unavailability -> Deterministic fallback behaves predictably.
10. Localization: Both English and Hausa explanations generated without changing detection engine.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import (
    ClaimVerificationStatus,
    ConfidenceLevel,
    EvidenceSourceType,
    InternalStatus,
    MessageRisk,
    PublicVerdict,
    UrlRisk,
)
from app.repositories.submissions import (
    DomainRepository,
    EvidenceSourceRepository,
    ThreatIndicatorRepository,
)
from app.schemas.ai_analysis import (
    AIAnalysisResult,
    ExtractedClaimItem,
    RequestedActionItem,
    RequestedActionType,
    ScamIndicatorItem,
    ScamPatternCategory,
)
from app.schemas.evidence import (
    ClaimVerificationEvaluation,
    EvidenceVerificationResult,
    RetrievedEvidenceItem,
    SourceCategory,
    VerificationVerdict,
)
from app.schemas.fusion import SupportedLanguage
from app.schemas.triage import (
    DeterministicTriageResult,
    ExtractedUrlFinding,
    NormalisedDomainSummary,
    RDAPRegistrationInfo,
    RiskIndicatorFinding,
    ThreatMatchFinding,
)
from app.services.risk_fusion_service import compute_risk_fusion


def _make_triage_result(
    url_risk: UrlRisk,
    canonical_host: str = "example.com.ng",
    has_threat_match: bool = False,
    is_young_domain: bool = False,
) -> DeterministicTriageResult:
    risk_indicators: list[RiskIndicatorFinding] = []
    reg_info: list[RDAPRegistrationInfo] = []

    if has_threat_match:
        risk_indicators.append(
            RiskIndicatorFinding(
                code="TR-CONFIRMED-THREAT-INDICATOR",
                severity="CRITICAL",
                weight_category="CONCLUSIVE_THREAT",
                target=canonical_host,
                description="Matched confirmed threat intelligence IOC.",
            )
        )

    if is_young_domain:
        risk_indicators.append(
            RiskIndicatorFinding(
                code="TR-NEWLY-REGISTERED-DOMAIN",
                severity="LOW",
                weight_category="WEAK_SIGNAL",
                target=canonical_host,
                description="Domain registered 3 days ago. Treated as weak signal.",
                evidence="age_days=3",
            )
        )
        reg_info.append(
            RDAPRegistrationInfo(
                lookup_status="SUCCESS",
                registered_domain=canonical_host,
                domain_age_days=3,
            )
        )

    return DeterministicTriageResult(
        extracted_urls=[
            ExtractedUrlFinding(
                raw_url=f"https://{canonical_host}",
                normalised_url=f"https://{canonical_host}",
                canonical_host=canonical_host,
                registered_domain=canonical_host,
            )
        ]
        if url_risk != UrlRisk.NO_URL
        else [],
        normalised_domains=[
            NormalisedDomainSummary(
                canonical_host=canonical_host,
                unicode_host=canonical_host,
                registered_domain=canonical_host,
                subdomain="",
                tld_suffix="com.ng",
                classification="OFFICIAL" if url_risk == UrlRisk.VERIFIED_OFFICIAL else "UNKNOWN",
            )
        ]
        if url_risk != UrlRisk.NO_URL
        else [],
        risk_indicators=risk_indicators,
        registration_info=reg_info,
        aggregated_url_risk=url_risk,
        contains_verified_official_domain=(url_risk == UrlRisk.VERIFIED_OFFICIAL),
    )


def _make_ai_result(
    message_risk: MessageRisk,
    is_degraded: bool = False,
    has_bvn_request: bool = False,
) -> AIAnalysisResult:
    indicators: list[ScamIndicatorItem] = []
    actions: list[RequestedActionItem] = []

    if has_bvn_request:
        actions.append(
            RequestedActionItem(
                action_type=RequestedActionType.SUBMIT_BVN,
                description="Submit BVN number",
                is_sensitive_or_financial=True,
                evidence_excerpt="send your BVN",
            )
        )
        indicators.append(
            ScamIndicatorItem(
                category=ScamPatternCategory.SENSITIVE_DATA_REQUEST,
                severity="CRITICAL",
                description="Demands bank verification details.",
                evidence_excerpt="BVN",
            )
        )

    return AIAnalysisResult(
        extracted_claims=[],
        mentioned_institutions=["INEC"] if message_risk != MessageRisk.LOW else [],
        requested_actions=actions,
        scam_indicators=indicators,
        impersonation_indicators=[],
        verification_requirements=[],
        explanation="Test AI summary",
        limitations=[],
        assessed_message_risk=message_risk,
        analysis_mode="FALLBACK_HEURISTIC" if is_degraded else "LLM_PRIMARY",
        is_degraded=is_degraded,
    )


def _make_evidence_result(
    claim_status: ClaimVerificationStatus,
) -> EvidenceVerificationResult:
    has_contra = (claim_status == ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL)
    has_verif = (claim_status == ClaimVerificationStatus.VERIFIED_OFFICIAL)

    evals: list[ClaimVerificationEvaluation] = []
    if has_contra:
        evals.append(
            ClaimVerificationEvaluation(
                claim_text="INEC pays N50,000 cash grant",
                claim_topic="CASH_GRANT",
                verdict=VerificationVerdict.FALSE,
                confidence=ConfidenceLevel.HIGH,
                contradicting_points=["Official INEC disclaimer: INEC does not distribute cash grants."],
                evidence_citations=["INEC Disclaimer Press Release (https://inecnigeria.org)"],
            )
        )
    elif has_verif:
        evals.append(
            ClaimVerificationEvaluation(
                claim_text="INEC voter registration resumes at LGA offices",
                claim_topic="VOTER_REGISTRATION",
                verdict=VerificationVerdict.VERIFIED,
                confidence=ConfidenceLevel.HIGH,
                supporting_points=["Supported by official INEC release dated May 2026."],
                evidence_citations=["Official CVR Resumption Notice (https://cvr.inecnigeria.org)"],
            )
        )

    return EvidenceVerificationResult(
        evaluated_claims=evals,
        overall_claim_status=claim_status.value,
        has_contradicted_claims=has_contra,
        has_verified_official_claims=has_verif,
        has_misleading_claims=False,
        sources_consulted_count=1 if (has_contra or has_verif) else 0,
        explanation="Evidence evaluation summary",
    )


# --------------------------------------------------------------------------- #
# Decision Table Tests
# --------------------------------------------------------------------------- #

def test_decision_table_confirmed_malicious_url_triggers_malicious_verdict() -> None:
    """Confirmed malicious URL must produce MALICIOUS verdict and block guidance."""
    triage = _make_triage_result(UrlRisk.MALICIOUS, has_threat_match=True)
    ai = _make_ai_result(MessageRisk.LOW)
    evid = _make_evidence_result(ClaimVerificationStatus.UNVERIFIED)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.MALICIOUS
    assert fusion.review_status == InternalStatus.CONFIRMED
    assert "RF-RULE-01-CONFIRMED-MALICIOUS-DESTINATION" in fusion.triggered_rules
    assert "DO NOT click the link" in fusion.recommended_action
    assert fusion.url_risk == UrlRisk.MALICIOUS
    assert fusion.message_risk == MessageRisk.LOW


def test_decision_table_suspicious_url_triggers_suspicious_verdict() -> None:
    """Suspicious URL (e.g., lookalike domain or shortener) must produce SUSPICIOUS."""
    triage = _make_triage_result(UrlRisk.SUSPICIOUS)
    ai = _make_ai_result(MessageRisk.LOW)
    evid = _make_evidence_result(ClaimVerificationStatus.UNVERIFIED)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.SUSPICIOUS
    assert fusion.review_status == InternalStatus.UNDER_REVIEW
    assert "RF-RULE-04-SUSPICIOUS-INDICATORS-DETECTED" in fusion.triggered_rules


def test_decision_table_official_domain_with_unverified_claims_never_auto_trusted() -> None:
    """Legitimate official domain does NOT prove accompanying message is genuine."""
    triage = _make_triage_result(UrlRisk.VERIFIED_OFFICIAL, canonical_host="inecnigeria.org")
    ai = _make_ai_result(MessageRisk.LOW)
    evid = _make_evidence_result(ClaimVerificationStatus.UNVERIFIED)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.UNVERIFIED
    assert fusion.review_status == InternalStatus.UNDER_REVIEW
    assert "RF-RULE-06B-OFFICIAL-DOMAIN-WITH-UNVERIFIED-CLAIMS" in fusion.triggered_rules
    assert any("Scammers sometimes share genuine government links" in u for u in fusion.uncertainty_indicators)


def test_decision_table_official_domain_with_verified_claims_yields_official() -> None:
    """Verified official domain + verified official claim + low message risk = OFFICIAL."""
    triage = _make_triage_result(UrlRisk.VERIFIED_OFFICIAL, canonical_host="inecnigeria.org")
    ai = _make_ai_result(MessageRisk.LOW)
    evid = _make_evidence_result(ClaimVerificationStatus.VERIFIED_OFFICIAL)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.OFFICIAL
    assert fusion.review_status == InternalStatus.CONFIRMED
    assert "RF-RULE-06A-VERIFIED-OFFICIAL-MESSAGE-AND-DOMAIN" in fusion.triggered_rules


def test_decision_table_no_url_with_critical_bvn_request_yields_malicious() -> None:
    """Strong scam indicators (sensitive BVN harvesting) without URL must yield MALICIOUS."""
    triage = _make_triage_result(UrlRisk.NO_URL)
    ai = _make_ai_result(MessageRisk.CRITICAL, has_bvn_request=True)
    evid = _make_evidence_result(ClaimVerificationStatus.UNVERIFIED)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.MALICIOUS
    assert fusion.url_risk == UrlRisk.NO_URL
    assert fusion.message_risk == MessageRisk.CRITICAL
    assert "RF-RULE-02-CRITICAL-SCAM-OR-CREDENTIAL-THEFT" in fusion.triggered_rules


def test_decision_table_false_claims_contradicted_by_evidence_yields_suspicious() -> None:
    """Contradicted claim surfaces official debunking notice and flags SUSPICIOUS."""
    triage = _make_triage_result(UrlRisk.NO_URL)
    ai = _make_ai_result(MessageRisk.LOW)
    evid = _make_evidence_result(ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.SUSPICIOUS
    assert fusion.claim_verification_status == ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL
    assert "RF-RULE-03-CONTRADICTED-BY-OFFICIAL-EVIDENCE" in fusion.triggered_rules
    assert any("Official INEC disclaimer" in r for r in fusion.reasons)


def test_decision_table_young_domain_treated_as_weak_signal_never_malicious_solely_on_age() -> None:
    """Domain age alone (3 days old) must NOT trigger MALICIOUS or SUSPICIOUS."""
    triage = _make_triage_result(UrlRisk.UNKNOWN, is_young_domain=True)
    ai = _make_ai_result(MessageRisk.LOW)
    evid = _make_evidence_result(ClaimVerificationStatus.UNVERIFIED)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.verdict == PublicVerdict.UNVERIFIED
    assert fusion.verdict != PublicVerdict.MALICIOUS
    assert "RF-RULE-08-INSUFFICIENT-EVIDENCE-ABSTAIN" in fusion.triggered_rules


def test_decision_table_ai_provider_failure_degrades_gracefully() -> None:
    """When AI provider fails or is degraded, fusion behaves predictably and marks is_degraded_mode=True."""
    triage = _make_triage_result(UrlRisk.NO_URL)
    ai = _make_ai_result(MessageRisk.LOW, is_degraded=True)
    evid = _make_evidence_result(ClaimVerificationStatus.UNVERIFIED)

    fusion = compute_risk_fusion(triage, ai, evid)

    assert fusion.is_degraded_mode is True
    assert fusion.verdict == PublicVerdict.UNVERIFIED
    assert fusion.message_risk == MessageRisk.LOW


def test_localization_generates_both_english_and_hausa_without_engine_changes() -> None:
    """Response structure includes English and Hausa explanations without changing detection matrix."""
    triage = _make_triage_result(UrlRisk.MALICIOUS, has_threat_match=True)
    ai = _make_ai_result(MessageRisk.CRITICAL, has_bvn_request=True)
    evid = _make_evidence_result(ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL)

    fusion_hausa = compute_risk_fusion(
        triage, ai, evid, preferred_language=SupportedLanguage.HAUSA
    )

    assert fusion_hausa.primary_explanation.language == SupportedLanguage.HAUSA
    assert "HATSARI" in fusion_hausa.primary_explanation.verdict_badge
    assert "KADA KA DANNA LINK DIN" in fusion_hausa.primary_explanation.recommended_action

    # English version also present in available_localizations
    en_expl = fusion_hausa.available_localizations.get("en")
    assert en_expl is not None
    assert en_expl.language == SupportedLanguage.ENGLISH
    assert "HIGH RISK" in en_expl.verdict_badge


@pytest.mark.asyncio
async def test_fusion_api_endpoint(async_client: AsyncClient) -> None:
    """Verify POST /api/v1/fusion/evaluate-text with both English and Hausa output."""
    resp = await async_client.post(
        "/api/v1/fusion/evaluate-text",
        json={
            "text": "Claim N50,000 FGN grant immediately at hxxps://inec-grant2026[.]com.ng/apply before midnight!",
            "language": "ha",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["message_risk"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert data["url_risk"] == "SUSPICIOUS"
    assert data["verdict"] in {"MALICIOUS", "SUSPICIOUS"}
    assert data["primary_explanation"]["language"] == "ha"
    assert "en" in data["available_localizations"]
    assert "ha" in data["available_localizations"]
