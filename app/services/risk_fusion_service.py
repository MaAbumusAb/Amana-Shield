"""Deterministic Decision Matrix & Localized Explanation Generator for Risk Fusion.

Enforces auditable, evidence-backed rules without black-box score collapse.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from app.models.entities import (
    ClaimVerificationStatus,
    ConfidenceLevel,
    InternalStatus,
    MessageRisk,
    PublicVerdict,
    UrlRisk,
)
from app.schemas.ai_analysis import AIAnalysisResult
from app.schemas.evidence import EvidenceVerificationResult
from app.schemas.fusion import (
    LocalizedExplanation,
    RiskFusionEvaluation,
    SupportedLanguage,
)
from app.schemas.triage import DeterministicTriageResult


def compute_risk_fusion(
    triage_result: Optional[DeterministicTriageResult],
    ai_result: Optional[AIAnalysisResult],
    evidence_result: Optional[EvidenceVerificationResult],
    submission_id: Optional[uuid.UUID] = None,
    preferred_language: SupportedLanguage = SupportedLanguage.ENGLISH,
) -> RiskFusionEvaluation:
    """Fuse the three independent pillars into a transparent public verdict and localized explanation."""
    # 1. Resolve Pillar 1: url_risk
    if triage_result is not None:
        url_risk = triage_result.aggregated_url_risk
    else:
        url_risk = UrlRisk.NO_URL

    # 2. Resolve Pillar 2: message_risk
    if ai_result is not None:
        message_risk = ai_result.assessed_message_risk
    else:
        message_risk = MessageRisk.LOW

    # 3. Resolve Pillar 3: claim_verification_status
    if evidence_result is not None:
        raw_status = evidence_result.overall_claim_status
        try:
            claim_status = ClaimVerificationStatus(raw_status)
        except ValueError:
            claim_status = ClaimVerificationStatus.UNVERIFIED
    else:
        claim_status = ClaimVerificationStatus.UNVERIFIED

    triggered_rules: list[str] = []
    reasons: list[str] = []
    evidence_points: list[str] = []
    uncertainty_indicators: list[str] = []

    # Gather evidence & triage signals
    if triage_result is not None:
        for r in triage_result.risk_indicators:
            triggered_rules.append(r.code)
            reasons.append(r.description)
            if r.evidence:
                evidence_points.append(f"{r.code}: {r.evidence}")

    if ai_result is not None:
        for ind in ai_result.scam_indicators:
            code = f"AI-{ind.category.value}"
            triggered_rules.append(code)
            reasons.append(ind.description)
            if ind.evidence_excerpt:
                evidence_points.append(f"Excerpt: \"{ind.evidence_excerpt}\"")
        if ai_result.prompt_injection_detected:
            triggered_rules.append("SEC-PROMPT-INJECTION-SANDBOXED")
            reasons.append("Message contained instructions attempting to bypass security checks.")

    if evidence_result is not None:
        for ev in evidence_result.evaluated_claims:
            for c in ev.contradicting_points:
                reasons.append(c)
            for s in ev.supporting_points:
                reasons.append(s)
            for cit in ev.evidence_citations:
                evidence_points.append(f"Curated Source: {cit}")
            if ev.uncertainty_explanation:
                uncertainty_indicators.append(ev.uncertainty_explanation)

    # 4. Deterministic Decision Matrix Evaluation
    # Rule 1: Confirmed malicious destination or threat intelligence indicator
    if url_risk == UrlRisk.MALICIOUS:
        verdict = PublicVerdict.MALICIOUS
        review_status = InternalStatus.CONFIRMED
        triggered_rules.append("RF-RULE-01-CONFIRMED-MALICIOUS-DESTINATION")
        confidence = ConfidenceLevel.HIGH

    # Rule 2: Critical message risk (sensitive credential theft / advance-fee) + non-official URL or contradicted claim
    elif message_risk == MessageRisk.CRITICAL and (
        url_risk in {UrlRisk.SUSPICIOUS, UrlRisk.UNKNOWN, UrlRisk.NO_URL}
        or claim_status == ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL
    ):
        verdict = PublicVerdict.MALICIOUS
        review_status = InternalStatus.UNDER_REVIEW
        triggered_rules.append("RF-RULE-02-CRITICAL-SCAM-OR-CREDENTIAL-THEFT")
        confidence = ConfidenceLevel.HIGH

    # Rule 3: Contradicted claim by official announcement/debunking notice
    elif claim_status == ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL:
        verdict = PublicVerdict.SUSPICIOUS
        review_status = InternalStatus.UNDER_REVIEW
        triggered_rules.append("RF-RULE-03-CONTRADICTED-BY-OFFICIAL-EVIDENCE")
        confidence = ConfidenceLevel.HIGH

    # Rule 4: Suspicious URL (brand lookalike, IDN punycode, shortener) or High message risk
    elif url_risk == UrlRisk.SUSPICIOUS or message_risk == MessageRisk.HIGH:
        verdict = PublicVerdict.SUSPICIOUS
        review_status = InternalStatus.UNDER_REVIEW
        triggered_rules.append("RF-RULE-04-SUSPICIOUS-INDICATORS-DETECTED")
        confidence = ConfidenceLevel.HIGH

    # Rule 5: Medium message risk without URL or with unknown URL
    elif message_risk == MessageRisk.MEDIUM:
        verdict = PublicVerdict.SUSPICIOUS
        review_status = InternalStatus.UNDER_REVIEW
        triggered_rules.append("RF-RULE-05-MEDIUM-RISK-PERSUASION-INDICATORS")
        confidence = ConfidenceLevel.MEDIUM

    # Rule 6: Legitimate / verified official domain present
    elif url_risk == UrlRisk.VERIFIED_OFFICIAL:
        # Crucial principle: Verified domain alone DOES NOT make the entire message official
        # unless claims are verified and message risk is low.
        if claim_status == ClaimVerificationStatus.VERIFIED_OFFICIAL and message_risk in {
            MessageRisk.NONE,
            MessageRisk.LOW,
        }:
            verdict = PublicVerdict.OFFICIAL
            review_status = InternalStatus.CONFIRMED
            triggered_rules.append("RF-RULE-06A-VERIFIED-OFFICIAL-MESSAGE-AND-DOMAIN")
            confidence = ConfidenceLevel.HIGH
        else:
            verdict = PublicVerdict.UNVERIFIED
            review_status = InternalStatus.UNDER_REVIEW
            triggered_rules.append("RF-RULE-06B-OFFICIAL-DOMAIN-WITH-UNVERIFIED-CLAIMS")
            reasons.append(
                "Contains a link to an official website, but the accompanying claims have not been officially confirmed."
            )
            uncertainty_indicators.append(
                "Scammers sometimes share genuine government links alongside fake instructions or phone numbers."
            )
            confidence = ConfidenceLevel.MEDIUM

    # Rule 7: Genuine claim verified, no malicious URL
    elif (
        claim_status == ClaimVerificationStatus.VERIFIED_OFFICIAL
        and message_risk in {MessageRisk.NONE, MessageRisk.LOW}
        and url_risk in {UrlRisk.NO_URL, UrlRisk.BENIGN_KNOWN}
    ):
        verdict = PublicVerdict.OFFICIAL
        review_status = InternalStatus.CONFIRMED
        triggered_rules.append("RF-RULE-07-VERIFIED-OFFICIAL-CLAIM-NO-RISK")
        confidence = ConfidenceLevel.HIGH

    # Rule 8: Unverified / Unknown destination or insufficient evidence
    else:
        verdict = PublicVerdict.UNVERIFIED
        review_status = InternalStatus.UNDER_REVIEW
        triggered_rules.append("RF-RULE-08-INSUFFICIENT-EVIDENCE-ABSTAIN")
        confidence = ConfidenceLevel.LOW
        uncertainty_indicators.append(
            "There is not enough official evidence yet to verify or refute this message. A lack of evidence is not proof that the claim is false."
        )

    # 5. Generate Clear, Jargon-Free Localized Explanations (English & Hausa)
    english_explanation = _build_localized_explanation(
        lang=SupportedLanguage.ENGLISH,
        verdict=verdict,
        message_risk=message_risk,
        url_risk=url_risk,
        claim_status=claim_status,
        reasons=reasons,
        evidence_points=evidence_points,
        uncertainty_indicators=uncertainty_indicators,
    )

    hausa_explanation = _build_localized_explanation(
        lang=SupportedLanguage.HAUSA,
        verdict=verdict,
        message_risk=message_risk,
        url_risk=url_risk,
        claim_status=claim_status,
        reasons=reasons,
        evidence_points=evidence_points,
        uncertainty_indicators=uncertainty_indicators,
    )

    chosen_explanation = (
        hausa_explanation if preferred_language == SupportedLanguage.HAUSA else english_explanation
    )

    is_degraded = False
    if ai_result and ai_result.is_degraded:
        is_degraded = True
    if triage_result and bool(triage_result.unavailable_checks):
        is_degraded = True

    return RiskFusionEvaluation(
        submission_id=submission_id,
        message_risk=message_risk,
        url_risk=url_risk,
        claim_verification_status=claim_status,
        verdict=verdict,
        review_status=review_status,
        triggered_rules=list(dict.fromkeys(triggered_rules)),
        reasons=list(dict.fromkeys(reasons)),
        evidence=list(dict.fromkeys(evidence_points)),
        confidence=confidence,
        uncertainty_indicators=list(dict.fromkeys(uncertainty_indicators)),
        primary_explanation=chosen_explanation,
        available_localizations={
            SupportedLanguage.ENGLISH.value: english_explanation,
            SupportedLanguage.HAUSA.value: hausa_explanation,
        },
        recommended_action=chosen_explanation.recommended_action,
        assessment_timestamp=datetime.now(timezone.utc),
        is_degraded_mode=is_degraded,
    )


def _build_localized_explanation(
    lang: SupportedLanguage,
    verdict: PublicVerdict,
    message_risk: MessageRisk,
    url_risk: UrlRisk,
    claim_status: ClaimVerificationStatus,
    reasons: list[str],
    evidence_points: list[str],
    uncertainty_indicators: list[str],
) -> LocalizedExplanation:
    """Format clear, user-facing explanation in plain English or Hausa."""
    if lang == SupportedLanguage.HAUSA:
        # Hausa localization
        if verdict == PublicVerdict.MALICIOUS:
            badge = "🚨 HATSARI (MALICIOUS)"
            summary = "Wannan sakon ya kunshi damfara ko kuma link mai hatsarin gaske."
            action = (
                "KADA KA DANNA LINK DIN, kuma kada ka bada lambar BVN, NIN, ko kudi. "
                "Goge wannan sakon nan take."
            )
        elif verdict == PublicVerdict.SUSPICIOUS:
            badge = "⚠️ ABIN ZATO (SUSPICIOUS)"
            summary = "Wannan sakon yana da alamun damfara ko kuma labaran karya na zabe."
            action = (
                "Kada ka yi gaggawar turawa mutane. Tabbatar da sanarwar daga shafin hukuma "
                "(misali: inecnigeria.org)."
            )
        elif verdict == PublicVerdict.OFFICIAL:
            badge = "✅ TABBATACCE DAGA HUKUMA (OFFICIAL)"
            summary = "Wannan sanarwa ce ta gaskiya wacce ta fito daga hukumar zabe ko gwamnati."
            action = "Kuna iya bin umarnin da ke cikin wannan sanarwa ta hanyar shafin hukuma."
        else:
            badge = "❓ BA A TABBATAR BA (UNVERIFIED)"
            summary = "Ba a samu cikakkun shaidu daga hukumomi ba don tabbatar da wannan sakon."
            action = (
                "Kada ka tura ko kuma ka bayar da bayananka har sai an samu tabbaci daga hukuma."
            )

        user_reasons = (
            reasons[:3]
            if reasons
            else ["Babu cikakkun bayanai a shafukan hukumomi."]
        )
        uncertainty = (
            uncertainty_indicators[0]
            if uncertainty_indicators
            else None
        )

        return LocalizedExplanation(
            language=SupportedLanguage.HAUSA,
            verdict_badge=badge,
            summary=summary,
            reasons=user_reasons,
            recommended_action=action,
            evidence_points=evidence_points[:3],
            uncertainty_note=uncertainty,
        )

    # English localization (default)
    if verdict == PublicVerdict.MALICIOUS:
        badge = "🚨 HIGH RISK (MALICIOUS)"
        summary = "This message contains confirmed scam tactics, fake portals, or dangerous links."
        action = (
            "DO NOT click the link, and NEVER share your BVN, NIN, OTP, or pay any fee. "
            "Delete or ignore this message."
        )
    elif verdict == PublicVerdict.SUSPICIOUS:
        badge = "⚠️ SUSPICIOUS (CAUTION)"
        summary = "This message shows strong warning signs of an electoral or government-related scam."
        action = (
            "Do not forward this message. Verify all announcements directly on official websites "
            "(such as https://inecnigeria.org)."
        )
    elif verdict == PublicVerdict.OFFICIAL:
        badge = "✅ VERIFIED OFFICIAL"
        summary = "This announcement is verified and confirmed by authentic official sources."
        action = "You can safely follow the official guidance provided on the verified portal."
    else:
        badge = "❓ UNVERIFIED"
        summary = "There is currently not enough official evidence to verify or disprove this message."
        action = (
            "Do not click unfamiliar links or share personal details until official confirmation is available."
        )

    user_reasons = (
        reasons[:3]
        if reasons
        else ["The claims in this message could not be matched with authentic government records."]
    )
    uncertainty = (
        uncertainty_indicators[0]
        if uncertainty_indicators
        else None
    )

    return LocalizedExplanation(
        language=SupportedLanguage.ENGLISH,
        verdict_badge=badge,
        summary=summary,
        reasons=user_reasons,
        recommended_action=action,
        evidence_points=evidence_points[:3],
        uncertainty_note=uncertainty,
    )
