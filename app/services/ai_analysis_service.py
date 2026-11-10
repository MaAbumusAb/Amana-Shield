"""AI-Powered Scam Message Analysis Service.

Analyses submitted message content to extract claims, mentioned institutions,
requested user actions, scam/persuasion patterns, impersonation indicators,
and verification requirements.

Complements deterministic triage and includes a resilient local heuristic fallback
when the LLM provider times out, fails, or is unconfigured.
"""

from __future__ import annotations

import logging
import re

from app.integrations.llm_client import LLMClientError, StructuredLLMClient
from app.integrations.llm_prompts import detect_prompt_injection_attempt
from app.models.entities import ConfidenceLevel, MessageRisk
from app.schemas.ai_analysis import (
    AIAnalysisResult,
    ExtractedClaimItem,
    ImpersonationIndicatorItem,
    LLMStructuredOutputPayload,
    RequestedActionItem,
    RequestedActionType,
    ScamIndicatorItem,
    ScamPatternCategory,
)
from app.utils.text import extract_basic_urls, normalise_message_text

logger = logging.getLogger("amana_shield.services.ai_analysis")

# Nigerian institutional dictionary for extraction and cross-checking
_INSTITUTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "INEC",
        re.compile(
            r"\b(?:INEC|Independent\s+National\s+Electoral\s+Commission)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FGN",
        re.compile(
            r"\b(?:FGN|FG|Federal\s+Government(?:\s+of\s+Nigeria)?|Presidency|State\s+House)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "NIMC",
        re.compile(
            r"\b(?:NIMC|National\s+Identity\s+Management\s+Commission)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CBN",
        re.compile(
            r"\b(?:CBN|Central\s+Bank(?:\s+of\s+Nigeria)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "EFCC",
        re.compile(
            r"\b(?:EFCC|Economic\s+and\s+Financial\s+Crimes\s+Commission)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "NYSC",
        re.compile(
            r"\b(?:NYSC|National\s+Youth\s+Service\s+Corps)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "NOA",
        re.compile(
            r"\b(?:NOA|National\s+Orientation\s+Agency)\b",
            re.IGNORECASE,
        ),
    ),
)

_CURRENCY_GRANT_RE = re.compile(
    r"(?:(?:\bN|₦|NGN)\s?\d{1,3}(?:,\d{3})+|\b\d+\s*(?:thousand|million)\s*naira\b|"
    r"\b(?:empowerment\s+(?:grant|fund|scheme|programme)|palliative\s+(?:fund|grant)|"
    r"cash\s+(?:grant|transfer|reward|payout))\b)",
    re.IGNORECASE,
)
_VOTER_REG_RE = re.compile(
    r"\b(?:continuous\s+voter\s+registration|CVR|voter\s+registration|voter\s+verification|"
    r"ad-?hoc\s+staff\s+recruitment|polling\s+unit)\b",
    re.IGNORECASE,
)
_PVC_COLLECTION_RE = re.compile(
    r"\b(?:PVC\s+(?:collection|verification|validation|activation|portal|card)|"
    r"Permanent\s+Voter(?:'?s)?\s+Card)\b",
    re.IGNORECASE,
)
_URGENCY_RE = re.compile(
    r"\b(?:urgent|immediately|before\s+midnight|expires?\s+today|last\s+chance|"
    r"closing\s+tonight|within\s+\d+\s+hours?|act\s+now|limited\s+slots?)\b",
    re.IGNORECASE,
)
_FEE_RE = re.compile(
    r"\b(?:processing\s+fee|registration\s+fee|activation\s+fee|clearance\s+fee|"
    r"validation\s+fee|pay\s+(?:the\s+sum\s+of\s+)?(?:\bN|₦|NGN)?\s?\d+)\b",
    re.IGNORECASE,
)
_FORWARD_RE = re.compile(
    r"\b(?:forward\s+(?:this\s+(?:message\s+)?)?to\s+(?:\d+|all|your)\s*(?:groups?|contacts?|friends?)|"
    r"share\s+until\s+the\s+bar\s+is\s+full|share\s+with\s+\d+\s+(?:WhatsApp\s+)?groups?)\b",
    re.IGNORECASE,
)
_MANIPULATION_RE = re.compile(
    r"\b(?:don'?t\s+miss\s+out|failure\s+to\s+(?:verify|comply)\s+will\s+result\s+in|"
    r"your\s+(?:PVC|account|NIN)\s+will\s+be\s+(?:blocked|deactivated|cancelled)|"
    r"only\s+for\s+the\s+first\s+\d+)\b",
    re.IGNORECASE,
)

_BVN_RE = re.compile(r"\b(?:BVN|Bank\s+Verification\s+Number)\b", re.IGNORECASE)
_NIN_RE = re.compile(r"\b(?:NIN|National\s+Identification\s+Number)\b", re.IGNORECASE)
_OTP_PIN_RE = re.compile(
    r"\b(?:OTP|one[- ]time\s+password|ATM\s+PIN|card\s+PIN|4[- ]digit\s+PIN|password)\b",
    re.IGNORECASE,
)
_BANK_ACCT_RE = re.compile(
    r"\b(?:account\s+number|bank\s+details|ATM\s+card\s+number|CVV|\d{10})\b",
    re.IGNORECASE,
)
_USSD_RE = re.compile(r"\*\d{3}(?:\*\d+)*#")
_PHONE_CALL_RE = re.compile(
    r"\b(?:call|whatsapp|chat|contact|send\s+(?:SMS|message)\s+to)\s+(?:\+?234\d{10}|0[789][01]\d{8})\b",
    re.IGNORECASE,
)


# Negation context, e.g. "INEC will NEVER ask for your BVN" must not count as a BVN request.
_NEGATION_PREFIX_RE = re.compile(
    r"\b(?:never|not|don'?t|do\s+not|will\s+not|won'?t|no\s+one|beware|warns?)\b[^.!?\n]{0,60}$",
    re.IGNORECASE,
)


def _find_requested(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    """Return the first pattern match that is not inside a negated/warning context."""
    for match in pattern.finditer(text):
        prefix = text[max(0, match.start() - 80) : match.start()]
        if _NEGATION_PREFIX_RE.search(prefix):
            continue
        return match
    return None


def compute_message_risk_level(
    scam_indicators: list[ScamIndicatorItem],
    requested_actions: list[RequestedActionItem],
    impersonation_indicators: list[ImpersonationIndicatorItem],
    prompt_injection_detected: bool = False,
) -> MessageRisk:
    """Compute a deterministic message_risk level from structured indicators.

    Enforces the rule that a single weak/suspicious word alone never produces CRITICAL/HIGH risk.
    """
    if prompt_injection_detected:
        return MessageRisk.HIGH

    has_sensitive_data_or_fee = any(
        a.action_type
        in {
            RequestedActionType.SUBMIT_BVN,
            RequestedActionType.SUBMIT_NIN,
            RequestedActionType.SUBMIT_OTP_OR_PIN,
            RequestedActionType.SUBMIT_BANK_DETAILS,
            RequestedActionType.PAY_REGISTRATION_OR_PROCESSING_FEE,
        }
        for a in requested_actions
    )
    has_impersonation = bool(impersonation_indicators) or any(
        s.category
        in {
            ScamPatternCategory.INSTITUTIONAL_IMPERSONATION,
            ScamPatternCategory.ELECTORAL_REGISTRATION_IMPERSONATION,
        }
        for s in scam_indicators
    )
    has_fake_grant_or_reward = any(
        s.category
        in {
            ScamPatternCategory.FAKE_EMPOWERMENT_ANNOUNCEMENT,
            ScamPatternCategory.FALSE_FINANCIAL_REWARD,
            ScamPatternCategory.FAKE_PVC_COLLECTION_CLAIM,
        }
        for s in scam_indicators
    )
    critical_or_high_count = sum(
        1 for s in scam_indicators if s.severity in {"CRITICAL", "HIGH"}
    )

    if has_sensitive_data_or_fee and (
        has_impersonation or has_fake_grant_or_reward or critical_or_high_count >= 2
    ):
        return MessageRisk.CRITICAL

    if has_sensitive_data_or_fee or (has_impersonation and has_fake_grant_or_reward):
        return MessageRisk.HIGH

    if critical_or_high_count >= 2 or (has_impersonation and len(scam_indicators) >= 2):
        return MessageRisk.HIGH

    if scam_indicators or any(a.is_sensitive_or_financial for a in requested_actions):
        return MessageRisk.MEDIUM

    return MessageRisk.LOW


class AIScamAnalysisService:
    """Analyses message content using an LLM with strict Pydantic validation and deterministic fallback."""

    def __init__(self, llm_client: StructuredLLMClient | None = None) -> None:
        self._llm_client = llm_client or StructuredLLMClient()

    async def analyse_message(self, raw_text: str) -> AIAnalysisResult:
        """Analyse a submitted message and return a validated AIAnalysisResult."""
        normalised_text = normalise_message_text(raw_text)
        injection_detected, injection_snippet = detect_prompt_injection_attempt(
            normalised_text
        )

        # First build baseline deterministic extraction so we can merge or fall back cleanly
        fallback_payload = self._run_rule_based_extraction(
            normalised_text,
            injection_detected=injection_detected,
            injection_snippet=injection_snippet,
        )

        if self._llm_client.is_configured():
            try:
                llm_payload, was_truncated = await self._llm_client.analyze_message(
                    normalised_text
                )
                merged = self._merge_llm_with_safety_guards(
                    llm_payload,
                    fallback_payload,
                    was_truncated=was_truncated,
                    injection_detected=injection_detected,
                )
                msg_risk = compute_message_risk_level(
                    scam_indicators=merged.scam_indicators,
                    requested_actions=merged.requested_actions,
                    impersonation_indicators=merged.impersonation_indicators,
                    prompt_injection_detected=injection_detected,
                )
                return AIAnalysisResult(
                    extracted_claims=merged.extracted_claims,
                    mentioned_institutions=merged.mentioned_institutions,
                    requested_actions=merged.requested_actions,
                    scam_indicators=merged.scam_indicators,
                    impersonation_indicators=merged.impersonation_indicators,
                    verification_requirements=merged.verification_requirements,
                    explanation=merged.explanation,
                    limitations=merged.limitations,
                    assessed_message_risk=msg_risk,
                    analysis_mode="LLM_PRIMARY",
                    prompt_injection_detected=injection_detected,
                    is_degraded=False,
                )
            except LLMClientError as exc:
                logger.warning("Falling back to deterministic heuristic extractor: %s", exc)
                degraded_reason = str(exc)
            except Exception as exc:
                logger.warning(
                    "Unexpected LLM error; using fallback extractor: %s",
                    exc.__class__.__name__,
                )
                degraded_reason = f"LLM error: {exc.__class__.__name__}"
        else:
            degraded_reason = "LLM provider not configured; used deterministic heuristic message analyser."

        msg_risk = compute_message_risk_level(
            scam_indicators=fallback_payload.scam_indicators,
            requested_actions=fallback_payload.requested_actions,
            impersonation_indicators=fallback_payload.impersonation_indicators,
            prompt_injection_detected=injection_detected,
        )
        return AIAnalysisResult(
            extracted_claims=fallback_payload.extracted_claims,
            mentioned_institutions=fallback_payload.mentioned_institutions,
            requested_actions=fallback_payload.requested_actions,
            scam_indicators=fallback_payload.scam_indicators,
            impersonation_indicators=fallback_payload.impersonation_indicators,
            verification_requirements=fallback_payload.verification_requirements,
            explanation=fallback_payload.explanation,
            limitations=fallback_payload.limitations,
            assessed_message_risk=msg_risk,
            analysis_mode="FALLBACK_HEURISTIC",
            prompt_injection_detected=injection_detected,
            is_degraded=True,
            degraded_reason=degraded_reason,
        )

    def _merge_llm_with_safety_guards(
        self,
        llm_payload: LLMStructuredOutputPayload,
        fallback_payload: LLMStructuredOutputPayload,
        *,
        was_truncated: bool,
        injection_detected: bool,
    ) -> LLMStructuredOutputPayload:
        """Ensure any critical indicator caught by deterministic patterns is never dropped by LLM."""
        institutions = list(
            dict.fromkeys(
                [*llm_payload.mentioned_institutions, *fallback_payload.mentioned_institutions]
            )
        )

        actions = list(llm_payload.requested_actions)
        existing_action_types = {a.action_type for a in actions}
        for fa in fallback_payload.requested_actions:
            if fa.action_type not in existing_action_types:
                actions.append(fa)

        indicators = list(llm_payload.scam_indicators)
        existing_categories = {i.category for i in indicators}
        for fi in fallback_payload.scam_indicators:
            if fi.category not in existing_categories:
                indicators.append(fi)

        impersonations = list(llm_payload.impersonation_indicators)
        existing_imp_names = {imp.institution_name.upper() for imp in impersonations}
        for fimp in fallback_payload.impersonation_indicators:
            if fimp.institution_name.upper() not in existing_imp_names:
                impersonations.append(fimp)

        claims = (
            llm_payload.extracted_claims
            if llm_payload.extracted_claims
            else fallback_payload.extracted_claims
        )
        verif_reqs = list(
            dict.fromkeys(
                [
                    *llm_payload.verification_requirements,
                    *fallback_payload.verification_requirements,
                ]
            )
        )
        limitations = list(
            dict.fromkeys([*llm_payload.limitations, *fallback_payload.limitations])
        )
        if was_truncated:
            limitations.append(
                "Submitted message exceeded maximum character limit and was truncated before AI analysis."
            )
        if injection_detected:
            limitations.append(
                "Submitted message contained instruction-override / prompt-injection patterns that were sandboxed."
            )

        return LLMStructuredOutputPayload(
            extracted_claims=claims,
            mentioned_institutions=institutions,
            requested_actions=actions,
            scam_indicators=indicators,
            impersonation_indicators=impersonations,
            verification_requirements=verif_reqs,
            explanation=llm_payload.explanation,
            limitations=limitations,
        )

    def _run_rule_based_extraction(
        self,
        text: str,
        *,
        injection_detected: bool = False,
        injection_snippet: str | None = None,
    ) -> LLMStructuredOutputPayload:
        """High-precision deterministic pattern extractor for Nigerian electoral & civic scams."""
        mentioned_institutions: list[str] = []
        for code, pattern in _INSTITUTION_PATTERNS:
            if pattern.search(text):
                mentioned_institutions.append(code)

        extracted_claims: list[ExtractedClaimItem] = []
        requested_actions: list[RequestedActionItem] = []
        scam_indicators: list[ScamIndicatorItem] = []
        impersonation_indicators: list[ImpersonationIndicatorItem] = []
        verification_requirements: list[str] = []

        primary_inst = mentioned_institutions[0] if mentioned_institutions else None

        # 1. Detect requested user actions
        urls = extract_basic_urls(text)
        if urls:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.CLICK_LINK,
                    description=f"Click or visit URL ({urls[0][:200]})",
                    is_sensitive_or_financial=False,
                    evidence_excerpt=urls[0][:200],
                )
            )

        bvn_match = _find_requested(_BVN_RE, text)
        if bvn_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.SUBMIT_BVN,
                    description="Submit Bank Verification Number (BVN)",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=bvn_match.group(0),
                )
            )

        nin_match = _find_requested(_NIN_RE, text)
        if nin_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.SUBMIT_NIN,
                    description="Submit National Identification Number (NIN)",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=nin_match.group(0),
                )
            )

        otp_match = _find_requested(_OTP_PIN_RE, text)
        if otp_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.SUBMIT_OTP_OR_PIN,
                    description="Provide OTP, PIN, or password",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=otp_match.group(0),
                )
            )

        bank_match = _find_requested(_BANK_ACCT_RE, text)
        if bank_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.SUBMIT_BANK_DETAILS,
                    description="Provide bank account or card details",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=bank_match.group(0),
                )
            )

        pvc_match = _PVC_COLLECTION_RE.search(text)
        if pvc_match and re.search(r"\b(?:enter|submit|verify|send|input)\b", text, re.I):
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.SUBMIT_PVC_OR_VOTER_ID,
                    description="Submit PVC or voter registration details online",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=pvc_match.group(0),
                )
            )

        fee_match = _find_requested(_FEE_RE, text)
        if fee_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.PAY_REGISTRATION_OR_PROCESSING_FEE,
                    description="Pay a registration, processing, or activation fee",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=fee_match.group(0),
                )
            )
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.REGISTRATION_OR_PROCESSING_FEE,
                    severity="CRITICAL",
                    description="Demands payment of a processing, registration, or activation fee.",
                    evidence_excerpt=fee_match.group(0),
                )
            )

        fwd_match = _FORWARD_RE.search(text)
        if fwd_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.FORWARD_MESSAGE_TO_GROUPS,
                    description="Forward message to multiple WhatsApp groups or contacts",
                    is_sensitive_or_financial=False,
                    evidence_excerpt=fwd_match.group(0),
                )
            )
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.VIRAL_FORWARDING_SOLICITATION,
                    severity="HIGH",
                    description="Instructs user to forward the message to WhatsApp groups/contacts to qualify.",
                    evidence_excerpt=fwd_match.group(0),
                )
            )

        ussd_match = _USSD_RE.search(text)
        if ussd_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.DIAL_USSD_CODE,
                    description=f"Dial USSD code {ussd_match.group(0)}",
                    is_sensitive_or_financial=True,
                    evidence_excerpt=ussd_match.group(0),
                )
            )

        phone_call_match = _PHONE_CALL_RE.search(text)
        if phone_call_match:
            requested_actions.append(
                RequestedActionItem(
                    action_type=RequestedActionType.CALL_OR_MESSAGE_PHONE_NUMBER,
                    description="Call or message a specified phone number",
                    is_sensitive_or_financial=False,
                    evidence_excerpt=phone_call_match.group(0),
                )
            )

        # Sensitive data request scam indicator
        if any(
            a.action_type
            in {
                RequestedActionType.SUBMIT_BVN,
                RequestedActionType.SUBMIT_NIN,
                RequestedActionType.SUBMIT_OTP_OR_PIN,
                RequestedActionType.SUBMIT_BANK_DETAILS,
            }
            for a in requested_actions
        ):
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.SENSITIVE_DATA_REQUEST,
                    severity="CRITICAL",
                    description="Requests sensitive personal or financial credentials (BVN, NIN, OTP, PIN, or bank details).",
                    evidence_excerpt=(
                        bvn_match.group(0)
                        if bvn_match
                        else (
                            nin_match.group(0)
                            if nin_match
                            else (otp_match.group(0) if otp_match else "bank details")
                        )
                    ),
                )
            )

        # 2. Detect scam patterns & extract main claims
        grant_match = _CURRENCY_GRANT_RE.search(text)
        if grant_match:
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.FAKE_EMPOWERMENT_ANNOUNCEMENT,
                    severity="HIGH",
                    description="Promises cash grant, empowerment payout, or financial palliative.",
                    evidence_excerpt=grant_match.group(0),
                )
            )
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.FALSE_FINANCIAL_REWARD,
                    severity="HIGH",
                    description="Offers financial reward or grant to entice user action.",
                    evidence_excerpt=grant_match.group(0),
                )
            )
            extracted_claims.append(
                ExtractedClaimItem(
                    claim_text=text[:300],
                    claim_topic="CASH_GRANT_OR_EMPOWERMENT",
                    impersonated_entity=primary_inst,
                    requires_external_verification=True,
                    confidence=ConfidenceLevel.HIGH,
                )
            )
            verification_requirements.append(
                "Verify against official Federal Government / institutional press releases whether any such cash grant or empowerment portal exists."
            )

        voter_match = _VOTER_REG_RE.search(text)
        if voter_match:
            extracted_claims.append(
                ExtractedClaimItem(
                    claim_text=text[:300],
                    claim_topic="VOTER_REGISTRATION",
                    impersonated_entity=primary_inst or "INEC",
                    requires_external_verification=True,
                    confidence=ConfidenceLevel.HIGH,
                )
            )
            verification_requirements.append(
                "Check official INEC announcements and cvr.inecnigeria.org to verify voter registration dates and procedures."
            )
            if any(a.is_sensitive_or_financial for a in requested_actions) or grant_match or fee_match:
                scam_indicators.append(
                    ScamIndicatorItem(
                        category=ScamPatternCategory.ELECTORAL_REGISTRATION_IMPERSONATION,
                        severity="CRITICAL",
                        description="Combines voter registration/electoral claims with financial lures or sensitive credential harvesting.",
                        evidence_excerpt=voter_match.group(0),
                    )
                )

        if pvc_match:
            if not any(c.claim_topic == "PVC_COLLECTION" for c in extracted_claims):
                extracted_claims.append(
                    ExtractedClaimItem(
                        claim_text=text[:300],
                        claim_topic="PVC_COLLECTION",
                        impersonated_entity=primary_inst or "INEC",
                        requires_external_verification=True,
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
            verification_requirements.append(
                "Verify PVC collection procedures and schedules against official INEC state/LGA announcements."
            )
            if any(a.is_sensitive_or_financial for a in requested_actions) or grant_match or fee_match:
                scam_indicators.append(
                    ScamIndicatorItem(
                        category=ScamPatternCategory.FAKE_PVC_COLLECTION_CLAIM,
                        severity="HIGH",
                        description="Uses PVC collection or activation claim to solicit sensitive data, fees, or suspicious link clicks.",
                        evidence_excerpt=pvc_match.group(0),
                    )
                )

        urgency_match = _URGENCY_RE.search(text)
        if urgency_match:
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.ARTIFICIAL_URGENCY,
                    severity="MEDIUM",
                    description="Uses high-pressure urgency or imminent deadline language.",
                    evidence_excerpt=urgency_match.group(0),
                )
            )

        manip_match = _MANIPULATION_RE.search(text)
        if manip_match:
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.BEHAVIOURAL_MANIPULATION,
                    severity="HIGH",
                    description="Uses fear of account/PVC deactivation or scarcity manipulation.",
                    evidence_excerpt=manip_match.group(0),
                )
            )

        if injection_detected:
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.BEHAVIOURAL_MANIPULATION,
                    severity="HIGH",
                    description="Message contains prompt-injection or instruction-override directives.",
                    evidence_excerpt=injection_snippet,
                )
            )

        # 3. Institutional impersonation evaluation
        if mentioned_institutions and (
            scam_indicators
            or any(a.is_sensitive_or_financial for a in requested_actions)
        ):
            for inst in mentioned_institutions:
                impersonation_indicators.append(
                    ImpersonationIndicatorItem(
                        institution_name=inst,
                        impersonation_method=(
                            f"References {inst} authority alongside suspicious requests or unverified claims."
                        ),
                        confidence=ConfidenceLevel.HIGH,
                        evidence_excerpt=inst,
                    )
                )
            scam_indicators.append(
                ScamIndicatorItem(
                    category=ScamPatternCategory.INSTITUTIONAL_IMPERSONATION,
                    severity="HIGH",
                    description=f"Claims authority from {', '.join(mentioned_institutions)} while exhibiting scam or credential-harvesting indicators.",
                    evidence_excerpt=", ".join(mentioned_institutions),
                )
            )

        # Ensure at least one claim is recorded if the message makes a statement
        if not extracted_claims:
            extracted_claims.append(
                ExtractedClaimItem(
                    claim_text=text[:300],
                    claim_topic="GENERAL_ANNOUNCEMENT",
                    impersonated_entity=primary_inst,
                    requires_external_verification=bool(mentioned_institutions or urls),
                    confidence=ConfidenceLevel.MEDIUM,
                )
            )
            if mentioned_institutions:
                verification_requirements.append(
                    f"Verify statement against official {', '.join(mentioned_institutions)} communications."
                )
            else:
                verification_requirements.append(
                    "Verify sender identity and claims through independent official channels before acting."
                )

        if scam_indicators:
            cat_names = ", ".join(dict.fromkeys(s.category.value for s in scam_indicators))
            explanation = (
                f"Message analysis identified {len(scam_indicators)} risk indicator(s) "
                f"({cat_names}). Claims involving {', '.join(mentioned_institutions) if mentioned_institutions else 'the sender'} "
                "require verification against curated official sources."
            )
        else:
            explanation = (
                "No overt scam or credential-harvesting patterns were detected in the message text. "
                "However, any factual or institutional claims still require external verification."
            )

        limitations = [
            "Message content analysis alone cannot confirm whether an announcement is authentic without checking curated official sources.",
            "Absence of scam keywords does not guarantee a message or unknown URL is safe.",
        ]

        return LLMStructuredOutputPayload(
            extracted_claims=extracted_claims,
            mentioned_institutions=mentioned_institutions,
            requested_actions=requested_actions,
            scam_indicators=scam_indicators,
            impersonation_indicators=impersonation_indicators,
            verification_requirements=verification_requirements,
            explanation=explanation,
            limitations=limitations,
        )
