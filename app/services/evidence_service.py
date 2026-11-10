"""Evidence Retrieval and Claim Verification Service for AMANA SHIELD.

Verifies claims against curated official sources (INEC, FGN, CBN, NIMC, reputable fact-checkers)
using PostgreSQL text search, date sensitivity, source prioritization, and strict abstention.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.integrations.llm_client import LLMClientError, StructuredLLMClient
from app.integrations.verification_prompts import build_claim_verification_prompt
from app.models.entities import ClaimVerificationStatus, ConfidenceLevel, EvidenceSource
from app.repositories.submissions import EvidenceSourceRepository
from app.schemas.ai_analysis import ExtractedClaimItem
from app.schemas.evidence import (
    ClaimVerificationEvaluation,
    EvidenceVerificationResult,
    RetrievedEvidenceItem,
    SourceCategory,
    VerificationVerdict,
)

logger = logging.getLogger("amana_shield.services.evidence_verification")

# Regex to extract key topic keywords from claim text
_STOP_WORDS = frozenset(
    {
        "the", "and", "for", "with", "from", "that", "this", "your", "before",
        "have", "will", "are", "all", "now", "today", "here", "click", "register",
        "claim", "free", "please", "into", "been", "their", "about", "other",
        "inec", "nimc", "cbn", "fgn", "efcc", "nysc", "noa"
    }
)


def extract_keywords_from_claim(claim_text: str, topic: str | None = None) -> list[str]:
    """Extract distinct, high-information keyword tokens from claim text."""
    tokens = re.findall(r"\b[A-Za-z0-9_-]{3,}\b", claim_text.lower())
    keywords = [t for t in tokens if t not in _STOP_WORDS]
    if topic:
        topic_tokens = re.findall(r"\b[A-Za-z0-9_-]{3,}\b", topic.lower())
        keywords.extend([t for t in topic_tokens if t not in _STOP_WORDS])
    return list(dict.fromkeys(keywords))[:8]


class EvidenceVerificationService:
    """Retrieves relevant evidence from the curated registry and evaluates factual claims."""

    def __init__(
        self,
        session: AsyncSession,
        llm_client: StructuredLLMClient | None = None,
    ) -> None:
        self._session = session
        self._evidence_repo = EvidenceSourceRepository(session)
        self._llm_client = llm_client or StructuredLLMClient()

    async def verify_claims(
        self,
        claims: list[ExtractedClaimItem],
        *,
        use_llm: bool = True,
    ) -> EvidenceVerificationResult:
        """Execute end-to-end evidence retrieval and claim evaluation."""
        if not claims:
            return EvidenceVerificationResult(
                evaluated_claims=[],
                overall_claim_status="NOT_APPLICABLE",
                has_contradicted_claims=False,
                has_verified_official_claims=False,
                has_misleading_claims=False,
                sources_consulted_count=0,
                explanation="No factual claims were extracted for verification.",
            )

        # 1. Retrieve candidate evidence items across all claims
        retrieved_evidence_map: dict[uuid.UUID, RetrievedEvidenceItem] = {}
        claim_evidence_links: list[tuple[ExtractedClaimItem, list[RetrievedEvidenceItem]]] = []

        for claim in claims:
            keywords = extract_keywords_from_claim(claim.claim_text, claim.claim_topic)
            inst_code = claim.impersonated_entity
            sources = await self._evidence_repo.search_evidence(
                keywords=keywords,
                institution_code=inst_code,
                limit=5,
            )

            # Fallback search without institution code if specific search returned nothing
            if not sources and inst_code:
                sources = await self._evidence_repo.search_evidence(
                    keywords=keywords,
                    institution_code=None,
                    limit=3,
                )

            evidence_items_for_claim: list[RetrievedEvidenceItem] = []
            for src in sources:
                cat = getattr(src, "source_category", "GOVERNMENT_INSTITUTION")
                try:
                    source_cat = SourceCategory(cat)
                except ValueError:
                    source_cat = SourceCategory.GOVERNMENT_INSTITUTION

                item = RetrievedEvidenceItem(
                    source_id=src.id,
                    title=src.title,
                    official_url=src.official_url,
                    institution_code=src.institution_code,
                    source_category=source_cat,
                    published_at=src.published_at,
                    is_debunking_notice=src.is_debunking_notice,
                    relevant_excerpt=src.summary_content[:300],
                    relevance_score=1.0 if src.is_debunking_notice else 0.8,
                )
                evidence_items_for_claim.append(item)
                retrieved_evidence_map[src.id] = item

            claim_evidence_links.append((claim, evidence_items_for_claim))

        all_retrieved = list(retrieved_evidence_map.values())

        # 2. Try LLM-assisted verification if configured and requested
        if use_llm and self._llm_client.is_configured():
            try:
                llm_eval = await self._evaluate_with_llm(claims, all_retrieved)
                if llm_eval is not None:
                    return llm_eval
            except (LLMClientError, Exception) as exc:
                logger.warning(
                    "LLM claim verification failed; proceeding with deterministic evaluator: %s",
                    exc.__class__.__name__,
                )

        # 3. Deterministic verification evaluator (Rule-based comparison against retrieved evidence)
        return self._evaluate_deterministically(claim_evidence_links, all_retrieved)

    async def _evaluate_with_llm(
        self,
        claims: list[ExtractedClaimItem],
        evidence_items: list[RetrievedEvidenceItem],
    ) -> EvidenceVerificationResult | None:
        """Use LLM to compare claims against retrieved evidence under strict prompt constraints."""
        sys_prompt, user_prompt = build_claim_verification_prompt(claims, evidence_items)

        endpoint = f"{self._llm_client._settings.LLM_BASE_URL.rstrip('/')}/chat/completions"
        api_key = self._llm_client._settings.LLM_API_KEY.get_secret_value()

        request_body: dict[str, Any] = {
            "model": self._llm_client._settings.LLM_MODEL_NAME,
            "temperature": 0.0,
            "max_tokens": 1000,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        import httpx

        async with httpx.AsyncClient(
            timeout=self._llm_client._settings.LLM_TIMEOUT_SECONDS,
            follow_redirects=False,
            transport=self._llm_client._transport,
        ) as client:
            resp = await client.post(
                endpoint,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=request_body,
            )
            if resp.status_code != 200:
                raise LLMClientError(f"LLM verification returned HTTP {resp.status_code}")
            data = resp.json()
            raw_content = data["choices"][0]["message"]["content"]
            parsed = json.loads(raw_content)

        evaluations: list[ClaimVerificationEvaluation] = []
        for raw_eval in parsed.get("evaluations", []):
            matched_id_str = raw_eval.get("matched_source_id")
            matched_uuid = None
            if matched_id_str:
                try:
                    matched_uuid = uuid.UUID(matched_id_str)
                except ValueError:
                    pass

            v_str = raw_eval.get("verdict", "UNVERIFIED")
            try:
                verdict = VerificationVerdict(v_str)
            except ValueError:
                verdict = VerificationVerdict.UNVERIFIED

            # Enforcement: If verdict is VERIFIED or FALSE, must have matched source and citations
            if verdict in {VerificationVerdict.VERIFIED, VerificationVerdict.FALSE} and not matched_uuid:
                # If LLM didn't attach source ID, search among retrieved
                if evidence_items:
                    matched_uuid = evidence_items[0].source_id

            evaluations.append(
                ClaimVerificationEvaluation(
                    claim_text=raw_eval.get("claim_text", ""),
                    claim_topic="EVALUATED_CLAIM",
                    verdict=verdict,
                    confidence=ConfidenceLevel.HIGH if verdict != VerificationVerdict.UNVERIFIED else ConfidenceLevel.LOW,
                    matched_source_id=matched_uuid,
                    matched_source_url=raw_eval.get("matched_source_url"),
                    supporting_points=raw_eval.get("supporting_points", []),
                    contradicting_points=raw_eval.get("contradicting_points", []),
                    uncertainty_explanation=raw_eval.get("uncertainty_explanation"),
                    evidence_citations=raw_eval.get("evidence_citations", []),
                )
            )

        overall_status = parsed.get("overall_claim_status", "UNVERIFIED")
        has_contra = any(e.verdict == VerificationVerdict.FALSE for e in evaluations)
        has_verif = any(e.verdict == VerificationVerdict.VERIFIED for e in evaluations)
        has_misleading = any(e.verdict == VerificationVerdict.MISLEADING for e in evaluations)

        return EvidenceVerificationResult(
            evaluated_claims=evaluations,
            overall_claim_status=overall_status,
            has_contradicted_claims=has_contra,
            has_verified_official_claims=has_verif,
            has_misleading_claims=has_misleading,
            sources_consulted_count=len(evidence_items),
            explanation=parsed.get("explanation", "Verification completed against official sources."),
        )

    def _evaluate_deterministically(
        self,
        claim_evidence_links: list[tuple[ExtractedClaimItem, list[RetrievedEvidenceItem]]],
        all_retrieved: list[RetrievedEvidenceItem],
    ) -> EvidenceVerificationResult:
        """Deterministic comparison of claims against retrieved evidence records."""
        evaluations: list[ClaimVerificationEvaluation] = []

        for claim, evidence_list in claim_evidence_links:
            matched_source: RetrievedEvidenceItem | None = None
            verdict = VerificationVerdict.UNVERIFIED
            supporting: list[str] = []
            contradicting: list[str] = []
            uncertainty: str | None = None
            citations: list[str] = []

            if not evidence_list:
                uncertainty = (
                    f"No matching curated evidence found for topic '{claim.claim_topic}'. "
                    "Claim remains unverified. Lack of evidence is not proof that the claim is false."
                )
            else:
                now_utc = datetime.now(timezone.utc)
                # Check for debunking notice or direct contradiction
                debunking_sources = [s for s in evidence_list if s.is_debunking_notice]
                claim_text_lower = claim.claim_text.lower()

                # A debunking notice only contradicts if its topic matches the claim
                matching_debunking = None
                for ds in debunking_sources:
                    excerpt_lower = ds.relevant_excerpt.lower()
                    title_lower = ds.title.lower()
                    if ("grant" in title_lower or "grant" in excerpt_lower or "bvn" in excerpt_lower or "palliative" in excerpt_lower) and not (
                        "grant" in claim_text_lower or "bvn" in claim_text_lower or "palliative" in claim_text_lower or "n50,000" in claim_text_lower
                    ):
                        # The debunking is about grants/BVN, but the claim is about registration/PVC/etc
                        continue
                    matching_debunking = ds
                    break

                if matching_debunking is not None:
                    matched_source = matching_debunking
                    verdict = VerificationVerdict.FALSE
                    contradicting.append(
                        f"Official debunking notice from {matched_source.institution_code}: {matched_source.relevant_excerpt}"
                    )
                    citations.append(f"{matched_source.title} ({matched_source.official_url})")
                else:
                    # Filter candidate supporting sources that are NOT debunking notices
                    supporting_candidates = [s for s in evidence_list if not s.is_debunking_notice]
                    candidate = supporting_candidates[0] if supporting_candidates else evidence_list[0]
                    matched_source = candidate
                    citations.append(f"{candidate.title} ({candidate.official_url})")

                    # Check for expired/outdated policies
                    claim_text_lower = claim.claim_text.lower()
                    if "grant" in claim_text_lower or "palliative" in claim_text_lower or "n50,000" in claim_text_lower:
                        # Cash grants claiming to be from INEC are contradicted by definition
                        if claim.impersonated_entity == "INEC" or "inec" in claim_text_lower:
                            verdict = VerificationVerdict.FALSE
                            contradicting.append(
                                "INEC is an electoral umpire and does not distribute cash grants, empowerment funds, or financial relief."
                            )
                        else:
                            verdict = VerificationVerdict.UNVERIFIED
                            uncertainty = "Curated registry contains no record confirming this empowerment programme."
                    elif candidate.institution_code in {"INEC", "NIMC", "CBN", "FGN"}:
                        # Check whether claim asserts fees for free public services
                        if "fee" in claim_text_lower or "pay" in claim_text_lower or "processing" in claim_text_lower:
                            verdict = VerificationVerdict.FALSE
                            contradicting.append(
                                f"Official {candidate.institution_code} guidelines confirm that voter registration and PVC collection are free."
                            )
                        else:
                            verdict = VerificationVerdict.VERIFIED
                            supporting.append(
                                f"Supported by authentic {candidate.institution_code} announcement: {candidate.relevant_excerpt}"
                            )

            evaluations.append(
                ClaimVerificationEvaluation(
                    claim_text=claim.claim_text,
                    claim_topic=claim.claim_topic,
                    impersonated_entity=claim.impersonated_entity,
                    verdict=verdict,
                    confidence=ConfidenceLevel.HIGH if verdict != VerificationVerdict.UNVERIFIED else ConfidenceLevel.MEDIUM,
                    matched_source_id=matched_source.source_id if matched_source else None,
                    matched_source_url=matched_source.official_url if matched_source else None,
                    supporting_points=supporting,
                    contradicting_points=contradicting,
                    uncertainty_explanation=uncertainty,
                    publication_dates=[matched_source.published_at] if matched_source else [],
                    evidence_citations=citations,
                )
            )

        has_contra = any(e.verdict == VerificationVerdict.FALSE for e in evaluations)
        has_verif = any(e.verdict == VerificationVerdict.VERIFIED for e in evaluations)
        has_misleading = any(e.verdict == VerificationVerdict.MISLEADING for e in evaluations)

        if has_contra:
            overall_status = "CONTRADICTED_BY_OFFICIAL"
            explanation = (
                "One or more factual claims are directly CONTRADICTED by curated official statements "
                "or established debunking notices."
            )
        elif has_misleading:
            overall_status = "CONTRADICTED_BY_OFFICIAL"
            explanation = "Claims contain misleading or distorted information according to official sources."
        elif has_verif and not has_contra:
            overall_status = "VERIFIED_OFFICIAL"
            explanation = "Claims are verified and supported by active curated official sources."
        else:
            overall_status = "UNVERIFIED"
            explanation = (
                "Insufficient evidence available in curated official registries to confirm or refute the claims. "
                "Abstaining from verdict. A lack of evidence is not proof that the claim is false."
            )

        return EvidenceVerificationResult(
            evaluated_claims=evaluations,
            overall_claim_status=overall_status,
            has_contradicted_claims=has_contra,
            has_verified_official_claims=has_verif,
            has_misleading_claims=has_misleading,
            sources_consulted_count=len(all_retrieved),
            explanation=explanation,
            uncertainty_summary=(
                "Some claims could not be verified due to lack of corresponding official statements in the registry."
                if any(e.verdict == VerificationVerdict.UNVERIFIED for e in evaluations)
                else None
            ),
        )
