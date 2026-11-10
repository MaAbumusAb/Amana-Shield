"""Prompt builder for comparing extracted factual claims against retrieved evidence."""

from __future__ import annotations

import json
from app.schemas.ai_analysis import ExtractedClaimItem
from app.schemas.evidence import RetrievedEvidenceItem


def build_claim_verification_prompt(
    claims: list[ExtractedClaimItem],
    evidence_items: list[RetrievedEvidenceItem],
) -> tuple[str, str]:
    """Construct system prompt and user prompt to evaluate claims against retrieved evidence.

    CRITICAL CONSTRAINTS:
    - Never invent sources, statements, or conclusions.
    - If evidence is inadequate, ABSTAIN and return UNVERIFIED.
    - Lack of evidence is NOT proof that a claim is false.
    - Output must strictly follow the JSON format.
    """
    system_prompt = """You are the AMANA SHIELD Evidence Verification Engine for Nigerian electoral and government information (AI4Elections 2026).

YOUR MISSION:
Compare user-submitted factual claims against retrieved curated official sources and fact-checks.

VERDICT RULES:
- "VERIFIED": The claim is directly supported by active official announcements, policy rules, or authentic portal records.
- "FALSE": The claim is directly contradicted by an official debunking notice or established official policy (e.g., INEC does NOT give cash grants or charge for CVR).
- "MISLEADING": The claim mixes real and fabricated elements, uses real past events out of context, or distorts authentic policies.
- "UNVERIFIED": The retrieved evidence is insufficient to prove or disprove the claim. You MUST abstain rather than guessing. Lack of evidence is NEVER proof of falsehood!

STRICT CONSTRAINTS:
1. Every conclusion must cite specific retrieved evidence sources.
2. If no matching evidence exists, verdict MUST be "UNVERIFIED".
3. Return ONLY a valid JSON object matching this schema:
{
  "evaluations": [
    {
      "claim_text": string,
      "verdict": "VERIFIED" | "FALSE" | "MISLEADING" | "UNVERIFIED",
      "confidence": "LOW" | "MEDIUM" | "HIGH",
      "matched_source_id": string or null,
      "matched_source_url": string or null,
      "supporting_points": [string],
      "contradicting_points": [string],
      "uncertainty_explanation": string or null,
      "evidence_citations": [string]
    }
  ],
  "overall_claim_status": "VERIFIED_OFFICIAL" | "CONTRADICTED_BY_OFFICIAL" | "OUTDATED_OR_EXPIRED" | "UNVERIFIED",
  "explanation": string
}"""

    claims_data = [
        {
            "claim_text": c.claim_text,
            "claim_topic": c.claim_topic,
            "impersonated_entity": c.impersonated_entity,
        }
        for c in claims
    ]

    evidence_data = [
        {
            "source_id": str(e.source_id),
            "institution_code": e.institution_code,
            "title": e.title,
            "official_url": e.official_url,
            "published_at": e.published_at.isoformat(),
            "is_debunking_notice": e.is_debunking_notice,
            "relevant_excerpt": e.relevant_excerpt,
        }
        for e in evidence_items
    ]

    user_prompt = f"""EVALUATE THE FOLLOWING CLAIMS AGAINST THE RETRIEVED EVIDENCE SOURCES:

<CLAIMS_TO_EVALUATE>
{json.dumps(claims_data, indent=2)}
</CLAIMS_TO_EVALUATE>

<RETRIEVED_EVIDENCE_SOURCES>
{json.dumps(evidence_data, indent=2) if evidence_data else "NO MATCHING EVIDENCE FOUND IN REGISTRY."}
</RETRIEVED_EVIDENCE_SOURCES>

Return strictly the required JSON object."""

    return system_prompt, user_prompt
