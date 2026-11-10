"""Submission intake service (foundation pipeline without AI integration)."""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import DuplicateSubmissionError, EntityNotFoundError
from app.core.security import compute_content_sha256, hash_sender_identifier
from app.models.entities import (
    Assessment,
    ClaimVerificationStatus,
    ExtractedClaim,
    InternalStatus,
    MessageRisk,
    ProcessingStatus,
    PublicVerdict,
    Submission,
    UrlRisk,
)
from app.repositories.submissions import DomainRepository, SubmissionRepository
from app.schemas.common import SubmissionCreateRequest
from app.services.ai_analysis_service import AIScamAnalysisService
from app.services.evidence_service import EvidenceVerificationService
from app.services.risk_fusion_service import compute_risk_fusion
from app.services.triage_service import DeterministicTriageService
from app.utils.text import normalise_message_text

logger = logging.getLogger("amana_shield.services.submission")


class SubmissionService:
    """Handles safe intake, normalisation, deduplication, deterministic triage, AI analysis, evidence verification, and persistence."""

    def __init__(
        self,
        session: AsyncSession,
        ai_service: AIScamAnalysisService | None = None,
        evidence_service: EvidenceVerificationService | None = None,
    ) -> None:
        self._session = session
        self._repo = SubmissionRepository(session)
        self._domain_repo = DomainRepository(session)
        self._triage_service = DeterministicTriageService(
            session=session,
            enable_live_network_checks=False,
        )
        self._ai_service = ai_service or AIScamAnalysisService()
        self._evidence_service = evidence_service or EvidenceVerificationService(session=session)

    async def create_submission(
        self, payload: SubmissionCreateRequest
    ) -> Submission:
        """Validate, normalise, run deterministic URL/domain triage, and persist submission."""
        existing = await self._repo.get_by_external_message_id(
            payload.external_message_id
        )
        if existing is not None:
            raise DuplicateSubmissionError(payload.external_message_id)

        normalised_text = normalise_message_text(payload.raw_text)
        content_sha256 = compute_content_sha256(normalised_text)
        sender_hash = hash_sender_identifier(payload.sender_identifier)

        triage_result = await self._triage_service.analyse_text(normalised_text)
        ai_result = await self._ai_service.analyse_message(normalised_text)
        evidence_result = await self._evidence_service.verify_claims(ai_result.extracted_claims)

        extracted_urls = [
            u.normalised_url if u.normalised_url else u.raw_url
            for u in triage_result.extracted_urls
        ]

        primary_domain_id: uuid.UUID | None = None
        if triage_result.normalised_domains:
            first_host = triage_result.normalised_domains[0].canonical_host
            dom_record = await self._domain_repo.get_by_canonical_host(first_host)
            if dom_record is not None:
                primary_domain_id = dom_record.id

        submission = Submission(
            channel=payload.channel.value,
            external_message_id=payload.external_message_id,
            sender_hash=sender_hash,
            raw_text=payload.raw_text,
            normalised_text=normalised_text,
            content_sha256=content_sha256,
            extracted_urls=extracted_urls,
            processing_status=ProcessingStatus.COMPLETED.value,
        )

        url_risk = triage_result.aggregated_url_risk
        message_risk = ai_result.assessed_message_risk

        # Execute final Risk Fusion combining the three independent assessment pillars
        fusion_eval = compute_risk_fusion(
            triage_result=triage_result,
            ai_result=ai_result,
            evidence_result=evidence_result,
        )

        assessment = Assessment(
            submission_id=submission.id,
            primary_domain_id=primary_domain_id,
            message_risk=fusion_eval.message_risk.value,
            url_risk=fusion_eval.url_risk.value,
            claim_verification_status=fusion_eval.claim_verification_status.value,
            public_verdict=fusion_eval.verdict.value,
            internal_status=fusion_eval.review_status.value,
            triggered_rules=fusion_eval.triggered_rules,
            triage_findings=triage_result.model_dump(mode="json"),
            ai_heuristics=ai_result.model_dump(mode="json"),
            explanation_text=fusion_eval.primary_explanation.summary,
            recommended_action=fusion_eval.recommended_action,
            is_degraded_mode=fusion_eval.is_degraded_mode,
        )

        saved = await self._repo.create_submission_with_assessment(
            submission=submission,
            assessment=assessment,
        )
        saved._fusion_evaluation = fusion_eval

        # Persist extracted claims linked to this assessment with matched evidence foreign keys
        if saved.assessment is not None and evidence_result.evaluated_claims:
            for eval_claim in evidence_result.evaluated_claims:
                db_outcome = ClaimVerificationStatus.UNVERIFIED.value
                if eval_claim.verdict.value == "VERIFIED":
                    db_outcome = ClaimVerificationStatus.VERIFIED_OFFICIAL.value
                elif eval_claim.verdict.value in {"FALSE", "MISLEADING"}:
                    db_outcome = ClaimVerificationStatus.CONTRADICTED_BY_OFFICIAL.value

                self._session.add(
                    ExtractedClaim(
                        assessment_id=saved.assessment.id,
                        claim_text=eval_claim.claim_text,
                        impersonated_entity=eval_claim.impersonated_entity,
                        claim_topic=eval_claim.claim_topic,
                        verification_outcome=db_outcome,
                        matched_evidence_id=eval_claim.matched_source_id,
                        confidence=eval_claim.confidence.value,
                    )
                )
            await self._session.commit()

        logger.info(
            "Submission recorded successfully",
            extra={
                "extra_fields": {
                    "submission_id": str(saved.id),
                    "channel": saved.channel,
                    "url_count": len(extracted_urls),
                    "public_verdict": assessment.public_verdict,
                }
            },
        )
        return saved

    async def get_submission(self, submission_id: uuid.UUID) -> Submission:
        """Retrieve a submission by UUID or raise EntityNotFoundError."""
        submission = await self._repo.get_by_id(submission_id)
        if submission is None:
            raise EntityNotFoundError(f"Submission '{submission_id}' was not found.")
        return submission
