"""API routes for the AMANA SHIELD Risk Fusion Engine."""

from __future__ import annotations

import uuid
from typing import Optional
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.models.entities import Submission
from app.repositories.submissions import SubmissionRepository
from app.schemas.fusion import RiskFusionEvaluation, SupportedLanguage
from app.services.ai_analysis_service import AIScamAnalysisService
from app.services.evidence_service import EvidenceVerificationService
from app.services.risk_fusion_service import compute_risk_fusion
from app.services.triage_service import DeterministicTriageService
from app.utils.text import normalise_message_text

router = APIRouter(prefix="/fusion", tags=["Risk Fusion Engine"])


class FusionInspectRequest(BaseModel):
    """Inspect and evaluate raw text using the full Risk Fusion pipeline."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    text: str = Field(min_length=1, max_length=10000)
    language: SupportedLanguage = SupportedLanguage.ENGLISH
    preferred_language: Optional[SupportedLanguage] = None

    @model_validator(mode="after")
    def resolve_language(self) -> "FusionInspectRequest":
        if self.preferred_language is not None:
            self.language = self.preferred_language
        return self


@router.post(
    "/evaluate-text",
    response_model=RiskFusionEvaluation,
    status_code=status.HTTP_200_OK,
    summary="Evaluate submitted text across all 3 pillars and return final public verdict",
)
async def evaluate_text_fusion(
    payload: FusionInspectRequest,
    session: AsyncSession = Depends(get_db_session),
) -> RiskFusionEvaluation:
    """Run Deterministic Triage, AI Message Analysis, and Evidence Verification, then fuse."""
    clean_text = normalise_message_text(payload.text)

    triage_service = DeterministicTriageService(session=session)
    ai_service = AIScamAnalysisService()
    evidence_service = EvidenceVerificationService(session=session)

    triage_res = await triage_service.analyse_text(clean_text)
    ai_res = await ai_service.analyse_message(clean_text)
    evidence_res = await evidence_service.verify_claims(ai_res.extracted_claims)

    return compute_risk_fusion(
        triage_result=triage_res,
        ai_result=ai_res,
        evidence_result=evidence_res,
        preferred_language=payload.language,
    )
