"""API routes for Evidence Source registry and claim verification."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.repositories.submissions import EvidenceSourceRepository
from app.schemas.ai_analysis import ExtractedClaimItem
from app.schemas.evidence import (
    EvidenceSourceRecordSchema,
    EvidenceSourceUpsertRequest,
    EvidenceVerificationResult,
)
from app.services.evidence_service import EvidenceVerificationService

router = APIRouter(prefix="/evidence", tags=["Evidence & Claim Verification"])


class ClaimVerifyRequest(BaseModel):
    """Request payload to verify a list of extracted claims."""

    model_config = ConfigDict(extra="forbid")

    claims: list[ExtractedClaimItem] = Field(min_length=1)
    use_llm: bool = True


@router.post(
    "/verify-claims",
    response_model=EvidenceVerificationResult,
    status_code=status.HTTP_200_OK,
    summary="Verify extracted claims against curated official evidence sources",
)
async def verify_claims_endpoint(
    payload: ClaimVerifyRequest,
    session: AsyncSession = Depends(get_db_session),
) -> EvidenceVerificationResult:
    """Compare extracted claims against curated sources and return evidence-backed verdicts."""
    service = EvidenceVerificationService(session=session)
    return await service.verify_claims(payload.claims, use_llm=payload.use_llm)


@router.post(
    "/sources",
    response_model=EvidenceSourceRecordSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Add or update a curated evidence source in the registry",
)
async def upsert_evidence_source_endpoint(
    payload: EvidenceSourceUpsertRequest,
    session: AsyncSession = Depends(get_db_session),
) -> EvidenceSourceRecordSchema:
    """Register or update an official announcement, debunking notice, or fact-check item."""
    repo = EvidenceSourceRepository(session)
    source = await repo.upsert_evidence_source(
        institution_code=payload.institution_code,
        title=payload.title,
        source_type=payload.source_type.value,
        summary_content=payload.summary_content,
        official_url=payload.official_url,
        published_at=payload.published_at,
        is_debunking_notice=payload.is_debunking_notice,
        valid_until=payload.valid_until,
        is_active=payload.is_active,
        source_category=payload.source_category.value,
        verification_status=payload.verification_status.value,
    )
    return EvidenceSourceRecordSchema.model_validate(source)


@router.get(
    "/sources",
    response_model=list[EvidenceSourceRecordSchema],
    status_code=status.HTTP_200_OK,
    summary="List curated evidence sources by institution",
)
async def list_evidence_sources_endpoint(
    institution: str,
    session: AsyncSession = Depends(get_db_session),
) -> list[EvidenceSourceRecordSchema]:
    """Retrieve active curated sources for an institution (e.g., INEC, FGN, NIMC)."""
    repo = EvidenceSourceRepository(session)
    sources = await repo.list_active_by_institution(institution)
    return [EvidenceSourceRecordSchema.model_validate(s) for s in sources]
