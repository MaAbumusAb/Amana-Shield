"""API routes for deterministic URL/domain triage and registry management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.repositories.submissions import DomainRepository, ThreatIndicatorRepository
from app.schemas.triage import (
    DeterministicTriageResult,
    DomainRegistryResponse,
    DomainRegistryUpsertRequest,
    ThreatIndicatorResponse,
    ThreatIndicatorUpsertRequest,
)
from app.services.triage_service import DeterministicTriageService

router = APIRouter(prefix="/triage", tags=["Deterministic Triage & Registry"])


class TriageInspectRequest(BaseModel):
    """Request payload for standalone deterministic URL and domain intelligence inspection."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    text: str = Field(
        min_length=1,
        max_length=10000,
        description="Plain text or URL(s) to inspect deterministically without LLM involvement.",
    )
    run_rdap: bool = False
    run_dns: bool = False
    run_redirects: bool = False


@router.post(
    "/inspect",
    response_model=DeterministicTriageResult,
    status_code=status.HTTP_200_OK,
    summary="Run deterministic URL extraction and domain intelligence on text",
)
async def inspect_urls_and_domains(
    payload: TriageInspectRequest,
    session: AsyncSession = Depends(get_db_session),
) -> DeterministicTriageResult:
    """Execute deterministic URL extraction, normalisation, registry matching, and optional network checks."""
    service = DeterministicTriageService(session=session)
    return await service.analyse_text(
        payload.text,
        run_rdap=payload.run_rdap,
        run_dns=payload.run_dns,
        run_redirects=payload.run_redirects,
    )


@router.post(
    "/domains",
    response_model=DomainRegistryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register or update a verified official, malicious, or suspicious domain",
)
async def upsert_domain_registry_entry(
    payload: DomainRegistryUpsertRequest,
    session: AsyncSession = Depends(get_db_session),
) -> DomainRegistryResponse:
    """Add or update a domain record with source, reason, status, expiry/review date, and reviewer."""
    repo = DomainRepository(session)
    record = await repo.upsert_domain_registry(payload)
    return DomainRegistryResponse.model_validate(record)


@router.get(
    "/domains",
    response_model=list[DomainRegistryResponse],
    status_code=status.HTTP_200_OK,
    summary="List registered domains by optional classification",
)
async def list_domain_registry_entries(
    classification: str | None = None,
    session: AsyncSession = Depends(get_db_session),
) -> list[DomainRegistryResponse]:
    """List curated domain registry records."""
    repo = DomainRepository(session)
    records = await repo.list_all_domains(classification=classification)
    return [DomainRegistryResponse.model_validate(r) for r in records]


@router.post(
    "/indicators",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register or update a threat indicator",
)
async def upsert_threat_indicator_entry(
    payload: ThreatIndicatorUpsertRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Add or update a confirmed or candidate threat intelligence indicator."""
    repo = ThreatIndicatorRepository(session)
    indicator = await repo.upsert_indicator(payload)
    return ThreatIndicatorResponse.model_validate(indicator)
