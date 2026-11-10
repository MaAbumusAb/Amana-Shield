"""Data access repositories using safe parameterised SQLAlchemy 2.x queries."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.entities import (
    Assessment,
    Domain,
    EvidenceSource,
    Submission,
    ThreatIndicator,
)
from app.schemas.triage import DomainRegistryUpsertRequest, ThreatIndicatorUpsertRequest
from app.utils.text import parse_and_normalise_url


class SubmissionRepository:
    """Repository for Submission and Assessment persistence operations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, submission_id: uuid.UUID) -> Submission | None:
        """Fetch a submission and its assessment by primary key UUID."""
        stmt = (
            select(Submission)
            .options(selectinload(Submission.assessment))
            .where(Submission.id == submission_id)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_external_message_id(
        self, external_message_id: str
    ) -> Submission | None:
        """Fetch a submission by its external_message_id (idempotency check)."""
        stmt = (
            select(Submission)
            .options(selectinload(Submission.assessment))
            .where(Submission.external_message_id == external_message_id)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def count_submissions_by_domain(self, domain_id: uuid.UUID) -> int:
        """Count how many prior assessments referenced a given primary domain."""
        stmt = (
            select(func.count())
            .select_from(Assessment)
            .where(Assessment.primary_domain_id == domain_id)
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def create_submission_with_assessment(
        self,
        submission: Submission,
        assessment: Assessment,
    ) -> Submission:
        """Persist a new submission and its initial assessment atomically."""
        self._session.add(submission)
        await self._session.flush()
        assessment.submission_id = submission.id
        self._session.add(assessment)
        await self._session.commit()
        return await self.get_by_id(submission.id)  # type: ignore[return-value]


class DomainRepository:
    """Repository for verified official domains, malicious/suspicious domains, and discovered hosts."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_canonical_host(self, canonical_host: str) -> Domain | None:
        stmt = select(Domain).where(Domain.canonical_host == canonical_host.lower())
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_matching_domain_records(
        self, canonical_host: str, registered_domain: str
    ) -> list[Domain]:
        """Lookup both exact canonical_host and parent registered_domain records."""
        stmt = select(Domain).where(
            or_(
                Domain.canonical_host == canonical_host.lower(),
                Domain.canonical_host == registered_domain.lower(),
                Domain.registered_domain == registered_domain.lower(),
            )
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_all_domains(
        self, classification: str | None = None
    ) -> list[Domain]:
        stmt = select(Domain).order_by(Domain.created_at.desc())
        if classification:
            stmt = stmt.where(Domain.classification == classification.upper())
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def upsert_domain_registry(
        self, payload: DomainRegistryUpsertRequest
    ) -> Domain:
        """Create or update a curated domain registry record (official, malicious, or suspicious)."""
        parsed = parse_and_normalise_url(
            payload.canonical_host, require_valid_tld_if_schemeless=False
        )
        canonical_host = (
            parsed.canonical_host
            if parsed and parsed.canonical_host
            else payload.canonical_host.lower()
        )
        registered_domain = (
            parsed.registered_domain
            if parsed and parsed.registered_domain
            else canonical_host
        )
        tld_suffix = (
            parsed.tld_suffix
            if parsed and parsed.tld_suffix
            else canonical_host.split(".")[-1]
        )
        is_idn = bool(parsed.is_idn_punycode) if parsed else ("xn--" in canonical_host)

        existing = await self.get_by_canonical_host(canonical_host)
        if existing is not None:
            existing.classification = payload.classification.value
            existing.official_institution = payload.official_institution
            existing.status = payload.status
            existing.source = payload.source
            existing.reason = payload.reason
            existing.review_date = payload.review_date
            existing.domain_expires_at = payload.domain_expires_at
            existing.reviewer = payload.reviewer
            await self._session.commit()
            await self._session.refresh(existing)
            return existing

        record = Domain(
            canonical_host=canonical_host,
            registered_domain=registered_domain,
            tld_suffix=tld_suffix,
            is_idn_punycode=is_idn,
            classification=payload.classification.value,
            official_institution=payload.official_institution,
            status=payload.status,
            source=payload.source,
            reason=payload.reason,
            review_date=payload.review_date,
            domain_expires_at=payload.domain_expires_at,
            reviewer=payload.reviewer,
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        return record


class ThreatIndicatorRepository:
    """Repository for confirmed and candidate threat indicators."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_indicators_by_values(
        self, values: list[str]
    ) -> list[ThreatIndicator]:
        """Lookup any active (CONFIRMED or CANDIDATE) threat indicators matching the given values."""
        if not values:
            return []
        now = datetime.now(timezone.utc)
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.indicator_value.in_(values),
            ThreatIndicator.status.in_(["CONFIRMED", "CANDIDATE"]),
            or_(
                ThreatIndicator.valid_until.is_(None),
                ThreatIndicator.valid_until > now,
            ),
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def find_confirmed_indicator(
        self, indicator_type: str, indicator_value: str
    ) -> ThreatIndicator | None:
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.indicator_type == indicator_type,
            ThreatIndicator.indicator_value == indicator_value,
            ThreatIndicator.status == "CONFIRMED",
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def upsert_indicator(
        self, payload: ThreatIndicatorUpsertRequest
    ) -> ThreatIndicator:
        """Create or update a threat indicator record."""
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.indicator_type == payload.indicator_type.value,
            ThreatIndicator.indicator_value == payload.indicator_value,
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is not None:
            existing.threat_category = payload.threat_category
            existing.confidence_level = payload.confidence_level.value
            existing.status = payload.status.value
            existing.source_origin = payload.source_origin
            existing.reason = payload.reason
            existing.valid_until = payload.valid_until
            existing.reviewer = payload.reviewer
            await self._session.commit()
            await self._session.refresh(existing)
            return existing

        indicator = ThreatIndicator(
            indicator_type=payload.indicator_type.value,
            indicator_value=payload.indicator_value,
            threat_category=payload.threat_category,
            confidence_level=payload.confidence_level.value,
            status=payload.status.value,
            source_origin=payload.source_origin,
            reason=payload.reason,
            valid_until=payload.valid_until,
            reviewer=payload.reviewer,
        )
        self._session.add(indicator)
        await self._session.commit()
        await self._session.refresh(indicator)
        return indicator


class EvidenceSourceRepository:
    """Repository for curated official announcements, debunking notices, and primary sources."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, source_id: uuid.UUID) -> EvidenceSource | None:
        stmt = select(EvidenceSource).where(EvidenceSource.id == source_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_official_url(self, official_url: str) -> EvidenceSource | None:
        stmt = select(EvidenceSource).where(EvidenceSource.official_url == official_url)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_active_by_institution(
        self, institution_code: str
    ) -> list[EvidenceSource]:
        stmt = (
            select(EvidenceSource)
            .where(
                EvidenceSource.institution_code == institution_code.upper(),
                EvidenceSource.is_active.is_(True),
            )
            .order_by(EvidenceSource.published_at.desc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def search_evidence(
        self,
        keywords: list[str],
        institution_code: str | None = None,
        limit: int = 5,
    ) -> list[EvidenceSource]:
        """Search active evidence sources using keywords and institution filtering with dialect fallback."""
        stmt = select(EvidenceSource).where(EvidenceSource.is_active.is_(True))

        if institution_code:
            stmt = stmt.where(EvidenceSource.institution_code == institution_code.upper())

        cleaned_keywords = [
            k.strip().lower()
            for k in keywords
            if k and len(k.strip()) >= 3 and k.strip().lower() not in {"and", "the", "for", "with", "this", "that", "inec"}
        ]

        if cleaned_keywords:
            conditions = []
            for kw in cleaned_keywords:
                pattern = f"%{kw}%"
                conditions.append(EvidenceSource.title.ilike(pattern))
                conditions.append(EvidenceSource.summary_content.ilike(pattern))
            stmt = stmt.where(or_(*conditions))

        # Prioritise debunking notices first, then newest published items
        stmt = stmt.order_by(
            EvidenceSource.is_debunking_notice.desc(),
            EvidenceSource.published_at.desc(),
        ).limit(limit)

        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def upsert_evidence_source(
        self,
        institution_code: str,
        title: str,
        source_type: str,
        summary_content: str,
        official_url: str,
        published_at: datetime,
        is_debunking_notice: bool = False,
        valid_until: datetime | None = None,
        is_active: bool = True,
        source_category: str = "GOVERNMENT_INSTITUTION",
        verification_status: str = "VERIFIED_AUTHENTIC",
    ) -> EvidenceSource:
        """Create or update a curated evidence source record."""
        existing = await self.get_by_official_url(official_url)
        if existing is not None:
            existing.institution_code = institution_code.upper()
            existing.title = title
            existing.source_type = source_type
            existing.summary_content = summary_content
            existing.is_debunking_notice = is_debunking_notice
            existing.published_at = published_at
            existing.valid_until = valid_until
            existing.is_active = is_active
            existing.source_category = source_category
            existing.verification_status = verification_status
            existing.last_checked_at = datetime.now(timezone.utc)
            await self._session.commit()
            await self._session.refresh(existing)
            return existing

        source = EvidenceSource(
            institution_code=institution_code.upper(),
            title=title,
            source_type=source_type,
            summary_content=summary_content,
            official_url=official_url,
            is_debunking_notice=is_debunking_notice,
            published_at=published_at,
            valid_until=valid_until,
            is_active=is_active,
            source_category=source_category,
            verification_status=verification_status,
            last_checked_at=datetime.now(timezone.utc),
        )
        self._session.add(source)
        await self._session.commit()
        await self._session.refresh(source)
        return source
