#!/usr/bin/env python3
"""Database Initial Seeding Script for AMANA SHIELD Production.

Populates initial curated Nigerian civic domains, official government registries,
fact-checking organizations, and baseline evidence debunking records.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import sys
import uuid
from datetime import datetime, timezone

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import dispose_engine, get_db_session
from app.models.entities import (
    ConfidenceLevel,
    Domain,
    DomainClassification,
    EvidenceSource,
    EvidenceSourceType,
    IndicatorStatus,
    IndicatorType,
    ThreatIndicator,
)
from app.schemas.evidence import SourceCategory, SourceVerificationStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_initial_data")

NOW = datetime.now(timezone.utc)

CURATED_DOMAINS = [
    {
        "canonical_host": "inecnigeria.org",
        "registered_domain": "inecnigeria.org",
        "tld_suffix": "org",
        "classification": DomainClassification.OFFICIAL.value,
        "official_institution": "INEC",
        "source": "CURATED_REGISTRY",
        "reason": "Official website of the Independent National Electoral Commission",
    },
    {
        "canonical_host": "cvr.inecnigeria.org",
        "registered_domain": "inecnigeria.org",
        "tld_suffix": "org",
        "classification": DomainClassification.OFFICIAL.value,
        "official_institution": "INEC",
        "source": "CURATED_REGISTRY",
        "reason": "Official INEC Continuous Voter Registration portal",
    },
    {
        "canonical_host": "statehouse.gov.ng",
        "registered_domain": "statehouse.gov.ng",
        "tld_suffix": "gov.ng",
        "classification": DomainClassification.OFFICIAL.value,
        "official_institution": "FGN",
        "source": "CURATED_REGISTRY",
        "reason": "Official website of the Presidency of Nigeria",
    },
    {
        "canonical_host": "nimc.gov.ng",
        "registered_domain": "nimc.gov.ng",
        "tld_suffix": "gov.ng",
        "classification": DomainClassification.OFFICIAL.value,
        "official_institution": "NIMC",
        "source": "CURATED_REGISTRY",
        "reason": "Official National Identity Management Commission portal",
    },
    {
        "canonical_host": "cbn.gov.ng",
        "registered_domain": "cbn.gov.ng",
        "tld_suffix": "gov.ng",
        "classification": DomainClassification.OFFICIAL.value,
        "official_institution": "CBN",
        "source": "CURATED_REGISTRY",
        "reason": "Official Central Bank of Nigeria portal",
    },
    {
        "canonical_host": "noa.gov.ng",
        "registered_domain": "noa.gov.ng",
        "tld_suffix": "gov.ng",
        "classification": DomainClassification.OFFICIAL.value,
        "official_institution": "NOA",
        "source": "CURATED_REGISTRY",
        "reason": "Official National Orientation Agency portal",
    },
    {
        "canonical_host": "dubawa.org",
        "registered_domain": "dubawa.org",
        "tld_suffix": "org",
        "classification": DomainClassification.BENIGN_KNOWN.value,
        "official_institution": None,
        "source": "FACT_CHECK_ORG",
        "reason": "Verified independent West African fact-checking organisation",
    },
    {
        "canonical_host": "africacheck.org",
        "registered_domain": "africacheck.org",
        "tld_suffix": "org",
        "classification": DomainClassification.BENIGN_KNOWN.value,
        "official_institution": None,
        "source": "FACT_CHECK_ORG",
        "reason": "Verified independent non-partisan fact-checking organisation",
    },
    {
        "canonical_host": "inec-pvc-activation.top",
        "registered_domain": "inec-pvc-activation.top",
        "tld_suffix": "top",
        "classification": DomainClassification.MALICIOUS.value,
        "official_institution": None,
        "source": "THREAT_INTEL",
        "reason": "Confirmed credential-harvesting phishing site masquerading as INEC portal",
    },
    {
        "canonical_host": "fg-empowerment-grant.xyz",
        "registered_domain": "fg-empowerment-grant.xyz",
        "tld_suffix": "xyz",
        "classification": DomainClassification.MALICIOUS.value,
        "official_institution": None,
        "source": "THREAT_INTEL",
        "reason": "Confirmed fake empowerment grant scam harvesting BVN and phone numbers",
    },
]

CURATED_EVIDENCE = [
    {
        "institution_code": "INEC",
        "title": "INEC Official Advisory: Voter Registration and PVC Collection Are Free",
        "source_type": EvidenceSourceType.DEBUNKING_NOTICE.value,
        "summary_content": (
            "INEC clarifies that voter registration, PVC collection, and polling unit transfers "
            "are completely free of charge. INEC never requests payment, processing fees, ATM PINs, "
            "or BVN from voters. Official registration occurs exclusively at cvr.inecnigeria.org "
            "or designated INEC LGA offices."
        ),
        "official_url": "https://inecnigeria.org/press-release-pvc-collection-is-free",
        "is_debunking_notice": True,
        "source_category": "GOVERNMENT_INSTITUTION",
        "verification_status": "VERIFIED_AUTHENTIC",
    },
    {
        "institution_code": "FGN",
        "title": "Federal Government Refutes N50,000 Cash Empowerment WhatsApp Link",
        "source_type": EvidenceSourceType.DEBUNKING_NOTICE.value,
        "summary_content": (
            "The Federal Government warns citizens against viral WhatsApp messages claiming an "
            "instant N50,000 presidential cash grant or palliative fund. No such online portal "
            "requiring BVN, bank details, or message forwarding to groups has been authorized. "
            "Official federal grants are published only via statehouse.gov.ng."
        ),
        "official_url": "https://statehouse.gov.ng/press-release-debunking-n50000-empowerment-scam",
        "is_debunking_notice": True,
        "source_category": "GOVERNMENT_INSTITUTION",
        "verification_status": "VERIFIED_AUTHENTIC",
    },
    {
        "institution_code": "INEC",
        "title": "INEC Official Notice: Ad-hoc Staff Recruitment Portal Security",
        "source_type": EvidenceSourceType.PRESS_RELEASE.value,
        "summary_content": (
            "INEC alerts the public that ad-hoc staff recruitment is conducted solely through its "
            "secure official portal pres.inecnigeria.org. INEC does not recruit via third-party "
            "blogs, WhatsApp groups, or phone calls, and no application fee is ever charged."
        ),
        "official_url": "https://inecnigeria.org/official-adhoc-recruitment-portal-notice",
        "is_debunking_notice": False,
        "source_category": "GOVERNMENT_INSTITUTION",
        "verification_status": "VERIFIED_AUTHENTIC",
    },
]

CURATED_THREAT_INDICATORS = [
    {
        "indicator_type": IndicatorType.DOMAIN.value,
        "indicator_value": "inec-pvc-activation.top",
        "threat_category": "CREDENTIAL_HARVESTING",
        "confidence_level": ConfidenceLevel.HIGH.value,
        "status": IndicatorStatus.CONFIRMED.value,
        "source_origin": "NIGERIAN_CERT_AND_INEC_INTEL",
        "reason": "Fake voter card validation portal soliciting NIN and phone numbers.",
    },
    {
        "indicator_type": IndicatorType.DOMAIN.value,
        "indicator_value": "fg-empowerment-grant.xyz",
        "threat_category": "FINANCIAL_ADVANCE_FEE_SCAM",
        "confidence_level": ConfidenceLevel.HIGH.value,
        "status": IndicatorStatus.CONFIRMED.value,
        "source_origin": "FACTCHECK_HUB_INTEL",
        "reason": "Phishing site imitating the Federal Ministry of Humanitarian Affairs.",
    },
]


async def seed_database() -> None:
    """Insert initial curated domain, evidence, and threat records if not already present."""
    logger.info("Starting database seeding...")
    async for session in get_db_session():
        # 1. Seed Domains
        for item in CURATED_DOMAINS:
            stmt = select(Domain).where(Domain.canonical_host == item["canonical_host"])
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if not existing:
                domain = Domain(
                    canonical_host=item["canonical_host"],
                    registered_domain=item["registered_domain"],
                    tld_suffix=item["tld_suffix"],
                    classification=item["classification"],
                    official_institution=item["official_institution"],
                    source=item["source"],
                    reason=item.get("reason"),
                    status="ACTIVE",
                    created_at=NOW,
                    updated_at=NOW,
                )
                session.add(domain)
                logger.info("Seeded domain: %s [%s]", item["canonical_host"], item["classification"])

        # 2. Seed Evidence Sources
        for item in CURATED_EVIDENCE:
            stmt = select(EvidenceSource).where(EvidenceSource.official_url == item["official_url"])
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if not existing:
                evidence = EvidenceSource(
                    institution_code=item["institution_code"],
                    title=item["title"],
                    source_type=item["source_type"],
                    summary_content=item["summary_content"],
                    official_url=item["official_url"],
                    is_debunking_notice=item["is_debunking_notice"],
                    published_at=NOW,
                    source_category=item["source_category"],
                    verification_status=item["verification_status"],
                    is_active=True,
                    created_at=NOW,
                    updated_at=NOW,
                )
                session.add(evidence)
                logger.info("Seeded evidence: %s", item["title"][:60])

        # 3. Seed Threat Indicators
        for item in CURATED_THREAT_INDICATORS:
            stmt = select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == item["indicator_type"],
                ThreatIndicator.indicator_value == item["indicator_value"],
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if not existing:
                indicator = ThreatIndicator(
                    indicator_type=item["indicator_type"],
                    indicator_value=item["indicator_value"],
                    threat_category=item["threat_category"],
                    confidence_level=item["confidence_level"],
                    status=item["status"],
                    source_origin=item["source_origin"],
                    reason=item.get("reason"),
                    reviewer="SYSTEM_INIT",
                    valid_from=NOW,
                    created_at=NOW,
                    updated_at=NOW,
                )
                session.add(indicator)
                logger.info("Seeded threat indicator: %s [%s]", item["indicator_value"], item["threat_category"])

        await session.commit()
        logger.info("Database seeding completed successfully.")

    await dispose_engine()


if __name__ == "__main__":
    asyncio.run(seed_database())
