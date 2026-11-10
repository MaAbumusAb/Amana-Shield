"""Deterministic URL and Domain Intelligence Service.

Operates strictly without an LLM:
1. Extracts and normalises URLs (standard, defanged, IDN/punycode, shortened, malformed).
2. Inspects domain and threat indicator registries in PostgreSQL.
3. Detects institutional lookalikes / brand impersonation (INEC, NIMC, CBN, EFCC, .gov.ng).
4. Optionally executes bounded RDAP, DNS, and SSRF-safe redirect checks.
5. Treats domain age as a weak risk indicator — never conclusive proof of malice.
6. Preserves the rule that a verified official domain does not automatically make a message trustworthy.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.integrations.domain_intel import DNSIntelligenceClient, RDAPIntelligenceClient
from app.integrations.safe_redirect import SafeRedirectInspector
from app.models.entities import Domain, DomainClassification, UrlRisk
from app.repositories.submissions import (
    DomainRepository,
    SubmissionRepository,
    ThreatIndicatorRepository,
)
from app.schemas.triage import (
    DeterministicTriageResult,
    DNSFinding,
    ExtractedUrlFinding,
    NormalisedDomainSummary,
    RDAPRegistrationInfo,
    RedirectAnalysisFinding,
    RiskIndicatorFinding,
    ThreatMatchFinding,
)
from app.utils.text import (
    detect_brand_impersonation,
    extract_urls_from_text,
    parse_and_normalise_url,
)


class DeterministicTriageService:
    """Orchestrates deterministic URL and domain intelligence analysis."""

    def __init__(
        self,
        session: AsyncSession,
        rdap_client: RDAPIntelligenceClient | None = None,
        dns_client: DNSIntelligenceClient | None = None,
        redirect_inspector: SafeRedirectInspector | None = None,
        enable_live_network_checks: bool = False,
    ) -> None:
        self._session = session
        self._domain_repo = DomainRepository(session)
        self._threat_repo = ThreatIndicatorRepository(session)
        self._submission_repo = SubmissionRepository(session)
        self._rdap_client = rdap_client or RDAPIntelligenceClient()
        self._dns_client = dns_client or DNSIntelligenceClient()
        self._redirect_inspector = redirect_inspector or SafeRedirectInspector()
        self._enable_live_network = enable_live_network_checks

    async def analyse_text(
        self,
        raw_text: str,
        *,
        run_rdap: bool | None = None,
        run_dns: bool | None = None,
        run_redirects: bool | None = None,
    ) -> DeterministicTriageResult:
        """Extract URLs from text and execute deterministic domain & threat intelligence."""
        extracted_urls = extract_urls_from_text(raw_text)
        return await self.analyse_extracted_urls(
            extracted_urls,
            run_rdap=run_rdap,
            run_dns=run_dns,
            run_redirects=run_redirects,
        )

    async def analyse_extracted_urls(
        self,
        extracted_urls: list[ExtractedUrlFinding],
        *,
        run_rdap: bool | None = None,
        run_dns: bool | None = None,
        run_redirects: bool | None = None,
    ) -> DeterministicTriageResult:
        """Run deterministic checks on a list of extracted URL findings."""
        if not extracted_urls:
            return DeterministicTriageResult(
                aggregated_url_risk=UrlRisk.NO_URL,
            )

        do_rdap = self._enable_live_network if run_rdap is None else run_rdap
        do_dns = self._enable_live_network if run_dns is None else run_dns
        do_redirects = (
            self._enable_live_network if run_redirects is None else run_redirects
        )

        normalised_domains: list[NormalisedDomainSummary] = []
        threat_matches: list[ThreatMatchFinding] = []
        registration_info: list[RDAPRegistrationInfo] = []
        dns_findings: list[DNSFinding] = []
        redirect_findings: list[RedirectAnalysisFinding] = []
        risk_indicators: list[RiskIndicatorFinding] = []
        unavailable_checks: list[str] = []

        seen_hosts: set[str] = set()
        seen_reg_domains_for_rdap: set[str] = set()

        # Collect all candidate lookup strings for batch ThreatIndicator query
        lookup_values: set[str] = set()
        for u in extracted_urls:
            if u.normalised_url:
                lookup_values.add(u.normalised_url)
            if u.canonical_host:
                lookup_values.add(u.canonical_host)
            if u.registered_domain:
                lookup_values.add(u.registered_domain)

        # 1. Inspect URL-level anomalies (malformed, defanged, shortened, private IP, IDN)
        for u in extracted_urls:
            if u.is_malformed:
                risk_indicators.append(
                    RiskIndicatorFinding(
                        code="TR-MALFORMED-URL",
                        severity="MEDIUM",
                        weight_category="STRONG_SIGNAL",
                        target=u.raw_url,
                        description="Submitted URL is structurally malformed or uses forbidden authority syntax.",
                        evidence=u.malformed_reason,
                    )
                )
                continue

            if u.was_defanged:
                risk_indicators.append(
                    RiskIndicatorFinding(
                        code="TR-DEFANGED-URL",
                        severity="LOW",
                        weight_category="WEAK_SIGNAL",
                        target=u.normalised_url or u.raw_url,
                        description="URL was submitted in defanged/obfuscated notation (e.g. hxxps or [.]).",
                        evidence=u.raw_url,
                    )
                )

            if u.is_private_or_reserved_ip:
                risk_indicators.append(
                    RiskIndicatorFinding(
                        code="TR-PRIVATE-OR-RESERVED-IP-URL",
                        severity="CRITICAL",
                        weight_category="CONCLUSIVE_THREAT",
                        target=u.normalised_url or u.raw_url,
                        description="URL points to a loopback, private, link-local, or cloud metadata IP address.",
                        evidence=u.canonical_host,
                    )
                )
            elif u.is_ip_literal:
                risk_indicators.append(
                    RiskIndicatorFinding(
                        code="TR-RAW-IP-LITERAL-URL",
                        severity="MEDIUM",
                        weight_category="STRONG_SIGNAL",
                        target=u.normalised_url or u.raw_url,
                        description="URL uses a raw IP address instead of a registered domain name.",
                        evidence=u.canonical_host,
                    )
                )

            if u.is_idn_punycode or u.has_mixed_script_or_confusable:
                risk_indicators.append(
                    RiskIndicatorFinding(
                        code="TR-IDN-PUNYCODE-CONFUSABLE",
                        severity="HIGH",
                        weight_category="STRONG_SIGNAL",
                        target=u.canonical_host or u.raw_url,
                        description="Domain uses IDN Punycode (xn--) or mixed Unicode scripts often used in homograph attacks.",
                        evidence=f"canonical={u.canonical_host}, unicode={u.unicode_host}",
                    )
                )

            if u.is_shortened_url:
                risk_indicators.append(
                    RiskIndicatorFinding(
                        code="TR-SHORTENED-URL",
                        severity="MEDIUM",
                        weight_category="WEAK_SIGNAL",
                        target=u.normalised_url or u.raw_url,
                        description="URL uses a link shortener service that masks the true destination domain.",
                        evidence=u.registered_domain,
                    )
                )

            # Optional controlled redirect analysis
            if do_redirects and u.normalised_url and not u.is_private_or_reserved_ip:
                redir_res = await self._redirect_inspector.inspect_url(u.normalised_url)
                redirect_findings.append(redir_res)
                if redir_res.ssrf_or_rebinding_blocked:
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-REDIRECT-SSRF-BLOCKED",
                            severity="CRITICAL",
                            weight_category="CONCLUSIVE_THREAT",
                            target=u.normalised_url,
                            description="Redirect chain attempted to reach a blocked private/reserved IP or failed DNS rebinding verification.",
                            evidence=redir_res.error_message,
                        )
                    )
                elif redir_res.error_message:
                    unavailable_checks.append(
                        f"REDIRECT_CHECK:{u.normalised_url}:{redir_res.error_message}"
                    )
                if (
                    redir_res.final_url
                    and redir_res.final_url != u.normalised_url
                    and not redir_res.ssrf_or_rebinding_blocked
                ):
                    final_parsed = parse_and_normalise_url(
                        redir_res.final_url, require_valid_tld_if_schemeless=False
                    )
                    if final_parsed and final_parsed.canonical_host:
                        lookup_values.add(final_parsed.canonical_host)
                        if final_parsed.registered_domain:
                            lookup_values.add(final_parsed.registered_domain)
                        if final_parsed.normalised_url:
                            lookup_values.add(final_parsed.normalised_url)

        # 2. Check ThreatIndicator table for any matching URLs or domains
        matched_indicators = await self._threat_repo.find_indicators_by_values(
            list(lookup_values)
        )
        for ind in matched_indicators:
            is_confirmed = ind.status == "CONFIRMED"
            threat_matches.append(
                ThreatMatchFinding(
                    match_source="THREAT_INDICATOR",
                    indicator_type=ind.indicator_type,
                    matched_value=ind.indicator_value,
                    classification=(
                        DomainClassification.MALICIOUS.value
                        if is_confirmed
                        else DomainClassification.SUSPICIOUS.value
                    ),
                    status=ind.status,
                    confidence=ind.confidence_level,
                    source=ind.source_origin,
                    reason=ind.reason or f"Matched {ind.threat_category} indicator",
                    date_added=ind.created_at,
                    expiry_or_review_date=ind.valid_until,
                    reviewer=ind.reviewer,
                )
            )
            risk_indicators.append(
                RiskIndicatorFinding(
                    code=(
                        "TR-CONFIRMED-THREAT-INDICATOR"
                        if is_confirmed
                        else "TR-CANDIDATE-THREAT-INDICATOR"
                    ),
                    severity="CRITICAL" if is_confirmed else "HIGH",
                    weight_category=(
                        "CONCLUSIVE_THREAT" if is_confirmed else "STRONG_SIGNAL"
                    ),
                    target=ind.indicator_value,
                    description=(
                        f"Matched {ind.status.lower()} threat intelligence indicator "
                        f"({ind.threat_category})."
                    ),
                    evidence=f"source={ind.source_origin}, confidence={ind.confidence_level}",
                )
            )

        # 3. Domain-level registry checks, impersonation analysis, DNS, and RDAP
        for u in extracted_urls:
            if u.is_malformed or not u.canonical_host or not u.registered_domain:
                continue
            if u.canonical_host in seen_hosts:
                continue
            seen_hosts.add(u.canonical_host)

            domain_records = await self._domain_repo.find_matching_domain_records(
                u.canonical_host, u.registered_domain
            )
            matched_domain: Domain | None = None
            for rec in domain_records:
                if rec.canonical_host == u.canonical_host:
                    matched_domain = rec
                    break
            if matched_domain is None and domain_records:
                matched_domain = domain_records[0]

            classification = DomainClassification.UNKNOWN.value
            official_inst: str | None = None
            prior_reports = 0

            if matched_domain is not None and matched_domain.status == "ACTIVE":
                classification = matched_domain.classification
                official_inst = matched_domain.official_institution
                prior_reports = await self._submission_repo.count_submissions_by_domain(
                    matched_domain.id
                )

                if classification in {
                    DomainClassification.MALICIOUS.value,
                    DomainClassification.SUSPICIOUS.value,
                    DomainClassification.OFFICIAL.value,
                }:
                    threat_matches.append(
                        ThreatMatchFinding(
                            match_source="DOMAIN_REGISTRY",
                            indicator_type="DOMAIN",
                            matched_value=matched_domain.canonical_host,
                            classification=classification,
                            status=matched_domain.status,
                            confidence="HIGH",
                            source=matched_domain.source,
                            reason=matched_domain.reason,
                            official_institution=official_inst,
                            date_added=matched_domain.created_at,
                            expiry_or_review_date=(
                                matched_domain.review_date
                                or matched_domain.domain_expires_at
                            ),
                            reviewer=matched_domain.reviewer,
                        )
                    )

                if classification == DomainClassification.MALICIOUS.value:
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-DOMAIN-REGISTRY-MALICIOUS",
                            severity="CRITICAL",
                            weight_category="CONCLUSIVE_THREAT",
                            target=u.canonical_host,
                            description="Domain is listed as MALICIOUS in the curated domain registry.",
                            evidence=matched_domain.reason or matched_domain.source,
                        )
                    )
                elif classification == DomainClassification.SUSPICIOUS.value:
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-DOMAIN-REGISTRY-SUSPICIOUS",
                            severity="HIGH",
                            weight_category="STRONG_SIGNAL",
                            target=u.canonical_host,
                            description="Domain is flagged as SUSPICIOUS in the domain registry.",
                            evidence=matched_domain.reason or matched_domain.source,
                        )
                    )
                elif classification == DomainClassification.OFFICIAL.value:
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-VERIFIED-OFFICIAL-DOMAIN",
                            severity="INFO",
                            weight_category="OFFICIAL_SIGNAL",
                            target=u.canonical_host,
                            description=(
                                f"Domain is a verified official portal for {official_inst}. "
                                "Note: Message content and claims must still be verified independently."
                            ),
                            evidence=official_inst,
                        )
                    )

                if (
                    prior_reports > 0
                    and classification != DomainClassification.OFFICIAL.value
                ):
                    threat_matches.append(
                        ThreatMatchFinding(
                            match_source="PRIOR_SUBMISSION",
                            indicator_type="DOMAIN",
                            matched_value=u.canonical_host,
                            classification=classification,
                            status="REPORTED",
                            confidence="LOW",
                            source="INTERNAL_SUBMISSION_HISTORY",
                            reason=f"Previously reported in {prior_reports} user submission(s).",
                            date_added=matched_domain.created_at,
                        )
                    )
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-PREVIOUSLY-REPORTED-DOMAIN",
                            severity="LOW",
                            weight_category="WEAK_SIGNAL",
                            target=u.canonical_host,
                            description=f"Domain has appeared in {prior_reports} prior user submission(s).",
                            evidence=f"sightings={prior_reports}",
                        )
                    )

            # Brand / institutional lookalike check (if not already verified OFFICIAL)
            impersonated_brand: str | None = None
            if classification != DomainClassification.OFFICIAL.value:
                impersonated_brand, imp_reason = detect_brand_impersonation(
                    u.canonical_host, u.registered_domain
                )
                if impersonated_brand and imp_reason:
                    if classification == DomainClassification.UNKNOWN.value:
                        classification = DomainClassification.SUSPICIOUS.value
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-INSTITUTIONAL-LOOKALIKE-DOMAIN",
                            severity="HIGH",
                            weight_category="STRONG_SIGNAL",
                            target=u.canonical_host,
                            description=imp_reason,
                            evidence=f"impersonated_institution={impersonated_brand}",
                        )
                    )

            normalised_domains.append(
                NormalisedDomainSummary(
                    canonical_host=u.canonical_host,
                    unicode_host=u.unicode_host or u.canonical_host,
                    registered_domain=u.registered_domain,
                    subdomain=u.subdomain,
                    tld_suffix=u.tld_suffix,
                    classification=classification,
                    official_institution=official_inst,
                    is_idn_punycode=u.is_idn_punycode,
                    is_shortened_service=u.is_shortened_url,
                    previously_reported_count=prior_reports,
                    impersonation_target=impersonated_brand,
                )
            )

            # Check cached RDAP data on Domain record or perform live RDAP lookup if enabled
            if not u.is_ip_literal and u.registered_domain not in seen_reg_domains_for_rdap:
                seen_reg_domains_for_rdap.add(u.registered_domain)
                rdap_info: RDAPRegistrationInfo | None = None

                if (
                    matched_domain is not None
                    and matched_domain.domain_registered_at is not None
                ):
                    reg_dt = matched_domain.domain_registered_at
                    if reg_dt.tzinfo is None:
                        reg_dt = reg_dt.replace(tzinfo=timezone.utc)
                    age_days = max(0, (datetime.now(timezone.utc) - reg_dt).days)
                    rdap_info = RDAPRegistrationInfo(
                        lookup_status="CACHED",
                        registered_domain=u.registered_domain,
                        registrar_name=matched_domain.registrar_name,
                        registered_at=reg_dt,
                        expires_at=matched_domain.domain_expires_at,
                        domain_age_days=age_days,
                    )
                elif do_rdap:
                    rdap_info = await self._rdap_client.lookup_domain(
                        u.registered_domain
                    )
                    if rdap_info.lookup_status in {"UNAVAILABLE", "RATE_LIMITED"}:
                        unavailable_checks.append(
                            f"RDAP:{u.registered_domain}:{rdap_info.error_message}"
                        )

                if rdap_info is not None:
                    registration_info.append(rdap_info)
                    # Domain age is strictly a WEAK risk signal, never conclusive proof!
                    if (
                        rdap_info.domain_age_days is not None
                        and rdap_info.domain_age_days < 30
                        and classification != DomainClassification.OFFICIAL.value
                    ):
                        risk_indicators.append(
                            RiskIndicatorFinding(
                                code="TR-NEWLY-REGISTERED-DOMAIN",
                                severity="LOW",
                                weight_category="WEAK_SIGNAL",
                                target=u.registered_domain,
                                description=(
                                    f"Domain was registered recently ({rdap_info.domain_age_days} days ago). "
                                    "Treated as a weak supporting indicator, not proof of malice."
                                ),
                                evidence=f"age_days={rdap_info.domain_age_days}",
                            )
                        )

            # Optional DNS check
            if do_dns and not u.is_ip_literal:
                dns_res = await self._dns_client.lookup_host(u.canonical_host)
                dns_findings.append(dns_res)
                if dns_res.lookup_status == "UNAVAILABLE":
                    unavailable_checks.append(
                        f"DNS:{u.canonical_host}:{dns_res.error_message}"
                    )
                elif dns_res.has_private_or_reserved_ip:
                    risk_indicators.append(
                        RiskIndicatorFinding(
                            code="TR-DNS-PRIVATE-IP-REBINDING",
                            severity="CRITICAL",
                            weight_category="CONCLUSIVE_THREAT",
                            target=u.canonical_host,
                            description="Domain resolves to a private, loopback, or reserved IP address (potential DNS rebinding).",
                            evidence=", ".join(dns_res.blocked_ips),
                        )
                    )

        # 4. Compute deterministic aggregated_url_risk
        # Crucially: Domain age (WEAK_SIGNAL) alone never escalates to MALICIOUS.
        has_conclusive_threat = any(
            r.weight_category == "CONCLUSIVE_THREAT" for r in risk_indicators
        )
        has_strong_signal = any(
            r.weight_category == "STRONG_SIGNAL" for r in risk_indicators
        )
        has_weak_signal = any(
            r.weight_category == "WEAK_SIGNAL" for r in risk_indicators
        )
        all_domains_official = bool(normalised_domains) and all(
            d.classification == DomainClassification.OFFICIAL.value
            for d in normalised_domains
        )
        any_domain_official = any(
            d.classification == DomainClassification.OFFICIAL.value
            for d in normalised_domains
        )

        if has_conclusive_threat:
            aggregated_url_risk = UrlRisk.MALICIOUS
        elif has_strong_signal:
            aggregated_url_risk = UrlRisk.SUSPICIOUS
        elif all_domains_official and not has_weak_signal:
            aggregated_url_risk = UrlRisk.VERIFIED_OFFICIAL
        elif has_weak_signal:
            # Weak signal alone (such as domain age < 30 days or defanged formatting)
            # never marks a URL as MALICIOUS; shortened URLs are SUSPICIOUS, others remain UNKNOWN/SUSPICIOUS.
            if any(u.is_shortened_url for u in extracted_urls):
                aggregated_url_risk = UrlRisk.SUSPICIOUS
            else:
                aggregated_url_risk = UrlRisk.UNKNOWN
        else:
            aggregated_url_risk = UrlRisk.UNKNOWN

        trust_warning: str | None = None
        if any_domain_official:
            trust_warning = (
                "Contains a verified official domain. A verified domain does not automatically "
                "make the surrounding message trustworthy; scammers frequently include legitimate "
                "URLs alongside fraudulent instructions, phone numbers, or bank accounts."
            )

        return DeterministicTriageResult(
            extracted_urls=extracted_urls,
            normalised_domains=normalised_domains,
            threat_matches=threat_matches,
            registration_info=registration_info,
            dns_findings=dns_findings,
            redirect_findings=redirect_findings,
            risk_indicators=risk_indicators,
            unavailable_checks=unavailable_checks,
            aggregated_url_risk=aggregated_url_risk,
            contains_verified_official_domain=any_domain_official,
            trust_warning=trust_warning,
        )
