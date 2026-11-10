"""Optional RDAP and DNS intelligence clients with timeouts, caching, and rate limits."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.schemas.triage import DNSFinding, RDAPRegistrationInfo
from app.utils.text import is_ip_blocked_or_reserved


class AsyncSlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter to protect outbound RDAP/DNS lookups."""

    def __init__(self, max_calls: int = 20, window_seconds: float = 60.0) -> None:
        self._max_calls = max_calls
        self._window_seconds = window_seconds
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_seconds
            self._timestamps = [ts for ts in self._timestamps if ts > cutoff]
            if len(self._timestamps) >= self._max_calls:
                return False
            self._timestamps.append(now)
            return True


class DNSIntelligenceClient:
    """Async DNS resolver with timeout, TTL cache, and private IP detection."""

    def __init__(
        self,
        timeout_seconds: float = 2.0,
        cache_ttl_seconds: float = 900.0,
        rate_limiter: AsyncSlidingWindowRateLimiter | None = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[float, DNSFinding]] = {}
        self._rate_limiter = rate_limiter or AsyncSlidingWindowRateLimiter(
            max_calls=30, window_seconds=60.0
        )

    async def lookup_host(self, canonical_host: str) -> DNSFinding:
        """Resolve A, AAAA, MX, and NS records with strict timeout and private IP checks."""
        host = canonical_host.lower().strip(".")
        now_mono = time.monotonic()
        cached = self._cache.get(host)
        if cached and (now_mono - cached[0]) < self._cache_ttl:
            return cached[1].model_copy(update={"lookup_status": "CACHED"})

        if not await self._rate_limiter.acquire():
            return DNSFinding(
                lookup_status="UNAVAILABLE",
                canonical_host=host,
                error_message="DNS lookup rate limit exceeded.",
            )

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self._timeout
        resolver.lifetime = self._timeout

        a_records: list[str] = []
        aaaa_records: list[str] = []
        mx_records: list[str] = []
        ns_records: list[str] = []
        nxdomain = False
        errors: list[str] = []

        async def _query(rdtype: str) -> list[str]:
            nonlocal nxdomain
            try:
                ans = await resolver.resolve(host, rdtype)
                return [r.to_text().rstrip(".") for r in ans]
            except dns.resolver.NXDOMAIN:
                nxdomain = True
                return []
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return []
            except dns.exception.Timeout:
                errors.append(f"{rdtype} timeout")
                return []
            except Exception as exc:
                errors.append(f"{rdtype} error: {exc.__class__.__name__}")
                return []

        a_res, aaaa_res, mx_res, ns_res = await asyncio.gather(
            _query("A"),
            _query("AAAA"),
            _query("MX"),
            _query("NS"),
        )
        a_records.extend(a_res)
        aaaa_records.extend(aaaa_res)
        mx_records.extend(mx_res)
        ns_records.extend(ns_res)

        blocked_ips: list[str] = []
        for ip_val in [*a_records, *aaaa_records]:
            is_blocked, _ = is_ip_blocked_or_reserved(ip_val)
            if is_blocked:
                blocked_ips.append(ip_val)

        if nxdomain and not (a_records or aaaa_records or mx_records or ns_records):
            finding = DNSFinding(
                lookup_status="NXDOMAIN",
                canonical_host=host,
                error_message="Domain does not exist (NXDOMAIN).",
            )
        elif errors and not (a_records or aaaa_records or mx_records or ns_records):
            finding = DNSFinding(
                lookup_status="UNAVAILABLE",
                canonical_host=host,
                error_message="; ".join(errors),
            )
        else:
            finding = DNSFinding(
                lookup_status="SUCCESS",
                canonical_host=host,
                a_records=sorted(set(a_records)),
                aaaa_records=sorted(set(aaaa_records)),
                mx_records=sorted(set(mx_records)),
                ns_records=sorted(set(ns_records)),
                has_private_or_reserved_ip=bool(blocked_ips),
                blocked_ips=sorted(set(blocked_ips)),
            )

        self._cache[host] = (now_mono, finding)
        return finding


class RDAPIntelligenceClient:
    """Async RDAP client with timeout, rate limiting, and TTL caching."""

    def __init__(
        self,
        base_url: str = "https://rdap.org/domain/",
        timeout_seconds: float = 3.0,
        cache_ttl_seconds: float = 3600.0,
        rate_limiter: AsyncSlidingWindowRateLimiter | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._timeout = timeout_seconds
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[float, RDAPRegistrationInfo]] = {}
        self._rate_limiter = rate_limiter or AsyncSlidingWindowRateLimiter(
            max_calls=15, window_seconds=60.0
        )
        self._transport = http_transport

    async def lookup_domain(self, registered_domain: str) -> RDAPRegistrationInfo:
        """Query RDAP registration metadata for a registered domain."""
        dom = registered_domain.lower().strip(".")
        now_mono = time.monotonic()
        cached = self._cache.get(dom)
        if cached and (now_mono - cached[0]) < self._cache_ttl:
            return cached[1].model_copy(update={"lookup_status": "CACHED"})

        if not await self._rate_limiter.acquire():
            return RDAPRegistrationInfo(
                lookup_status="RATE_LIMITED",
                registered_domain=dom,
                error_message="RDAP lookup rate limit exceeded.",
            )

        url = f"{self._base_url}{dom}"
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                max_redirects=2,
                transport=self._transport,
            ) as client:
                response = await client.get(
                    url, headers={"Accept": "application/rdap+json, application/json"}
                )
                if response.status_code != 200:
                    return RDAPRegistrationInfo(
                        lookup_status="UNAVAILABLE",
                        registered_domain=dom,
                        error_message=f"RDAP returned HTTP {response.status_code}",
                    )
                payload = response.json()
        except Exception as exc:
            return RDAPRegistrationInfo(
                lookup_status="UNAVAILABLE",
                registered_domain=dom,
                error_message=f"RDAP query failed: {exc.__class__.__name__}",
            )

        registered_at: datetime | None = None
        expires_at: datetime | None = None
        for event in payload.get("events", []):
            action = str(event.get("eventAction", "")).lower()
            date_str = event.get("eventDate")
            if not date_str:
                continue
            try:
                parsed_dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if action in {"registration", "registered"} and registered_at is None:
                registered_at = parsed_dt
            elif action in {"expiration", "expires"} and expires_at is None:
                expires_at = parsed_dt

        registrar_name: str | None = None
        for entity in payload.get("entities", []):
            roles = [str(r).lower() for r in entity.get("roles", [])]
            if "registrar" in roles:
                vcard = entity.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            registrar_name = str(item[3])
                            break
                if not registrar_name and entity.get("handle"):
                    registrar_name = str(entity["handle"])
                break

        age_days: int | None = None
        if registered_at is not None:
            delta = datetime.now(timezone.utc) - registered_at
            age_days = max(0, delta.days)

        info = RDAPRegistrationInfo(
            lookup_status="SUCCESS",
            registered_domain=dom,
            registrar_name=registrar_name,
            registered_at=registered_at,
            expires_at=expires_at,
            domain_age_days=age_days,
        )
        self._cache[dom] = (now_mono, info)
        return info
