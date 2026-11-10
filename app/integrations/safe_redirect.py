"""SSRF-safe, DNS-rebinding-resistant redirect inspector.

Performs manual step-by-step HTTP HEAD redirect inspection (max 3 hops):
- Pre-resolves and validates every hop's IP addresses before connecting.
- Blocks loopback, private (RFC 1918), link-local, cloud metadata (169.254.169.254), and reserved IPs.
- Re-validates DNS on every redirect hop to mitigate DNS rebinding and open-redirect SSRF.
- Never downloads response bodies or executes remote payloads.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Callable, Coroutine
from urllib.parse import urljoin

import httpx

from app.schemas.triage import RedirectAnalysisFinding, RedirectHopFinding
from app.utils.text import is_ip_blocked_or_reserved, parse_and_normalise_url

IPResolverFunc = Callable[[str], Coroutine[None, None, list[str]]]


async def default_async_ip_resolver(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses using the event loop's getaddrinfo."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
        timeout=2.0,
    )
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            ip_str = sockaddr[0]
            if ip_str not in ips:
                ips.append(ip_str)
    return ips


class SafeRedirectInspector:
    """Controlled redirect analysis with strict SSRF and DNS rebinding defenses."""

    def __init__(
        self,
        max_hops: int = 3,
        hop_timeout_seconds: float = 2.5,
        ip_resolver: IPResolverFunc | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._max_hops = max_hops
        self._hop_timeout = hop_timeout_seconds
        self._ip_resolver = ip_resolver or default_async_ip_resolver
        self._http_transport = http_transport

    async def _validate_host_ips(self, hostname: str) -> tuple[list[str], str | None]:
        """Resolve and verify that all resolved IPs for hostname are globally routable."""
        blocked, reason = is_ip_blocked_or_reserved(hostname)
        if blocked:
            return [hostname], f"Blocked literal IP ({reason}): {hostname}"

        try:
            resolved_ips = await self._ip_resolver(hostname)
        except Exception as exc:
            return [], f"DNS resolution failed for '{hostname}': {exc.__class__.__name__}"

        if not resolved_ips:
            return [], f"No IP addresses resolved for '{hostname}'."

        for ip_str in resolved_ips:
            is_bad, bad_reason = is_ip_blocked_or_reserved(ip_str)
            if is_bad:
                return (
                    resolved_ips,
                    f"Blocked non-public destination IP {ip_str} ({bad_reason}) for host '{hostname}'.",
                )

        return resolved_ips, None

    async def inspect_url(self, initial_url: str) -> RedirectAnalysisFinding:
        """Trace up to max_hops redirects without downloading bodies or following into private IPs."""
        hops: list[RedirectHopFinding] = []
        current_url = initial_url
        final_host: str | None = None

        async with httpx.AsyncClient(
            timeout=self._hop_timeout,
            follow_redirects=False,
            max_redirects=0,
            transport=self._http_transport,
        ) as client:
            for hop_idx in range(1, self._max_hops + 1):
                parsed = parse_and_normalise_url(
                    current_url, require_valid_tld_if_schemeless=False
                )
                if parsed is None or parsed.is_malformed or not parsed.canonical_host:
                    hops.append(
                        RedirectHopFinding(
                            hop_number=hop_idx,
                            url=current_url,
                            blocked_reason=(
                                parsed.malformed_reason
                                if parsed and parsed.malformed_reason
                                else "Malformed redirect destination URL."
                            ),
                        )
                    )
                    return RedirectAnalysisFinding(
                        initial_url=initial_url,
                        final_url=current_url,
                        final_canonical_host=final_host,
                        hops=hops,
                        redirect_count=max(0, hop_idx - 1),
                        ssrf_or_rebinding_blocked=True,
                        error_message="Redirect halted due to malformed target URL.",
                    )

                target_host = parsed.canonical_host
                resolved_ips, block_reason = await self._validate_host_ips(target_host)
                if block_reason is not None:
                    hops.append(
                        RedirectHopFinding(
                            hop_number=hop_idx,
                            url=parsed.normalised_url or current_url,
                            resolved_ips=resolved_ips,
                            blocked_reason=block_reason,
                        )
                    )
                    is_ssrf = "Blocked" in block_reason
                    return RedirectAnalysisFinding(
                        initial_url=initial_url,
                        final_url=parsed.normalised_url or current_url,
                        final_canonical_host=target_host,
                        hops=hops,
                        redirect_count=max(0, hop_idx - 1),
                        ssrf_or_rebinding_blocked=is_ssrf,
                        is_truncated_or_Incomplete=not is_ssrf,
                        error_message=block_reason,
                    )

                # Re-resolve immediately before sending request to guard against fast DNS rebinding
                second_ips, second_block = await self._validate_host_ips(target_host)
                if second_block is not None:
                    hops.append(
                        RedirectHopFinding(
                            hop_number=hop_idx,
                            url=parsed.normalised_url or current_url,
                            resolved_ips=second_ips,
                            blocked_reason=f"DNS rebinding detected: {second_block}",
                        )
                    )
                    return RedirectAnalysisFinding(
                        initial_url=initial_url,
                        final_url=parsed.normalised_url or current_url,
                        final_canonical_host=target_host,
                        hops=hops,
                        redirect_count=max(0, hop_idx - 1),
                        ssrf_or_rebinding_blocked=True,
                        error_message=f"DNS rebinding detected: {second_block}",
                    )

                try:
                    response = await client.request(
                        "HEAD",
                        parsed.normalised_url or current_url,
                        headers={"User-Agent": "AmanaShield-SafeTriage/0.1"},
                    )
                except Exception as exc:
                    hops.append(
                        RedirectHopFinding(
                            hop_number=hop_idx,
                            url=parsed.normalised_url or current_url,
                            resolved_ips=resolved_ips,
                            blocked_reason=f"Network fetch error: {exc.__class__.__name__}",
                        )
                    )
                    return RedirectAnalysisFinding(
                        initial_url=initial_url,
                        final_url=parsed.normalised_url or current_url,
                        final_canonical_host=target_host,
                        hops=hops,
                        redirect_count=max(0, hop_idx - 1),
                        is_truncated_or_Incomplete=True,
                        error_message=f"Redirect check failed: {exc.__class__.__name__}",
                    )

                location = response.headers.get("location")
                hops.append(
                    RedirectHopFinding(
                        hop_number=hop_idx,
                        url=parsed.normalised_url or current_url,
                        resolved_ips=resolved_ips,
                        status_code=response.status_code,
                        location_header=location,
                    )
                )
                final_host = target_host

                if response.status_code in {301, 302, 303, 307, 308} and location:
                    if hop_idx == self._max_hops:
                        return RedirectAnalysisFinding(
                            initial_url=initial_url,
                            final_url=urljoin(parsed.normalised_url or current_url, location),
                            final_canonical_host=final_host,
                            hops=hops,
                            redirect_count=hop_idx,
                            is_truncated_or_Incomplete=True,
                            error_message=f"Maximum redirect hops ({self._max_hops}) reached.",
                        )
                    current_url = urljoin(parsed.normalised_url or current_url, location)
                    continue

                return RedirectAnalysisFinding(
                    initial_url=initial_url,
                    final_url=parsed.normalised_url or current_url,
                    final_canonical_host=final_host,
                    hops=hops,
                    redirect_count=hop_idx - 1,
                )

        return RedirectAnalysisFinding(
            initial_url=initial_url,
            final_url=current_url,
            final_canonical_host=final_host,
            hops=hops,
            redirect_count=len(hops),
        )
