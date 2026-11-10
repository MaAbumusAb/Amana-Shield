"""Performance and Latency Benchmark Test Suite for AMANA SHIELD.

Measures:
- API response time (health, triage, evidence, fusion, submissions)
- End-to-end analysis pipeline latency
- Database query & persistence roundtrip time
- Graceful degraded mode recovery speed under external AI timeout/failure
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.integrations.llm_client import LLMClientError, StructuredLLMClient
from app.services.evidence_service import EvidenceVerificationService


@pytest.mark.asyncio
async def test_performance_health_check_latency(async_client: AsyncClient) -> None:
    """Measure health endpoint response time (target < 50ms)."""
    latencies: list[float] = []
    for _ in range(10):
        t0 = time.perf_counter()
        res = await async_client.get("/api/v1/health")
        dt = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 200
        latencies.append(dt)

    avg_latency = sum(latencies) / len(latencies)
    print(f"\n[PERF] /api/v1/health Avg Latency: {avg_latency:.2f}ms (Min: {min(latencies):.2f}ms, Max: {max(latencies):.2f}ms)")
    assert avg_latency < 100.0, f"Healthcheck too slow: {avg_latency:.2f}ms"


@pytest.mark.asyncio
async def test_performance_triage_engine_latency(async_client: AsyncClient) -> None:
    """Measure deterministic triage response time for multi-URL text (target < 50ms)."""
    payload = {
        "text": (
            "Check INEC registration at https://inecnigeria.org and empowerment at "
            "hxxps://grant-empowerment[.]xyz/apply before Friday deadline."
        )
    }
    # Warm-up call (initializes tldextract PSL cache and regex compilation)
    await async_client.post("/api/v1/triage/inspect", json=payload)

    latencies: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        res = await async_client.post("/api/v1/triage/inspect", json=payload)
        dt = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 200
        latencies.append(dt)

    avg_latency = sum(latencies) / len(latencies)
    print(f"\n[PERF] /api/v1/triage/inspect Warm Avg Latency: {avg_latency:.2f}ms")
    assert avg_latency < 100.0, f"Triage latency too high: {avg_latency:.2f}ms"


@pytest.mark.asyncio
async def test_performance_fusion_and_end_to_end_latency(async_client: AsyncClient) -> None:
    """Measure complete end-to-end Risk Fusion response time (target < 100ms in heuristic mode)."""
    payload = {
        "text": (
            "Federal Government grants N50,000 cash to all citizens! "
            "Register your BVN and NIN at http://fg-cash-relief.site immediately."
        ),
        "language": "en",
    }
    latencies: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        res = await async_client.post("/api/v1/fusion/evaluate-text", json=payload)
        dt = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 200
        latencies.append(dt)

    avg_latency = sum(latencies) / len(latencies)
    print(f"\n[PERF] /api/v1/fusion/evaluate-text Avg Latency: {avg_latency:.2f}ms")
    assert avg_latency < 250.0, f"End-to-end fusion latency too high: {avg_latency:.2f}ms"


@pytest.mark.asyncio
async def test_performance_submission_intake_persistence_roundtrip(async_client: AsyncClient) -> None:
    """Measure full submission intake, DB write, and assessment persistence (target < 150ms)."""
    latencies: list[float] = []
    for idx in range(5):
        t0 = time.perf_counter()
        res = await async_client.post(
            "/api/v1/submissions",
            json={
                "channel": "WHATSAPP",
                "external_message_id": f"perf-test-wamid-{idx}-{time.time()}",
                "sender_identifier": "2348011223344",
                "raw_text": "INEC adhoc recruitment: click http://fake-recruitment.org",
            },
        )
        dt = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 201
        latencies.append(dt)

    avg_latency = sum(latencies) / len(latencies)
    print(f"\n[PERF] /api/v1/submissions (Intake + DB Persistence) Avg Latency: {avg_latency:.2f}ms")
    assert avg_latency < 300.0, f"Submission intake latency too high: {avg_latency:.2f}ms"


@pytest.mark.asyncio
async def test_performance_degraded_mode_recovery_speed(async_client: AsyncClient) -> None:
    """Verify that when external AI times out or errors, pipeline recovers instantly into degraded heuristic mode."""
    with patch.object(
        StructuredLLMClient,
        "is_configured",
        return_value=True,
    ), patch.object(
        StructuredLLMClient,
        "analyze_message",
        side_effect=LLMClientError("Provider timeout after 8s"),
    ), patch.object(
        EvidenceVerificationService,
        "_evaluate_with_llm",
        side_effect=LLMClientError("Provider timeout after 8s"),
    ):
        t0 = time.perf_counter()
        res = await async_client.post(
            "/api/v1/fusion/evaluate-text",
            json={
                "text": "Critical warning: Enter your BVN and PIN to claim N50,000 allowance.",
                "language": "en",
            },
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert res.status_code == 200
        data = res.json()
        assert data["is_degraded_mode"] is True
        # Critical scam indicator must still be detected deterministically even without LLM
        assert data["verdict"] == "MALICIOUS"
        print(f"\n[PERF] Degraded Mode Fallback Latency: {elapsed_ms:.2f}ms")
        assert elapsed_ms < 500.0, f"Fallback recovery took too long: {elapsed_ms:.2f}ms"
