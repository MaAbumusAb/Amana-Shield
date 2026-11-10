"""Structured JSON LLM API client with timeouts, limited retries, rate limiting, and schema validation.

Does not use any agent framework. Uses async HTTPX with strict JSON schema validation via Pydantic.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.config import Settings, get_settings
from app.integrations.domain_intel import AsyncSlidingWindowRateLimiter
from app.integrations.llm_prompts import build_sandboxed_analysis_prompts
from app.schemas.ai_analysis import LLMStructuredOutputPayload

logger = logging.getLogger("amana_shield.integrations.llm_client")


class LLMClientError(Exception):
    """Raised when the LLM provider times out, fails, or returns invalid structured output."""


class StructuredLLMClient:
    """Lightweight async LLM client enforcing timeouts, token limits, and Pydantic validation."""

    def __init__(
        self,
        settings: Settings | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        rate_limiter: AsyncSlidingWindowRateLimiter | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._transport = http_transport
        self._rate_limiter = rate_limiter or AsyncSlidingWindowRateLimiter(
            max_calls=self._settings.LLM_RATE_LIMIT_PER_MINUTE,
            window_seconds=60.0,
        )

    def is_configured(self) -> bool:
        """Return True if a non-placeholder LLM API key or custom test transport is configured."""
        if self._transport is not None:
            return True
        api_key = self._settings.LLM_API_KEY.get_secret_value().strip()
        if not api_key or api_key.startswith("dev-only") or "CHANGE_ME" in api_key.upper():
            return False
        return True

    async def analyze_message(
        self, normalised_text: str
    ) -> tuple[LLMStructuredOutputPayload, bool]:
        """Call the LLM provider with sandboxed prompts and validate the JSON response."""
        if not self.is_configured():
            raise LLMClientError("LLM provider API key is not configured.")

        if not await self._rate_limiter.acquire():
            raise LLMClientError("Outbound LLM request rate limit exceeded.")

        system_prompt, user_prompt, was_truncated = build_sandboxed_analysis_prompts(
            normalised_text,
            max_chars=self._settings.LLM_MAX_INPUT_CHARS,
        )

        endpoint = f"{self._settings.LLM_BASE_URL.rstrip('/')}/chat/completions"
        api_key = self._settings.LLM_API_KEY.get_secret_value()

        request_body: dict[str, Any] = {
            "model": self._settings.LLM_MODEL_NAME,
            "temperature": 0.0,
            "max_tokens": self._settings.LLM_MAX_OUTPUT_TOKENS,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        max_attempts = 1 + self._settings.LLM_MAX_RETRIES
        last_error: Exception | None = None

        async with httpx.AsyncClient(
            timeout=self._settings.LLM_TIMEOUT_SECONDS,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            for attempt in range(1, max_attempts + 1):
                try:
                    response = await client.post(
                        endpoint,
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json",
                        },
                        json=request_body,
                    )
                    if response.status_code != 200:
                        raise LLMClientError(
                            f"LLM provider returned HTTP {response.status_code}"
                        )

                    data = response.json()
                    choices = data.get("choices")
                    if not isinstance(choices, list) or not choices:
                        raise LLMClientError("LLM response missing 'choices' array.")

                    raw_content = choices[0].get("message", {}).get("content", "")
                    if not raw_content or not isinstance(raw_content, str):
                        raise LLMClientError("LLM response content is empty.")

                    cleaned_json_str = raw_content.strip()
                    if cleaned_json_str.startswith("```"):
                        cleaned_json_str = cleaned_json_str.strip("`")
                        if cleaned_json_str.lower().startswith("json"):
                            cleaned_json_str = cleaned_json_str[4:].strip()

                    parsed_dict = json.loads(cleaned_json_str)
                    validated = LLMStructuredOutputPayload.model_validate(parsed_dict)
                    return validated, was_truncated
                except Exception as exc:
                    last_error = exc
                    logger.warning(
                        "LLM analysis attempt %d/%d failed: %s",
                        attempt,
                        max_attempts,
                        exc.__class__.__name__,
                    )

        raise LLMClientError(
            f"LLM analysis failed after {max_attempts} attempt(s): {last_error}"
        )
