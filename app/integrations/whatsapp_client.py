"""Official Meta WhatsApp Cloud API outbound integration client."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

from app.core.config import Settings, get_settings
from app.schemas.whatsapp import WhatsAppSendMessageRequest, WhatsAppSendTextBody

logger = logging.getLogger("amana_shield.integrations.whatsapp")


class WhatsAppApiError(Exception):
    """Raised when the WhatsApp Cloud API call fails unrecoverably."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.details = details or {}


class WhatsAppCloudApiClient:
    """Outbound client for sending messages via Meta's WhatsApp Cloud API."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._phone_number_id = self._settings.WHATSAPP_PHONE_NUMBER_ID
        self._access_token = self._settings.WHATSAPP_ACCESS_TOKEN.get_secret_value()
        self._base_url = "https://graph.facebook.com/v21.0"
        self._http_client = http_client
        self._timeout = 10.0
        self._max_retries = 2

    @property
    def _messages_endpoint(self) -> str:
        return f"{self._base_url}/{self._phone_number_id}/messages"

    @staticmethod
    def _mask_phone(phone: str) -> str:
        """Mask phone number for safe logging without storing or exposing PII."""
        if len(phone) <= 6:
            return "***"
        return f"{phone[:4]}***{phone[-2:]}"

    async def send_text_message(
        self,
        to_phone: str,
        message_body: str,
        preview_url: bool = False,
    ) -> dict[str, Any]:
        """Send a text message to a WhatsApp user via Meta Cloud API."""
        payload = WhatsAppSendMessageRequest(
            messaging_product="whatsapp",
            recipient_type="individual",
            to=to_phone.lstrip("+"),
            type="text",
            text=WhatsAppSendTextBody(
                preview_url=preview_url,
                body=message_body,
            ),
        )

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "User-Agent": f"AmanaShield/{self._settings.APP_VERSION}",
        }

        masked_to = self._mask_phone(to_phone)
        payload_data = payload.model_dump()

        attempt = 0
        while attempt <= self._max_retries:
            attempt += 1
            try:
                if self._http_client is not None:
                    response = await self._http_client.post(
                        self._messages_endpoint,
                        headers=headers,
                        json=payload_data,
                        timeout=self._timeout,
                    )
                else:
                    async with httpx.AsyncClient(timeout=self._timeout) as client:
                        response = await client.post(
                            self._messages_endpoint,
                            headers=headers,
                            json=payload_data,
                        )

                if response.status_code in (200, 201):
                    data = response.json()
                    logger.info(
                        "WhatsApp reply delivered successfully to %s",
                        masked_to,
                        extra={"extra_fields": {"recipient_masked": masked_to, "messages": data.get("messages")}},
                    )
                    return data

                # Check retryable status codes (e.g. 429, 500, 502, 503, 504)
                if response.status_code in (429, 500, 502, 503, 504) and attempt <= self._max_retries:
                    wait_time = 0.5 * (2 ** (attempt - 1))
                    logger.warning(
                        "Transient WhatsApp API error (HTTP %d). Retrying in %.1fs...",
                        response.status_code,
                        wait_time,
                    )
                    await asyncio.sleep(wait_time)
                    continue

                # Permanent failure
                err_body = response.text
                logger.error(
                    "WhatsApp Cloud API rejected message delivery to %s: HTTP %d: %s",
                    masked_to,
                    response.status_code,
                    err_body,
                )
                try:
                    err_json = response.json()
                except Exception:
                    err_json = {"raw": err_body}
                raise WhatsAppApiError(
                    f"WhatsApp API delivery failed with status {response.status_code}",
                    status_code=response.status_code,
                    details=err_json,
                )

            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt <= self._max_retries:
                    wait_time = 0.5 * (2 ** (attempt - 1))
                    logger.warning(
                        "Network error delivering WhatsApp message to %s (%s). Retrying in %.1fs...",
                        masked_to,
                        str(exc),
                        wait_time,
                    )
                    await asyncio.sleep(wait_time)
                    continue
                logger.error(
                    "Network error delivering WhatsApp message to %s after %d attempts: %s",
                    masked_to,
                    attempt,
                    str(exc),
                )
                raise WhatsAppApiError(f"Network error contacting WhatsApp API: {exc}") from exc

        raise WhatsAppApiError("Exhausted retries contacting WhatsApp Cloud API")
