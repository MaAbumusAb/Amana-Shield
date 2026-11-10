"""Pydantic v2 schemas for Meta WhatsApp Cloud API webhooks and outbound messaging."""

from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class WhatsAppMetadata(BaseModel):
    """Metadata regarding the receiving business phone number."""

    model_config = ConfigDict(extra="ignore")

    display_phone_number: Optional[str] = None
    phone_number_id: Optional[str] = None


class WhatsAppProfile(BaseModel):
    """WhatsApp sender profile info."""

    model_config = ConfigDict(extra="ignore")

    name: Optional[str] = None


class WhatsAppContact(BaseModel):
    """Contact record included in webhook changes."""

    model_config = ConfigDict(extra="ignore")

    profile: Optional[WhatsAppProfile] = None
    wa_id: str


class WhatsAppTextMessage(BaseModel):
    """Text body payload within an incoming WhatsApp message."""

    model_config = ConfigDict(extra="ignore")

    body: str = Field(min_length=1, max_length=10000)


class WhatsAppIncomingMessage(BaseModel):
    """Incoming user message payload delivered via Meta Cloud API webhook."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=4, max_length=128, description="WhatsApp message ID (wamid)")
    from_: str = Field(alias="from", min_length=2, max_length=32, description="Sender phone number")
    timestamp: str
    type: str = Field(
        description="Message type: text, image, audio, video, document, interactive, sticker, location"
    )
    text: Optional[WhatsAppTextMessage] = None
    image: Optional[dict[str, Any]] = None
    audio: Optional[dict[str, Any]] = None
    video: Optional[dict[str, Any]] = None
    document: Optional[dict[str, Any]] = None
    sticker: Optional[dict[str, Any]] = None
    location: Optional[dict[str, Any]] = None


class WhatsAppStatusUpdate(BaseModel):
    """Delivery status update notification from WhatsApp Cloud API."""

    model_config = ConfigDict(extra="ignore")

    id: str
    status: Literal["sent", "delivered", "read", "failed"]
    timestamp: str
    recipient_id: str


class WhatsAppChangeValue(BaseModel):
    """Value object within a webhook change event."""

    model_config = ConfigDict(extra="ignore")

    messaging_product: str = "whatsapp"
    metadata: Optional[WhatsAppMetadata] = None
    contacts: Optional[list[WhatsAppContact]] = None
    messages: Optional[list[WhatsAppIncomingMessage]] = None
    statuses: Optional[list[WhatsAppStatusUpdate]] = None


class WhatsAppChange(BaseModel):
    """Individual change event within an entry."""

    model_config = ConfigDict(extra="ignore")

    field: str = "messages"
    value: WhatsAppChangeValue


class WhatsAppEntry(BaseModel):
    """Entry object containing WhatsApp account event changes."""

    model_config = ConfigDict(extra="ignore")

    id: str
    changes: list[WhatsAppChange] = Field(default_factory=list)


class WhatsAppWebhookPayload(BaseModel):
    """Root webhook event payload delivered by Meta Cloud API."""

    model_config = ConfigDict(extra="ignore")

    object: str = Field(
        default="whatsapp_business_account",
        description="Must be whatsapp_business_account for WhatsApp Cloud events",
    )
    entry: list[WhatsAppEntry] = Field(default_factory=list)


class WhatsAppSendTextBody(BaseModel):
    """Outbound text message specification."""

    model_config = ConfigDict(extra="forbid")

    preview_url: bool = False
    body: str = Field(min_length=1, max_length=4096)


class WhatsAppSendMessageRequest(BaseModel):
    """Outbound message API request schema sent to Meta Graph API."""

    model_config = ConfigDict(extra="forbid")

    messaging_product: str = "whatsapp"
    recipient_type: str = "individual"
    to: str = Field(min_length=2, max_length=32)
    type: Literal["text"] = "text"
    text: WhatsAppSendTextBody
