"""Security and cryptographic helpers (sender hashing, constant-time HMAC verification)."""

from __future__ import annotations

import hashlib
import hmac

from app.core.config import get_settings


def hash_sender_identifier(raw_identifier: str, pepper: str | None = None) -> str:
    """Compute a deterministic HMAC-SHA256 hash of a sender phone number or ID.

    Prevents storing plaintext phone numbers in the database while allowing
    per-sender rate limiting and abuse detection.
    """
    normalized = raw_identifier.strip().lower()
    if not normalized:
        raise ValueError("Sender identifier cannot be empty.")
    secret_pepper = pepper or get_settings().PHONE_HASH_PEPPER.get_secret_value()
    return hmac.new(
        secret_pepper.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def compute_content_sha256(text: str) -> str:
    """Compute SHA-256 hex digest of normalised text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_hmac_sha256_signature(
    payload_bytes: bytes, signature_header: str, secret: str
) -> bool:
    """Verify Meta X-Hub-Signature-256 header in constant time."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_mac = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    provided_mac = signature_header.removeprefix("sha256=").strip()
    return hmac.compare_digest(expected_mac, provided_mac)
