#!/usr/bin/env python3
"""Cryptographic Secret Generator for AMANA SHIELD Production Deployments.

Generates high-entropy secrets for:
- SECRET_KEY (64-character hex string)
- PHONE_HASH_PEPPER (64-character hex string)
- ANALYST_API_KEY (64-character url-safe token)
- WHATSAPP_VERIFY_TOKEN (32-character random string)
"""

from __future__ import annotations

import secrets
import sys


def generate_production_secrets() -> None:
    """Generate and display cryptographically secure tokens for .env."""
    secret_key = secrets.token_hex(32)
    phone_pepper = secrets.token_hex(32)
    analyst_key = secrets.token_urlsafe(32)
    whatsapp_verify = secrets.token_urlsafe(24)

    output = f"""
==============================================================================
               AMANA SHIELD — PRODUCTION SECRETS GENERATOR
==============================================================================
Copy and paste the following into your production .env file:

SECRET_KEY="{secret_key}"
PHONE_HASH_PEPPER="{phone_pepper}"
ANALYST_API_KEY="{analyst_key}"
WHATSAPP_VERIFY_TOKEN="{whatsapp_verify}"

IMPORTANT:
- Keep these values strictly confidential.
- Never commit .env to GitHub or any public repository.
- Use a secure password manager or cloud secret store to back them up.
==============================================================================
"""
    print(output.strip())


if __name__ == "__main__":
    generate_production_secrets()
