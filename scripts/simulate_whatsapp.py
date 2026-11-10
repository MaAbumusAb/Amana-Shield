#!/usr/bin/env python3
"""Interactive WhatsApp Bot Simulator for AMANA SHIELD Local Testing.

Simulates an incoming WhatsApp message forwarded by a citizen to the bot.
Signs the webhook request with HMAC-SHA256 matching WHATSAPP_APP_SECRET in .env,
sends it to the running local server, and displays the exact formatted WhatsApp reply.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
import uuid

# Reconfigure stdout to UTF-8 for Windows console emoji support
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from app.core.config import get_settings
from app.services.whatsapp_formatter import format_whatsapp_reply


def simulate_incoming_whatsapp(message_text: str, sender_phone: str = "2348012345678") -> None:
    settings = get_settings()
    app_secret = settings.WHATSAPP_APP_SECRET.get_secret_value()
    wamid = f"wamid.TEST_{uuid.uuid4().hex[:16]}_{int(time.time())}"

    # Build standard Meta WhatsApp Cloud API webhook JSON payload
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "100000000000000",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "2348000000000",
                                "phone_number_id": settings.WHATSAPP_PHONE_NUMBER_ID,
                            },
                            "contacts": [
                                {
                                    "profile": {"name": "Citizen User"},
                                    "wa_id": sender_phone,
                                }
                            ],
                            "messages": [
                                {
                                    "from": sender_phone,
                                    "id": wamid,
                                    "timestamp": str(int(time.time())),
                                    "type": "text",
                                    "text": {"body": message_text},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }

    raw_body = json.dumps(payload).encode("utf-8")

    # Generate valid Meta HMAC-SHA256 signature
    sig = hmac.new(
        key=app_secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    endpoint = "http://127.0.0.1:8000/api/v1/webhooks/whatsapp"

    print("==============================================================================")
    print("                 AMANA SHIELD — WHATSAPP SIMULATION                           ")
    print("==============================================================================")
    print(f"From (Citizen): +{sender_phone[:6]}***{sender_phone[-2:]}")
    print(f"Message ID:    {wamid}")
    print(f"User Message:\n   \"{message_text}\"\n")
    print("[*] Sending HMAC-signed webhook to local server...")

    with httpx.Client(timeout=10.0) as client:
        try:
            response = client.post(
                endpoint,
                content=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": f"sha256={sig}",
                },
            )
        except Exception as exc:
            print(f"\n[!] Failed to connect to local server: {exc}")
            print("Ensure 'python run_local.py' is running on http://127.0.0.1:8000")
            return

        if response.status_code == 200:
            data = response.json()
            print(f"[*] Webhook Processed: Status = {response.status_code} OK (Status: {data.get('status')})")

            # Query the evaluate-text endpoint to show the exact WhatsApp formatted reply
            res_eval = client.post(
                "http://127.0.0.1:8000/api/v1/fusion/evaluate-text",
                json={"text": message_text, "language": "en"},
            )
            if res_eval.status_code == 200:
                from app.schemas.fusion import RiskFusionEvaluation

                eval_model = RiskFusionEvaluation.model_validate(res_eval.json())
                reply_text = format_whatsapp_reply(eval_model)

                print("\n------------------------------------------------------------------------------")
                print("         DELIVERED WHATSAPP BOT RESPONSE (WHAT CITIZEN SEES ON PHONE)         ")
                print("------------------------------------------------------------------------------")
                print(reply_text)
                print("------------------------------------------------------------------------------")
                print(f"Verdict:         {eval_model.verdict.value}")
                print(f"Message Risk:    {eval_model.message_risk.value}")
                print(f"URL Risk:        {eval_model.url_risk.value}")
                print(f"Claim Status:    {eval_model.claim_verification_status.value}")
                print("==============================================================================")
        else:
            print(f"[!] Server returned HTTP {response.status_code}: {response.text}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        text = (
            "Federal Government has approved N50,000 cash grant to all citizens! "
            "Register your BVN and account details at http://fg-cash-relief.site immediately."
        )
    simulate_incoming_whatsapp(text)
