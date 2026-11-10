"""WhatsApp response formatting service.

Produces clear, culturally resonant, non-technical safety advisories for ordinary Nigerian citizens.
"""

from __future__ import annotations

from typing import Optional

from app.models.entities import PublicVerdict
from app.schemas.fusion import RiskFusionEvaluation


def format_whatsapp_reply(
    evaluation: RiskFusionEvaluation,
    include_hausa_summary: bool = True,
) -> str:
    """Format a RiskFusionEvaluation into a WhatsApp-optimised advisory message."""
    verdict = evaluation.verdict
    primary = evaluation.primary_explanation

    # 1. Verdict Header & Emoji Badge
    if verdict == PublicVerdict.MALICIOUS:
        header = "🚨 *DANGER: MALICIOUS CONTENT DETECTED*"
        if include_hausa_summary:
            header += " / *TARIHI: BABBAN HADARI*"
    elif verdict == PublicVerdict.SUSPICIOUS:
        header = "⚠️ *CAUTION: SUSPICIOUS MESSAGE*"
        if include_hausa_summary:
            header += " / *HANKALI: SAKO MAI SHAKKU*"
    elif verdict == PublicVerdict.OFFICIAL:
        header = "✅ *OFFICIAL & VERIFIED*"
        if include_hausa_summary:
            header += " / *TABBATACCE: DAGA HUKUMA*"
    else:
        header = "ℹ️ *UNVERIFIED CONTENT*"
        if include_hausa_summary:
            header += " / *BA A TABBATAR BA*"

    parts = [header, ""]

    # 2. Main Explanation Summary
    parts.append(primary.summary)
    parts.append("")

    # 3. Warning Signs (if any)
    if primary.reasons:
        parts.append("⚠️ *Warning Signs / Dalilan Fadakarwa:*")
        for reason in primary.reasons[:4]:  # Limit to 4 key reasons for readability
            parts.append(f"• {reason}")
        parts.append("")

    # 4. Evidence / Fact-check Sources (if available)
    if primary.evidence_points:
        parts.append("🔍 *Verified Evidence / Hujjoji:*")
        for ev in primary.evidence_points[:3]:
            parts.append(f"• {ev}")
        parts.append("")

    # 5. Uncertainty note (for unverified/degraded)
    if primary.uncertainty_note:
        parts.append(f"ℹ️ _{primary.uncertainty_note}_")
        parts.append("")

    # 6. Recommended Action
    parts.append("🛡️ *Recommended Action / Shawara:*")
    parts.append(primary.recommended_action)
    parts.append("")

    # 7. Trust Footer
    parts.append("— AMANA SHIELD • AI4Elections Nigeria")

    message_text = "\n".join(parts)
    # Ensure WhatsApp message does not exceed safe length
    if len(message_text) > 3800:
        return message_text[:3750] + "\n\n[Content truncated for length]"
    return message_text


def format_unsupported_media_reply() -> str:
    """Guidance message when an unsupported media type (image/audio/file) is received."""
    return (
        "🛡️ *AMANA SHIELD Notice*\n\n"
        "AMANA SHIELD currently analyses *text messages and website links*.\n\n"
        "To check a suspicious message, please *copy and paste the message text or URL directly* into this chat.\n\n"
        "————————\n"
        "AMANA SHIELD a halin yanzu yana binciken *rubutun sako da adireshin yanar gizo* ne kadai. "
        "Don bincika sako mai shakku, da fatan za a *kwafi rubutun ko hanyar yanar gizo (link)* a turo mana kai tsaye.\n\n"
        "— AMANA SHIELD • AI4Elections Nigeria"
    )
