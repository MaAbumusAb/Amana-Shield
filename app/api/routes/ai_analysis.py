"""API route for AI-powered scam message analysis."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.ai_analysis import AIAnalysisResult
from app.services.ai_analysis_service import AIScamAnalysisService

router = APIRouter(prefix="/ai", tags=["AI Message Analysis"])


class AIMessageAnalyzeRequest(BaseModel):
    """Request schema for standalone AI message analysis."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    text: str = Field(
        min_length=1,
        max_length=10000,
        description="Untrusted message text to analyse for scam indicators, claims, and impersonation.",
    )


def get_ai_analysis_service() -> AIScamAnalysisService:
    """Dependency provider for AIScamAnalysisService."""
    return AIScamAnalysisService()


@router.post(
    "/analyze-message",
    response_model=AIAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyse message text for scam patterns, claims, and impersonation",
)
async def analyze_message_content(
    payload: AIMessageAnalyzeRequest,
    service: AIScamAnalysisService = Depends(get_ai_analysis_service),
) -> AIAnalysisResult:
    """Run AI-powered scam message analysis with prompt-injection sandboxing and fallback protection."""
    return await service.analyse_message(payload.text)
