"""Submission intake and retrieval API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.schemas.common import (
    ErrorEnvelopeResponse,
    SubmissionCreateRequest,
    SubmissionResponse,
)
from app.services.submission_service import SubmissionService

router = APIRouter(prefix="/submissions", tags=["Submissions"])


def get_submission_service(
    session: AsyncSession = Depends(get_db_session),
) -> SubmissionService:
    """Dependency provider for SubmissionService."""
    return SubmissionService(session)


@router.post(
    "",
    response_model=SubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a suspicious message or URL for analysis",
    responses={
        status.HTTP_409_CONFLICT: {
            "model": ErrorEnvelopeResponse,
            "description": "Duplicate external_message_id (idempotency lock triggered)",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorEnvelopeResponse,
            "description": "Validation error on request body",
        },
    },
)
async def create_submission(
    payload: SubmissionCreateRequest,
    service: SubmissionService = Depends(get_submission_service),
) -> SubmissionResponse:
    """Normalise and persist a user submission and return its initial assessment."""
    submission = await service.create_submission(payload)
    return SubmissionResponse.model_validate(submission)


@router.get(
    "/{submission_id}",
    response_model=SubmissionResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve a submission and its assessment by UUID",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorEnvelopeResponse,
            "description": "Submission not found",
        }
    },
)
async def get_submission(
    submission_id: uuid.UUID,
    service: SubmissionService = Depends(get_submission_service),
) -> SubmissionResponse:
    """Fetch an existing submission record and its associated assessment."""
    submission = await service.get_submission(submission_id)
    return SubmissionResponse.model_validate(submission)
