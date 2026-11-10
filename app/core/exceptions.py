"""Centralised application exceptions and FastAPI error handlers."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_ctx_var

logger = logging.getLogger("amana_shield.errors")


class AmanaError(Exception):
    """Base exception for domain and application errors."""

    def __init__(
        self,
        message: str,
        code: str = "AMANA_ERROR",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class EntityNotFoundError(AmanaError):
    """Raised when a requested resource does not exist."""

    def __init__(self, message: str = "Requested resource was not found.") -> None:
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateSubmissionError(AmanaError):
    """Raised when an external_message_id has already been processed."""

    def __init__(self, external_message_id: str) -> None:
        super().__init__(
            message="Submission with this external_message_id has already been processed.",
            code="DUPLICATE_SUBMISSION",
            status_code=status.HTTP_409_CONFLICT,
            details={"external_message_id": external_message_id},
        )


class PayloadTooLargeError(AmanaError):
    """Raised when request body exceeds configured maximum size."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(
            message=f"Request payload exceeds maximum allowed size of {max_bytes} bytes.",
            code="PAYLOAD_TOO_LARGE",
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        )


def build_error_Envelope(
    code: str,
    message: str,
    details: Any = None,
) -> dict[str, Any]:
    """Build standard error response payload with request correlation ID."""
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id_ctx_var.get("-"),
            "details": details,
        }
    }


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers that never leak internal stack traces."""

    @app.exception_handler(AmanaError)
    async def handle_amana_error(request: Request, exc: AmanaError) -> JSONResponse:
        logger.warning(
            "Domain error handled: %s (%s)",
            exc.code,
            exc.message,
            extra={"extra_fields": {"path": request.url.path, "code": exc.code}},
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=build_error_Envelope(
                code=exc.code,
                message=exc.message,
                details=exc.details or None,
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
            content=build_error_Envelope(
                code=f"HTTP_{exc.status_code}",
                message=str(exc.detail),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        sanitized_errors = [
            {
                "loc": list(err.get("loc", ())),
                "msg": err.get("msg", "Invalid value"),
                "type": err.get("type", "value_error"),
            }
            for err in exc.errors()
        ]
        logger.info(
            "Request validation failed on %s",
            request.url.path,
            extra={"extra_fields": {"error_count": len(sanitized_errors)}},
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=build_error_Envelope(
                code="VALIDATION_ERROR",
                message="Request payload validation failed.",
                details=sanitized_errors,
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_exception(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.error(
            "Unhandled server exception on %s: %s",
            request.url.path,
            exc.__class__.__name__,
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=build_error_Envelope(
                code="INTERNAL_SERVER_ERROR",
                message="An unexpected error occurred while processing the request.",
            ),
        )
