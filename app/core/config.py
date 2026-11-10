"""Environment configuration management with strict Pydantic validation."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded strictly from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application metadata
    APP_NAME: str = "AMANA SHIELD"
    APP_ENV: Literal["development", "testing", "staging", "production"] = "development"
    APP_DEBUG: bool = False
    APP_VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    MAX_REQUEST_BODY_BYTES: int = Field(default=65536, ge=4096, le=1048576)

    # Database configuration
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://amana_user:placeholder@localhost:5432/amana_shield",
        description="SQLAlchemy 2.x async connection URL (postgresql+asyncpg or postgresql+psycopg)",
    )
    DB_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0, le=100)
    DB_ECHO: bool = False

    # Security & Privacy Secrets
    SECRET_KEY: SecretStr = Field(
        default=SecretStr("dev-only-secret-key-change-in-production-32chars"),
        description="Application cryptographic secret key",
    )
    PHONE_HASH_PEPPER: SecretStr = Field(
        default=SecretStr("dev-only-phone-pepper-change-in-production-32c"),
        description="Server-side secret pepper for HMAC-SHA256 sender hashing",
    )
    ANALYST_API_KEY: SecretStr = Field(
        default=SecretStr("dev-only-analyst-api-key-change-in-production"),
        description="API key for protected analyst endpoints",
    )

    # Meta WhatsApp Cloud API Settings
    WHATSAPP_VERIFY_TOKEN: SecretStr = Field(
        default=SecretStr("dev-only-whatsapp-verify-token")
    )
    WHATSAPP_APP_SECRET: SecretStr = Field(
        default=SecretStr("dev-only-whatsapp-app-secret")
    )
    WHATSAPP_ACCESS_TOKEN: SecretStr = Field(
        default=SecretStr("dev-only-whatsapp-access-token")
    )
    WHATSAPP_PHONE_NUMBER_ID: str = "000000000000000"

    # AI / LLM Settings
    LLM_API_KEY: SecretStr = Field(default=SecretStr("dev-only-llm-api-key"))
    LLM_BASE_URL: str = "https://api.openai.com/v1"
    LLM_MODEL_NAME: str = "gpt-4o-mini"
    LLM_TIMEOUT_SECONDS: float = Field(default=8.0, ge=1.0, le=30.0)
    LLM_MAX_RETRIES: int = Field(default=1, ge=0, le=3)
    LLM_MAX_INPUT_CHARS: int = Field(default=4000, ge=256, le=10000)
    LLM_MAX_OUTPUT_TOKENS: int = Field(default=900, ge=200, le=4000)
    LLM_RATE_LIMIT_PER_MINUTE: int = Field(default=30, ge=1, le=600)

    @field_validator("API_V1_PREFIX")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("API_V1_PREFIX must start with '/'")
        return value.rstrip("/")

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        allowed_schemes = (
            "postgresql+asyncpg://",
            "postgresql+psycopg://",
            "postgresql://",
            "sqlite+aiosqlite://",
        )
        if not value.startswith(allowed_schemes):
            raise ValueError(
                f"DATABASE_URL must start with one of {allowed_schemes}"
            )
        return value

    @model_validator(mode="after")
    def enforce_production_security_invariants(self) -> "Settings":
        """Reject insecure debug flags or default placeholder secrets in staging/production."""
        if self.APP_ENV in ("staging", "production"):
            if self.APP_DEBUG:
                raise ValueError("APP_DEBUG must be False in staging and production.")
            if self.DATABASE_URL.startswith("sqlite"):
                raise ValueError(
                    "SQLite is only allowed in local testing; PostgreSQL is required in staging/production."
                )
            for field_name in ("SECRET_KEY", "PHONE_HASH_PEPPER", "ANALYST_API_KEY"):
                secret_val = getattr(self, field_name).get_secret_value()
                if (
                    len(secret_val) < 32
                    or "CHANGE_ME" in secret_val.upper()
                    or secret_val.startswith("dev-only")
                ):
                    raise ValueError(
                        f"{field_name} must be a strong secret (>= 32 chars) and not a placeholder in {self.APP_ENV}."
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
