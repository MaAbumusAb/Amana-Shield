# syntax=docker/dockerfile:1
# ==============================================================================
# AMANA SHIELD — Production Hardened Multi-Stage Dockerfile
# Runs as non-root user (amana:10001) with least-privilege system dependencies.
# ==============================================================================

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

WORKDIR /app

# Create non-root system group and user
RUN groupadd --gid 10001 amana && \
    useradd --uid 10001 --gid amana --shell /sbin/nologin --no-create-home amana

# Install system dependencies (curl for healthchecks, libpq5 for PostgreSQL)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl bash && \
    rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application, migrations, and deployment scripts
COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts

# Set permissions
RUN chmod +x /app/scripts/*.sh /app/scripts/*.py && \
    chown -R amana:amana /app

USER amana

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
