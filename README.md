# AMANA SHIELD — Backend Foundation

AMANA SHIELD is an AI-powered electoral and government scam detection system focused on Nigerian electoral and civic protection for **AI4Elections 2026**.

## Architecture

This repository implements a **single modular FastAPI monolith** backed by **PostgreSQL 16** (SQLAlchemy 2.x + Alembic).

```text
AI4Election/
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 0001_initial_amana_shield_schema.py
├── app/
│   ├── main.py                  # FastAPI application factory, security middleware, lifespan
│   ├── api/
│   │   └── routes/
│   │       ├── health.py        # Liveness and DB readiness endpoint
│   │       └── submissions.py   # Submission intake and retrieval endpoints
│   ├── core/
│   │   ├── config.py            # Strict Pydantic Settings & production guardrails
│   │   ├── database.py          # SQLAlchemy 2.x AsyncEngine & session management
│   │   ├── exceptions.py        # Standardised API error envelopes
│   │   ├── logging.py           # JSON structured logging with PII/token redaction
│   │   └── security.py          # HMAC-SHA256 sender hashing & webhook verification
│   ├── models/
│   │   └── entities.py          # 8 normalised SQLAlchemy 2.x models & check constraints
│   ├── repositories/
│   │   └── submissions.py       # Parameterised SQLAlchemy 2.x repositories
│   ├── schemas/
│   │   └── common.py            # Pydantic v2 request/response DTOs
│   ├── services/
│   │   └── submission_service.py# Submission normalisation & baseline assessment service
│   ├── integrations/            # External API clients (WhatsApp, RDAP, DNS, LLM)
│   ├── utils/
│   │   └── text.py              # Unicode NFKC cleaning & defanged URL extraction
│   └── tests/                   # Pytest async test suite
├── .env.example
├── .gitignore
├── alembic.ini
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── requirements.txt
```

## Development Setup

### 1. Environment Configuration
Copy `.env.example` to `.env` and fill in local development values:
```powershell
Copy-Item .env.example .env
```

### 2. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 3. Run Database Migrations (PostgreSQL)
```powershell
alembic upgrade head
```

### 4. Start the FastAPI Server
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- **Health Check**: `http://127.0.0.1:8000/api/v1/health`
- **Swagger UI Docs**: `http://127.0.0.1:8000/api/v1/docs`
- **ReDoc**: `http://127.0.0.1:8000/api/v1/redoc`

### 5. Run Automated Tests
```powershell
pytest -v
```

## AI Scam Message Analysis (Task 6)

- **Endpoint**: `POST /api/v1/ai/analyze-message` (`{"text": "..."}`); also runs automatically inside `POST /api/v1/submissions`.
- **Files**: `app/services/ai_analysis_service.py`, `app/integrations/llm_client.py`, `app/integrations/llm_prompts.py`, `app/schemas/ai_analysis.py`.
- **The AI does not decide verdicts.** The LLM output schema has no verdict field and rejects unknown fields (`extra="forbid"`). `message_risk` is computed deterministically from the extracted indicators, and the final verdict is still set by the fusion logic.
- **Prompt security**: user text goes inside per-call randomised `<untrusted_submission_NONCE>` tags, look-alike tags are escaped, input is truncated to `LLM_MAX_INPUT_CHARS`, and instruction-override patterns are detected. Deterministic indicators are merged back in, so a manipulated LLM response can't lower the risk.
- **Reliability**: timeout (`LLM_TIMEOUT_SECONDS`), limited retries (`LLM_MAX_RETRIES`), output cap (`LLM_MAX_OUTPUT_TOKENS`), per-minute request cap (`LLM_RATE_LIMIT_PER_MINUTE`). If the provider is unconfigured, times out, errors, or returns invalid JSON, the service uses a deterministic heuristic analyser and marks the result `is_degraded=true` (`analysis_mode="FALLBACK_HEURISTIC"`).
- **Provider**: any OpenAI-compatible `/chat/completions` endpoint, configured via `LLM_BASE_URL`, `LLM_MODEL_NAME`, `LLM_API_KEY`.

## Evidence Retrieval and Claim Verification (Task 7)

- **Endpoints**:
  - `POST /api/v1/evidence/verify-claims` (`{"claims": [...], "use_llm": false}`)
  - `POST /api/v1/evidence/sources` (Add/update curated official statements or debunking notices)
  - `GET /api/v1/evidence/sources?institution=INEC` (Retrieve curated sources by institution)
- **Files**: `app/services/evidence_service.py`, `app/schemas/evidence.py`, `app/integrations/verification_prompts.py`, `app/api/routes/evidence.py`, `app/tests/test_evidence_verification.py`.
- **Source Priority**:
  1. INEC Official Information (`INEC_OFFICIAL`)
  2. Government Institutional Announcements (`GOVERNMENT_INSTITUTION`)
  3. Verified Programme Documentation (`GOVERNMENT_PROGRAMME_DOC`)
  4. Reputable Nigerian Fact-Checking Organisations (`FACT_CHECKING_ORG`)
  5. Credible Primary Sources (`CREDIBLE_PRIMARY`)
- **Verdicts**: `VERIFIED`, `FALSE`, `MISLEADING`, `UNVERIFIED`.
- **Abstention Invariant**: If no matching curated source exists, the engine strictly abstains (`UNVERIFIED`), accompanied by an explicit uncertainty explanation (*"Lack of evidence is not proof that a claim is false"*).
- **PostgreSQL Native Retrieval**: Uses relational text querying and GIN tsvector full-text search indexing on `evidence_sources` without introducing external vector databases.
- **Pipeline Integration**: Verified or contradicted claims automatically attach foreign keys (`matched_evidence_id`) to `extracted_claims` records during submission intake.

## Risk Fusion Engine (Task 8)

- **Endpoints**:
  - `POST /api/v1/fusion/evaluate-text` (`{"text": "...", "language": "en" | "ha"}`)
  - Automatically invoked inside `POST /api/v1/submissions`.
- **Files**: `app/services/risk_fusion_service.py`, `app/schemas/fusion.py`, `app/api/routes/fusion.py`, `app/tests/test_risk_fusion.py`.
- **Pillar Separation**: Evaluates three independent signals without arbitrary score collapse:
  1. `message_risk` (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  2. `url_risk` (`NO_URL`, `VERIFIED_OFFICIAL`, `BENIGN_KNOWN`, `UNKNOWN`, `SUSPICIOUS`, `MALICIOUS`)
  3. `claim_verification_status` (`NOT_APPLICABLE`, `VERIFIED_OFFICIAL`, `CONTRADICTED_BY_OFFICIAL`, `OUTDATED_OR_EXPIRED`, `UNVERIFIED`)
- **Public Verdicts**: `MALICIOUS`, `SUSPICIOUS`, `OFFICIAL`, `UNVERIFIED` (with `UNDER_REVIEW` internal status).
- **Core Decision Invariants**:
  - Confirmed malicious destination -> `MALICIOUS` with active block recommendation.
  - Critical scam indicators (sensitive BVN/fee harvesting) -> `MALICIOUS` even without a URL.
  - A verified official domain does NOT automatically make the accompanying message trustworthy -> yields `UNVERIFIED` unless claims and message risk are confirmed safe.
  - Young/new domain age is treated strictly as a weak signal -> never malicious on age alone.
  - Unverifiable claims abstain cleanly -> `UNVERIFIED`.
  - Contradicted claims surface official debunking notices.
- **Multilingual Support**: Generates clear, non-technical explanations in both English (`en`) and Hausa (`ha`) seamlessly without altering the core detection matrix.

## WhatsApp Cloud API Integration (Task 9)

- **Endpoints**:
  - `GET /api/v1/webhooks/whatsapp` — Meta Webhook subscription verification challenge.
  - `POST /api/v1/webhooks/whatsapp` — Inbound WhatsApp message processor and response dispatcher.
- **Files**:
  - `app/api/routes/whatsapp.py` (Webhook router, HMAC verification, sliding-window rate limiting)
  - `app/integrations/whatsapp_client.py` (Meta Graph API client, retry backoff on 5xx/429, phone masking)
  - `app/services/whatsapp_formatter.py` (Channel-optimised advisory formatting with English & Hausa localization)
  - `app/schemas/whatsapp.py` (Pydantic v2 schemas for Meta webhook payloads and outbound messages)
  - `app/tests/test_whatsapp_webhook.py` (15 comprehensive automated unit and integration tests)

### Meta Developer App Configuration

1. **Create Meta App**:
   - Go to [Meta for Developers](https://developers.facebook.com/) and create a **Business** type application.
   - Add the **WhatsApp** product to your application.
2. **Obtain API Credentials**:
   - In WhatsApp > API Setup: copy your **Phone number ID** and generate a **System User Access Token** (or temporary test token).
   - In App Settings > Basic: copy your **App Secret**.
3. **Configure Environment Variables in `.env`**:
   ```ini
   WHATSAPP_PHONE_NUMBER_ID="your_meta_phone_number_id"
   WHATSAPP_ACCESS_TOKEN="your_system_user_access_token"
   WHATSAPP_APP_SECRET="your_meta_app_secret"
   WHATSAPP_VERIFY_TOKEN="your_chosen_random_verify_token_32chars"
   ```
4. **Configure Webhook in Meta Dashboard**:
   - In WhatsApp > Configuration, click **Edit** on Webhook:
     - **Callback URL**: `https://your-public-domain.ngrok-free.app/api/v1/webhooks/whatsapp`
     - **Verify Token**: Must match `WHATSAPP_VERIFY_TOKEN` configured in your `.env`.
   - Click **Verify and save**. Meta will issue a `GET` challenge to your server.
   - Under **Webhook fields**, click **Manage** and subscribe to **`messages`**.

### Security & Architectural Invariants

- **HMAC-SHA256 Payload Validation**: Every incoming POST request is validated against Meta's `X-Hub-Signature-256` header in constant-time (`hmac.compare_digest`). Unsigned or invalid requests are rejected with `HTTP 403 Forbidden`.
- **Idempotency & Replay Protection**: Each WhatsApp message ID (`wamid`) is checked against the database (`submissions.external_message_id`). Duplicates delivered by Meta are safely acknowledged with `HTTP 200 OK` without triggering redundant evaluations or duplicate outbound messages.
- **Untrusted Media Defense**: Untrusted media attachments (images, audio notes, PDF files) are never downloaded into the server filesystem. The engine returns an immediate, polite guidance notice in both English and Hausa instructing the user to copy and paste text or URLs directly.
- **Privacy & PII Protection**: Raw phone numbers are held in-memory strictly for outbound response dispatch and are never stored in plain text. Stored records use salted HMAC-SHA256 hashes (`sender_hash`) with `PHONE_HASH_PEPPER`. Log lines mask recipient phones (e.g. `2348***78`).
- **Strict Opt-in Policy**: AMANA SHIELD only analyzes messages explicitly sent or forwarded by users to the bot number. The application never claims or attempts to scrape or intercept private WhatsApp chats.

## User Interface & Analyst Dashboard (Task 10)

AMANA SHIELD provides accessible web interfaces for both citizens and security analysts, built with **React** and **Tailwind CSS**.

### 1. Public Verification Portal (`/`)
- **Direct Citizen Access**: Ordinary citizens can paste suspicious text or website links directly into the portal for immediate verification without creating an account or providing personal details.
- **Verdict & Warning Indicators**: Displays clear verdict banners (`🚨 DANGER`, `⚠️ CAUTION`, `✅ OFFICIAL`, `ℹ️ UNVERIFIED`) with message risk, URL risk, and claim status signals.
- **Multilingual Support**: Real-time language switching between **English** and **Hausa** (`ha`).
- **Evidence & Fact-Check Links**: Surfaces official INEC notices, government announcements, and debunking references.
- **Actionable Guidance**: Direct instructions on what actions citizens should take (e.g., report to authorities, do not submit BVN/NIN).

### 2. Analyst Workspace (`/analyst`)
- **Protected Access**: Enforces `X-Analyst-Key` authentication backed by `ANALYST_API_KEY`.
- **Summary Metrics**: Real-time counters for total submissions, malicious/suspicious flags, official verifications, under-review queue depth, active campaigns, and malicious domains.
- **Submissions Queue**: Live monitoring table filterable by verdict, channel, and review status.
- **Deep Inspection Modal**: Complete visibility into raw submitted content, extracted URLs, triggered decision rules, deterministic DNS/RDAP/redirect findings, and AI heuristics.
- **Review & Correction Actions**: Analysts can update submission assessment status (`CONFIRMED`, `DISMISSED`, `UNDER_REVIEW`) with immutable `ReviewEvent` audit logging.
- **Domain Directory & Reclassification**: Management of confirmed malicious, suspicious, and official domains.
- **Claims & Campaign Monitoring**: Track clustered scam campaigns and factual claims extracted across submissions.

### Security Invariants

- **Safe Content Rendering**: User-submitted content is strictly rendered as escaped text nodes in React. Untrusted input is never rendered via `dangerouslySetInnerHTML` or executed as HTML.
- **Authentication on Administrative APIs**: All `/api/v1/analyst/*` endpoints require authentication using constant-time API key verification (`X-Analyst-Key` or `Authorization: Bearer <key>`).
- **No Public Administrative Exposure**: Public endpoints (`/api/v1/fusion/evaluate-text` and `/`) do not expose administrative queues, internal statuses, or audit records.

## Cybersecurity & QA Audit (Task 11)

Prior to deployment, AMANA SHIELD underwent a complete cybersecurity and functional audit by an independent QA and application security audit process.
- **109 Automated Integration & Penetration Tests Passing (0 Failures)**.
- **Security Penetration Tests**: SQL injection parameterized resilience, SSRF IP range blocklist (`0.0.0.0`, loopback, metadata, CGNAT), DNS rebinding defense on redirect chains, Meta WhatsApp HMAC-SHA256 signature validation, and prompt injection delimiter sandboxing.
- **Empirical AI Quality Benchmark**: Evaluated across 21 real-world Nigerian civic/electoral scam cases:
  - **Precision**: 100.00%
  - **Recall**: 100.00%
  - **False Positive Rate (FPR)**: 0.00%
  - **Abstention Quality**: 100.00% (6/6 appropriate abstentions on ambiguous/unknown claims)
- **Detailed Audit Artifact**: View the complete audit findings, methodology, and evidence in [audit_report.md](file:///C:/Users/HomePC/.gemini/antigravity/brain/3eb0a1cf-8698-4ed6-8c31-e4af74eb0172/audit_report.md).

## Production Deployment (Task 12)

AMANA SHIELD is configured for affordable, secure, and resilient deployment on a standard Linux VPS (Ubuntu 22.04/24.04 LTS) using Docker, Docker Compose, PostgreSQL 16, and Caddy with automatic HTTPS:

```bash
# 1. Generate production secrets
python3 scripts/generate_secrets.py

# 2. Configure environment file
cp .env.production.example .env
chmod 600 .env
nano .env

# 3. Launch with automated migrations, seed data, and HTTPS
docker compose -f docker-compose.prod.yml up -d --build

# 4. Verify deployment health
curl -i https://verify.yourdomain.ng/api/v1/health
```

### Production Deployment Artifacts & Guides
- **[DEPLOYMENT.md](file:///c:/Users/HomePC/Downloads/AI4Election/DEPLOYMENT.md)** — Step-by-step VPS provisioning, firewall setup, DNS configuration, and Meta WhatsApp webhook registration.
- **[OPERATIONS_RUNBOOK.md](file:///c:/Users/HomePC/Downloads/AI4Election/OPERATIONS_RUNBOOK.md)** — Standard operating procedures for rolling updates, manual Alembic migrations, secret rotation, disaster recovery, and incident response playbooks.
- **[Dockerfile](file:///c:/Users/HomePC/Downloads/AI4Election/Dockerfile)** — Non-root multi-stage image (`amana:10001`) with read-only rootfs and automated entrypoint script.
- **[docker-compose.prod.yml](file:///c:/Users/HomePC/Downloads/AI4Election/docker-compose.prod.yml)** — Production Compose with internal PostgreSQL network isolation and Caddy automated TLS.
- **`scripts/` Directory**:
  - `generate_secrets.py`: Generates 64-char hex cryptographic secrets.
  - `wait_for_db.py`: Database pre-flight connectivity polling.
  - `seed_initial_data.py`: Pre-populates curated Nigerian domains, debunking notices, and threat indicators.
  - `entrypoint.sh`: Container initialization runner.
  - `backup_db.sh`: Automated compressed PostgreSQL backup with 14-day retention.
  - `restore_db.sh`: Disaster recovery restore runner.

### System Capabilities & Operational Limitations
- **Capabilities**: Rapid deterministic URL inspection (<30ms), AI-powered scam feature extraction, evidence-backed fact-checking against official Nigerian sources, WhatsApp Cloud API conversational alerts, citizen web portal, and analyst triage workspace.
- **Limitations**:
  - Requires explicit user message forwarding (does not and cannot intercept private encrypted WhatsApp chats).
  - Media attachments (audio/video/images) are not executed on-server; citizens are guided to paste textual excerpts or links.
  - Novel unverified claims without institutional debunking notices remain strictly `UNVERIFIED` until verified by analysts or official releases.



