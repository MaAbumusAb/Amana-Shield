# AMANA SHIELD — Operations & Incident Response Runbook

This runbook defines standard operational procedures (SOPs) for site reliability engineers (SREs), system administrators, and security analysts maintaining AMANA SHIELD in production.

---

## 1. Quick Operations Reference

| Operation | Command |
| :--- | :--- |
| **Check Container Status** | `docker compose -f docker-compose.prod.yml ps` |
| **View Live API Logs** | `docker compose -f docker-compose.prod.yml logs -f --tail=100 api` |
| **View Access Proxy Logs** | `docker compose -f docker-compose.prod.yml logs -f --tail=100 caddy` |
| **Check Database Liveness** | `curl -s https://<DOMAIN>/api/v1/health \| jq .` |
| **Restart Application Container** | `docker compose -f docker-compose.prod.yml restart api` |
| **Create Immediate Database Backup** | `./scripts/backup_db.sh` |

---

## 2. Standard Operating Procedures (SOP)

### SOP-01: Updating the Application (Zero-Downtime Rolling Update)

When pulling a new code release or deploying bug fixes:

1. **Pull the latest Git commit**:
   ```bash
   cd /opt/amana-shield
   git pull origin main
   ```
2. **Review migration files**:
   Check if new files exist in `alembic/versions/`.
3. **Build the updated Docker image**:
   ```bash
   docker compose -f docker-compose.prod.yml build api
   ```
4. **Re-create and launch the API service**:
   ```bash
   docker compose -f docker-compose.prod.yml up -d --no-deps api
   ```
5. **Verify migration and container health**:
   ```bash
   docker compose -f docker-compose.prod.yml logs -f api
   curl -i https://<DOMAIN>/api/v1/health
   ```

---

### SOP-02: Executing Database Migrations Manually

While migrations execute automatically during container startup, you can run or inspect Alembic migrations manually inside the running container:

```bash
# Check current migration revision
docker compose -f docker-compose.prod.yml exec api alembic current

# Show pending migrations
docker compose -f docker-compose.prod.yml exec api alembic show head

# Execute migration upgrade
docker compose -f docker-compose.prod.yml exec api alembic upgrade head

# Rollback one migration revision
docker compose -f docker-compose.prod.yml exec api alembic downgrade -1
```

---

### SOP-03: Rotating Secrets & API Keys

#### 1. Rotating `ANALYST_API_KEY` or `SECRET_KEY`
1. Generate new 64-character tokens:
   ```bash
   python3 scripts/generate_secrets.py
   ```
2. Update `.env`:
   ```bash
   nano .env
   ```
3. Restart the `api` container:
   ```bash
   docker compose -f docker-compose.prod.yml up -d --no-deps api
   ```

#### 2. Rotating `PHONE_HASH_PEPPER`
> [!WARNING]
> `PHONE_HASH_PEPPER` is used to compute SHA-256 hashes of incoming telephone numbers for privacy and rate limiting. Rotating this pepper resets historical rate-limiting lookup correlations, but is safe to rotate during major election cycles or upon key compromise suspicion.

#### 3. Rotating WhatsApp Credentials (`WHATSAPP_ACCESS_TOKEN` / `WHATSAPP_APP_SECRET`)
1. Generate a new System User access token in the **Meta Business Manager**.
2. Update `WHATSAPP_ACCESS_TOKEN` in `.env`.
3. Apply the changes with `docker compose -f docker-compose.prod.yml up -d --no-deps api`.

---

### SOP-04: Structured Log Inspection & Troubleshooting

AMANA SHIELD produces structured JSON logs. To inspect logs cleanly:

#### Filter for Application Errors & Warnings
```bash
docker compose -f docker-compose.prod.yml logs api | grep -E '"level": "(ERROR|WARNING)"'
```

#### Track a Specific Request by Correlation ID
Every HTTP request is assigned a unique `X-Request-ID`:
```bash
docker compose -f docker-compose.prod.yml logs api | grep "09f7a858-f91c-4b53-bcf5-9dd23947b19a"
```

#### Monitor WhatsApp Webhook Ingestion Events
```bash
docker compose -f docker-compose.prod.yml logs -f api | grep "amana_shield.api.routes.whatsapp"
```

---

### SOP-05: Database Backup & Disaster Recovery

#### 1. On-Demand Manual Backup
```bash
./scripts/backup_db.sh
```
The archive is saved to `backups/amana_shield_backup_<TIMESTAMP>.sql.gz`.

#### 2. Complete Database Restoration
To restore a snapshot into PostgreSQL:

```bash
./scripts/restore_db.sh ./backups/amana_shield_backup_20261110_020000.sql.gz
```
The script will prompt you to type `RESTORE` before applying changes and will verify table record counts upon completion.

---

### SOP-06: Rolling Back an Application Release

If a newly deployed release exhibits unexpected regressions:

1. **Identify the previous stable Git commit**:
   ```bash
   git log --oneline -n 5
   ```
2. **Check out the previous release tag or commit**:
   ```bash
   git checkout <PREVIOUS_COMMIT_HASH>
   ```
3. **Roll back database schema if a migration was introduced**:
   ```bash
   docker compose -f docker-compose.prod.yml exec api alembic downgrade -1
   ```
4. **Rebuild and restart the container**:
   ```bash
   docker compose -f docker-compose.prod.yml up -d --build --no-deps api
   ```
5. **Verify healthcheck**:
   ```bash
   curl -i https://<DOMAIN>/api/v1/health
   ```

---

## 3. Incident Response Playbooks

### Incident 1: External AI / LLM Provider Outage or Timeout
- **Symptoms**: Outbound AI calls timing out or returning 429/500 from OpenAI/Azure.
- **System Behavior**: AMANA SHIELD automatically activates **Degraded Heuristic Mode**. It continues extracting URLs, matching confirmed domain indicators, evaluating institutional negation patterns, and returning evidence-backed verdicts without crashing.
- **Action Required**:
  1. Inspect `is_degraded_mode: true` occurrences in logs:
     ```bash
     docker compose -f docker-compose.prod.yml logs api | grep "Falling back to deterministic heuristic extractor"
     ```
  2. If the LLM provider outage is prolonged, verify whether account rate limits or billing credits have lapsed.

### Incident 2: High Submission Spike (Election Day Surge)
- **Symptoms**: Increased latency on `/api/v1/fusion/evaluate-text` or WhatsApp webhook backlog.
- **Action Required**:
  1. Increase Uvicorn worker count in `.env`:
     ```ini
     UVICORN_WORKERS=4
     ```
  2. Increase PostgreSQL connection pool size:
     ```ini
     DB_POOL_SIZE=30
     DB_MAX_OVERFLOW=50
     ```
  3. Reload API service:
     ```bash
     docker compose -f docker-compose.prod.yml up -d --no-deps api
     ```

### Incident 3: WhatsApp Webhook Signature Mismatch (`403 Forbidden`)
- **Symptoms**: Meta Developer Dashboard reports failing webhook deliveries.
- **Root Cause**: `WHATSAPP_APP_SECRET` in `.env` does not match the Meta App Secret for the WhatsApp App.
- **Action Required**:
  1. Verify the App Secret in **Meta App Settings $\rightarrow$ Basic $\rightarrow$ App Secret**.
  2. Correct `WHATSAPP_APP_SECRET` in `.env` and restart `api`.
