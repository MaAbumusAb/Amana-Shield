# AMANA SHIELD — Production Deployment Guide

This guide details the complete, step-by-step procedure to deploy the **AMANA SHIELD** production MVP on a standard Linux Virtual Private Server (VPS) or cloud virtual machine using Docker, Docker Compose, PostgreSQL 16, and Caddy with automated HTTPS.

---

## 1. Architecture & Infrastructure Overview

AMANA SHIELD uses a lightweight, secure modular monolith deployment stack:
- **FastAPI Monolith (`api`)**: Non-root container (`amana:10001`), read-only root filesystem with tmpfs, automated pre-flight connectivity checks, and Alembic schema migrations on startup.
- **PostgreSQL 16 (`db`)**: Runs in an isolated Docker bridge network (`amana_internal`) with **zero exposed host ports**. Only the `api` container can communicate with the database.
- **Caddy 2.8 Reverse Proxy (`caddy`)**: Single-binary automated TLS manager. Handles automatic Let's Encrypt / ZeroSSL certificate issuance and renewal, enforces HTTP/3 and TLS 1.3, applies security headers, and reverse proxies requests to `api:8000`.

```
 Internet (WhatsApp / Citizens / Analysts)
                 │
                 ▼
      [ Port 80 / 443 / HTTPS ]
                 │
          ┌──────────────┐
          │ Caddy Proxy  │ (Auto-TLS, Rate Limiting, Security Headers)
          └──────┬───────┘
                 │ (Internal Docker Network: amana_web)
                 ▼
        ┌──────────────────┐
        │  FastAPI Monolith │ (Port 8000, Non-Root User)
        └────────┬─────────┘
                 │ (Internal Docker Network: amana_internal)
                 ▼
       ┌────────────────────┐
       │ PostgreSQL 16 DB   │ (Isolated, Persistent Volume)
       └────────────────────┘
```

---

## 2. Infrastructure & Sizing Requirements

| Resource | Minimum (MVP) | Recommended (Election-Day Traffic) |
| :--- | :--- | :--- |
| **Hosting Provider** | Hetzner, DigitalOcean, Linode, AWS EC2, or Azure VM | Same |
| **Operating System** | Ubuntu 22.04 LTS or 24.04 LTS (x86_64 / arm64) | Ubuntu 24.04 LTS |
| **vCPU** | 1 vCPU | 2 - 4 vCPUs |
| **RAM** | 2 GB | 4 GB |
| **Disk Storage** | 25 GB SSD/NVMe | 50 GB NVMe |
| **Est. Monthly Cost** | ~\$5 – \$12 / month | ~\$20 – \$40 / month |

---

## 3. Pre-Deployment Server Preparation

### 3.1 Install Docker Engine & Docker Compose
Log in to your VPS via SSH as a sudo user:

```bash
# Update package repositories
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker prerequisites
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker and Docker Compose Plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify installation
docker --version
docker compose version
```

### 3.2 Configure Firewall (UFW)
Only expose ports 22 (SSH), 80 (HTTP for ACME challenges), and 443 (HTTPS):

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp comment 'HTTP/3 QUIC'
sudo ufw enable
```

> [!IMPORTANT]
> Port 5432 (PostgreSQL) is **NOT** opened in the firewall. PostgreSQL is accessible only through Docker's internal container network.

---

## 4. DNS Configuration

Configure DNS records with your registrar or DNS provider (e.g., Cloudflare, Route53, Namecheap):
- **A Record**: `verify.yourdomain.ng` $\rightarrow$ `YOUR_SERVER_PUBLIC_IP`
- **TTL**: 300 seconds (recommended during initial launch)

Verify DNS propagation before launching:
```bash
dig +short verify.yourdomain.ng
```

---

## 5. Application Deployment Steps

### 5.1 Clone Repository
```bash
sudo mkdir -p /opt/amana-shield
sudo chown -R $USER:$USER /opt/amana-shield
cd /opt/amana-shield

git clone https://github.com/your-org/AI4Election.git .
```

### 5.2 Configure Production Environment Variables
Generate cryptographic secrets and populate `.env`:

```bash
# Generate high-entropy secrets
python3 scripts/generate_secrets.py

# Create production .env file
cp .env.production.example .env
chmod 600 .env

# Edit .env using your preferred editor
nano .env
```

Ensure the following variables are configured:
```ini
DOMAIN="verify.yourdomain.ng"
ACME_EMAIL="ops@yourdomain.ng"
POSTGRES_USER="amana_prod_user"
POSTGRES_PASSWORD="<STRONG_GENERATED_PASSWORD>"
SECRET_KEY="<GENERATED_64_CHAR_HEX>"
PHONE_HASH_PEPPER="<GENERATED_64_CHAR_HEX>"
ANALYST_API_KEY="<GENERATED_64_CHAR_HEX>"
WHATSAPP_VERIFY_TOKEN="<STRONG_VERIFY_TOKEN>"
WHATSAPP_APP_SECRET="<META_APP_SECRET>"
WHATSAPP_ACCESS_TOKEN="<META_PERMANENT_GRAPH_TOKEN>"
WHATSAPP_PHONE_NUMBER_ID="<META_PHONE_NUMBER_ID>"
LLM_API_KEY="<OPENAI_OR_AZURE_KEY>"
```

### 5.3 Launch the Production Stack
```bash
# Build and start containers in detached mode
docker compose -f docker-compose.prod.yml up -d --build
```

### 5.4 Inspect Startup & Migrations
```bash
docker compose -f docker-compose.prod.yml logs -f api
```

The container entrypoint will automatically:
1. Wait for PostgreSQL to become healthy.
2. Run `alembic upgrade head` to apply all migrations.
3. Run `python scripts/seed_initial_data.py` to seed curated official registries.
4. Launch Uvicorn workers.

---

## 6. Post-Deployment Verification

### 6.1 Verify Health Probe
```bash
curl -i https://verify.yourdomain.ng/api/v1/health
```
Expected output:
```json
HTTP/2 200
x-content-type-options: nosniff
x-frame-options: DENY

{
  "status": "healthy",
  "service": "AMANA SHIELD",
  "version": "1.0.0",
  "environment": "production",
  "database": "connected",
  "timestamp": "2026-11-10T..."
}
```

### 6.2 Test End-to-End Submission & Risk Fusion
Test a public verification request through the API:

```bash
curl -s -X POST https://verify.yourdomain.ng/api/v1/fusion/evaluate-text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Federal government offers N50,000 cash grant to all citizens! Register your BVN at http://fake-grant-palliative.xyz immediately.",
    "language": "en"
  }' | jq .
```
Expected response:
- `verdict`: `"MALICIOUS"`
- `message_risk`: `"CRITICAL"`
- `primary_explanation.recommended_action`: Clear warning advising the citizen not to enter sensitive credentials.

---

## 7. Meta WhatsApp Cloud API Webhook Integration

### 7.1 Configure Webhook in Meta Developer Portal
1. Navigate to **[Meta App Dashboard](https://developers.facebook.com/apps/)** $\rightarrow$ Your App $\rightarrow$ **WhatsApp** $\rightarrow$ **Configuration**.
2. Click **Edit** under **Webhook**:
   - **Callback URL**: `https://verify.yourdomain.ng/api/v1/whatsapp/webhook`
   - **Verify Token**: Enter the exact string configured in your `.env` for `WHATSAPP_VERIFY_TOKEN`.
3. Click **Verify and Save**. Meta will send a `GET` request to your endpoint; AMANA SHIELD validates the challenge and responds with `HTTP 200` containing `hub.challenge`.
4. Under **Webhook Fields**, subscribe to `messages`.

### 7.2 Send a Live Test Message
From a WhatsApp client, send a test suspicious message to your configured WhatsApp Business number. AMANA SHIELD will ingest the message, analyze it across the 3 security pillars, and deliver a formatted advisory response within ~1-2 seconds.

---

## 8. Automated Database Backup Setup

Configure an automated daily backup cron job:

```bash
# Test backup script manually
./scripts/backup_db.sh

# Install root cron job
sudo crontab -e
```

Add the following line to run daily backups at 02:00 UTC with 14-day automated retention:
```cron
0 2 * * * /opt/amana-shield/scripts/backup_db.sh >> /var/log/amana_backup.log 2>&1
```
