# Swan Production Deployment & Configuration Guide

This guide details the complete procedure for deploying, configuring, and operating Swan in production using Docker containers or native systemd services behind a secure reverse proxy (Caddy or Nginx).

---

## 1. Prerequisites & System Requirements

### Hardware Requirements
| Resource | Minimum (Small PDS, <100 accounts) | Recommended (Standard PDS, 100–10k accounts) | High Throughput (>10k accounts / High Firehose Lag) |
|---|---|---|---|
| **CPU** | 2 vCPUs (x86_64 or ARM64) | 4 vCPUs | 8+ vCPUs |
| **RAM** | 2 GiB | 4–8 GiB | 16+ GiB |
| **Disk** | 20 GiB NVMe SSD | 100–500 GiB NVMe SSD | 1+ TB Fast NVMe (High IOPS for SQLite WAL) |
| **Network** | 100 Mbps | 1 Gbps | 10 Gbps with low-latency peering |

### Software Prerequisites
- **Operating System:** Linux (Ubuntu 24.04 LTS / Debian 12 / RHEL 9) or macOS (14+) for local development.
- **Container Engine (if containerized):** Docker Engine 26+ and Docker Compose v2.27+.
- **Native Runtime (if systemd):** Swift 6.0+ runtime libraries, SQLite 3.45+, OpenSSL 3.0+.
- **Domain & DNS:** Fully qualified domain name (FQDN, e.g. `pds.example.com`) with DNS A/AAAA records pointing to your public ingress IP.
- **TLS Reverse Proxy:** Caddy 2.8+ or Nginx 1.26+ for automated TLS termination, HTTP/2 & HTTP/3, and WebSocket connection upgrade.

---

## 2. Secrets Management & Key Generation

Swan enforces a **zero-secret environment policy** in production. Private keys, signing secrets, master encryption keys, and SMTP credentials must **never** be passed through command-line arguments or environment variables. All secrets are read from owner-only mounted files (`chmod 0600` on host, `chmod 0400` inside containers).

### Required Secrets Summary
| Secret Name | Format | Recommended Permissions | Description |
|---|---|---|---|
| `oauth-server-key` | 32-byte URL-safe base64 | `0600` / `0400` | Master symmetric key for encrypting OAuth browser sessions, refresh tokens, and CSRF receipts. |
| `account-kek` | 32-byte URL-safe base64 | `0600` / `0400` | Key Encryption Key (KEK) used to envelope-encrypt per-account repository and signing private keys. |
| `operator-secret` | High-entropy string | `0600` / `0400` | Bearer token authorizing access to the loopback management port (3001) and CLI recovery operations. |
| `legacy-session-signing-key` | 32-byte URL-safe base64 | `0600` / `0400` | HMAC secret for signing legacy session JWTs (`com.atproto.server.createSession`). |
| `email-proof-key` | 32-byte URL-safe base64 | `0600` / `0400` | HMAC secret for signing email verification and password reset tokens. |
| `signup-secret` | 32-byte URL-safe base64 | `0600` / `0400` | HMAC secret for validating signup invitations and pre-registration proofs. |
| `turnstile-secret` | Cloudflare secret key | `0600` / `0400` | Turnstile CAPTCHA secret key (required when `--signup-policy openProtected`). |
| `did-web-signing-key` | 32-byte URL-safe base64 | `0600` / `0400` | Private key for signing reserved `did:web` identity documents. |
| `email-smtp-username` | Plain text | `0600` / `0400` | SMTP username for transactional email dispatch. |
| `email-smtp-password` | Plain text | `0600` / `0400` | SMTP password for transactional email dispatch. |

### Generation Script for Production Secrets

Run the following script on your secure host to initialize an owner-only secrets directory:

```bash
#!/usr/bin/env bash
set -euo pipefail

SECRETS_DIR="/etc/swan/secrets"
sudo mkdir -p "${SECRETS_DIR}"
sudo chmod 0700 "${SECRETS_DIR}"

# Helper function to generate URL-safe 32-byte base64 string
gen_b64url() {
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | tr -d '\n'
}

echo "Generating cryptographic secrets in ${SECRETS_DIR}..."

# 1. OAuth Server Key
sudo bash -c "gen_b64url > ${SECRETS_DIR}/oauth-server-key"
# 2. Account KEK (Primary)
sudo bash -c "gen_b64url > ${SECRETS_DIR}/account-kek"
# 3. Operator Secret
sudo bash -c "openssl rand -hex 32 | tr -d '\n' > ${SECRETS_DIR}/operator-secret"
# 4. Legacy Session Signing Key
sudo bash -c "gen_b64url > ${SECRETS_DIR}/legacy-session-signing-key"
# 5. Email Proof HMAC Key
sudo bash -c "gen_b64url > ${SECRETS_DIR}/email-proof-key"
# 6. Signup Secret
sudo bash -c "gen_b64url > ${SECRETS_DIR}/signup-secret"
# 7. did:web Signing Key
sudo bash -c "gen_b64url > ${SECRETS_DIR}/did-web-signing-key"

# Set strict permissions
sudo chmod 0600 ${SECRETS_DIR}/*
sudo chown -R 10001:10001 "${SECRETS_DIR}"

echo "All secrets generated successfully with permissions 0600 (owner: 10001:10001)."
```

---

## 3. CLI Configuration Reference (`swan serve`)

The primary daemon is started via `swan serve`. Below is the exhaustive reference of all CLI flags, their environment semantics, and default behaviors:

### Core Listener & Server Options
| Flag | Type / Default | Description |
|---|---|---|
| `--host <addr>` | String (`127.0.0.1`) | Network interface for public HTTP listener. Typically `127.0.0.1` behind reverse proxy. |
| `--port <int>` | Int (`3000`) | TCP port for public HTTP listener. |
| `--public-url <url>` | String (Required in Prod) | Canonical HTTPS public issuer URL (e.g. `https://pds.example.com`). |
| `--data-directory <path>` | String (`.swan-data`) | Path to directory storing SQLite databases, blob storage, and encrypted key envelopes. |
| `--max-connections <int>` | Int (`256`) | Total accepted connection budget; 25% is automatically reserved for anonymous firehose subscribers. |
| `--public-profile <id\|path>` | String (`default`) | Public protocol profile selector. Defaults to build's attested profile. |
| `--login-trusted-proxy-peer <ip>` | String (Repeatable) | Exact IP address of the reverse proxy trusted to supply the client IP via `X-Swan-Client-IP`. |

### OAuth 2.1 Subsystem Flags
| Flag | Type / Default | Description |
|---|---|---|
| `--enable-oauth-authorization-server` | Flag (`false`) | Enables the complete remote/public OAuth 2.1 AS with PAR, PKCE, DPoP, and revocation. |
| `--oauth-server-key-file <path>` | String (File path) | Owner-only file containing the URL-safe base64 32-byte OAuth master key. |
| `--enable-lexicon-resolution` | Flag (`false`) | Resolves `include:<nsid>` and `space:<type>` scope permissions dynamically via repository records. |
| `--oauth-allow-localhost-development-client`| Flag (`false`) | Enables the AT Protocol development exception for `http://localhost` client metadata. |

### Public Firehose & Repository Flags
| Flag | Type / Default | Description |
|---|---|---|
| `--enable-public-firehose` | Flag (`false`) | Enables public firehose sequencing into `firehose.sqlite` and WebSocket streaming on `/xrpc/com.atproto.sync.subscribeRepos`. |
| `--public-firehose-retention-age-hours <int>`| Int64 (`72`) | Maximum age (in hours) before firehose event frames are pruned. |
| `--public-firehose-retention-max-rows <int>` | Int64 (`1000000`) | Maximum total firehose event rows retained in database. |
| `--public-firehose-retention-max-bytes <int>`| Int64 (`1073741824`) | Maximum total byte capacity (1 GiB) for retained firehose frames. |
| `--public-firehose-retention-interval-seconds <int>`| Int64 (`60`) | Frequency of background firehose pruning reaper execution. |
| `--enable-public-repository-mutations` | Flag (`false`) | Enables OAuth-authenticated public record writes (`repo.putRecord`, `repo.applyWrites`, etc.). |
| `--public-account-kek-file <path>` | String (File path) | Account KEK file for signing public repository commits. |

### Account Portal, Signup & MFA Flags
| Flag | Type / Default | Description |
|---|---|---|
| `--enable-account-portal` | Flag (`false`) | Serves the compiled SvelteKit static portal assets and `/account/**` REST APIs. |
| `--account-portal-directory <path>` | String (`/usr/local/share/swan/account`) | Filesystem location of the static account portal build. |
| `--signup-policy <policy>` | String (`closed`) | Admission policy: `closed`, `inviteRequired`, or `openProtected`. |
| `--signup-secret-file <path>` | String (File path) | 32-byte HMAC secret file for signup token and invite code verification. |
| `--signup-account-kek-file <path>` | String (File path) | Account KEK file for provisioning cryptographic key envelopes during registration. |
| `--turnstile-secret-file <path>` | String (File path) | Cloudflare Turnstile verification secret file (required for `openProtected`). |

### Email & Transactional SMTP Flags
| Flag | Type / Default | Description |
|---|---|---|
| `--enable-email-recovery` | Flag (`false`) | Enables email-based password recovery, email verification, and outbox dispatching. |
| `--email-proof-key-file <path>` | String (File path) | 32-byte base64url HMAC secret for signing email confirmation tokens. |
| `--email-sender <email>` | String (e.g. `no-reply@example.com`) | Canonical sender address in `From:` headers. |
| `--email-smtp-host <host>` | String | Outbound SMTP server hostname. |
| `--email-smtp-port <int>` | Int (`587` or `465`) | Outbound SMTP server port. |
| `--email-smtp-mode <mode>` | String (`startTLS`) | Transport security: `startTLS`, `implicitTLS`, or `plaintextLab`. |
| `--email-smtp-mechanism <mech>` | String (`plain`) | Authentication mechanism: `plain`, `login`, or `xoauth2`. |
| `--email-smtp-username-file <path>` | String (File path) | File containing the SMTP authentication username. |
| `--email-smtp-password-file <path>` | String (File path) | File containing the SMTP authentication password. |

### AppView Proxy & Legacy Session Flags
| Flag | Type / Default | Description |
|---|---|---|
| `--enable-legacy-sessions` | Flag (`false`) | Enables `com.atproto.server.createSession` and scoped app-password bearer authentication. |
| `--legacy-session-signing-key-file <path>` | String (File path) | 32-byte HMAC secret file for signing legacy session JWTs. |
| `--appview-url <url>` | String (`https://api.bsky.app`) | Upstream HTTPS URL for proxying unmatched `app.bsky.*` read queries. |
| `--appview-did <did>` | String (`did:web:api.bsky.app`) | Service DID of the target AppView. |
| `--appview-proxy-account-kek-file <path>` | String (File path) | Account KEK file used to mint per-request service-auth JWTs for AppView proxying. |

### Loopback Management Listener Flags
| Flag | Type / Default | Description |
|---|---|---|
| `--management-port <int>` | Int (e.g. `3001`) | Enables the separate loopback management listener. |
| `--management-address <addr>` | String (`127.0.0.1`) | Loopback IP address for management (`127.0.0.1` or `::1`). |
| `--management-operator-secret-file <path>` | String (File path) | Mounted secret file containing the bearer authorization token. |
| `--enable-management-plc-provisioning` | Flag (`false`) | Enables `/v1/accounts/plc/prepare` and `/v1/accounts/plc/activate`. |
| `--enable-management-permanent-deletion` | Flag (`false`) | Enables `/v1/accounts/delete` with PLC directory tombstoning. |

---

## 4. Production Docker Deployment

### Architecture Topology
```
                  ┌──────────────────────────────────────────────────────────┐
                  │                      Host Machine                        │
                  │  /etc/swan/secrets (0700, root:root)                     │
                  │  /var/lib/swan/data (0700, uid 10001)                    │
                  └─────────────┬────────────────────────────┬───────────────┘
                                │                            │
                     (Read-only Secrets)              (Durable Data)
                                │                            │
  ┌─────────────────────────────▼────────────────────────────▼─────────────────────────────┐
  │ Docker Container: swan (UID 10001, Read-only RootFS, NoNewPrivileges)                  │
  │                                                                                        │
  │   Listeners:                                                                           │
  │     - 0.0.0.0:3000 -> Public HTTP & Firehose WebSocket                                 │
  │     - 127.0.0.1:3001 -> Loopback Management API (Optional)                            │
  │                                                                                        │
  │   Mounted Volumes:                                                                     │
  │     - /run/secrets/swan (ro, mode 0400)                                                │
  │     - /var/lib/swan (rw, named volume or host mount)                                   │
  │     - /tmp (rw, tmpfs, noexec, nosuid, size=64m)                                       │
  └────────────────────────────────────────▲───────────────────────────────────────────────┘
                                           │
                           HTTP Reverse Proxy (Caddy / Nginx)
                                           │
                                  TLS 1.3 / HTTPS / WSS
```

### Production `docker-compose.yml`

```yaml
version: "3.8"

services:
  swan:
    image: ghcr.io/your-org/swan:latest
    container_name: swan-pds
    restart: unless-stopped
    read_only: true
    user: "10001:10001"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:size=64M,noexec,nosuid,nodev,mode=1777
    volumes:
      - /var/lib/swan/data:/data:rw
      - /etc/swan/secrets:/run/secrets/swan:ro
    ports:
      - "127.0.0.1:3000:3000"
    command:
      - "serve"
      - "--host"
      - "0.0.0.0"
      - "--port"
      - "3000"
      - "--public-url"
      - "https://pds.example.com"
      - "--data-directory"
      - "/data"
      - "--login-trusted-proxy-peer"
      - "127.0.0.1"
      - "--enable-oauth-authorization-server"
      - "--oauth-server-key-file"
      - "/run/secrets/swan/oauth-server-key"
      - "--enable-public-firehose"
      - "--enable-public-repository-mutations"
      - "--public-account-kek-file"
      - "/run/secrets/swan/account-kek"
      - "--enable-account-portal"
      - "--account-portal-directory"
      - "/usr/local/share/swan/account"
      - "--signup-policy"
      - "inviteRequired"
      - "--signup-secret-file"
      - "/run/secrets/swan/signup-secret"
      - "--signup-account-kek-file"
      - "/run/secrets/swan/account-kek"
      - "--enable-legacy-sessions"
      - "--legacy-session-signing-key-file"
      - "/run/secrets/swan/legacy-session-signing-key"
      - "--legacy-session-account-kek-file"
      - "/run/secrets/swan/account-kek"
      - "--appview-proxy-account-kek-file"
      - "/run/secrets/swan/account-kek"
      - "--enable-email-recovery"
      - "--email-proof-key-file"
      - "/run/secrets/swan/email-proof-key"
      - "--email-sender"
      - "no-reply@example.com"
      - "--email-smtp-host"
      - "smtp.sendgrid.net"
      - "--email-smtp-port"
      - "587"
      - "--email-smtp-mode"
      - "startTLS"
      - "--email-smtp-mechanism"
      - "plain"
      - "--email-smtp-username-file"
      - "/run/secrets/swan/email-smtp-username"
      - "--email-smtp-password-file"
      - "/run/secrets/swan/email-smtp-password"
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://127.0.0.1:3000/health || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
```

---

## 5. Native systemd Deployment

For bare-metal or VM deployments without Docker, run Swan natively under systemd.

### 1. User & Directory Layout
```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/swan -u 10001 swan
sudo mkdir -p /var/lib/swan/data /etc/swan/secrets /usr/local/share/swan/account
sudo chown -R swan:swan /var/lib/swan
sudo chmod 0700 /var/lib/swan/data /etc/swan/secrets
```

### 2. systemd Unit File (`/etc/systemd/system/swan.service`)

```ini
[Unit]
Description=Swan AT Protocol Personal Data Server
Documentation=https://github.com/your-org/swan
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=swan
Group=swan
WorkingDirectory=/var/lib/swan
ExecStart=/usr/local/bin/swan serve \
    --host 127.0.0.1 \
    --port 3000 \
    --public-url https://pds.example.com \
    --data-directory /var/lib/swan/data \
    --login-trusted-proxy-peer 127.0.0.1 \
    --enable-oauth-authorization-server \
    --oauth-server-key-file /etc/swan/secrets/oauth-server-key \
    --enable-public-firehose \
    --enable-public-repository-mutations \
    --public-account-kek-file /etc/swan/secrets/account-kek \
    --enable-account-portal \
    --account-portal-directory /usr/local/share/swan/account \
    --signup-policy inviteRequired \
    --signup-secret-file /etc/swan/secrets/signup-secret \
    --signup-account-kek-file /etc/swan/secrets/account-kek \
    --enable-legacy-sessions \
    --legacy-session-signing-key-file /etc/swan/secrets/legacy-session-signing-key \
    --legacy-session-account-kek-file /etc/swan/secrets/account-kek \
    --appview-proxy-account-kek-file /etc/swan/secrets/account-kek \
    --enable-email-recovery \
    --email-proof-key-file /etc/swan/secrets/email-proof-key \
    --email-sender no-reply@example.com \
    --email-smtp-host smtp.sendgrid.net \
    --email-smtp-port 587 \
    --email-smtp-mode startTLS \
    --email-smtp-mechanism plain \
    --email-smtp-username-file /etc/swan/secrets/email-smtp-username \
    --email-smtp-password-file /etc/swan/secrets/email-smtp-password

Restart=always
RestartSec=5s

# Security Hardening
LimitNOFILE=65536
LimitNPROC=4096
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/swan/data /tmp
ReadOnlyPaths=/etc/swan/secrets /usr/local/share/swan/account
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

### 3. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now swan
sudo systemctl status swan
```

---

## 6. Reverse Proxy Configuration

Swan must be placed behind a reverse proxy that terminates TLS, applies proper client IP forwarding headers, and handles WebSocket upgrades for the public firehose.

### Option A: Caddyfile Configuration (Recommended)

```caddy
pds.example.com {
    # Automatic TLS via Let's Encrypt / ZeroSSL
    encode zstd gzip

    # WebSocket and API Reverse Proxy
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        # Client IP header for Swan's admission limiter
        header_up X-Swan-Client-IP {remote_host}

        # WebSocket Buffer Configuration
        flush_interval -1
    }

    # Security Headers
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # Logging
    log {
        output file /var/log/caddy/pds.example.com.access.log {
            roll_size 100mb
            roll_keep 10
        }
    }
}
```

### Option B: Nginx Configuration

```nginx
# Rate Limiting Zone
limit_req_zone $binary_remote_addr zone=pds_limit:10m rate=50r/s;

# Upstream Definition
upstream swan_backend {
    server 127.0.0.1:3000;
    keepalive 32;
}

# WebSocket Upgrade Map
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name pds.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name pds.example.com;

    ssl_certificate /etc/letsencrypt/live/pds.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pds.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    client_max_body_size 10M;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # Firehose WebSocket Endpoint
    location /xrpc/com.atproto.sync.subscribeRepos {
        proxy_pass http://swan_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Swan-Client-IP $remote_addr;
        
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
    }

    # General XRPC, OAuth, and Account Portal
    location / {
        limit_req zone=pds_limit burst=100 nodelay;
        proxy_pass http://swan_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Swan-Client-IP $remote_addr;

        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
}
```
