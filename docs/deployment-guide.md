# Deployment guide

This guide describes how to plan, configure, and deploy Swan in production using Docker containers or native systemd services behind a TLS-terminating reverse proxy.

## Pre-deployment decisions

Before deploying Swan, you must decide on the following operational parameters:

1. **Canonical public URL**: Swan requires a canonical public HTTPS issuer URL (for example, `https://pds.example.com`). This URL is advertised in OAuth metadata, server descriptors, and DID documents.
2. **Public protocol profile**: Swan uses a pinned protocol profile to declare its supported XRPC route surface and schema version. The default profile is `permissioned-data-0016-2026-09-10` (`Profiles/permissioned-data-0016-2026-09-10.json`). Omitting `--public-profile` selects the profile attested by the current build without reading the filesystem.
3. **Signup admission policy**:
   - `closed` (default): Registration via the public HTTP API or account portal is disabled. Accounts can only be provisioned using the CLI (`swan account install-local`, `swan account prepare-plc`, `swan account activate-plc`) or the authenticated loopback management API.
   - `inviteRequired`: New users must provide a valid invite code signed with the secret configured in `--signup-secret-file`.
   - `openProtected`: Public signups are permitted but require Cloudflare Turnstile CAPTCHA verification configured via `--turnstile-secret-file`.
4. **Subsystem selection**: Determine which subsystems to activate:
   - **OAuth 2.1 authorization server** (`--enable-oauth-authorization-server`): Enables the standard remote OAuth 2.1 AS with PAR, PKCE, and DPoP sender-constrained tokens.
   - **Public firehose** (`--enable-public-firehose`): Sequences public repository events into `firehose.sqlite` and serves the `/xrpc/com.atproto.sync.subscribeRepos` WebSocket stream.
   - **Public repository mutations** (`--enable-public-repository-mutations`): Permits OAuth-authorized write operations (`repo.putRecord`, `repo.applyWrites`).
   - **Account portal** (`--enable-account-portal`): Serves the precompiled static account portal frontend and `/account/**` APIs.
   - **Email recovery** (`--enable-email-recovery`): Dispatches transactional verification and password-reset emails over SMTP.
   - **Legacy sessions** (`--enable-legacy-sessions`): Enables `com.atproto.server.createSession` and scoped app-password bearer tokens.
   - **AppView proxying** (enabled by default; disable with `--disable-appview-proxy`): Proxies unmatched `app.bsky.*` queries to an upstream AppView using minted service-auth tokens.
   - **Management listener** (`--management-port`): Binds a separate loopback listener for authenticated administrative tasks.

## Prerequisites and system requirements

### Hardware requirements

| Resource | Small deployment (<100 accounts) | Standard deployment (100–10,000 accounts) | High-throughput deployment (>10,000 accounts) |
|---|---|---|---|
| CPU | 2 vCPUs (x86_64 or ARM64) | 4 vCPUs | 8+ vCPUs |
| Memory | 2 GiB | 4–8 GiB | 16+ GiB |
| Storage | 20 GiB NVMe SSD | 100–500 GiB NVMe SSD | 1+ TB NVMe SSD with high random-write IOPS |
| Network | 100 Mbps | 1 Gbps | 10 Gbps |

### Software prerequisites

- **Container engine** (for containerized deployments): Docker Engine with Compose v2.
- **Container base image**: the `Dockerfile` builds and runs on `swift:6.1-jammy`,
  pinned by digest. Its build stage adds `libsodium-dev` and `pkg-config`; its
  runtime stage adds `ca-certificates`, `curl`, `libsodium23`, and `libsecret-1-0`.
- **Native runtime** (for systemd deployments): the Swift 6.1 runtime libraries
  and the same runtime packages the image installs — libsodium and libsecret.
  Swan builds against `swift-tools-version: 6.1`, so an older toolchain will not
  resolve the manifest.
- **DNS**: Public DNS A and AAAA records pointing your hostname (e.g. `pds.example.com`) to your reverse proxy ingress IP.
- **Reverse proxy**: Caddy or NGINX, configured for automated TLS termination,
  HTTP/2 or HTTP/3, and WebSocket connection upgrade. The Compose laboratory
  topology uses Caddy as its sole ingress.

### Secrets handling and file permissions

Swan operates under a zero-secret environment policy. Private keys, signing keys, master encryption keys, and credentials must never be passed via CLI arguments or environment variables. All secrets must be stored in owner-only files:

- On the host filesystem, secret files must be mode `0600` and the secrets directory must be mode `0700`.
- Inside containers, secret files must be mounted read-only (`ro`) with mode `0400`.
- Storage directories must be owned by the runtime user (recommended UID `10001:10001`).

| Secret name | Format | Recommended permissions | Purpose |
|---|---|---|---|
| `oauth-server-key` | 32-byte URL-safe base64 | `0600` (host) / `0400` (container) | Master symmetric key for encrypting OAuth browser sessions, refresh tokens, and CSRF receipts. |
| `account-kek` | 32-byte URL-safe base64 | `0600` (host) / `0400` (container) | Key Encryption Key (KEK) used to envelope-encrypt per-account private keys in `<data-directory>/keys/`. |
| `operator-secret` | 32-byte hex or high-entropy string | `0600` (host) / `0400` (container) | Bearer token authorizing access to the loopback management port and administrative CLI operations. |
| `legacy-session-signing-key` | 32-byte URL-safe base64 | `0600` (host) / `0400` (container) | HMAC key for signing legacy session JWTs (`com.atproto.server.createSession`). |
| `email-proof-key` | 32-byte URL-safe base64 | `0600` (host) / `0400` (container) | HMAC key for signing email verification and password reset tokens. |
| `signup-secret` | 32-byte URL-safe base64 | `0600` (host) / `0400` (container) | HMAC key for signing and verifying signup invite codes. |
| `turnstile-secret` | Cloudflare secret key string | `0600` (host) / `0400` (container) | Cloudflare Turnstile verification secret (required when `--signup-policy openProtected`). |
| `did-web-signing-key` | 32-byte URL-safe base64 | `0600` (host) / `0400` (container) | Private key for signing reserved `did:web` identity documents. |
| `email-smtp-username` | Plain text | `0600` (host) / `0400` (container) | Username for outbound SMTP authentication. |
| `email-smtp-password` | Plain text | `0600` (host) / `0400` (container) | Password for outbound SMTP authentication. |

To generate the standard secret files, run:

```bash
#!/usr/bin/env bash
set -euo pipefail

SECRETS_DIR="/etc/swan/secrets"
sudo mkdir -p "${SECRETS_DIR}"
sudo chmod 0700 "${SECRETS_DIR}"

gen_b64url() {
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
}

echo "Generating cryptographic secret files in ${SECRETS_DIR}..."

# 1. OAuth server key
gen_b64url | sudo tee "${SECRETS_DIR}/oauth-server-key" > /dev/null

# 2. Account KEK
gen_b64url | sudo tee "${SECRETS_DIR}/account-kek" > /dev/null

# 3. Operator secret
openssl rand -hex 32 | tr -d '\n' | sudo tee "${SECRETS_DIR}/operator-secret" > /dev/null

# 4. Legacy session signing key
gen_b64url | sudo tee "${SECRETS_DIR}/legacy-session-signing-key" > /dev/null

# 5. Email proof HMAC key
gen_b64url | sudo tee "${SECRETS_DIR}/email-proof-key" > /dev/null

# 6. Signup invite HMAC secret
gen_b64url | sudo tee "${SECRETS_DIR}/signup-secret" > /dev/null

# 7. did:web reserved signing key
gen_b64url | sudo tee "${SECRETS_DIR}/did-web-signing-key" > /dev/null

# Set strict permissions
sudo chmod 0600 "${SECRETS_DIR}"/*
sudo chown -R 10001:10001 "${SECRETS_DIR}"

echo "All secret files generated with permissions 0600 (owner: 10001:10001)."
```

**Verification:** To confirm secret file permissions, run `ls -la /etc/swan/secrets`. Every secret file must display `-rw-------` permissions.

## Server configuration reference (`swan serve`)

The primary server daemon is started using `swan serve`. Below is the complete reference of all configuration options and flags.

### Core listener and storage options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--host <addr>` | String (`127.0.0.1`) | Network interface for public HTTP listener. Typically `127.0.0.1` behind a reverse proxy. |
| `--port <int>` | Int (`3000`) | TCP port for public HTTP listener. |
| `--public-url <url>` | String (Optional, required in production) | Canonical HTTPS public issuer URL (e.g. `https://pds.example.com`). |
| `--data-directory <path>` | String (`.swan-data`) | Path to directory storing SQLite databases (`control.sqlite`, `firehose.sqlite`, `<did>.sqlite`), blobs, and encrypted key envelopes. |
| `--profile <path>` | String (`Profiles/permissioned-data-0016-2026-09-10.json`) | Path to pinned permissioned-data protocol profile JSON. |
| `--public-profile <id\|path>` | String (Optional) | Public-data protocol profile selecting public XRPC route surface: either a registered profile ID or path to JSON. Omit to use the build's attested profile. |
| `--max-connections <int>` | Int (`256`) | Total accepted connection budget; one quarter (64 connections by default) is reserved for anonymous firehose subscribers. |
| `--login-trusted-proxy-peer <ip>` | String (Repeatable) | Exact IPv4 or IPv6 socket peer address trusted to supply client IP via `X-Swan-Client-IP`. |
| `--space-oplog-retention <int>` | Int (`10000`) | Retained permissioned-repository operations per account. |

### OAuth 2.1 authorization server flags

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--enable-oauth-authorization-server` | Flag (`false`) | Enables the complete remote OAuth 2.1 authorization server with PAR, PKCE, DPoP, and token revocation. |
| `--oauth-server-key-file <path>` | String (File path) | Path to owner-only file containing URL-safe base64 32-byte OAuth master key. |
| `--enable-lexicon-resolution` | Flag (`false`) | Resolves `include:<nsid>` and `space:<type>` scope permissions from authority repository records (spec §5.7.4). |
| `--enable-foreign-handle-resolution` | Flag (`false`) | Answers `com.atproto.identity.resolveHandle` for unmanaged handles using DNS TXT and HTTPS `/.well-known/atproto-did`. |
| `--oauth-allow-localhost-development-client` | Flag (`false`) | Permits the AT Protocol `http://localhost` development client metadata exception. |
| `--enable-localhost-oauth` | Flag (`false`) | Enables localhost development client PAR, browser authorization, token, and refresh bridge. |
| `--enable-localhost-par` | Flag (`false`) | Enables only the localhost development client PAR bridge. |
| `--oauth-allow-metadata-ip <ip>` | String (Repeatable) | Explicit literal IP allowlist for laboratory OAuth client metadata and JWKS retrieval. |

### Public firehose and repository mutation options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--enable-public-firehose` | Flag (`false`) | Enables public firehose sequencing into `firehose.sqlite` and WebSocket streaming on `/xrpc/com.atproto.sync.subscribeRepos`. |
| `--public-firehose-retention-age-hours <int>` | Int64 (`72`) | Maximum age in hours before firehose event frames are pruned by the retention reaper. |
| `--public-firehose-retention-max-rows <int>` | Int64 (`1000000`) | Maximum total firehose event rows retained in database. |
| `--public-firehose-retention-max-bytes <int>` | Int64 (`1073741824`) | Maximum total byte capacity (1 GiB) for retained firehose frames. |
| `--public-firehose-retention-interval-seconds <int>` | Int64 (`60`) | Frequency in seconds of background firehose pruning reaper execution. |
| `--enable-public-repository-mutations` | Flag (`false`) | Enables OAuth-authorized public record writes (`repo.putRecord`, `repo.applyWrites`). |
| `--public-account-kek-file <path>` | String (File path) | Owner-only mounted account KEK file for signing public repository commits. |
| `--public-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for public repository mutations. |
| `--public-account-key-directory <path>` | String (`<data-directory>/keys`) | Account key-envelope directory for public repository mutations. |
| `--enable-local-space-interop` | Flag (`false`) | Enables local account-key credential, delegation, and repository-sync interop. |
| `--space-account-kek-file <path>` | String (File path) | Account KEK file for local space interop. |
| `--space-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for local space interop. |
| `--space-account-key-directory <path>` | String (`<data-directory>/keys`) | Key-envelope directory for local space interop. |

### Account portal, signup, and MFA options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--enable-account-portal` | Flag (`false`) | Serves compiled SvelteKit static portal assets and `/account/**` REST API surface. |
| `--account-portal-directory <path>` | String (`/usr/local/share/swan/account`) | Directory containing compiled static account portal assets. |
| `--signup-policy <policy>` | String (`closed`) | Admission policy: `closed`, `inviteRequired`, or `openProtected`. |
| `--signup-secret-file <path>` | String (File path) | Owner-only 32-byte base64url HMAC secret file for signup token and invite verification. |
| `--signup-account-kek-file <path>` | String (File path) | Account KEK file for provisioning cryptographic key envelopes during signup. |
| `--signup-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for signup provisioning. |
| `--signup-account-key-directory <path>` | String (`<data-directory>/keys`) | Key-envelope directory for signup provisioning. |
| `--turnstile-secret-file <path>` | String (File path) | Owner-only Cloudflare Turnstile verification secret file (required for `openProtected`). |

### Email and transactional SMTP options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--enable-email-recovery` | Flag (`false`) | Enables email-based password recovery, email verification, and outbox dispatching. |
| `--email-proof-key-file <path>` | String (File path) | Owner-only 32-byte base64url HMAC secret file for signing email confirmation tokens. |
| `--email-sender <email>` | String (e.g. `no-reply@example.com`) | Canonical sender address in outbound email headers. |
| `--email-smtp-host <host>` | String | Outbound SMTP server hostname. |
| `--email-smtp-port <int>` | Int (`587` or `465`) | Outbound SMTP server port. |
| `--email-smtp-mode <mode>` | String (`startTLS`) | Transport security mode: `startTLS`, `implicitTLS`, or `plaintextLab`. |
| `--email-smtp-mechanism <mech>` | String (`plain`) | Authentication mechanism: `plain`, `login`, or `xoauth2`. |
| `--email-smtp-username-file <path>` | String (File path) | Owner-only file containing SMTP username. |
| `--email-smtp-password-file <path>` | String (File path) | Owner-only file containing SMTP password. |
| `--email-smtp-expected-hostname <host>` | String | TLS certificate hostname expected from the SMTP server. |
| `--email-smtp-max-attempts <int>` | Int (`3`) | Bounded maximum SMTP delivery attempts per outbox item. |
| `--email-worker-id <id>` | String | Stable lease owner ID for the account email background worker. |

### Legacy session and AppView proxy options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--enable-legacy-sessions` | Flag (`false`) | Enables `com.atproto.server.createSession` and scoped app-password bearer tokens. |
| `--legacy-session-signing-key-file <path>` | String (File path) | Owner-only 32-byte base64url HMAC secret file for signing legacy session JWTs. |
| `--legacy-session-account-kek-file <path>` | String (File path) | Account KEK file for legacy session service-JWT signing. |
| `--legacy-session-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for legacy sessions. |
| `--legacy-session-account-key-directory <path>` | String (`<data-directory>/keys`) | Key-envelope directory for legacy sessions. |
| `--appview-did <did>` | String (`did:web:api.bsky.app`) | Service DID of upstream AppView. |
| `--appview-url <url>` | String (`https://api.bsky.app`) | HTTPS origin of upstream AppView for proxying unmatched `app.bsky.*` queries. |
| `--appview-service-fragment <frag>` | String (`bsky_appview`) | DID document service fragment naming the configured AppView. |
| `--disable-appview-proxy` | Flag (`false`) | Disables AppView proxying and refuses unmatched `app.bsky.*` queries locally. |
| `--appview-proxy-account-kek-file <path>` | String (File path) | Account KEK file used to mint per-request service-auth JWTs for AppView proxying. |
| `--appview-proxy-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for AppView proxying. |
| `--appview-proxy-account-key-directory <path>` | String (`<data-directory>/keys`) | Key-envelope directory for AppView proxying. |

### Loopback management listener options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--management-port <int>` | Int (e.g. `3001`) | Enables the separate loopback-only management listener on this TCP port. |
| `--management-address <addr>` | String (`127.0.0.1`) | Loopback IP address for management (`127.0.0.1` or `::1`). |
| `--management-operator-secret-file <path>` | String (File path) | Owner-only file containing bearer authorization token for management APIs. |
| `--enable-management-plc-provisioning` | Flag (`false`) | Enables `/v1/accounts/plc/prepare` and `/v1/accounts/plc/activate`. |
| `--enable-management-permanent-deletion` | Flag (`false`) | Enables `/v1/accounts/delete` with PLC directory tombstoning. |
| `--enable-management-firehose-sync` | Flag (`false`) | Enables authenticated in-process firehose `#sync` emission. |
| `--management-account-kek-file <path>` | String (File path) | Account KEK file for management PLC provisioning and deletion. |
| `--management-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for management operations. |
| `--management-account-key-directory <path>` | String (`<data-directory>/keys`) | Key-envelope directory for management operations. |
| `--management-deletion-plc-origin <url>` | String | PLC directory origin used for permanent deletion. |
| `--management-deletion-plc-laboratory` | Flag (`false`) | Selects explicit PLC laboratory policy for permanent deletion. |
| `--management-deletion-plc-laboratory-allowlisted-host <host>` | String | Explicit DNS host allowed for deletion PLC laboratory origin. |
| `--management-deletion-plc-reference-compatibility <comp>` | String | Pinned permanent-deletion PLC compatibility (`did-plc-server-0.0.1`). |

### Identity and notification options

| Option / Flag | Type / Default | Description |
|---|---|---|
| `--did-web-revalidation-interval-seconds <int>` | Int (`3600`) | Background revalidation interval in seconds for `did:web` identities. |
| `--did-web-revalidation-grace-seconds <int>` | Int (`86400`) | Grace period in seconds before an unreachable `did:web` identity is suspended. |
| `--did-web-signing-key-file <path>` | String (File path) | Owner-only 32-byte base64url `did:web` reserved signing key. |
| `--notification-config <json\|path>` | String | Owner-supplied JSON or file with ES256/ES256K public pins and destination bindings. |
| `--enable-notification-delivery` | Flag (`false`) | Enables durable peer-pinned writer notifications and deletion recovery delivery. |
| `--notification-account-kek-file <path>` | String (File path) | Account KEK file for signing writer notifications. |
| `--notification-account-kek-id <id>` | String (`primary`) | Active account KEK identifier for notification signing. |
| `--notification-account-key-directory <path>` | String (`<data-directory>/keys`) | Key-envelope directory for notification signing. |
| `--managing-service-audience <aud>` | String | Explicit service-JWT audience for `com.atproto.simplespace.checkUserAccess`. |

## Docker deployment

### Architecture layout

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
  │     - /data (rw, durable storage)                                                      │
  │     - /tmp (rw, tmpfs, noexec, nosuid, size=64m)                                       │
  └────────────────────────────────────────▲───────────────────────────────────────────────┘
                                           │
                           HTTP Reverse Proxy (Caddy / NGINX)
                                           │
                                  TLS 1.3 / HTTPS / WSS
```

### Docker Compose deployment steps

1. Create durable host directories:
   ```bash
   sudo mkdir -p /var/lib/swan/data
   sudo chown -R 10001:10001 /var/lib/swan/data
   sudo chmod 0700 /var/lib/swan/data
   ```

2. Create `docker-compose.yml`:
   ```yaml
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

3. Start the container:
   ```bash
   docker compose up -d
   ```

**Verification:** To check container status and liveness, run:
```bash
docker compose ps
docker compose logs --tail=50 swan
curl -sS -f http://127.0.0.1:3000/health
```
The output from `/health` must be `OK`.

## Native systemd deployment

To deploy Swan natively on Linux without containers:

### 1. Create system user and directory layout

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/swan -u 10001 swan
sudo mkdir -p /var/lib/swan/data /etc/swan/secrets /usr/local/share/swan/account
sudo chown -R swan:swan /var/lib/swan
sudo chmod 0700 /var/lib/swan/data /etc/swan/secrets
```

### 2. Configure systemd service (`/etc/systemd/system/swan.service`)

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

# Security hardening
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

### 3. Start and enable systemd service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now swan
sudo systemctl status swan
```

**Verification:** To confirm the daemon is running, execute:
```bash
journalctl -u swan -n 20 --no-pager
curl -sS -f http://127.0.0.1:3000/health
```

## Reverse-proxy configuration

Swan requires a reverse proxy to terminate TLS, manage HTTP/2 or HTTP/3, provide WebSocket streaming for the public firehose, and pass client IP headers.

### Caddy configuration

Create `/etc/caddy/Caddyfile`:

```caddy
pds.example.com {
    encode zstd gzip

    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        # Client IP header for Swan rate limiting and admission
        header_up X-Swan-Client-IP {remote_host}

        # Disable buffering for WebSocket firehose streams
        flush_interval -1
    }

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    log {
        output file /var/log/caddy/pds.example.com.access.log {
            roll_size 100mb
            roll_keep 10
        }
    }
}
```

Reload Caddy:
```bash
sudo systemctl reload caddy
```

### NGINX configuration

Create `/etc/nginx/sites-available/swan`:

```nginx
# Upstream definition
upstream swan_backend {
    server 127.0.0.1:3000;
    keepalive 32;
}

# WebSocket upgrade map
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

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # Public firehose WebSocket endpoint
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

Enable the configuration and reload NGINX:
```bash
sudo ln -sf /etc/nginx/sites-available/swan /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Post-deployment verification

To verify your production deployment end-to-end:

1. **Verify public HTTPS endpoint and liveness**:
   ```bash
   curl -sS -i https://pds.example.com/health
   ```
   The response must return HTTP `200 OK` with body `OK`.

2. **Verify server identity and DID document**:
   ```bash
   curl -sS https://pds.example.com/.well-known/did.json | jq .
   ```
   The JSON response must contain the service DID matching your server configuration.

3. **Verify server capability descriptor**:
   ```bash
   curl -sS https://pds.example.com/xrpc/com.atproto.server.describeServer | jq .
   ```
   The response must return `availableUserDomains` and server capabilities.

4. **Verify firehose WebSocket connectivity**:
   ```bash
   curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Host: pds.example.com" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
     -H "Sec-WebSocket-Version: 13" \
     https://pds.example.com/xrpc/com.atproto.sync.subscribeRepos
   ```
   The response must return HTTP `101 Switching Protocols`.
