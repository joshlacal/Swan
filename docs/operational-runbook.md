# Operational runbook

This operational runbook provides step-by-step procedures for health checking, taking and restoring account backups, rotating cryptographic keys, executing account lifecycle operations, performing database maintenance, and diagnosing operational incidents on a production Swan server.

## Health checking and diagnostic probing

### Liveness and readiness endpoints

Swan exposes the following HTTP endpoints for monitoring and health verification:

| Endpoint | Method | Success | Content type | Purpose |
|---|---|---|---|---|
| `/health` | `GET` | `200 OK` | `text/plain` | Liveness probe. Verifies HTTP listener and Hummingbird event loop responsiveness. |
| `/.well-known/did.json` | `GET` | `200 OK` | `application/json` | Identity probe. Verifies server DID document resolution. |
| `/xrpc/com.atproto.server.describeServer` | `GET` | `200 OK` | `application/json` | Capability probe. Returns supported user domains, contact email, and features. |
| `/xrpc/community.lexicon.service.describe` | `GET` | `200 OK` | `application/json` | Lexicon method discovery probe. Returns supported XRPC NSID methods. |

### Running health probes

To check server health and descriptors:

```bash
# 1. Check liveness
curl -sS -f http://127.0.0.1:3000/health

# 2. Check DID document
curl -sS -f http://127.0.0.1:3000/.well-known/did.json | jq .

# 3. Check server description and active capabilities
curl -sS -f http://127.0.0.1:3000/xrpc/com.atproto.server.describeServer | jq .
```

**Verification:** `/health` must return `OK` with exit code `0`.

### Key operational metrics and thresholds

Monitor the following indicators on your production host:

1. **HTTP 5xx error rate**: Sustained HTTP 500 or 503 errors indicate unhandled exceptions, database locks, or missing key files. Alert if 5xx responses exceed 0.5% over a 5-minute rolling window.
2. **Firehose subscriber quota**: Swan reserves 25% of `--max-connections` (64 out of 256 connections by default) for anonymous WebSocket firehose subscribers. Alert if active firehose subscribers reach 90% of the reserved capacity.
3. **Outbox queue depth**: The `outbox_deliveries` table in `control.sqlite` records outbound emails and notifications. Alert if pending rows exceed 1,000 or if the oldest pending item is older than 15 minutes.
4. **SQLite WAL size**: `control.sqlite-wal`, `firehose.sqlite-wal`, and `<did>.sqlite-wal` files should not exceed 64 MiB under normal checkpointing. Alert if any WAL file exceeds 256 MiB.
5. **Disk space**: Alert if filesystem utilization on the data directory mount exceeds 80%.

## Taking and restoring backups

Swan supports two backup workflows:
- **Encrypted operator backup (`swan backup` / `swan restore`)**: Creates an authenticated, encrypted snapshot of an individual account's state, metadata, and key envelopes.
- **Portable logical export (`swan export` / `swan restore`)**: Generates a checksummed, unencrypted CAR and JSON archive for cross-implementation migration.
- **Full SQLite hot-backup**: Uses SQLite `VACUUM INTO` for zero-downtime node-level snapshots.

### Procedure 1: Create an encrypted account backup (`swan backup`)

#### Prerequisites
- Active account DID to back up.
- Owner-only operator secret file (`mode 0600`).
- Owner-only active account KEK file (`mode 0600`).
- Dedicated 32-byte operator backup key file (`mode 0600`).

#### Steps
1. If an operator backup key file does not exist, generate one:
   ```bash
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | sudo tee /etc/swan/secrets/operator-backup-key > /dev/null
   sudo chmod 0600 /etc/swan/secrets/operator-backup-key
   sudo chown 10001:10001 /etc/swan/secrets/operator-backup-key
   ```

2. Run `swan backup` targeting a new, nonexistent output directory:
   ```bash
   swan backup \
     --data-directory /var/lib/swan/data \
     --did "did:plc:12345678abcdefgh" \
     --output-directory "/var/backups/swan/did:plc:12345678abcdefgh_$(date +%Y%m%d_%H%M%S)" \
     --operator-secret-file /etc/swan/secrets/operator-secret \
     --account-kek-file /etc/swan/secrets/account-kek \
     --backup-key-file /etc/swan/secrets/operator-backup-key \
     --account-kek-id "primary"
   ```

#### Verification
Check the command output. It returns a JSON object containing the backed-up account DID, repository commit CID, and manifest checksum. Verify the target directory exists and contains encrypted artifact files.

### Procedure 2: Restore an encrypted account backup (`swan restore`)

#### Prerequisites
- Target backup directory produced by `swan backup`.
- Owner-only operator secret file (`mode 0600`).
- Owner-only operator backup key file (`mode 0600`).
- Owner-only target account KEK file (`mode 0600`).
- Clean or recovery data directory.

#### Steps
Run `swan restore` with backup options:

```bash
swan restore \
  --data-directory /var/lib/swan/data \
  --input-directory /var/backups/swan/did:plc:12345678abcdefgh_20260822_120000 \
  --operator-secret-file /etc/swan/secrets/operator-secret \
  --backup-key-file /etc/swan/secrets/operator-backup-key \
  --account-kek-file /etc/swan/secrets/account-kek \
  --account-kek-id "primary"
```

#### Verification
Verify the restored account metadata using `swan account show`:
```bash
swan account show \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh"
```
The account status must be `active`.

### Procedure 3: Create a portable logical export (`swan export`)

To create an unencrypted portable account archive suitable for migration to another AT Protocol PDS:

#### Prerequisites
- Active account DID.
- Owner-only operator secret file (`mode 0600`).
- Owner-only account KEK file (`mode 0600`).

#### Steps
Run `swan export`:

```bash
swan export \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh" \
  --output-directory "/var/backups/swan/export_did:plc:12345678abcdefgh_$(date +%Y%m%d_%H%M%S)" \
  --operator-secret-file /etc/swan/secrets/operator-secret \
  --account-kek-file /etc/swan/secrets/account-kek \
  --account-kek-id "primary"
```

#### Verification
The command outputs JSON containing `manifestSHA256` and the list of exported files (repository CAR, blob index, account metadata). The manifest reference is automatically recorded in `control.sqlite`.

### Procedure 4: Stage a portable logical archive (`swan restore`)

To stage an unencrypted portable archive into Swan storage:

#### Prerequisites
- Directory containing the unencrypted portable export files.
- Owner-only operator secret file (`mode 0600`).

#### Steps
Run `swan restore` without backup key options:

```bash
swan restore \
  --data-directory /var/lib/swan/data \
  --input-directory /var/backups/swan/export_did:plc:12345678abcdefgh_20260822_120000 \
  --operator-secret-file /etc/swan/secrets/operator-secret
```

#### Verification
Confirm the staged account state using `swan account show`.

### Procedure 5: Hot SQLite backup using `VACUUM INTO`

To create atomic, zero-downtime filesystem copies of all databases while Swan is actively running:

#### Prerequisites
- `sqlite3` CLI utility installed.
- Sufficient disk space on the backup destination mount.

#### Steps
```bash
#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="/var/lib/swan/data"
BACKUP_DEST="/var/backups/swan_node_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${BACKUP_DEST}"

# 1. Safely backup control plane database
sqlite3 "${DATA_DIR}/control.sqlite" "VACUUM INTO '${BACKUP_DEST}/control.sqlite';"

# 2. Safely backup firehose database if present
if [ -f "${DATA_DIR}/firehose.sqlite" ]; then
  sqlite3 "${DATA_DIR}/firehose.sqlite" "VACUUM INTO '${BACKUP_DEST}/firehose.sqlite';"
fi

# 3. Safely backup all per-account databases
for db in "${DATA_DIR}"/did:*.sqlite; do
  [ -f "$db" ] || continue
  filename="$(basename "$db")"
  sqlite3 "$db" "VACUUM INTO '${BACKUP_DEST}/${filename}';"
done

# 4. Copy key envelopes and blobs
if [ -d "${DATA_DIR}/keys" ]; then
  cp -a "${DATA_DIR}/keys" "${BACKUP_DEST}/keys"
fi
if [ -d "${DATA_DIR}/blobs" ]; then
  cp -a "${DATA_DIR}/blobs" "${BACKUP_DEST}/blobs"
fi

echo "Full node hot-backup completed at ${BACKUP_DEST}."
```

#### Verification
Verify the backup databases with `sqlite3 "${BACKUP_DEST}/control.sqlite" "PRAGMA integrity_check;"`. The command must return `ok`.

## Rotating cryptographic keys

### Procedure 1: Account Key Encryption Key (KEK) rotation

The Account KEK protects per-account private key envelopes stored in `<data-directory>/keys/`. Each envelope records the active KEK identifier under which it was encrypted.

#### Prerequisites
- Root or administrative access to the secrets directory.

#### Steps
1. Generate the new Account KEK file:
   ```bash
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | sudo tee /etc/swan/secrets/account-kek-v2 > /dev/null
   sudo chmod 0600 /etc/swan/secrets/account-kek-v2
   sudo chown 10001:10001 /etc/swan/secrets/account-kek-v2
   ```

2. Update the server startup configuration to point to the new key file and pass the new identifier `v2`:
   - Set `--public-account-kek-file /etc/swan/secrets/account-kek-v2` and `--public-account-kek-id v2`.
   - Set `--signup-account-kek-file /etc/swan/secrets/account-kek-v2` and `--signup-account-kek-id v2`.
   - Update `--legacy-session-account-kek-file` and `--appview-proxy-account-kek-file` if enabled.

3. Restart Swan:
   ```bash
   sudo systemctl restart swan
   ```

> Existing key envelopes created under earlier KEK identifiers remain readable as long as their corresponding key files remain accessible, while all newly provisioned accounts or rotated keys use the active `v2` identifier.

#### Verification
Provision a test account or rotate an existing account's PLC keys to confirm envelopes are created under `v2`.

### Procedure 2: OAuth server master key rotation

The `oauth-server-key` is the master key for encrypting browser sessions, CSRF receipts, and refresh tokens.

> Rotating `oauth-server-key` invalidates existing active browser portal sessions and OAuth refresh tokens. Users and client applications will need to re-authenticate.

#### Prerequisites
- Root access to `/etc/swan/secrets`.

#### Steps
1. Generate the new OAuth server key:
   ```bash
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | sudo tee /etc/swan/secrets/oauth-server-key.new > /dev/null
   sudo chmod 0600 /etc/swan/secrets/oauth-server-key.new
   sudo chown 10001:10001 /etc/swan/secrets/oauth-server-key.new
   ```

2. Atomically swap the secret file:
   ```bash
   sudo mv /etc/swan/secrets/oauth-server-key.new /etc/swan/secrets/oauth-server-key
   ```

3. Restart Swan:
   ```bash
   sudo systemctl restart swan
   ```

#### Verification
Authenticate via the account portal or an OAuth client to confirm token issuance succeeds.

### Procedure 3: Account PLC identity key rotation (`swan account rotate-plc`)

To rotate an account's PLC signing and rotation key pair and publish the signed operation to the PLC directory:

#### Prerequisites
- Active account DID.
- Owner-only operator secret file (`mode 0600`).
- Owner-only account KEK file (`mode 0600`).

#### Steps
Run `swan account rotate-plc`:

```bash
swan account rotate-plc \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh" \
  --plc-origin "https://plc.directory" \
  --operator-secret-file /etc/swan/secrets/operator-secret \
  --account-kek-file /etc/swan/secrets/account-kek \
  --account-kek-id "primary"
```

#### Verification
Check the command output. It returns JSON containing the new signing key CID and updated PLC operation CID. Query the PLC directory to confirm the updated genesis:
```bash
curl -sS "https://plc.directory/did:plc:12345678abcdefgh/log" | jq .
```

## Account lifecycle operations

### Installing a local account (`swan account install-local`)

To install the durable, local half of an account offline (generating key envelopes, control records, and an empty public repository):

1. Write the initial password to an owner-only file:
   ```bash
   echo -n "SecretPassword123" > /tmp/account-password.txt
   chmod 0600 /tmp/account-password.txt
   ```

2. Run `install-local`:
   ```bash
   swan account install-local \
     --data-directory /var/lib/swan/data \
     --did "did:plc:12345678abcdefgh" \
     --handle "alice.example.com" \
     --revision "3k2aaaaaaae22" \
     --password-file /tmp/account-password.txt \
     --operator-secret-file /etc/swan/secrets/operator-secret \
     --account-kek-file /etc/swan/secrets/account-kek \
     --account-kek-id "primary"
   ```

3. Securely remove the temporary password file:
   ```bash
   rm -f /tmp/account-password.txt
   ```

**Verification:** Run `swan account show --data-directory /var/lib/swan/data --did did:plc:12345678abcdefgh`.

### Preparing a PLC identity (`swan account prepare-plc`)

To prepare and submit a recoverable PLC identity without activating it:

```bash
swan account prepare-plc \
  --data-directory /var/lib/swan/data \
  --request-id "req-$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  --handle "bob.example.com" \
  --pds-origin "https://pds.example.com" \
  --repository-revision "3k2aaaaaaae22" \
  --plc-origin "https://plc.directory" \
  --operator-secret-file /etc/swan/secrets/operator-secret \
  --account-kek-file /etc/swan/secrets/account-kek \
  --account-kek-id "primary"
```

### Activating a prepared PLC identity (`swan account activate-plc`)

To activate a submitted PLC identity after handle and directory verification:

```bash
swan account activate-plc \
  --data-directory /var/lib/swan/data \
  --request-id "req-12345678-abcd-1234-abcd-1234567890ab" \
  --password-file /tmp/account-password.txt \
  --plc-origin "https://plc.directory" \
  --operator-secret-file /etc/swan/secrets/operator-secret \
  --account-kek-file /etc/swan/secrets/account-kek \
  --account-kek-id "primary"
```

### Deactivating and reactivating accounts

To temporarily suspend an account:
```bash
swan account deactivate \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh" \
  --operator-secret-file /etc/swan/secrets/operator-secret
```

To reactivate a deactivated account:
```bash
swan account reactivate \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh" \
  --operator-secret-file /etc/swan/secrets/operator-secret
```

### Permanently deleting an account (`swan account delete`)

To permanently deactivate an account, remove its keys and private data, and record a tombstone in the PLC directory:

```bash
swan account delete \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh" \
  --tombstone-reason "User requested GDPR erasure" \
  --plc-origin "https://plc.directory" \
  --operator-secret-file /etc/swan/secrets/operator-secret \
  --account-kek-file /etc/swan/secrets/account-kek \
  --account-kek-id "primary"
```

**Verification:** Run `swan account show --data-directory /var/lib/swan/data --did did:plc:12345678abcdefgh`. The status must show `deleted` with the declared tombstone.

## Firehose operations and sync announcement

### Forcing a firehose `#sync` announcement (`swan firehose force-sync`)

If downstream relays or AppViews miss public repository commits (for example, following network partition recovery or repository import), use `force-sync` to enqueue a manual `#sync` event:

```bash
swan firehose force-sync \
  --data-directory /var/lib/swan/data \
  --did "did:plc:12345678abcdefgh"
```

**Verification:** The command outputs `enqueued forced #sync for <did> (request <uuid>)`.

### Inspecting a relay CAR archive (`swan firehose inspect-relay-car`)

To inspect an exported relay repository CAR file:

```bash
swan firehose inspect-relay-car \
  --car /tmp/repo-snapshot.car
```

### Verifying relay capture against PLC (`swan firehose verify-relay-capture`)

To verify relay event captures and Swan repository state against authenticated PLC keys:

```bash
swan firehose verify-relay-capture \
  --manifest /path/to/relay-verifier-manifest.json \
  --plc-origin "https://plc.directory"
```

## Database maintenance and storage tuning

### WAL checkpointing and truncation

To prevent SQLite WAL files from expanding indefinitely and to reclaim disk space, run regular checkpoints across all databases:

```bash
#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="/var/lib/swan/data"

for db in "${DATA_DIR}"/*.sqlite; do
  [ -f "$db" ] || continue
  echo "Checkpointing $db..."
  sqlite3 "$db" "PRAGMA wal_checkpoint(TRUNCATE);"
done

echo "All SQLite WAL files checkpointed and truncated."
```

### Database integrity checks

To run full integrity checks across all control and account databases:

```bash
#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="/var/lib/swan/data"

for db in "${DATA_DIR}"/*.sqlite; do
  [ -f "$db" ] || continue
  echo "Checking integrity of $db..."
  integrity=$(sqlite3 "$db" "PRAGMA integrity_check;")
  fk=$(sqlite3 "$db" "PRAGMA foreign_key_check;")
  
  if [ "$integrity" != "ok" ]; then
    echo "ERROR: Integrity check failed on $db: $integrity" >&2
    exit 1
  fi
  if [ -n "$fk" ]; then
    echo "ERROR: Foreign key violations on $db: $fk" >&2
    exit 1
  fi
done

echo "All databases passed integrity and foreign key checks."
```

### Automatic firehose retention and compaction

Swan manages `firehose.sqlite` automatically during runtime using the built-in background retention reaper. The reaper runs every `--public-firehose-retention-interval-seconds` (default: `60` seconds) and prunes event frames exceeding:
- `--public-firehose-retention-age-hours` (default: `72` hours).
- `--public-firehose-retention-max-rows` (default: `1000000` rows).
- `--public-firehose-retention-max-bytes` (default: `1073741824` bytes / 1 GiB).

To adjust retention parameters, update the `swan serve` flags in your systemd unit or `docker-compose.yml`. To reclaim freed space from `firehose.sqlite` after heavy pruning:
```bash
sqlite3 /var/lib/swan/data/firehose.sqlite "VACUUM;"
```

## Diagnosing operational failures

### Structured diagnostic log events

Swan emits structured log events for authentication and outbound proxy events to give operators diagnostic visibility without logging sensitive credentials or tokens.

#### 1. `legacy createSession rejected`

Emitted when authentication fails on `com.atproto.server.createSession`. To protect against account enumeration, clients receive a constant-time opaque 401 error. The server log records the exact failure stage and factor token shape:

```
[INFO] legacy createSession rejected [stage: "identifier_unresolved", factorToken: "absent"]
```

Fixed vocabulary for `stage`:
- `identifier_unresolved`: The handle or DID does not exist or does not belong to an active account on this server.
- `no_credential_matched`: The identifier resolved, but neither the primary password nor any scoped app password matched.
- `auth_factor_token_required`: The primary password verified, but the account has active MFA/email factors and no factor token was presented.
- `rate_limited`: The client IP or account identifier exceeded login rate limits.
- `malformed_request`: The JSON body exceeded byte bounds or contained invalid fields.
- `token_rejected`: An invalid or expired token was presented.
- `unavailable`: Internal storage or password hasher was temporarily unavailable.

Fixed vocabulary for `factorToken`:
- `absent`: The `authFactorToken` field was not present in the request JSON.
- `empty`: The `authFactorToken` field was present but empty.
- `present`: An `authFactorToken` value was supplied in the request.

#### 2. `xrpc pipethrough upstream failed`

Emitted when an outbound HTTP request to an upstream service (such as the AppView or an `atproto-proxy` target) fails. The client receives an opaque HTTP 502 Bad Gateway; the server log records:

```
[INFO] xrpc pipethrough upstream failed [nsid: "app.bsky.feed.getTimeline", host: "api.bsky.app", reason: "connection timed out"]
```

Key metadata fields:
- `nsid`: The requested XRPC method.
- `host`: Target destination hostname.
- `reason`: Underlying transport or DNS failure (minted service tokens are never logged).

### Common operational troubleshooting scenarios

#### Scenario 1: SQLite database locked or WAL growing rapidly

**Symptoms**: HTTP 500/503 responses; WAL files exceed 256 MiB; log messages mentioning `database is locked`.

**Resolution**:
1. Check for long-running read transactions or external backup processes holding locks:
   ```bash
   fuser -v /var/lib/swan/data/control.sqlite
   ```
2. Run manual checkpointing:
   ```bash
   sqlite3 /var/lib/swan/data/control.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
   ```
3. Ensure storage is backed by fast NVMe SSD storage and that `PRAGMA busy_timeout` has not been altered.

#### Scenario 2: Upstream AppView returns 502 Bad Gateway

**Symptoms**: Client requests to `app.bsky.*` endpoints fail with HTTP 502; `xrpc pipethrough upstream failed` appears in logs.

**Resolution**:
1. Inspect the `host` and `reason` metadata in the `xrpc pipethrough upstream failed` log entry.
2. Verify DNS resolution and HTTPS connectivity to the configured AppView from the host:
   ```bash
   curl -sS -I https://api.bsky.app/xrpc/_health
   ```
3. Verify that `--appview-proxy-account-kek-file` is configured with a valid account KEK so service-auth tokens can be signed.

#### Scenario 3: Anonymous firehose subscribers receive 429 Too Many Requests

**Symptoms**: Relay or consumer connections to `/xrpc/com.atproto.sync.subscribeRepos` are rejected with HTTP 429 or 503.

**Resolution**:
1. Check current connection usage. By default, 25% of `--max-connections` (64 out of 256) is reserved for anonymous firehose subscribers.
2. If legitimate traffic requires more subscriber capacity, increase `--max-connections` (for example, `--max-connections 512` allows 128 subscribers):
   ```bash
   # Update systemd or docker-compose with --max-connections 512
   sudo systemctl restart swan
   ```

#### Scenario 4: Outbox deliveries or email verification stalled

**Symptoms**: Users do not receive password reset or email verification emails; rows in `outbox_deliveries` accumulate.

**Resolution**:
1. Check the count of pending items in `control.sqlite`:
   ```bash
   sqlite3 /var/lib/swan/data/control.sqlite "SELECT COUNT(*) FROM outbox_deliveries WHERE status = 'pending';"
   ```
2. Verify SMTP credentials and connectivity to your SMTP provider (`--email-smtp-host` on port `587` or `465`).
3. Check daemon logs for SMTP handshake failures or authentication refusals.
