#!/usr/bin/env bash
set -euo pipefail

# Live, disposable Compose acceptance for the durable permissioned outbox.
# The seed Swan process commits one write with delivery disabled, then receives
# SIGKILL. A recovery-enabled Swan process then starts only after a
# loopback-only proxy is ready. The proxy loses the first successful
# acknowledgement, observes exactly two successful forwards of the stable
# event, and the authority records exactly one receiver effect.
#
# The scenario writes request bodies and OAuth results only to container tmpfs.
# Its host-side state contains transport counts and SHA-256 digests, never
# credentials, service-auth headers, record bodies, or permissioned values.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

wait_timeout="${SWAN_NOTIFICATION_RESTART_TIMEOUT:-180}"
if [[ ! "$wait_timeout" =~ ^[1-9][0-9]*$ ]] \
  || ((wait_timeout > 600))
then
  echo "SWAN_NOTIFICATION_RESTART_TIMEOUT must be an integer from 1 through 600" >&2
  exit 64
fi

[[ -n "${SWAN_INTEROP_SECRETS_DIR:-}" ]] || {
  echo "SWAN_INTEROP_SECRETS_DIR is required" >&2
  exit 64
}
command -v docker >/dev/null 2>&1 || {
  echo "Docker is required" >&2
  exit 69
}
docker compose version >/dev/null

SWAN_INTEROP_SECRETS_DIR="$({
  ./interop/verify-secret-source.sh "$root" "$SWAN_INTEROP_SECRETS_DIR"
})"
export SWAN_INTEROP_SECRETS_DIR

read_lab_value() {
  local name="$1"
  tr -d '\r\n' < "${SWAN_INTEROP_SECRETS_DIR}/${name}"
}

# The bootstrap service provisions real PLC identities from the handles.  The
# DID fixture files are retained for secret-source validation, but are not the
# authority of record: a PLC laboratory may assign a fresh DID on each clean
# data volume.  Resolve the actual DIDs from Swan's durable control metadata
# after bootstrap rather than inventing a second hard-coded identity set.
authority_handle="$(read_lab_value authority.handle)"
member_handle="$(read_lab_value member.handle)"
if [[ -z "$authority_handle" || "$authority_handle" =~ [[:space:]] ]] \
  || [[ -z "$member_handle" || "$member_handle" =~ [[:space:]] ]]
then
  echo "interop identity fixtures are malformed" >&2
  exit 64
fi
authority_did=""
member_did=""
space_uri=""
collection="app.bsky.feed.post"
rkey="restart-outbox"
project_name="${SWAN_NOTIFICATION_RESTART_PROJECT:-swan-notification-restart-${PPID}-$$}"
temporary_root="${SWAN_NOTIFICATION_RESTART_TMPDIR:-/tmp}"
[[ "$temporary_root" = /* ]] || {
  echo "SWAN_NOTIFICATION_RESTART_TMPDIR must be an absolute directory" >&2
  exit 64
}
# Docker Desktop shares /tmp by default, while macOS TMPDIR commonly points
# into a private /var/folders path that cannot be bind-mounted into a Linux
# container.  Keep the override for CI, but make the portable default a
# repository-local ignored directory under the host's shared /Users tree.
if [[ -z "${SWAN_NOTIFICATION_RESTART_TMPDIR:-}" ]]; then
  temporary_root="$root/.interop-live"
fi
mkdir -p "$temporary_root"
chmod 700 "$temporary_root"
temporary_directory="$(mktemp -d "${temporary_root%/}/swan-notification-restart.XXXXXX")"
seed_container="${project_name}-seed"
proxy_container="${project_name}-ack-proxy"
recovery_container="${project_name}-recovery"
proxy_id=""
recovery_id=""

compose() {
  if [[ "${SWAN_NOTIFICATION_RESTART_NO_BUILD:-0}" == "1" && "${1:-}" == "up" ]]; then
    # Compose names build-only images after the project. A caller may choose a
    # fresh project name while reusing a previously built cache; in that case
    # `up --no-build` fails before any service starts because the new image
    # names do not exist. Keep the fast path when every required local image
    # is present, but fall back to the normal pinned build instead of turning
    # an image-tag mismatch into a false acceptance failure.
    local images_available=1
    local service
    for service in \
      caddy-ca-ready caddy reference-pds reference-plc swan-bootstrap \
      swan-data-init swan-secrets-init swan
    do
      if ! docker image inspect "${project_name}-${service}:latest" \
        >/dev/null 2>&1
      then
        images_available=0
        break
      fi
    done
    if ((images_available)); then
      shift
      ./interop/compose.sh --project-name "$project_name" up --no-build "$@"
      return
    fi
    echo "notification acceptance: project-scoped images unavailable; building pinned services" >&2
  fi
  ./interop/compose.sh --project-name "$project_name" "$@"
}

bounded_cleanup_command() {
  "$@" >/dev/null 2>&1 &
  local cleanup_pid=$!
  # Compose may need several seconds to remove the disposable network and
  # named volumes. Keep cleanup bounded, but do not turn a successful
  # acceptance into a noisy forced-termination path on Docker Desktop.
  local deadline=$((SECONDS + 30))
  while kill -0 "$cleanup_pid" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      kill -TERM "$cleanup_pid" >/dev/null 2>&1 || true
      local termination_deadline=$((SECONDS + 2))
      while kill -0 "$cleanup_pid" >/dev/null 2>&1 \
        && ((SECONDS < termination_deadline))
      do
        sleep 1
      done
      kill -KILL "$cleanup_pid" >/dev/null 2>&1 || true
      break
    fi
    sleep 1
  done
  wait "$cleanup_pid" >/dev/null 2>&1 || true
}

cleanup() {
  trap - EXIT INT TERM HUP
  if [[ -n "$recovery_id" ]]; then
    bounded_cleanup_command docker rm --force "$recovery_id"
  fi
  if [[ -n "$proxy_id" ]]; then
    bounded_cleanup_command docker rm --force "$proxy_id"
  fi
  bounded_cleanup_command docker rm --force "$seed_container"
  bounded_cleanup_command compose down --volumes --remove-orphans
  rm -rf "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

container_id() {
  local service="$1"
  # compose.sh performs the pinned-reference check on every invocation and
  # emits its success marker on stdout.  Only accept a Docker container ID
  # here so that the marker cannot be mistaken for the service identifier.
  compose ps --all -q "$service" | awk '/^[0-9a-f]{64}$/ { print; exit }'
}

wait_for_healthy_container() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  local status=""
  while ((SECONDS < deadline)); do
    status="$(
      docker inspect \
        --format '{{if .State.Running}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}{{.State.Status}}{{end}}' \
        "$container" 2>/dev/null || true
    )"
    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      return 0
    fi
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "${label} exited before becoming healthy" >&2
      exit 1
    fi
    sleep 1
  done
  echo "${label} did not become healthy before the bounded timeout" >&2
  exit 1
}

wait_for_successful_container() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  local status=""
  local exit_code=""
  while ((SECONDS < deadline)); do
    status="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)"
    if [[ "$status" == "exited" ]]; then
      exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$container")"
      if [[ "$exit_code" == "0" ]]; then
        return 0
      fi
      echo "${label} failed" >&2
      exit 1
    fi
    sleep 1
  done
  echo "${label} did not complete before the bounded timeout" >&2
  exit 1
}

wait_for_swan_http() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  local status=""
  while ((SECONDS < deadline)); do
    status="$(
      docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null \
        || true
    )"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "${label} exited before its HTTP listener became healthy" >&2
      exit 1
    fi
    if docker exec "$container" \
      curl --fail --silent --show-error --max-time 2 \
        http://127.0.0.1:3000/health >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  echo "${label} did not expose a healthy HTTP listener before the bounded timeout" >&2
  exit 1
}

wait_for_stopped_container() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  local status=""
  while ((SECONDS < deadline)); do
    status="$(
      docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null \
        || true
    )"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "${label} did not stop before the bounded timeout" >&2
  exit 1
}

mount_name() {
  local container="$1"
  local destination="$2"
  docker inspect \
    --format '{{range .Mounts}}{{if eq .Destination "'"$destination"'"}}{{.Name}}{{end}}{{end}}' \
    "$container"
}

compose up --detach

normal_swan_id="$(container_id swan)"
bootstrap_id="$(container_id swan-bootstrap)"
caddy_id="$(container_id caddy)"
reference_pds_id="$(container_id reference-pds)"
for required_id in \
  "$normal_swan_id" \
  "$bootstrap_id" \
  "$caddy_id" \
  "$reference_pds_id"
do
  [[ -n "$required_id" ]] || {
    echo "the disposable Compose project is missing a required container" >&2
    exit 1
  }
done

wait_for_successful_container "$bootstrap_id" "Swan account bootstrap"
wait_for_healthy_container "$normal_swan_id" "normal Swan"
wait_for_healthy_container "$caddy_id" "Caddy"

swan_image="$(docker inspect --format '{{.Image}}' "$normal_swan_id")"
reference_image="$(docker inspect --format '{{.Image}}' "$reference_pds_id")"
data_volume="$(mount_name "$normal_swan_id" /var/lib/swan)"
runtime_secrets_volume="$(mount_name "$normal_swan_id" /run/secrets/swan-runtime)"
bootstrap_secrets_volume="$(mount_name "$bootstrap_id" /run/secrets/swan-bootstrap)"
caddy_trust_id="$(container_id caddy-ca-ready)"
[[ -n "$caddy_trust_id" ]] || {
  echo "the Caddy trust preparation container is missing" >&2
  exit 1
}
wait_for_successful_container "$caddy_trust_id" "Caddy trust preparation"
caddy_trust_volume="$(mount_name "$caddy_trust_id" /prepared-trust)"
network_name="$(
  docker inspect \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s" $name}}{{end}}' \
    "$normal_swan_id"
)"
for required_value in \
  "$swan_image" \
  "$reference_image" \
  "$data_volume" \
  "$runtime_secrets_volume" \
  "$bootstrap_secrets_volume" \
  "$caddy_trust_volume" \
  "$network_name"
do
  [[ -n "$required_value" ]] || {
    echo "the disposable Compose project has an incomplete volume or network boundary" >&2
    exit 1
  }
done

# Resolve the PLC-generated DIDs while the normal service is still available.
# The command only returns sanitized control metadata (DID, handle, status),
# and the values are held in shell variables; credentials and repository data
# never enter the host-side acceptance artifacts.
account_metadata_for_handle() {
  local handle="$1"
  docker exec "$normal_swan_id" \
    /usr/local/bin/swan account show \
    --data-directory /var/lib/swan/data \
    --handle "$handle"
}

account_field() {
  local field="$1"
  python3 -c '
import json
import sys

value = json.load(sys.stdin).get(sys.argv[1])
if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
    raise SystemExit(1)
print(value)
' "$field"
}

authority_metadata="$(account_metadata_for_handle "$authority_handle")" || {
  echo "bootstrap did not provision the authority handle" >&2
  exit 1
}
member_metadata="$(account_metadata_for_handle "$member_handle")" || {
  echo "bootstrap did not provision the member handle" >&2
  exit 1
}
authority_did="$(printf '%s' "$authority_metadata" | account_field did)" || {
  echo "authority account metadata did not contain a valid DID" >&2
  exit 1
}
member_did="$(printf '%s' "$member_metadata" | account_field did)" || {
  echo "member account metadata did not contain a valid DID" >&2
  exit 1
}
authority_handle="$(printf '%s' "$authority_metadata" | account_field canonicalHandle)" || {
  echo "authority account metadata did not contain a valid handle" >&2
  exit 1
}
member_handle="$(printf '%s' "$member_metadata" | account_field canonicalHandle)" || {
  echo "member account metadata did not contain a valid handle" >&2
  exit 1
}
if [[ ! "$authority_did" =~ ^did:[a-z0-9:._-]+$ ]] \
  || [[ ! "$member_did" =~ ^did:[a-z0-9:._-]+$ ]]
then
  echo "bootstrap account metadata contained a malformed DID" >&2
  exit 1
fi
space_uri="at://${authority_did}/space/app.bsky.bookmarks/restart-outbox"

notification_config_path="${temporary_directory}/notification-config.json"
python3 - "$notification_config_path" "$authority_did" <<'PY'
import json
import os
import sys

path, authority = sys.argv[1:]
configuration = {
    "credentialPublicKeys": [],
    "servicePublicKeys": [],
    "authorityDestinations": [{
        "key": authority,
        "endpoint": "http://localhost:3001",
        "audience": authority,
        "finalPeer": "127.0.0.1",
    }],
    "registrationDestinations": [],
    "recipientServiceBindings": [],
    "managingServiceAudience": "did:web:interop-swan-managing-service",
    "credentialKeyPLC": {
        "origin": "http://reference-plc:2582",
        "laboratory": True,
        "allowlistedHost": "reference-plc",
    },
}
with open(path, "x", encoding="utf-8") as output:
    json.dump(configuration, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
os.chmod(path, 0o600)
PY

compose stop --timeout 10 swan

# Seed through the real HTTP/OAuth write path under the same persistent volume.
# This process intentionally omits --enable-notification-delivery so the
# committed event remains pending when SIGKILL simulates the crash boundary.
docker run --detach \
  --name "$seed_container" \
  --network "$network_name" \
  --network-alias swan \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
  --mount "type=volume,src=${runtime_secrets_volume},dst=/run/secrets/swan-runtime,readonly" \
  --mount "type=bind,src=${notification_config_path},dst=/tmp/notification-config.json,readonly" \
  "$swan_image" \
  serve \
  --host 0.0.0.0 \
  --port 3000 \
  --public-url https://swan.test \
  --profile /usr/local/share/swan/Profiles/permissioned-data-0016-2026-07-30.json \
  --data-directory /var/lib/swan/data \
  --enable-local-space-interop \
  --space-account-kek-file /run/secrets/swan-runtime/account-kek \
  --space-account-kek-id primary \
  --enable-public-repository-mutations \
  --public-account-kek-file /run/secrets/swan-runtime/account-kek \
  --public-account-kek-id primary \
  --oauth-server-key-file /run/secrets/swan-runtime/oauth-server-key \
  --enable-oauth-authorization-server \
  --oauth-allow-localhost-development-client \
  --notification-config /tmp/notification-config.json \
  --managing-service-audience did:web:interop-swan-managing-service \
  >/dev/null

wait_for_swan_http "$seed_container" "delivery-disabled seed Swan"

# The runner generates its private record value inside tmpfs, verifies that the
# sanitized artifact does not retain it, and exits without copying either file
# to the host.
docker run --rm \
  --network "$network_name" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --entrypoint /bin/sh \
  "$swan_image" \
  -ec '
    secrets=/run/secrets/swan-bootstrap
    private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")"
    umask 077
    printf \
      '"'"'{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n'"'"' \
      "$1" "$2" "$3" "$4" "$private_value" \
      >/tmp/permissioned-record.json
    export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt
    export SWAN_LAB_PRODUCER_HANDLE="$5"
    export SWAN_LAB_CONSUMER_HANDLE="$6"
    SWAN_LAB_PRODUCER_PASSWORD="$(tr -d "\r\n" < "${secrets}/member.password")"
    SWAN_LAB_CONSUMER_PASSWORD="$(tr -d "\r\n" < "${secrets}/authority.password")"
    export SWAN_LAB_PRODUCER_PASSWORD SWAN_LAB_CONSUMER_PASSWORD
    # The resource server deliberately distinguishes the management scope from
    # the space-scoped read/create grants. Encode the same qualified scopes in
    # the localhost client metadata so the lab exercises the real authorization
    # path instead of relying on a broad implicit grant.
    authority_did="${1#at://}"
    authority_did="${authority_did%%/space/*}"
    read_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${4}&action=read"
    create_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${4}&action=create&collection=${3}"
    client_id="http://localhost?scope=atproto%20space%3Aapp.bsky.bookmarks%3Fauthority%3D${authority_did}%26skey%3D${4}%26action%3Dread%20space%3Aapp.bsky.bookmarks%3Fauthority%3D${authority_did}%26skey%3D${4}%26action%3Dcreate%26collection%3D${3}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback"
    if ! /usr/local/bin/swan lab live \
      --mode permissioned \
      --name notification-restart-seed \
      --producer-url https://swan.test \
      --consumer-url https://swan.test \
      --producer-auth oauth \
      --consumer-auth oauth \
      --producer-client-id "$client_id" \
      --producer-redirect-uri http://127.0.0.1/callback \
      --consumer-client-id "$client_id" \
      --consumer-redirect-uri http://127.0.0.1/callback \
      --scope atproto \
      --scope "$read_scope" \
      --scope "$create_scope" \
      --space "$1" \
      --provision-space \
      --body-file /tmp/permissioned-record.json \
      --read-query \
        "space=$1" \
        "repo=$2" \
        "collection=$3" \
        "rkey=$4" \
      --output /tmp/sanitized-artifact.json \
      >/tmp/live-interop.log 2>&1
    then
      # Keep OAuth/HTTP diagnostics bounded and local to the disposable
      # tmpfs.  Never stream the full trace, which could contain request
      # metadata from a future scenario.
      tail -n 40 /tmp/live-interop.log >&2 || true
      exit 1
    fi
    if grep -F -- "$private_value" /tmp/sanitized-artifact.json >/dev/null; then
      echo "sanitized live artifact retained a permissioned value" >&2
      exit 1
    fi
    if ! grep -q '"'"'"status":"passed"'"'"' /tmp/sanitized-artifact.json; then
      tail -n 40 /tmp/live-interop.log >&2 || true
      exit 1
    fi
    unset private_value SWAN_LAB_PRODUCER_PASSWORD SWAN_LAB_CONSUMER_PASSWORD
  ' _ \
  "$space_uri" "$member_did" "$collection" "$rkey" \
  "$member_handle" "$authority_handle"

# Run only read-only, value-free assertions through the already-pinned
# reference image's SQLite module. The helper emits the stable event ID for
# internal correlation but never reads or prints a permissioned record table.
database_assertion() {
  docker run --rm \
    --network none \
    --user 0:0 \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=volume,src=${data_volume},dst=/var/lib/swan,readonly" \
    "$reference_image" \
    node -e '
      const crypto = require("node:crypto");
      const path = require("node:path");
      const Database = require("better-sqlite3");
      const [mode, authority, member, space, expectedEvent] = process.argv.slice(1);
      const databasePath = (did) => {
        const digest = crypto.createHash("sha256").update(did, "utf8").digest("hex");
        return path.join("/var/lib/swan/data/actors", digest.slice(0, 2), `${digest}.sqlite`);
      };
      const open = (did) => new Database(databasePath(did), {
        readonly: true,
        fileMustExist: true,
      });
      const fail = (message) => {
        process.stderr.write(`${message}\n`);
        process.exit(1);
      };
      const memberDatabase = open(member);
      if (mode === "pending") {
        const rows = memberDatabase.prepare(`
          SELECT id, attempts, lease_token, CAST(payload AS TEXT) AS opaque_payload
          FROM permissioned_space_outbox
          WHERE space_uri = ? AND author_did = ?
        `).all(space, member);
        if (
          rows.length !== 1 ||
          rows[0].attempts !== 0 ||
          rows[0].lease_token !== null ||
          rows[0].opaque_payload !== rows[0].id.toLowerCase()
        ) {
          fail("committed pending notification invariant failed");
        }
        process.stdout.write(rows[0].id);
        process.exit(0);
      }
      if (mode !== "delivered" || !expectedEvent) {
        fail("notification database assertion mode is invalid");
      }
      const remaining = memberDatabase.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_space_outbox
        WHERE space_uri = ? AND author_did = ?
      `).get(space, member).count;
      const authorityDatabase = open(authority);
      const receipts = authorityDatabase.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_space_notification_receipts
        WHERE issuer = ? AND event_id = ? AND space_uri = ?
      `).get(member, expectedEvent, space).count;
      const totalReceipts = authorityDatabase.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_space_notification_receipts
        WHERE issuer = ? AND space_uri = ?
      `).get(member, space).count;
      const writerEffects = authorityDatabase.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_space_writers
        WHERE space_uri = ? AND repo_did = ?
      `).get(space, member).count;
      if (
        remaining !== 0 ||
        receipts !== 1 ||
        totalReceipts !== 1 ||
        writerEffects !== 1
      ) {
        fail("notification convergence invariant failed");
      }
      process.stdout.write("ok");
    ' \
    "$1" "$authority_did" "$member_did" "$space_uri" "${2:-}"
}

event_id="$(database_assertion pending)"
[[ "$event_id" =~ ^[0-9A-Fa-f-]{36}$ ]] || {
  echo "pending notification did not have a stable event identifier" >&2
  exit 1
}

docker kill --signal KILL "$seed_container" >/dev/null
wait_for_stopped_container "$seed_container" "delivery-disabled seed Swan"
post_crash_event_id="$(database_assertion pending)"
[[ "$post_crash_event_id" == "$event_id" ]] || {
  echo "the committed pending notification did not survive the Swan crash" >&2
  exit 1
}
docker rm "$seed_container" >/dev/null

# Start and wait for the loopback proxy before the recovery-enabled process is
# allowed to inspect the pending outbox. The proxy owns the network namespace
# and the recovery process joins it, so localhost:3001 is already accepting
# connections before notification delivery starts. The proxy forwards only
# notifyWrite, drops the first 2xx acknowledgement after the authority commits,
# and persists counts and body digests only.
proxy_id="$(
  docker run --detach \
    --name "$proxy_container" \
    --network "$network_name" \
    --network-alias swan \
    --user 0:0 \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=bind,src=${temporary_directory},dst=/state" \
    "$reference_image" \
    node -e '
      const crypto = require("node:crypto");
      const fs = require("node:fs");
      const http = require("node:http");
      const state = {
        successfulForwards: 0,
        uniqueRequestDigests: 0,
        droppedAcknowledgements: 0,
        returnedAcknowledgements: 0,
        unexpectedRequests: 0,
        upstreamStatuses: [],
        upstreamErrors: 0,
      };
      const digests = new Set();
      const persist = () => {
        state.uniqueRequestDigests = digests.size;
        const temporary = "/state/result.json.tmp";
        fs.writeFileSync(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600 });
        fs.renameSync(temporary, "/state/result.json");
      };
      const reject = (response, status) => {
        response.writeHead(status, { "cache-control": "no-store" });
        response.end();
      };
      const server = http.createServer((request, response) => {
        if (
          request.method !== "POST" ||
          request.url !== "/xrpc/com.atproto.space.notifyWrite" ||
          state.successfulForwards >= 2
        ) {
          state.unexpectedRequests += 1;
          persist();
          reject(response, 503);
          return;
        }
        const chunks = [];
        let length = 0;
        request.on("data", (chunk) => {
          length += chunk.length;
          if (length > 1_048_576) {
            request.destroy();
            return;
          }
          chunks.push(chunk);
        });
        request.on("end", () => {
          if (length > 1_048_576) {
            state.unexpectedRequests += 1;
            persist();
            reject(response, 413);
            return;
          }
          const body = Buffer.concat(chunks);
          const upstream = http.request({
            hostname: "127.0.0.1",
            port: 3000,
            path: request.url,
            method: "POST",
            headers: { ...request.headers, host: "localhost:3000" },
          }, (upstreamResponse) => {
            upstreamResponse.resume();
            upstreamResponse.on("end", () => {
              state.upstreamStatuses.push(upstreamResponse.statusCode || 0);
              persist();
              if (
                upstreamResponse.statusCode < 200 ||
                upstreamResponse.statusCode > 299
              ) {
                reject(response, upstreamResponse.statusCode || 502);
                return;
              }
              digests.add(crypto.createHash("sha256").update(body).digest("hex"));
              state.successfulForwards += 1;
              if (state.successfulForwards === 1) {
                state.droppedAcknowledgements += 1;
                persist();
                response.destroy();
                return;
              }
              state.returnedAcknowledgements += 1;
              persist();
              response.writeHead(200, { "cache-control": "no-store" });
              response.end();
            });
          });
          upstream.on("error", () => {
            state.upstreamErrors += 1;
            persist();
            reject(response, 503);
          });
          upstream.end(body);
        });
      });
      server.listen(3001, "127.0.0.1", () => {
        fs.writeFileSync("/state/ready", "", { mode: 0o600 });
      });
    '
)"

deadline=$((SECONDS + wait_timeout))
until [[ -f "$temporary_directory/ready" ]]; do
  proxy_status="$(
    docker inspect --format '{{.State.Status}}' "$proxy_id" 2>/dev/null || true
  )"
  if [[ "$proxy_status" == "exited" || "$proxy_status" == "dead" ]]; then
    echo "the loopback acknowledgement-loss proxy exited before becoming ready" >&2
    exit 1
  fi
  if ((SECONDS >= deadline)); then
    echo "the loopback acknowledgement-loss proxy did not become ready" >&2
    exit 1
  fi
  sleep 1
done

recovery_id="$(
  docker run --detach \
    --name "$recovery_container" \
    --network "container:${proxy_id}" \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
    --mount "type=volume,src=${runtime_secrets_volume},dst=/run/secrets/swan-runtime,readonly" \
    --mount "type=bind,src=${notification_config_path},dst=/tmp/notification-config.json,readonly" \
    "$swan_image" \
    serve \
    --host 0.0.0.0 \
    --port 3000 \
    --public-url https://swan.test \
    --profile /usr/local/share/swan/Profiles/permissioned-data-0016-2026-07-30.json \
    --data-directory /var/lib/swan/data \
    --enable-local-space-interop \
    --space-account-kek-file /run/secrets/swan-runtime/account-kek \
    --space-account-kek-id primary \
    --enable-public-repository-mutations \
    --public-account-kek-file /run/secrets/swan-runtime/account-kek \
    --public-account-kek-id primary \
    --oauth-server-key-file /run/secrets/swan-runtime/oauth-server-key \
    --enable-oauth-authorization-server \
    --oauth-allow-localhost-development-client \
    --notification-config /tmp/notification-config.json \
    --enable-notification-delivery \
    --managing-service-audience did:web:interop-swan-managing-service
)"
wait_for_swan_http "$recovery_container" "recovery-enabled Swan"

proxy_converged() {
  python3 - "$temporary_directory/result.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(1)
state = json.loads(path.read_text(encoding="utf-8"))
expected = {
    "successfulForwards": 2,
    "uniqueRequestDigests": 1,
    "droppedAcknowledgements": 1,
    "returnedAcknowledgements": 1,
    "unexpectedRequests": 0,
    "upstreamStatuses": [200, 200],
    "upstreamErrors": 0,
}
raise SystemExit(0 if state == expected else 1)
PY
}

deadline=$((SECONDS + wait_timeout))
until proxy_converged; do
  recovery_status="$(
    docker inspect --format '{{.State.Status}}' "$recovery_id" 2>/dev/null || true
  )"
  proxy_status="$(
    docker inspect --format '{{.State.Status}}' "$proxy_id" 2>/dev/null || true
  )"
  if [[ "$recovery_status" != "running" || "$proxy_status" != "running" ]]; then
    echo "notification recovery stopped before transport convergence" >&2
    exit 1
  fi
  if ((SECONDS >= deadline)); then
    if [[ -f "$temporary_directory/result.json" ]]; then
      echo "notification proxy diagnostics:" >&2
      python3 -m json.tool "$temporary_directory/result.json" >&2 || true
    fi
    echo "notification delivery did not converge after the Swan restart" >&2
    exit 1
  fi
  sleep 1
done
database_converged() {
  local result=""
  result="$(database_assertion delivered "$event_id" 2>/dev/null || true)"
  [[ "$result" == "ok" ]]
}
deadline=$((SECONDS + wait_timeout))
until database_converged; do
  if ((SECONDS >= deadline)); then
    echo "notification database convergence was not observed" >&2
    exit 1
  fi
  sleep 1
done
proxy_converged || {
  echo "notification transport counts changed after database convergence" >&2
  exit 1
}

# Stop the recovery process before removing the network namespace that it
# shares with the proxy. The normal Compose Swan service is then started with
# the already-empty outbox and without the proxy.
docker stop --time 10 "$recovery_id" >/dev/null
wait_for_stopped_container "$recovery_id" "recovery-enabled Swan"
docker rm "$recovery_id" >/dev/null
recovery_id=""
docker rm --force "$proxy_id" >/dev/null
proxy_id=""

# Starting the normal Compose service proves that its enabled recovery worker
# observes the acknowledged empty outbox and single durable receiver effect
# even with the loopback proxy gone.
compose start swan
wait_for_healthy_container "$normal_swan_id" "final normal Swan restart"
[[ "$(database_assertion delivered "$event_id")" == "ok" ]] || {
  echo "notification convergence did not remain durable across restart" >&2
  exit 1
}

echo "NOTIFICATION RESTART OUTBOX CONVERGENCE OK: successful_forwards=2 receiver_effects=1"
