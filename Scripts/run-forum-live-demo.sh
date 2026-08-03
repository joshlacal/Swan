#!/usr/bin/env bash
set -euo pipefail

# Live, disposable Compose acceptance for the `swan lab forum` test vehicle.
# The scenario provisions a forum space on the Swan authority, adds two
# members (Carol on Swan, Bob on the pinned TypeScript reference PDS), posts
# roots and cross-host replies from three writer identities across the two
# hosts, then runs the syncer (`forum thread`) as Carol: one delegation
# token, one space credential, writer-set discovery via listRepos, per-writer
# repo sync with per-writer commit verification keys, and one merged thread.
#
# The stock reference image cannot complete TLS to the authority and its
# value-bearing listRepoOps/getRepo endpoints are unavailable, so the scenario
# deliberately uses the checksum-pinned recovery overlay for reference-pds
# plus an ephemeral TLS-trust override, and restores the stock image and the
# normal Compose topology on every exit path.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

project_name="${SWAN_FORUM_PROJECT:-swan-alpha-current-20260801}"
output_path="${SWAN_FORUM_OUTPUT:-${root}/artifacts/forum/live-demo.json}"
wait_timeout="${SWAN_FORUM_TIMEOUT:-300}"
skip_build="${SWAN_FORUM_NO_BUILD:-0}"
recovery_mode="${SWAN_FORUM_RECOVERY:-1}"
[[ "$project_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || {
  echo "SWAN_FORUM_PROJECT must name the running disposable Compose project" >&2
  exit 64
}
[[ "$output_path" = /* ]] || {
  echo "SWAN_FORUM_OUTPUT must be absolute" >&2
  exit 64
}
case "$skip_build" in 0|1) ;; *) exit 64 ;; esac
case "$recovery_mode" in 0|1) ;; *) exit 64 ;; esac
[[ "$wait_timeout" =~ ^[1-9][0-9]*$ ]] && ((wait_timeout <= 600)) || {
  echo "SWAN_FORUM_TIMEOUT must be an integer from 1 through 600" >&2
  exit 64
}
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

compose() {
  ./interop/compose.sh --project-name "$project_name" "$@"
}

container_id() {
  local service="$1"
  compose ps --all -q "$service" | awk '/^[0-9a-f]{64}$/ { print; exit }'
}

mount_name() {
  local container="$1"
  local destination="$2"
  docker inspect \
    --format '{{range .Mounts}}{{if eq .Destination "'"$destination"'"}}{{.Name}}{{end}}{{end}}' \
    "$container"
}

wait_for_container() {
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
      echo "$label exited before becoming healthy" >&2
      exit 1
    fi
    sleep 1
  done
  echo "$label did not become healthy before the bounded timeout" >&2
  exit 1
}

wait_for_swan_http() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  while ((SECONDS < deadline)); do
    if docker exec "$container" \
      curl --fail --silent --show-error --max-time 2 \
        http://127.0.0.1:3000/health >/dev/null 2>&1
    then
      return 0
    fi
    if [[ "$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)" =~ ^(exited|dead)$ ]]; then
      echo "$label exited before exposing its HTTP listener" >&2
      exit 1
    fi
    sleep 1
  done
  echo "$label did not expose a healthy HTTP listener before the bounded timeout" >&2
  exit 1
}

wait_for_swan_tls_route() {
  local label="$1"
  local deadline=$((SECONDS + wait_timeout))
  while ((SECONDS < deadline)); do
    if docker run --rm \
      --network "$network_name" \
      --user 999:999 \
      --read-only \
      --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
      curlimages/curl:8.13.0@sha256:d43bdb28bae0be0998f3be83199bfb2b81e0a30b034b6d7586ce7e05de34c3fd \
      --fail --silent --show-error --max-time 2 \
      --cacert /etc/ssl/certs/caddy-local-root.crt \
      https://swan.test/health >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  echo "$label did not become reachable through Caddy TLS" >&2
  exit 1
}

wait_for_reference_health() {
  local deadline=$((SECONDS + wait_timeout))
  while ((SECONDS < deadline)); do
    local state
    state="$(
      docker inspect \
        --format '{{if .State.Running}}running{{else}}{{.State.Status}}{{end}}' \
        "$reference_pds_id" 2>/dev/null || true
    )"
    if [[ "$state" == "running" ]]; then
      if docker exec "$reference_pds_id" \
        node -e 'fetch("http://127.0.0.1:3000/xrpc/_health").then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))' \
        >/dev/null 2>&1
      then
        return 0
      fi
    elif [[ "$state" =~ ^(exited|dead)$ ]]; then
      echo "reference PDS exited before becoming healthy" >&2
      docker logs --tail 20 "$reference_pds_id" >&2 || true
      exit 1
    fi
    sleep 2
  done
  docker logs --tail 20 "$reference_pds_id" >&2 || true
  echo "reference PDS did not become healthy before the bounded timeout" >&2
  exit 1
}

json_field() {
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

read_lab_value() {
  local name="$1"
  tr -d '\r\n' < "${SWAN_INTEROP_SECRETS_DIR}/${name}"
}

normal_swan_id="$(container_id swan)"
reference_pds_id="$(container_id reference-pds)"
caddy_id="$(container_id caddy)"
caddy_trust_id="$(container_id caddy-ca-ready)"
bootstrap_id="$(container_id swan-bootstrap)"
for required_id in "$normal_swan_id" "$reference_pds_id" "$caddy_id" "$caddy_trust_id" "$bootstrap_id"; do
  [[ -n "$required_id" ]] || {
    echo "the Compose project is missing a required service" >&2
    exit 1
  }
done
wait_for_container "$normal_swan_id" "Swan"
wait_for_container "$reference_pds_id" "reference PDS"
wait_for_container "$caddy_id" "Caddy"

data_volume="$(mount_name "$normal_swan_id" /var/lib/swan)"
runtime_secrets_volume="$(mount_name "$normal_swan_id" /run/secrets/swan-runtime)"
bootstrap_secrets_volume="$(mount_name "$bootstrap_id" /run/secrets/swan-bootstrap)"
caddy_trust_volume="$(mount_name "$caddy_trust_id" /prepared-trust)"
network_name="$(
  docker inspect \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s" $name}}{{end}}' \
    "$normal_swan_id"
)"
swan_ip="$(
  docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$normal_swan_id"
)"
caddy_ip="$(
  docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$caddy_id"
)"
for required_value in \
  "$data_volume" "$runtime_secrets_volume" "$bootstrap_secrets_volume" \
  "$caddy_trust_volume" "$network_name" "$swan_ip" "$caddy_ip"
do
  [[ -n "$required_value" ]] || {
    echo "the Compose project has an incomplete runtime boundary" >&2
    exit 1
  }
done

temporary_root="${root}/.interop-live"
mkdir -p "$temporary_root"
chmod 700 "$temporary_root"
temporary_directory="$(mktemp -d "${temporary_root}/forum-live-demo.XXXXXX")"

forum_config_path="${temporary_directory}/notification-config.json"
tls_override_path="${temporary_directory}/tls-override.yml"
thread_artifact_path="${temporary_directory}/thread.json"
dynamic_container="${project_name}-forum-dynamic-swan"
normal_stopped=0
recovery_deployed=0

cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  docker rm --force "$dynamic_container" >/dev/null 2>&1 || true
  if ((normal_stopped)); then
    docker start "$normal_swan_id" >/dev/null 2>&1 || true
    wait_for_container "$normal_swan_id" "Swan" || true
  fi
  if ((recovery_deployed)); then
    compose build reference-pds >/dev/null 2>&1 || true
    compose up -d reference-pds >/dev/null 2>&1 || true
    reference_pds_id="$(container_id reference-pds)"
    wait_for_reference_health || true
  fi
  docker volume rm "$caddy_cert_volume" >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [[ "$skip_build" != "1" ]]; then
  compose build swan
fi
swan_image="$(docker image inspect --format '{{.Id}}' "${project_name}-swan:latest")" || {
  echo "the project-scoped Swan image is unavailable" >&2
  exit 1
}

# The pinned reference PDS cannot complete TLS to the authority (its node
# user cannot read the mode-0700 trust volume) and its value-bearing
# permissioned sync endpoints are unavailable. Deploy the checksum-pinned
# recovery overlay and an ephemeral TLS-trust override backed by a
# world-readable cert copy volume; the stock image is rebuilt and restored on
# cleanup.
caddy_cert_volume="swan-forum-caddy-trust-copy"
docker volume create "$caddy_cert_volume" >/dev/null
docker run --rm \
  -v "${caddy_trust_volume}":/prepared-trust:ro \
  -v "${caddy_cert_volume}":/data \
  alpine sh -c 'cp /prepared-trust/caddy-local-root.crt /data/ && chmod 644 /data/caddy-local-root.crt && chmod 755 /data'
if [[ "$recovery_mode" == "1" ]]; then
  cat > "$tls_override_path" <<EOF
services:
  reference-pds:
    build:
      dockerfile: Swan/interop/Dockerfile.reference-pds-recovery
    volumes:
      - caddy-trust:/etc/ssl/certs:ro
    environment:
      NODE_EXTRA_CA_CERTS: /etc/ssl/certs/caddy-local-root.crt
volumes:
  caddy-trust:
    name: ${caddy_cert_volume}
    external: true
EOF
  compose \
    --file "$root/docker-compose.yml" \
    --file "$root/interop/docker-compose.reference-recovery.yml" \
    --file "$tls_override_path" \
    build reference-pds
else
  cat > "$tls_override_path" <<EOF
services:
  reference-pds:
    volumes:
      - caddy-trust:/etc/ssl/certs:ro
    environment:
      NODE_EXTRA_CA_CERTS: /etc/ssl/certs/caddy-local-root.crt
volumes:
  caddy-trust:
    name: ${caddy_cert_volume}
    external: true
EOF
fi
compose \
  --file "$root/docker-compose.yml" \
  --file "$tls_override_path" \
  up -d reference-pds
recovery_deployed=1
reference_pds_id="$(container_id reference-pds)"
reference_image="$(docker inspect --format '{{.Image}}' "$reference_pds_id")"
wait_for_reference_health
wait_for_container "$reference_pds_id" "reference PDS"

# Fresh TypeScript member account (Bob) through the reference PDS admin path.
suffix="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
reference_handle="forum-${suffix}.pds.test"
reference_email="forum-${suffix}@example.com"
reference_password="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
export SWAN_REFERENCE_HANDLE="$reference_handle"
export SWAN_REFERENCE_EMAIL="$reference_email"
export SWAN_REFERENCE_PASSWORD="$reference_password"
reference_account="$({
  docker exec \
    --env SWAN_REFERENCE_HANDLE \
    --env SWAN_REFERENCE_EMAIL \
    --env SWAN_REFERENCE_PASSWORD \
    "$reference_pds_id" \
    node -e '
const fs = require("node:fs")

async function json(response, label) {
  const body = await response.json().catch(() => ({}))
  if (!response.ok) {
    const code = typeof body.error === "string" ? body.error : "UnknownError"
    const message = typeof body.message === "string"
      ? body.message.replace(/[^a-zA-Z0-9 ._:-]/g, "").slice(0, 160)
      : ""
    throw new Error(`${label}:${response.status}:${code}:${message}`)
  }
  return body
}

async function main() {
  const admin = fs.readFileSync(
    "/run/secrets/reference-pds/pds-admin-password",
    "utf8",
  ).trim()
  const authorization = `Basic ${Buffer.from(`admin:${admin}`).toString("base64")}`
  const invite = await json(await fetch(
    "http://127.0.0.1:3000/xrpc/com.atproto.server.createInviteCode",
    {
      method: "POST",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify({ useCount: 1 }),
    },
  ), "invite")
  const account = await json(await fetch(
    "http://127.0.0.1:3000/xrpc/com.atproto.server.createAccount",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        handle: process.env.SWAN_REFERENCE_HANDLE,
        email: process.env.SWAN_REFERENCE_EMAIL,
        password: process.env.SWAN_REFERENCE_PASSWORD,
        inviteCode: invite.code,
      }),
    },
  ), "account")
  process.stdout.write(JSON.stringify(account))
}

main().catch((error) => {
  process.stderr.write(`reference account provisioning failed: ${error.message}\n`)
  process.exit(1)
})
'
})" || exit 1
unset SWAN_REFERENCE_HANDLE SWAN_REFERENCE_EMAIL SWAN_REFERENCE_PASSWORD
bob_did="$(printf '%s' "$reference_account" | json_field did)" || exit 1
bob_token="$(printf '%s' "$reference_account" | json_field accessJwt)" || exit 1
export SWAN_LAB_PRODUCER_TOKEN="$bob_token"
unset reference_account reference_password reference_email

# Swan accounts: the space authority (Alice) and the second member (Carol).
authority_handle="$(read_lab_value authority.handle)"
authority_did="$({
  docker exec "$normal_swan_id" \
    /usr/local/bin/swan account show \
    --data-directory /var/lib/swan/data \
    --handle "$authority_handle"
})" || exit 1
authority_did="$(printf '%s' "$authority_did" | json_field did)" || exit 1
member_handle="$(read_lab_value member.handle)"
member_did="$({
  docker exec "$normal_swan_id" \
    /usr/local/bin/swan account show \
    --data-directory /var/lib/swan/data \
    --handle "$member_handle"
})" || exit 1
member_did="$(printf '%s' "$member_did" | json_field did)" || exit 1

# Resolve every writer's canonical repository signing key from the PLC audit.
resolve_commit_key() {
  local resolve_did="$1"
  docker exec \
    --env SWAN_RESOLVE_DID="$resolve_did" \
    "$reference_pds_id" \
    node -e '
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
function decode(value) {
  const bytes = Buffer.from(value, "utf8")
  let digits = [0]
  for (const byte of bytes) {
    const index = alphabet.indexOf(String.fromCharCode(byte))
    if (index < 0) throw new Error("invalid base58")
    let carry = index
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] * 58
      digits[i] = carry & 255
      carry >>= 8
    }
    while (carry > 0) {
      digits.push(carry & 255)
      carry >>= 8
    }
  }
  let leading = 0
  while (leading < bytes.length && bytes[leading] === 49) leading += 1
  return Buffer.concat([Buffer.alloc(leading), Buffer.from(digits.reverse())])
}
async function main() {
  const did = process.env.SWAN_RESOLVE_DID
  const response = await fetch(`http://reference-plc:2582/${did}/log/audit`)
  if (!response.ok) throw new Error(`PLC audit status ${response.status}`)
  const audit = await response.json()
  const encoded = audit.at(-1)?.operation?.verificationMethods?.atproto
  if (!Array.isArray(audit) || audit.length === 0 || typeof encoded !== "string" || !encoded.startsWith("did:key:z")) {
    throw new Error("PLC atproto key is not canonical did:key")
  }
  const decoded = decode(encoded.slice("did:key:z".length))
  const secp256k1 = decoded.length === 35 && decoded[0] === 0xe7 && decoded[1] === 0x01
  const p256 = decoded.length === 35 && decoded[0] === 0x80 && decoded[1] === 0x24
  if (!secp256k1 && !p256) {
    throw new Error("PLC atproto key is not a supported repository key")
  }
  process.stdout.write(`${encoded}\n`)
}
main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exit(1) })
'
}
authority_key="$(resolve_commit_key "$authority_did")" || exit 1
member_key="$(resolve_commit_key "$member_did")" || exit 1
bob_key="$(resolve_commit_key "$bob_did")" || exit 1

# Forum notification configuration: the dynamic authority accepts its own
# members' service auth (local accounts), self-notifies its own space, pins
# Bob's service key, and resolves Bob's delegation tokens through the
# allowlisted lab PLC.
python3 - "$forum_config_path" "$authority_did" "$bob_did" "$bob_key" <<'PY'
import base64
import json
import os
import sys

path, authority, bob, key = sys.argv[1:]

alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_decode(value):
    digits = [0]
    for char in value:
        index = alphabet.index(char)
        carry = index
        for i in range(len(digits)):
            carry += digits[i] * 58
            digits[i] = carry & 255
            carry >>= 8
        while carry:
            digits.append(carry & 255)
            carry >>= 8
    leading = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading + bytes(reversed(digits))

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

assert key.startswith("did:key:z")
decoded = base58_decode(key[len("did:key:z"):])
assert len(decoded) == 35, "unsupported did:key length"
if decoded[:2] == b"\xe7\x01":
    pin = {"secp256k1": b64url(decoded[2:])}
elif decoded[:2] == b"\x80\x24":
    pin = {"p256X963": b64url(decoded[2:])}
else:
    raise SystemExit("unsupported did:key multicodec")

configuration = {
    "credentialPublicKeys": [],
    "servicePublicKeys": [dict(pin, issuer=bob, generation=1)],
    "authorityDestinations": [{
        "key": authority,
        "endpoint": "http://localhost:3001",
        "audience": authority,
        "finalPeer": "127.0.0.1",
    }],
    "registrationDestinations": [],
    "recipientServiceBindings": [],
    "managingServiceAudience": "did:web:interop-swan-managing-service",
    "delegationKeyPLC": {
        "origin": "http://reference-plc:2582",
        "laboratory": True,
        "allowlistedHost": "reference-plc",
        "allowedIssuers": [bob],
    },
}
with open(path, "x", encoding="utf-8") as output:
    json.dump(configuration, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
os.chmod(path, 0o600)
PY

docker stop --time 10 "$normal_swan_id" >/dev/null
normal_stopped=1

docker run --detach \
  --name "$dynamic_container" \
  --network "$network_name" \
  --ip "$swan_ip" \
  --network-alias swan \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
  --mount "type=volume,src=${runtime_secrets_volume},dst=/run/secrets/swan-runtime,readonly" \
  --mount "type=bind,src=${forum_config_path},dst=/tmp/notification-config.json,readonly" \
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
  --login-trusted-proxy-peer "$caddy_ip" \
  --notification-config /tmp/notification-config.json \
  --managing-service-audience did:web:interop-swan-managing-service \
  >/dev/null
wait_for_swan_http "$dynamic_container" "forum Swan"
wait_for_swan_tls_route "forum Swan"

space_key="forum-demo-${suffix}"
space_uri="at://${authority_did}/space/blue.catbird.lab.forum/${space_key}"
read_scope="space:blue.catbird.lab.forum?authority=${authority_did}&skey=${space_key}&action=read"
create_scope="space:blue.catbird.lab.forum?authority=${authority_did}&skey=${space_key}&action=create&collection=blue.catbird.lab.post"
scope_client_id="$(python3 - "$read_scope" "$create_scope" <<'PY'
import sys
from urllib.parse import quote

print("http://localhost?scope=" + quote("atproto " + sys.argv[1] + " " + sys.argv[2], safe="") +
      "&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")
PY
)"

# One-shot forum command runner. OAuth credentials are read inside the
# container from the owner-only bootstrap secrets volume and never appear in
# process arguments. Producer/consumer roles select the credential set.
# `producer-account` is member or authority; `consumer-account` is member.
run_lab() {
  local subcommand="$1"
  shift
  local producer_account="${SWAN_FORUM_PRODUCER:-member}"
  local consumer_account="${SWAN_FORUM_CONSUMER:-member}"
  local command_line=()
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --producer-account) producer_account="$2"; shift 2 ;;
      --consumer-account) consumer_account="$2"; shift 2 ;;
      *) command_line+=("$1"); shift ;;
    esac
  done
  local producer_secret="member"
  if [[ "$producer_account" == "authority" ]]; then
    producer_secret="authority"
  fi
  local consumer_secret="member"
  if [[ "$consumer_account" == "authority" ]]; then
    consumer_secret="authority"
  fi
  docker run --rm \
    --network "$network_name" \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
    --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
    --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
    --mount "type=bind,src=${temporary_directory},dst=/run/forum" \
    --env SWAN_LAB_CA_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt \
    --env SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt \
    --env SWAN_LAB_PRODUCER_TOKEN \
    --env SWAN_LAB_COMMIT_KEY_ALICE="$authority_key" \
    --env SWAN_LAB_COMMIT_KEY_CAROL="$member_key" \
    --env SWAN_LAB_COMMIT_KEY_BOB="$bob_key" \
    --entrypoint /bin/sh \
    "$swan_image" \
    -ec '
      umask 077
      subcommand="$1"
      producer="$2"
      consumer="$3"
      shift 3
      SWAN_LAB_AUTHORITY_HANDLE="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/authority.handle)"
      SWAN_LAB_AUTHORITY_PASSWORD="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/authority.password)"
      SWAN_LAB_PRODUCER_HANDLE="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/${producer}.handle)"
      SWAN_LAB_PRODUCER_PASSWORD="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/${producer}.password)"
      SWAN_LAB_CONSUMER_HANDLE="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/${consumer}.handle)"
      SWAN_LAB_CONSUMER_PASSWORD="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/${consumer}.password)"
      export SWAN_LAB_AUTHORITY_HANDLE SWAN_LAB_AUTHORITY_PASSWORD
      export SWAN_LAB_PRODUCER_HANDLE SWAN_LAB_PRODUCER_PASSWORD
      export SWAN_LAB_CONSUMER_HANDLE SWAN_LAB_CONSUMER_PASSWORD
      exec /usr/local/bin/swan lab "$subcommand" "$@"
    ' _ "$subcommand" "$producer_secret" "$consumer_secret" "${command_line[@]}"
}

run_forum() {
  run_lab forum "$@"
}

forum_provision() {
  local member="$1"
  run_forum \
    provision \
    --authority-url https://swan.test \
    --space "$space_uri" \
    --member-did "$member" \
    --authority-auth oauth \
    --authority-client-id "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback" \
    --authority-redirect-uri http://127.0.0.1/callback \
    --request-timeout-seconds 20
}

forum_post() {
  local producer_url="$1"
  local auth="$2"
  local text="$3"
  local reply_to="${4:-}"
  local label="$5"
  local producer_account="${6:-member}"
  local repo_args=()
  if [[ "$producer_url" == "https://pds.test" ]]; then
    repo_args=(--repo "$bob_did")
  fi
  local reply_args=()
  if [[ -n "$reply_to" ]]; then
    reply_args=(--reply-to "$reply_to")
  fi
  local output_file="${temporary_directory}/post-${label}.json"
  # shellcheck disable=SC2086
  local result
  result="$(run_forum \
    --producer-account "$producer_account" \
    post \
    --producer-url "$producer_url" \
    --space "$space_uri" \
    --text "$text" \
    --producer-auth "$auth" \
    --producer-client-id "$scope_client_id" \
    --producer-redirect-uri http://127.0.0.1/callback \
    --request-timeout-seconds 20 \
    --output "/run/forum/post-${label}.json" \
    ${repo_args[@]+"${repo_args[@]}"} ${reply_args[@]+"${reply_args[@]}"})" || true
  if [[ -f "$output_file" ]]; then
    if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("status")=="passed" else 1)' "$output_file"; then
      printf '%s\n' "$result"
      return 0
    fi
    echo "forum post failed; artifact:" >&2
    cat "$output_file" >&2
    echo "forum dynamic swan logs:" >&2
    docker logs --tail 40 "$dynamic_container" >&2 2>&1 || true
    echo "forum granted OAuth scopes for the member account:" >&2
    docker run --rm \
      --network none \
      --user 0:0 \
      --read-only \
      --tmpfs /tmp:size=16m,mode=1777 \
      --mount "type=volume,src=${data_volume},dst=/var/lib/swan,readonly" \
      "$reference_image" \
      node -e '
        const Database = require("better-sqlite3");
        const [did] = process.argv.slice(1);
        const database = new Database("/var/lib/swan/data/control.sqlite", {
          readonly: true,
          fileMustExist: true,
        });
        const rows = database.prepare(`
          SELECT client_id, CAST(scopes AS TEXT) AS scopes, revoked_at, expires_at
          FROM oauth_control_token_families
          WHERE subject = ?
        `).all(did);
        for (const row of rows) process.stdout.write(JSON.stringify(row) + "\n");
      ' "$member_did" >&2 || true
    printf '%s\n' "$result" >&2
    return 1
  fi
  printf '%s\n' "$result"
  return 1
}

echo "FORUM: provisioning space $space_uri"
forum_provision "$bob_did"
forum_provision "$member_did"

if [[ "${SWAN_FORUM_DEBUG_LAB_LIVE:-0}" == "1" ]]; then
  echo "FORUM DEBUG: lab live createRecord against the forum space"
  python3 - "$space_uri" "$member_did" "${temporary_directory}/debug-body.json" <<'PY'
import json
import sys

space, member, output = sys.argv[1:]
body = {
    "space": space,
    "repo": member,
    "collection": "blue.catbird.lab.post",
    "rkey": "debug-0001",
    "record": {"$type": "blue.catbird.lab.post", "text": "debug lab-live write", "createdAt": "2026-08-04T00:00:00Z"},
}
with open(output, "x", encoding="utf-8") as handle:
    json.dump(body, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
  run_lab \
    live \
    --mode permissioned \
    --name forum-debug-lab-live \
    --producer-url https://swan.test \
    --consumer-url https://swan.test \
    --producer-auth oauth \
    --producer-client-id "$scope_client_id" \
    --producer-redirect-uri http://127.0.0.1/callback \
    --consumer-auth oauth \
    --consumer-client-id "$scope_client_id" \
    --consumer-redirect-uri http://127.0.0.1/callback \
    --scope atproto \
    --scope "$read_scope" \
    --scope "$create_scope" \
    --space "$space_uri" \
    --permissioned-read-host authority \
    --read-query "space=$space_uri" "repo=$member_did" "collection=blue.catbird.lab.post" "rkey=debug-0001" \
    --body-file /run/forum/debug-body.json \
    --request-timeout-seconds 30 || true
fi

echo "FORUM: Carol posts a root"
forum_post "https://swan.test" oauth "Hello from Carol! First post in the live forum demo." "" carol-root
carol_root_uri="$({
  python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); print(a.get("uri") or "")' \
    "${temporary_directory}/post-carol-root.json"
})"
[[ -n "$carol_root_uri" ]] || {
  echo "Carol root post produced no URI" >&2
  exit 1
}

echo "FORUM: Carol replies to her root"
forum_post "https://swan.test" oauth "Carol replying to her own root." "$carol_root_uri" carol-reply

echo "FORUM: Alice posts from the authority account"
forum_post "https://swan.test" oauth "Welcome, everyone — Alice here, forum owner." "" alice-root authority

echo "FORUM: Bob posts from the pinned TypeScript PDS"
forum_post "https://pds.test" bearer "Bob checking in from the pinned TypeScript PDS!" "" bob-root
bob_root_uri="$({
  python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); print(a.get("uri") or "")' \
    "${temporary_directory}/post-bob-root.json"
})"
[[ -n "$bob_root_uri" ]] || {
  echo "Bob root post produced no URI" >&2
  exit 1
}

echo "FORUM: Carol replies to Bob across hosts"
forum_post "https://swan.test" oauth "Cross-host reply from Carol to Bob's TypeScript post." "$bob_root_uri" carol-cross

echo "FORUM: syncer runs as Carol"
run_forum \
  thread \
  --consumer-url https://swan.test \
  --authority-url https://swan.test \
  --space "$space_uri" \
  --receiver-did "$member_did" \
  --data-directory /var/lib/swan/data \
  --consumer-auth oauth \
  --consumer-client-id "$scope_client_id" \
  --consumer-redirect-uri http://127.0.0.1/callback \
  --plc-origin http://reference-plc:2582 \
  --plc-laboratory \
  --plc-laboratory-allowlisted-host reference-plc \
  --writer-host "$authority_did=https://swan.test:${authority_key}" \
  --writer-host "$member_did=https://swan.test:${member_key}" \
  --writer-host "$bob_did=https://pds.test:${bob_key}" \
  --request-timeout-seconds 30 \
  --output /run/forum/thread.json

if [[ ! -f "$thread_artifact_path" ]]; then
  echo "thread artifact was not produced" >&2
  exit 1
fi

python3 - "$thread_artifact_path" "$authority_did" "$member_did" "$bob_did" <<'PY'
import json
import os
import sys

path, alice, carol, bob = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    artifact = json.load(handle)
writers = artifact.get("writers")
thread = artifact.get("thread")
if not isinstance(writers, list) or not isinstance(thread, dict):
    raise SystemExit("thread artifact is missing writers or thread structure")
dids = {writer.get("did") for writer in writers}
for did, label in ((alice, "alice"), (carol, "carol"), (bob, "bob")):
    if did not in dids:
        raise SystemExit(f"thread artifact is missing writer {label}")
failed = [w for w in writers if w.get("outcome") not in (
    "applied", "exact_duplicate", "unchanged", "full_car_applied"
)]
if failed:
    raise SystemExit(f"thread has failed writers: {failed}")
nodes = artifact.get("thread")
if not isinstance(nodes, list) or not nodes:
    raise SystemExit("thread artifact has no thread nodes")
if artifact.get("postCount", 0) + artifact.get("unlinkedCount", 0) != len(nodes):
    raise SystemExit("thread artifact node counts do not match")
os.chmod(path, 0o600)
print("FORUM THREAD VALIDATED: writers=%d posts=%d replies=%d unlinked=%d status=%s" % (
    len(writers),
    artifact.get("postCount", 0),
    artifact.get("replyCount", 0),
    artifact.get("unlinkedCount", 0),
    artifact.get("status"),
))
PY

install -m 0600 "$thread_artifact_path" "$output_path"
echo "FORUM LIVE DEMO ARTIFACT WRITTEN: $output_path"
