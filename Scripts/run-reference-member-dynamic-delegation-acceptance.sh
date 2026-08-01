#!/usr/bin/env bash
set -euo pipefail

# Exercise the pinned TypeScript PDS as a permissioned repository host while
# Swan is the authority.  The reference member's delegation key is discovered
# from the laboratory PLC through Swan's bounded, issuer-allowlisted resolver;
# no static public-key pin is supplied to the authority.
#
# This harness attaches to an already-running disposable Compose project.  It
# creates one disposable reference-PDS account, temporarily replaces only that
# project's Swan service, runs the credential/write/read path, then restores
# the normal Compose-managed Swan service.  Tokens, passwords, DPoP material,
# record values, and the generated resolver configuration remain outside the
# output artifact.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

project_name="${SWAN_DYNAMIC_DELEGATION_PROJECT:-}"
output_path="${SWAN_DYNAMIC_DELEGATION_OUTPUT:-${root}/artifacts/live/reference-member-dynamic-delegation.json}"
wait_timeout="${SWAN_DYNAMIC_DELEGATION_TIMEOUT:-180}"

[[ "$project_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || {
  echo "SWAN_DYNAMIC_DELEGATION_PROJECT must name a running disposable Compose project" >&2
  exit 64
}
[[ "$output_path" = /* ]] || {
  echo "SWAN_DYNAMIC_DELEGATION_OUTPUT must be an absolute path" >&2
  exit 64
}
if [[ ! "$wait_timeout" =~ ^[1-9][0-9]*$ ]] \
  || ((wait_timeout > 600))
then
  echo "SWAN_DYNAMIC_DELEGATION_TIMEOUT must be an integer from 1 through 600" >&2
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
bootstrap_id="$(container_id swan-bootstrap)"
reference_pds_id="$(container_id reference-pds)"
caddy_id="$(container_id caddy)"
caddy_trust_id="$(container_id caddy-ca-ready)"
for required_id in \
  "$normal_swan_id" "$bootstrap_id" "$reference_pds_id" "$caddy_id" \
  "$caddy_trust_id"
do
  [[ -n "$required_id" ]] || {
    echo "the Compose project is missing a required service" >&2
    exit 1
  }
done
wait_for_container "$normal_swan_id" "Swan"
wait_for_container "$reference_pds_id" "reference PDS"
wait_for_container "$caddy_id" "Caddy"

authority_handle="$(read_lab_value authority.handle)"
authority_metadata="$({
  docker exec "$normal_swan_id" \
    /usr/local/bin/swan account show \
    --data-directory /var/lib/swan/data \
    --handle "$authority_handle"
})" || {
  echo "the Compose project has no provisioned Swan authority" >&2
  exit 1
}
authority_did="$(printf '%s' "$authority_metadata" | json_field did)" || {
  echo "the Swan authority metadata is invalid" >&2
  exit 1
}
authority_handle="$(printf '%s' "$authority_metadata" | json_field canonicalHandle)" || {
  echo "the Swan authority handle is invalid" >&2
  exit 1
}

# The pinned PDS permits at most 18 characters before its service-domain
# suffix. "dynamic-" plus eight random hexadecimal characters is exactly 16.
suffix="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
reference_handle="dynamic-${suffix}.pds.test"
reference_email="dynamic-${suffix}@example.com"
reference_password="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
export SWAN_REFERENCE_HANDLE="$reference_handle"
export SWAN_REFERENCE_EMAIL="$reference_email"
export SWAN_REFERENCE_PASSWORD="$reference_password"

# The reference PDS requires an invite. Its administrator secret is consumed
# inside the container and never crosses into a process argument or artifact.
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
      headers: {
        authorization,
        "content-type": "application/json",
      },
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
reference_did="$(printf '%s' "$reference_account" | json_field did)" || {
  echo "the reference account response has no valid DID" >&2
  exit 1
}
reference_access_token="$(printf '%s' "$reference_account" | json_field accessJwt)" || {
  echo "the reference account response has no access token" >&2
  exit 1
}
unset reference_account reference_password reference_email

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

# Rebuild the project-scoped Swan image from this checkout unless the caller
# explicitly chose an already-built current image.
if [[ "${SWAN_DYNAMIC_DELEGATION_NO_BUILD:-0}" != "1" ]]; then
  compose build swan
fi
swan_image="$(docker image inspect --format '{{.Id}}' "${project_name}-swan:latest")" || {
  echo "the project-scoped Swan image is unavailable" >&2
  exit 1
}

temporary_root="${root}/.interop-live"
mkdir -p "$temporary_root"
chmod 700 "$temporary_root"
temporary_directory="$(mktemp -d "${temporary_root}/swan-reference-dynamic.XXXXXX")"
notification_config_path="${temporary_directory}/notification-config.json"
runner_output_path="${temporary_directory}/artifact.json"
dynamic_container="${project_name}-reference-dynamic-swan"
normal_stopped=0

cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  unset reference_access_token
  docker rm --force "$dynamic_container" >/dev/null 2>&1 || true
  if ((normal_stopped)); then
    docker start "$normal_swan_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$temporary_directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

python3 - "$notification_config_path" "$authority_did" "$reference_did" <<'PY'
import json
import os
import sys

path, authority, member = sys.argv[1:]
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
    "delegationKeyPLC": {
        "origin": "http://reference-plc:2582",
        "laboratory": True,
        "allowlistedHost": "reference-plc",
        "allowedIssuers": [member],
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
  --login-trusted-proxy-peer "$caddy_ip" \
  --notification-config /tmp/notification-config.json \
  --managing-service-audience did:web:interop-swan-managing-service \
  >/dev/null
wait_for_swan_http "$dynamic_container" "dynamic-key Swan"

space_uri="at://${authority_did}/space/app.bsky.bookmarks/dynamic-${suffix}"
collection="app.bsky.feed.post"
rkey="dynamic-${suffix}"
export SWAN_LAB_PRODUCER_TOKEN="$reference_access_token"

docker run --rm \
  --network "$network_name" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${temporary_directory},dst=/run/acceptance" \
  --env SWAN_LAB_PRODUCER_TOKEN \
  --entrypoint /bin/sh \
  "$swan_image" \
  -ec '
    private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")"
    umask 077
    printf \
      '"'"'{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n'"'"' \
      "$1" "$2" "$3" "$4" "$private_value" \
      >/tmp/permissioned-record.json
    export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt
    export SWAN_LAB_CONSUMER_HANDLE="$5"
    SWAN_LAB_CONSUMER_PASSWORD="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/authority.password)"
    export SWAN_LAB_CONSUMER_PASSWORD
    client_id="http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback"
    if ! /usr/local/bin/swan lab live \
      --mode permissioned \
      --name reference-member-dynamic-delegation \
      --producer-url https://pds.test \
      --consumer-url https://swan.test \
      --producer-auth bearer \
      --consumer-auth oauth \
      --consumer-client-id "$client_id" \
      --consumer-redirect-uri http://127.0.0.1/callback \
      --scope atproto \
      --space "$1" \
      --permissioned-read-host member \
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
      tail -n 40 /tmp/live-interop.log >&2 || true
      exit 1
    fi
    grep -q '"'"'"status":"passed"'"'"' /tmp/sanitized-artifact.json
    if grep -F -- "$private_value" /tmp/sanitized-artifact.json >/dev/null; then
      echo "sanitized artifact retained a permissioned value" >&2
      exit 1
    fi
    cp /tmp/sanitized-artifact.json /run/acceptance/artifact.json
    chmod 0600 /run/acceptance/artifact.json
    unset private_value SWAN_LAB_CONSUMER_PASSWORD
  ' _ \
  "$space_uri" "$reference_did" "$collection" "$rkey" "$authority_handle"

unset SWAN_LAB_PRODUCER_TOKEN reference_access_token
mkdir -p "$(dirname "$output_path")"
install -m 0600 "$runner_output_path" "$output_path"

docker rm --force "$dynamic_container" >/dev/null
docker start "$normal_swan_id" >/dev/null
normal_stopped=0
wait_for_container "$normal_swan_id" "restored Swan"

echo "REFERENCE MEMBER DYNAMIC DELEGATION OK: artifact=${output_path}"
