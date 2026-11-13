#!/usr/bin/env bash
set -euo pipefail

# Exercise a pinned TypeScript/Swan permissioned round trip with dynamic PLC
# key discovery. The default `member` direction uses the TypeScript host as a
# member while Swan is the authority; `authority` reverses that placement so
# Swan is the member and dynamically resolves the TypeScript authority's
# credential-signing key. Stateful sync/full-CAR verification is supported in
# both directions when the recovery-qualified reference image is selected.
# No static public-key pin is supplied in either case.
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
compose_file="${SWAN_DYNAMIC_DELEGATION_COMPOSE_FILE:-}"
output_path="${SWAN_DYNAMIC_DELEGATION_OUTPUT:-${root}/artifacts/live/reference-member-dynamic-delegation.json}"
wait_timeout="${SWAN_DYNAMIC_DELEGATION_TIMEOUT:-180}"
stateful_mode="${SWAN_DYNAMIC_DELEGATION_STATEFUL:-0}"
direction="${SWAN_DYNAMIC_DELEGATION_DIRECTION:-member}"
recovery_mode="${SWAN_DYNAMIC_DELEGATION_RECOVERY:-0}"
fault_mode="${SWAN_DYNAMIC_DELEGATION_FAULT_MODE:-}"

[[ "$project_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || {
  echo "SWAN_DYNAMIC_DELEGATION_PROJECT must name a running disposable Compose project" >&2
  exit 64
}
if [[ -n "$compose_file" ]]; then
  [[ "$compose_file" = /* && -f "$compose_file" ]] || {
    echo "SWAN_DYNAMIC_DELEGATION_COMPOSE_FILE must be an absolute Compose file" >&2
    exit 64
  }
fi
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
case "$stateful_mode" in
  0|1) ;;
  *) echo "SWAN_DYNAMIC_DELEGATION_STATEFUL must be 0 or 1" >&2; exit 64 ;;
esac
case "$direction" in
  member|authority) ;;
  *) echo "SWAN_DYNAMIC_DELEGATION_DIRECTION must be member or authority" >&2; exit 64 ;;
esac
case "$recovery_mode" in
  0|1) ;;
  *) echo "SWAN_DYNAMIC_DELEGATION_RECOVERY must be 0 or 1" >&2; exit 64 ;;
esac
if [[ "$recovery_mode" == "1" && "$direction" != "member" ]]; then
  echo "SWAN_DYNAMIC_DELEGATION_RECOVERY currently requires member direction" >&2
  exit 64
fi
case "$fault_mode" in
  ""|normal|offline|disconnected|delayed|duplicated|reordered|corrupted) ;;
  *) echo "SWAN_DYNAMIC_DELEGATION_FAULT_MODE is invalid" >&2; exit 64 ;;
esac
if [[ -n "$fault_mode" && ( "$direction" != "member" || "$stateful_mode" != "1" ) ]]; then
  echo "SWAN_DYNAMIC_DELEGATION_FAULT_MODE requires member direction and stateful mode" >&2
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
  if [[ -n "$compose_file" ]]; then
    ./interop/compose.sh \
      --file "$root/docker-compose.yml" \
      --file "$compose_file" \
      --project-name "$project_name" "$@"
  else
    ./interop/compose.sh --project-name "$project_name" "$@"
  fi
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
toxiproxy_id="$(container_id toxiproxy)"
for required_id in \
  "$normal_swan_id" "$bootstrap_id" "$reference_pds_id" "$caddy_id" \
  "$caddy_trust_id" "$toxiproxy_id"
do
  [[ -n "$required_id" ]] || {
    echo "the Compose project is missing a required service" >&2
    exit 1
  }
done
wait_for_container "$normal_swan_id" "Swan"
wait_for_container "$reference_pds_id" "reference PDS"
wait_for_container "$caddy_id" "Caddy"

if [[ "$direction" == "member" ]]; then
  swan_role="authority"
else
  swan_role="member"
fi
swan_handle="$(read_lab_value "${swan_role}.handle")"
swan_metadata="$({
  docker exec "$normal_swan_id" \
    /usr/local/bin/swan account show \
    --data-directory /var/lib/swan/data \
    --handle "$swan_handle"
})" || {
  echo "the Compose project has no provisioned Swan ${swan_role}" >&2
  exit 1
}
swan_did="$(printf '%s' "$swan_metadata" | json_field did)" || {
  echo "the Swan ${swan_role} metadata is invalid" >&2
  exit 1
}
swan_handle="$(printf '%s' "$swan_metadata" | json_field canonicalHandle)" || {
  echo "the Swan ${swan_role} handle is invalid" >&2
  exit 1
}
if [[ "$direction" == "member" ]]; then
  space_authority_did="$swan_did"
  local_consumer_handle="$swan_handle"
else
  space_member_did="$swan_did"
fi

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

if [[ "$direction" == "member" ]]; then
  space_member_did="$reference_did"
else
  space_authority_did="$reference_did"
fi

reference_commit_key=""
if [[ "$stateful_mode" == "1" ]]; then
  # The PLC audit endpoint exposes the canonical did:key used by the
  # repository signer. Resolve the repository DID (not merely the authority
  # DID) so reverse-authority runs verify Swan's P-256 commit with Swan's key.
  # The Swift runner validates the multicodec and curve before using it.
  commit_repository_did="$reference_did"
  if [[ "$direction" == "authority" ]]; then
    commit_repository_did="$space_member_did"
  fi
  reference_commit_key="$({
    docker exec \
      --env SWAN_REFERENCE_DID="$commit_repository_did" \
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
  const did = process.env.SWAN_REFERENCE_DID
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
 ' # end PLC audit script
  })" || {
    echo "the PLC did not expose a canonical repository signing key" >&2
    exit 1
  }
  [[ "$reference_commit_key" =~ ^did:key:z[A-Za-z0-9]+$ ]] || {
    echo "the repository signing key did not decode to a canonical did:key" >&2
    exit 1
  }
fi

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
  # Keep a sanitized semantic artifact for a failed run. The runner never
  # writes credentials, request bodies, record values, or personal selectors
  # to this file; preserving it makes an interoperability failure reviewable
  # after the disposable container and its tmpfs have been removed.
  if ((result != 0)) && [[ -f "${runner_output_path:-}" ]]; then
    local failed_output="${output_path}.failed"
    local failed_directory
    failed_directory="$(dirname "$failed_output")"
    mkdir -p "$failed_directory"
    local failed_temporary
    failed_temporary="$(mktemp "${failed_directory}/.reference-member-dynamic-failed.XXXXXX")"
    install -m 0600 "$runner_output_path" "$failed_temporary"
    mv -f "$failed_temporary" "$failed_output"
  fi
  docker rm --force "$dynamic_container" >/dev/null 2>&1 || true
  if [[ -n "$fault_mode" ]]; then
    docker restart "$toxiproxy_id" >/dev/null 2>&1 || true
    for _ in $(seq 1 "$wait_timeout"); do
      if docker exec "$reference_pds_id" node -e '
fetch("http://toxiproxy:8474/proxies/reference-pds")
  .then((response) => process.exit(response.ok ? 0 : 1))
  .catch(() => process.exit(1))
' >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  fi
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

python3 - "$notification_config_path" "$space_authority_did" "$space_member_did" "$direction" <<'PY'
import json
import os
import sys

path, authority, member, direction = sys.argv[1:]
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
}
if direction == "member":
    configuration["delegationKeyPLC"] = {
        "origin": "http://reference-plc:2582",
        "laboratory": True,
        "allowlistedHost": "reference-plc",
        "allowedIssuers": [member],
    }
else:
    configuration["credentialKeyPLC"] = {
        "origin": "http://reference-plc:2582",
        "laboratory": True,
        "allowlistedHost": "reference-plc",
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
  --profile /usr/local/share/swan/Profiles/permissioned-data-0016-2026-11-12.json \
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
wait_for_swan_tls_route "dynamic-key Swan"

space_uri="at://${space_authority_did}/space/app.bsky.bookmarks/dynamic-${suffix}"
space_scope="space:app.bsky.bookmarks?authority=${space_authority_did}&skey=dynamic-${suffix}&action=read"
write_scope="space:app.bsky.bookmarks?authority=${space_authority_did}&skey=dynamic-${suffix}&action=create&collection=app.bsky.feed.post"
space_scope_client_id="$(python3 - "$space_scope" "$write_scope" <<'PY'
import sys
from urllib.parse import quote

print("http://localhost?scope=" + quote("atproto " + sys.argv[1] + " " + sys.argv[2], safe="") +
      "&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")
PY
)"
collection="app.bsky.feed.post"
rkey="dynamic-${suffix}"
printf '%s' "$reference_access_token" > "${temporary_directory}/reference-access.token"
chmod 0600 "${temporary_directory}/reference-access.token"

docker run --rm \
  --network "$network_name" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
  --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${temporary_directory},dst=/run/acceptance" \
  --env SWAN_DYNAMIC_DELEGATION_DIRECTION="$direction" \
  --env SWAN_DYNAMIC_DELEGATION_STATEFUL="$stateful_mode" \
  --env SWAN_DYNAMIC_DELEGATION_RECOVERY="$recovery_mode" \
  --env SWAN_DYNAMIC_DELEGATION_FAULT_MODE="$fault_mode" \
  --env SWAN_DYNAMIC_DELEGATION_SPACE_SCOPE="$space_scope" \
  --env SWAN_DYNAMIC_DELEGATION_WRITE_SCOPE="$write_scope" \
  --env SWAN_DYNAMIC_DELEGATION_SCOPE_CLIENT_ID="$space_scope_client_id" \
  --env SWAN_LAB_PERMISSIONED_COMMIT_KEY="$reference_commit_key" \
  --entrypoint /bin/sh \
  "$swan_image" \
  -ec '
    private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")"
    blob_value="swan-permissioned-blob-${private_value}"
    printf "%s" "$blob_value" >/tmp/permissioned-blob.bin
    blob_size="$(wc -c </tmp/permissioned-blob.bin | tr -d "[:space:]")"
    umask 077
    printf \
      '"'"'{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s","blob":{"$type":"blob","ref":{"$link":"{{BLOB_CID}}"},"mimeType":"application/octet-stream","size":%s}}}\n'"'"' \
      "$1" "$2" "$3" "$4" "$private_value" "$blob_size" \
      >/tmp/permissioned-record.json
    export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt
    if [ "${SWAN_DYNAMIC_DELEGATION_DIRECTION:-member}" = "member" ]; then
      export SWAN_LAB_CONSUMER_HANDLE="$5"
      producer_url="https://pds.test"
      consumer_url="https://swan.test"
      producer_auth_args="--producer-auth bearer --producer-token-file /run/acceptance/reference-access.token"
      consumer_auth_args="--consumer-auth oauth --consumer-password-file /run/secrets/swan-bootstrap/authority.password --consumer-client-id http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback --consumer-redirect-uri http://127.0.0.1/callback"
      scope_args="--scope atproto"
      read_host="member"
      scenario_name="reference-member-dynamic-delegation"
    else
      SWAN_LAB_PRODUCER_HANDLE="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/member.handle)"
      export SWAN_LAB_PRODUCER_HANDLE
      producer_url="https://swan.test"
      consumer_url="https://pds.test"
      producer_auth_args="--producer-auth oauth --producer-password-file /run/secrets/swan-bootstrap/member.password --producer-handle-env SWAN_LAB_PRODUCER_HANDLE --producer-client-id ${SWAN_DYNAMIC_DELEGATION_SCOPE_CLIENT_ID} --producer-redirect-uri http://127.0.0.1/callback"
      consumer_auth_args="--consumer-auth bearer --consumer-token-file /run/acceptance/reference-access.token"
      scope_args="--scope atproto --scope ${SWAN_DYNAMIC_DELEGATION_SPACE_SCOPE} --scope ${SWAN_DYNAMIC_DELEGATION_WRITE_SCOPE}"
      read_host="member"
      scenario_name="reference-authority-dynamic-credential"
    fi
    if [ "${SWAN_DYNAMIC_DELEGATION_STATEFUL:-0}" = "1" ]; then
      export SWAN_LAB_PERMISSIONED_COMMIT_KEY
      stateful_flags="--permissioned-list-ops --permissioned-get-repo --permissioned-stateful-matrix"
    else
      stateful_flags=""
    fi
    if ! /usr/local/bin/swan lab live \
      --mode permissioned \
      --name "$scenario_name" \
      --producer-url "$producer_url" \
      --consumer-url "$consumer_url" \
      $producer_auth_args \
      $consumer_auth_args \
      $scope_args \
      --space "$1" \
      --permissioned-read-host "$read_host" \
      --provision-space \
      --body-file /tmp/permissioned-record.json \
      --blob-file /tmp/permissioned-blob.bin \
      --read-query \
        "space=$1" \
        "repo=$2" \
        "collection=$3" \
        "rkey=$4" \
      $stateful_flags \
      --output /tmp/sanitized-artifact.json \
      --no-fail-on-failure \
      >/tmp/live-interop.log 2>&1
    then
      tail -n 40 /tmp/live-interop.log >&2 || true
      exit 1
    fi
    if [ -n "${SWAN_DYNAMIC_DELEGATION_FAULT_MODE:-}" ]; then
      fault_mode="${SWAN_DYNAMIC_DELEGATION_FAULT_MODE}"
      # A full-CAR bootstrap does not consume an incremental sequence. Every
      # fresh target therefore starts its contiguous delivery stream at 1.
      sequence_base=1
      next_sequence=1
      newest_sequence=2
      snapshot_head() {
        /usr/local/bin/swan lab permissioned-replica-head \
          --receiver-did "$6" --repository "$2" --space "$1" \
          --data-directory /var/lib/swan/data --output "$7" \
          >/tmp/permissioned-head.log 2>&1
      }
      sync_replica() {
        sync_sequence="$7"
        sync_request_id="$8"
        sync_output="$9"
        sync_replay_flag="${10:-}"
        /usr/local/bin/swan lab sync-permissioned \
          --receiver-did "$6" --repository "$2" --space "$1" \
          --data-directory /var/lib/swan/data \
          --source-url https://pds.test --authority-url https://swan.test \
          --source-auth bearer --source-token-file /run/acceptance/reference-access.token \
          --scope atproto \
          --permissioned-commit-key-env SWAN_LAB_PERMISSIONED_COMMIT_KEY \
          --request-id "$sync_request_id" \
          --request-sequence "$sync_sequence" \
          $sync_replay_flag \
          --output "$sync_output" --no-fail-on-failure
      }
      toxiproxy_post() {
        toxic_path="$7"
        toxic_body="$8"
        curl --fail --silent --show-error --max-time 4 \
          -X POST -H "content-type: application/json" \
          --data "$toxic_body" \
          "http://toxiproxy:8474/${toxic_path}" >/dev/null
      }
      toxiproxy_delete() {
        curl --fail --silent --show-error --max-time 4 \
          -X DELETE "http://toxiproxy:8474/$7" >/dev/null 2>&1 || true
      }

      # Establish a durable last-good receiver head before injecting a fault.
      if ! sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$sequence_base" "${4}-baseline" /tmp/baseline-sync.json \
        >/tmp/baseline-sync.log 2>&1
      then
        tail -n 60 /tmp/baseline-sync.log >&2 || true
        exit 1
      fi
      snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/before-head.json

      # Add one fresh source revision. The live verifier supplies the intended
      # signed revision and commitment without publishing it to the receiver.
      next_private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")"
      next_rkey="${4}-next"
      printf \
        '"'"'{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n'"'"' \
        "$1" "$2" "$3" "$next_rkey" "$next_private_value" \
        >/tmp/permissioned-next-record.json
      if ! /usr/local/bin/swan lab live \
        --mode permissioned --name "${scenario_name}-fault-source" \
        --producer-url "$producer_url" --consumer-url "$consumer_url" \
        $producer_auth_args $consumer_auth_args $scope_args \
        --space "$1" --permissioned-read-host "$read_host" \
        --body-file /tmp/permissioned-next-record.json \
        --read-query "space=$1" "repo=$2" "collection=$3" "rkey=$next_rkey" \
        $stateful_flags --output /tmp/fault-source-artifact.json \
        >/tmp/fault-source.log 2>&1
      then
        tail -n 60 /tmp/fault-source.log >&2 || true
        exit 1
      fi
      python3 - /tmp/before-head.json /tmp/fault-source-artifact.json /tmp/intended-head.json <<'PY'
import json
import sys

before_path, source_path, output_path = sys.argv[1:]
with open(before_path, encoding="utf-8") as handle:
    before = json.load(handle).get("head")
with open(source_path, encoding="utf-8") as handle:
    source = json.load(handle).get("roundTrip", {})
if not isinstance(before, dict):
    raise SystemExit("baseline head missing")
revision = source.get("syncCommitRevision")
commitment = source.get("syncCommitment")
if not isinstance(revision, str) or not isinstance(commitment, str):
    raise SystemExit("intended signed head missing")
intended = {
    "generation": before["generation"],
    "revision": revision,
    "commitment": commitment,
}
with open(output_path, "x", encoding="utf-8") as handle:
    json.dump({"head": intended}, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY

      fault_observed=false
      invalid_delivery_rejected=false
      case "$fault_mode" in
        normal)
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-normal" /tmp/fault-sync.json \
            >/tmp/fault-sync.log 2>&1
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-fault-head.json
          cp /tmp/after-fault-head.json /tmp/after-heal-head.json
          ;;
        delayed)
          toxiproxy_post "$1" "$2" "$3" "$4" "$5" "$6" \
            proxies/reference-pds/toxics \
            '"'"'{"name":"stateful-delay-upstream","type":"latency","stream":"upstream","toxicity":1.0,"attributes":{"latency":250,"jitter":25}}'"'"'
          toxiproxy_post "$1" "$2" "$3" "$4" "$5" "$6" \
            proxies/reference-pds/toxics \
            '"'"'{"name":"stateful-delay-downstream","type":"latency","stream":"downstream","toxicity":1.0,"attributes":{"latency":250,"jitter":25}}'"'"'
          fault_observed=true
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-delayed" /tmp/fault-sync.json \
            >/tmp/fault-sync.log 2>&1
          toxiproxy_delete "$1" "$2" "$3" "$4" "$5" "$6" proxies/reference-pds/toxics/stateful-delay-upstream
          toxiproxy_delete "$1" "$2" "$3" "$4" "$5" "$6" proxies/reference-pds/toxics/stateful-delay-downstream
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-fault-head.json
          cp /tmp/after-fault-head.json /tmp/after-heal-head.json
          ;;
        offline)
          toxiproxy_post "$1" "$2" "$3" "$4" "$5" "$6" \
            proxies/reference-pds '"'"'{"enabled":false}'"'"'
          fault_observed=true
          if sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-offline" /tmp/fault-sync.json \
            >/tmp/fault-sync.log 2>&1
          then
            echo "offline sync unexpectedly succeeded" >&2
            exit 1
          fi
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-fault-head.json
          toxiproxy_post "$1" "$2" "$3" "$4" "$5" "$6" \
            proxies/reference-pds '"'"'{"enabled":true}'"'"'
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-offline-heal" /tmp/heal-sync.json \
            >/tmp/heal-sync.log 2>&1
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-heal-head.json
          ;;
        disconnected)
          toxiproxy_post "$1" "$2" "$3" "$4" "$5" "$6" \
            proxies/reference-pds/toxics \
            '"'"'{"name":"stateful-disconnect","type":"reset_peer","stream":"downstream","toxicity":1.0,"attributes":{"timeout":0}}'"'"'
          fault_observed=true
          if sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-disconnected" /tmp/fault-sync.json \
            >/tmp/fault-sync.log 2>&1
          then
            echo "disconnected sync unexpectedly succeeded" >&2
            exit 1
          fi
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-fault-head.json
          toxiproxy_delete "$1" "$2" "$3" "$4" "$5" "$6" proxies/reference-pds/toxics/stateful-disconnect
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-disconnected-heal" /tmp/heal-sync.json \
            >/tmp/heal-sync.log 2>&1
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-heal-head.json
          ;;
        duplicated)
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-duplicate" /tmp/fault-sync-second.json --verify-exact-duplicate-replay \
            >/tmp/fault-sync-second.log 2>&1
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-fault-head.json
          cp /tmp/after-fault-head.json /tmp/after-heal-head.json
          if python3 - /tmp/fault-sync-second.json <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    artifact = json.load(handle)
witness = artifact.get("exactDuplicateReplay")
if (
    artifact.get("outcome") != "exact_duplicate"
    or not isinstance(witness, dict)
    or witness.get("applyAttempts") != 2
    or witness.get("firstOutcome") != "applied"
    or witness.get("secondOutcome") != "exact_duplicate"
    or not isinstance(witness.get("requestDigest"), str)
    or len(witness["requestDigest"]) != 64
):
    raise SystemExit(1)
PY
          then invalid_delivery_rejected=true; fi
          fault_observed=true
          ;;
        reordered)
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$newest_sequence" "${4}-newest-first" /tmp/fault-sync-newest.json \
            >/tmp/fault-sync-newest.log 2>&1 || true
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-fault-head.json
          if python3 - /tmp/fault-sync-newest.json /tmp/before-head.json /tmp/after-fault-head.json <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    outcome = json.load(handle).get("outcome")
with open(sys.argv[2], encoding="utf-8") as handle:
    before = json.load(handle).get("head")
with open(sys.argv[3], encoding="utf-8") as handle:
    after = json.load(handle).get("head")
if outcome != "stale_or_reordered" or before != after:
    raise SystemExit(1)
PY
          then invalid_delivery_rejected=true; fi
          sync_replica "$1" "$2" "$3" "$4" "$5" "$6" "$next_sequence" "${4}-ordered-heal" /tmp/heal-sync.json \
            >/tmp/heal-sync.log 2>&1
          snapshot_head "$1" "$2" "$3" "$4" "$5" "$6" /tmp/after-heal-head.json
          fault_observed=true
          ;;
        corrupted)
          /usr/local/bin/swan lab recover-permissioned \
            --name "${scenario_name}-corrupted" \
            --receiver-did "$6" --repository "$2" --space "$1" \
            --data-directory /var/lib/swan/data \
            --source-url https://pds.test --authority-url https://swan.test \
            --source-auth bearer --source-token-file /run/acceptance/reference-access.token \
            --scope atproto --since 2222222222222 \
            --allow-full-car-fallback --require-prior-head \
            --permissioned-commit-key-env SWAN_LAB_PERMISSIONED_COMMIT_KEY \
            --output /tmp/corruption-recovery.json \
            >/tmp/corruption-recovery.log 2>&1
          if /usr/local/bin/swan-project-corruption-recovery-witness \
            /tmp/corruption-recovery.json \
            /tmp/before-head.json /tmp/intended-head.json \
            /tmp/after-fault-head.json /tmp/after-heal-head.json
          then invalid_delivery_rejected=true; fi
          fault_observed=true
          ;;
      esac
      python3 - "$fault_mode" /tmp/before-head.json /tmp/intended-head.json /tmp/after-fault-head.json /tmp/after-heal-head.json "$fault_observed" "$invalid_delivery_rejected" /tmp/fault-cell.json <<'PY'
import json
import sys

mode, before_path, intended_path, fault_path, heal_path, observed, rejected, output_path = sys.argv[1:]
def head(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle).get("head")
cell = {
    "mode": mode,
    "before": head(before_path),
    "intended": head(intended_path),
    "afterFault": head(fault_path),
    "afterHeal": head(heal_path),
    "faultObserved": observed == "true",
    "invalidDeliveryRejected": rejected == "true",
}
with open(output_path, "x", encoding="utf-8") as handle:
    json.dump(cell, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
      python3 - /tmp/sanitized-artifact.json /tmp/fault-cell.json <<'PY'
import json
import sys
live_path, cell_path = sys.argv[1:]
with open(live_path, encoding="utf-8") as handle:
    live = json.load(handle)
with open(cell_path, encoding="utf-8") as handle:
    live["faultWitness"] = json.load(handle)
diagnostics = []
for path in [
    "/tmp/fault-sync.json", "/tmp/fault-sync-first.json",
    "/tmp/fault-sync-second.json", "/tmp/fault-sync-newest.json",
    "/tmp/fault-sync-stale.json", "/tmp/heal-sync.json",
]:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        continue
    diagnostics.append({key: value.get(key) for key in [
        "outcome", "status", "priorRevision", "finalRevision",
    ]})
live["faultDiagnostics"] = diagnostics
with open(live_path, "w", encoding="utf-8") as handle:
    json.dump(live, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
      unset next_private_value
    fi
    if [ "${SWAN_DYNAMIC_DELEGATION_RECOVERY:-0}" = "1" ]; then
      recovery_failed=0
      recovery_artifact="/tmp/recovery-artifact.json"
      recovery_command_status=0
      if /usr/local/bin/swan lab recover-permissioned \
        --name "${scenario_name}-recovery" \
        --receiver-did "$6" \
        --repository "$2" \
        --space "$1" \
        --data-directory /var/lib/swan/data \
        --source-url https://pds.test \
        --authority-url https://swan.test \
        --source-auth bearer \
        --source-token-file /run/acceptance/reference-access.token \
        --scope atproto \
        --since 2222222222222 \
        --allow-full-car-fallback \
        --permissioned-commit-key-env SWAN_LAB_PERMISSIONED_COMMIT_KEY \
        --output "$recovery_artifact" \
        --no-fail-on-failure \
        >/tmp/permissioned-recovery.log 2>&1; then
        recovery_command_status=0
      else
        recovery_command_status=$?
      fi
      if [ "$recovery_command_status" -ne 0 ]; then
        tail -n 60 /tmp/permissioned-recovery.log >&2 || true
      fi
      recovery_status=failed
      if python3 - "$recovery_artifact" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    artifact = json.load(handle)
if artifact.get("status") != "passed":
    raise SystemExit(1)
PY
      then
        recovery_status=passed
      else
        tail -n 60 /tmp/permissioned-recovery.log >&2 || true
      fi
      python3 - /tmp/sanitized-artifact.json "$recovery_artifact" <<'PY'
import json
import sys

live_path, recovery_path = sys.argv[1:]
with open(live_path, encoding="utf-8") as handle:
    live = json.load(handle)
try:
    with open(recovery_path, encoding="utf-8") as handle:
        recovery = json.load(handle)
except (OSError, ValueError):
    recovery = {"status": "failed", "errorCode": "recovery_artifact_unavailable"}
live["recovery"] = recovery
live["status"] = "passed" if live.get("status") == "passed" and recovery.get("status") == "passed" else "failed"
with open(live_path, "w", encoding="utf-8") as handle:
    json.dump(live, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
      if [ "$recovery_command_status" -ne 0 ] || [ "$recovery_status" != "passed" ]; then
        recovery_failed=1
      fi
    fi
    cp /tmp/sanitized-artifact.json /run/acceptance/artifact.json
    chmod 0600 /run/acceptance/artifact.json
    if ! /usr/local/bin/swan-validate-live-interop-artifact \
      /tmp/sanitized-artifact.json
    then
      tail -n 40 /tmp/live-interop.log >&2 || true
      exit 1
    fi
    if grep -F -- "$private_value" /tmp/sanitized-artifact.json >/dev/null; then
      echo "sanitized artifact retained a permissioned value" >&2
      exit 1
    fi
    if grep -F -- "$blob_value" /tmp/sanitized-artifact.json >/dev/null; then
      echo "sanitized artifact retained permissioned blob bytes" >&2
      exit 1
    fi
    if [ "${recovery_failed:-0}" -ne 0 ]; then
      exit 1
    fi
    unset private_value blob_value
  ' _ \
  "$space_uri" "$space_member_did" "$collection" "$rkey" "${local_consumer_handle:-}" "$space_authority_did"

rm -f "${temporary_directory}/reference-access.token"
unset reference_access_token reference_commit_key
mkdir -p "$(dirname "$output_path")"
install -m 0600 "$runner_output_path" "$output_path"

docker rm --force "$dynamic_container" >/dev/null
docker start "$normal_swan_id" >/dev/null
normal_stopped=0
wait_for_container "$normal_swan_id" "restored Swan"

echo "REFERENCE DYNAMIC PERMISSIONED INTEROP OK: direction=${direction} artifact=${output_path}"
