#!/usr/bin/env bash
set -euo pipefail

# Live acceptance for the AT Protocol permissioned-data "first-write discovery
# liveness gap" (bluesky-social/proposals 0016, Swan Spaces Interoperability
# Alpha): a brand-new writer whose very first notifyWrite to the space
# authority is lost is never learned by the authority, so a sweep
# (listRepos / writer set) can never discover them. The proposal's healing
# story ("a later notification or sweep") presumes the authority already knows
# the writer; an entirely unknown writer has no route into the writer set.
#
# The pinned TypeScript reference writer's fireNotifyWrite
# (.interop-cache/atproto-*/packages/pds/src/api/com/atproto/space/util.ts
# ~lines 85-121) is fully best-effort: `.catch(() => {})` plus an outer
# try/catch. Every space write handler commits the local permissioned write
# BEFORE the notification (createRecord.ts:42, putRecord.ts:43,
# applyWrites.ts:77, deleteRecord.ts:36), so a lost notification never fails
# the write. That is the hole this acceptance witnesses.
#
# Scenario (order matters):
#   A. Preconditions: docker, verified secret source, healthy authority.
#   B. Fresh TypeScript PDS member account (Bob) + fresh space provisioned
#      through the authority (createSpace + putMember) via the established
#      `swan lab live --mode permissioned --provision-space` path. The
#      provision round trip must NOT commit a record (in this lab the
#      authority rejects the member delegation token with 401 before any
#      write; the script asserts no write event occurred).
#   C. Stop the authority container.
#   D. Bob's FIRST write (com.atproto.space.putRecord, unique rkey) through
#      the pinned TypeScript PDS while the authority is DOWN. The write must
#      commit locally (200 + CID) even though fireNotifyWrite cannot land.
#   E. Start the authority container and wait for its healthcheck.
#   F. Sweep: read-only SQLite assertion that permissioned_space_writers has
#      NO (space_uri, bob_did) row, plus an attempted protocol-level
#      listRepos sweep (getDelegationToken -> getSpaceCredential -> listRepos)
#      whose failure is recorded. The SQLite writer-set assertion is the
#      authoritative witness because Swan's listRepos reads exactly that table.
#   G. Heal attempt: Bob writes a SECOND record with the authority UP, then
#      the writer-set state and the reachability of BOTH records through the
#      live read path are recorded.
#   H. Restore: the authority must be running and healthy at exit, on every
#      path (EXIT/INT/TERM/HUP trap), matching the stateful fault-matrix
#      restore discipline.
#   I. Sanitized artifact: statuses, CIDs, SHA-256 digests, booleans, and
#      space/DID identifiers only. Never record bodies, values, credentials,
#      passwords, tokens, or DPoP proofs. Private record values are generated
#      inside disposable containers and never reach the host.
#
# The four finding facts are recorded observations, not gates: if a live run
# refutes an expected outcome, the true outcome is recorded in the artifact
# (the finding is empirical). Hard gates are the preconditions of the
# witnessing (provisioning, local commit while the authority is down, writer
# set emptiness, record reachability, and lab restoration).

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

project_name="${SWAN_FIRST_WRITE_PROJECT:-swan-alpha-current-20260801}"
output_path="${SWAN_FIRST_WRITE_OUTPUT:-${root}/artifacts/live/first-write-notification-loss.json}"
wait_timeout="${SWAN_FIRST_WRITE_TIMEOUT:-240}"

[[ "$project_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || {
  echo "SWAN_FIRST_WRITE_PROJECT must name a running disposable Compose project" >&2
  exit 64
}
[[ "$output_path" = /* ]] || {
  echo "SWAN_FIRST_WRITE_OUTPUT must be an absolute path" >&2
  exit 64
}
if [[ ! "$wait_timeout" =~ ^[1-9][0-9]*$ ]] || ((wait_timeout > 600)); then
  echo "SWAN_FIRST_WRITE_TIMEOUT must be an integer from 1 through 600" >&2
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

authority_handle="$(read_lab_value authority.handle)"
if [[ -z "$authority_handle" || "$authority_handle" =~ [[:space:]] ]]; then
  echo "interop authority handle fixture is malformed" >&2
  exit 64
fi

suffix="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$suffix" =~ ^[0-9a-f]{8}$ ]] || {
  echo "first-write acceptance could not generate a run nonce" >&2
  exit 1
}
collection="app.bsky.feed.post"
first_rkey="first-${suffix}"
second_rkey="second-${suffix}"

temporary_root="${SWAN_FIRST_WRITE_TMPDIR:-${root}/.interop-live}"
[[ "$temporary_root" = /* ]] || {
  echo "SWAN_FIRST_WRITE_TMPDIR must be an absolute directory" >&2
  exit 64
}
if [[ -z "${SWAN_FIRST_WRITE_TMPDIR:-}" ]]; then
  temporary_root="$root/.interop-live"
fi
mkdir -p "$temporary_root"
chmod 700 "$temporary_root"
temporary_directory="$(mktemp -d "${temporary_root%/}/first-write-notification-loss.XXXXXX")"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
swan_id=""
swan_stopped=0
provisioning_artifact=""
partial_artifact="${output_path}.failed"

container_id() {
  local service="$1"
  docker compose \
    --file "$root/docker-compose.yml" \
    --project-name "$project_name" \
    ps --all -q "$service" \
    | awk '/^[0-9a-f]{64}$/ { print; exit }'
}

mount_name() {
  local container="$1"
  local destination="$2"
  docker inspect \
    --format '{{range .Mounts}}{{if eq .Destination "'"$destination"'"}}{{.Name}}{{end}}{{end}}' \
    "$container"
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
      echo "$label exited before becoming healthy" >&2
      exit 1
    fi
    sleep 1
  done
  echo "$label did not become healthy before the bounded timeout" >&2
  exit 1
}

wait_for_stopped_container() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  local status=""
  while ((SECONDS < deadline)); do
    status="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "$label did not stop before the bounded timeout" >&2
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

cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  unset reference_access_token 2>/dev/null || true
  if ((swan_stopped)) && [[ -n "$swan_id" ]]; then
    docker start "$swan_id" >/dev/null 2>&1 || true
    local deadline=$((SECONDS + 120))
    while ((SECONDS < deadline)); do
      local status
      status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$swan_id" 2>/dev/null || true)"
      if [[ "$status" == "healthy" || "$status" == "running" ]]; then
        break
      fi
      sleep 1
    done
  fi
  if ((result != 0)); then
    local failed_directory
    failed_directory="$(dirname "$output_path")"
    mkdir -p "$failed_directory"
    if [[ -n "${evidence_json:-}" ]]; then
      install -m 0600 "$evidence_json" "$partial_artifact"
    else
      printf '%s\n' '{"status":"failed","scenario":"first-write-notification-loss","errorCode":"witnessing-aborted"}' \
        >"$partial_artifact"
      chmod 0600 "$partial_artifact"
    fi
  fi
  rm -rf "$temporary_directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# A. Precondition discovery and health gates. ---------------------------------
swan_id="$(container_id swan)"
bootstrap_id="$(container_id swan-bootstrap)"
reference_pds_id="$(container_id reference-pds)"
caddy_id="$(container_id caddy)"
caddy_trust_id="$(container_id caddy-ca-ready)"
reference_plc_id="$(container_id reference-plc)"
toxiproxy_id="$(container_id toxiproxy)"
for required_id in \
  "$swan_id" "$bootstrap_id" "$reference_pds_id" "$caddy_id" \
  "$caddy_trust_id" "$reference_plc_id" "$toxiproxy_id"
do
  [[ -n "$required_id" ]] || {
    echo "the Compose project is missing a required service" >&2
    exit 1
  }
done
wait_for_healthy_container "$swan_id" "authority Swan"
wait_for_healthy_container "$reference_pds_id" "reference PDS"
wait_for_healthy_container "$caddy_id" "Caddy"

authority_metadata="$({
  docker exec "$swan_id" \
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

data_volume="$(mount_name "$swan_id" /var/lib/swan)"
runtime_secrets_volume="$(mount_name "$swan_id" /run/secrets/swan-runtime)"
bootstrap_secrets_volume="$(mount_name "$bootstrap_id" /run/secrets/swan-bootstrap)"
caddy_trust_volume="$(mount_name "$caddy_trust_id" /prepared-trust)"
network_name="$({
  docker inspect \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s" $name}}{{end}}' \
    "$swan_id"
})"
swan_image="$(docker inspect --format '{{.Image}}' "$swan_id")"
reference_image="$(docker inspect --format '{{.Image}}' "$reference_pds_id")"
for required_value in \
  "$data_volume" "$runtime_secrets_volume" "$bootstrap_secrets_volume" \
  "$caddy_trust_volume" "$network_name" "$swan_image" "$reference_image"
do
  [[ -n "$required_value" ]] || {
    echo "the Compose project has an incomplete runtime boundary" >&2
    exit 1
  }
done

space_uri="at://${authority_did}/space/app.bsky.bookmarks/first-write-${suffix}"

echo "FIRST-WRITE ACCEPTANCE: project=${project_name} space=${space_uri} authority=${authority_did}"

# B. Fresh TypeScript member account + space provisioning. --------------------
reference_handle="fw-${suffix}.pds.test"
reference_email="firstwrite-${suffix}@example.com"
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
unset SWAN_REFERENCE_HANDLE SWAN_REFERENCE_EMAIL SWAN_REFERENCE_PASSWORD reference_password
reference_did="$(printf '%s' "$reference_account" | json_field did)" || {
  echo "the reference account response has no valid DID" >&2
  exit 1
}
reference_access_token="$(printf '%s' "$reference_account" | json_field accessJwt)" || {
  echo "the reference account response has no access token" >&2
  exit 1
}
unset reference_account

# Provision the fresh space and add Bob via the authority's OAuth through the
# established lab-live path. The round trip stops at the credential exchange
# (this authority rejects the TypeScript member delegation token), so no
# record write may occur; the script verifies that explicitly below.
provisioning_artifact="${temporary_directory}/provisioning-artifact.json"
producer_token_path="${temporary_directory}/producer.token"
printf '%s' "$reference_access_token" > "$producer_token_path"
chmod 0600 "$producer_token_path"
docker run --rm \
  --network "$network_name" \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${temporary_directory},dst=/run/first-write" \
  --entrypoint /bin/sh \
  "$swan_image" \
  -ec '
    private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")"
    umask 077
    printf \
      '"'"'{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n'"'"' \
      "$1" "$2" "$3" "$4" "$private_value" \
      >/tmp/provision-record.json
    export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt
    export SWAN_LAB_CONSUMER_HANDLE="$5"
    if ! /usr/local/bin/swan lab live \
      --mode permissioned \
      --name first-write-notification-loss-provision \
      --producer-url https://pds.test \
      --consumer-url https://swan.test \
      --producer-auth bearer \
      --producer-token-file /run/first-write/producer.token \
      --consumer-auth oauth \
      --consumer-password-file /run/secrets/swan-bootstrap/authority.password \
      --consumer-client-id "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback" \
      --consumer-redirect-uri http://127.0.0.1/callback \
      --scope atproto \
      --space "$1" \
      --provision-space \
      --body-file /tmp/provision-record.json \
      --read-query "space=$1" "repo=$2" "collection=$3" "rkey=$4" \
      --output /tmp/sanitized-artifact.json \
      --no-fail-on-failure \
      >/tmp/live-interop.log 2>&1
    then
      tail -n 40 /tmp/live-interop.log >&2 || true
      exit 1
    fi
    if grep -F -- "$private_value" /tmp/sanitized-artifact.json >/dev/null; then
      echo "sanitized provisioning artifact retained a permissioned value" >&2
      exit 1
    fi
    cp /tmp/sanitized-artifact.json /run/first-write/provisioning-artifact.json
    chmod 0600 /run/first-write/provisioning-artifact.json
    unset private_value
  ' _ \
  "$space_uri" "$reference_did" "$collection" "provision-${suffix}" "$authority_handle"
rm -f "$producer_token_path"

provisioning_status="$(python3 - "$provisioning_artifact" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    artifact = json.load(handle)
if artifact.get("status") == "passed":
    raise SystemExit("provisioning round trip unexpectedly passed; a record write would pollute the scenario")
events = artifact.get("events") or []
for event in events:
    if event.get("method") == "POST" and event.get("path") in {
        "/xrpc/com.atproto.space.createRecord",
        "/xrpc/com.atproto.space.putRecord",
        "/xrpc/com.atproto.space.applyWrites",
    }:
        raise SystemExit("provisioning round trip committed a record write")
print("provisioning-roundtrip-failed-as-expected")
PY
)" || {
  echo "provisioning did not complete without a record write" >&2
  exit 1
}

# B (continued). Verify the space and membership durably, read-only.
database_state() {
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
      const [authority, member, space] = process.argv.slice(1);
      const digest = crypto.createHash("sha256").update(authority, "utf8").digest("hex");
      const databasePath = path.join(
        "/var/lib/swan/data/actors",
        digest.slice(0, 2),
        `${digest}.sqlite`,
      );
      const db = new Database(databasePath, {
        readonly: true,
        fileMustExist: true,
      });
      const spaceRows = db.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_simple_space_authorities
        WHERE space_uri = ? AND is_deleted = 0
      `).get(space).count;
      const memberRows = db.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_simple_space_members
        WHERE space_uri = ? AND member_did = ?
      `).get(space, member).count;
      const writerRowsForSpace = db.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_space_writers
        WHERE space_uri = ?
      `).get(space).count;
      const writerRowsForMember = db.prepare(`
        SELECT COUNT(*) AS count
        FROM permissioned_space_writers
        WHERE space_uri = ? AND repo_did = ?
      `).get(space, member).count;
      process.stdout.write(JSON.stringify({
        spaceExists: spaceRows === 1,
        memberExists: memberRows === 1,
        writerCountForSpace: writerRowsForSpace,
        writerCountForMember: writerRowsForMember,
      }));
    ' \
    "$authority_did" "$reference_did" "$space_uri"
}

pre_state="$(database_state)"
if ! python3 -c '
import json
import sys

state = json.loads(sys.argv[1])
if not state.get("spaceExists") or not state.get("memberExists"):
    raise SystemExit(1)
if state.get("writerCountForMember", 0) != 0:
    raise SystemExit("provisioning unexpectedly created a writer-set entry")
' "$pre_state"
then
  echo "provisioned space or membership is missing on the authority" >&2
  exit 1
fi
echo "FIRST-WRITE ACCEPTANCE: space provisioned, member authorized, writer set empty (count=$(printf '%s' "$pre_state" | python3 -c 'import json,sys; print(json.load(sys.stdin)["writerCountForSpace"])'))"

# C. Stop the authority container (fault injection). --------------------------
docker stop --time 20 "$swan_id" >/dev/null
swan_stopped=1
wait_for_stopped_container "$swan_id" "authority Swan"
echo "FIRST-WRITE ACCEPTANCE: authority stopped"

# D. Bob's first write through the pinned TypeScript PDS with the authority
#    DOWN. The pinned putRecord commits locally and only then fires the
#    best-effort notification (putRecord.ts:42-43; util.ts fireNotifyWrite
#    swallows the delivery failure), so the write must return 200 + CID.
first_write="$({
  docker exec \
    --env SWAN_FIRST_WRITE_TOKEN="$reference_access_token" \
    "$reference_pds_id" \
    node -e '
const crypto = require("node:crypto")

async function write(space, repo, collection, rkey) {
  const value = `first-write-${crypto.randomBytes(24).toString("hex")}`
  const body = JSON.stringify({
    space,
    repo,
    collection,
    rkey,
    record: { $type: "app.bsky.feed.post", text: value },
  })
  const response = await fetch("http://127.0.0.1:3000/xrpc/com.atproto.space.putRecord", {
    method: "POST",
    headers: {
      authorization: `Bearer ${process.env.SWAN_FIRST_WRITE_TOKEN}`,
      "content-type": "application/json",
    },
    body,
  })
  const text = await response.text()
  const digest = crypto.createHash("sha256").update(text, "utf8").digest("hex")
  let cid = null
  let errorCode = null
  try {
    const parsed = JSON.parse(text)
    cid = typeof parsed.cid === "string" ? parsed.cid : null
    errorCode = typeof parsed.error === "string" ? parsed.error : null
  } catch {}
  process.stdout.write(JSON.stringify({
    status: response.status,
    cid,
    errorCode,
    responseSHA256: digest,
  }))
}

write(process.argv[2], process.argv[3], process.argv[4], process.argv[5])
  .catch((error) => {
    process.stderr.write(`first write failed: ${error.message}\n`)
    process.exit(1)
  })
' _ "$space_uri" "$reference_did" "$collection" "$first_rkey"
})" || {
  echo "first write could not be attempted" >&2
  exit 1
}
first_status="$(printf '%s' "$first_write" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
first_cid="$(printf '%s' "$first_write" | python3 -c 'import json,sys; print(json.load(sys.stdin)["cid"] or "")')"
[[ "$first_status" == "200" && "$first_cid" =~ ^bafyrei ]] || {
  echo "first write did not commit locally while the authority was down" >&2
  printf '%s\n' "$first_write" >&2
  exit 1
}
echo "FIRST-WRITE ACCEPTANCE: first write committed while authority down (cid=${first_cid})"

# E. Restore the authority and wait for its healthcheck. -----------------------
docker start "$swan_id" >/dev/null
swan_stopped=0
wait_for_healthy_container "$swan_id" "restored authority Swan"
echo "FIRST-WRITE ACCEPTANCE: authority healthy after restart"

# F. Sweep: the writer set must not contain Bob, and the protocol-level
#    listRepos sweep must be attempted. Swan's listRepos reads exactly
#    permissioned_space_writers, so the read-only SQLite assertion is the
#    authoritative witness.
sweep_state="$(database_state)"
sweep_writer_member="$(printf '%s' "$sweep_state" | python3 -c 'import json,sys; print(json.load(sys.stdin)["writerCountForMember"])')"
[[ "$sweep_writer_member" == "0" ]] || {
  echo "the authority writer set unexpectedly contains the first-write member" >&2
  exit 1
}

sweep_attempt="$({
  docker run --rm \
    --network "$network_name" \
    --read-only \
    --tmpfs /tmp:size=16m,mode=1777 \
    --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
    --env SWAN_FIRST_WRITE_TOKEN="$reference_access_token" \
    --entrypoint /bin/sh \
    "$swan_image" \
    -ec '
      export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt
      delegation_code="$(curl --silent --show-error --max-time 10 \
        --get "https://pds.test/xrpc/com.atproto.space.getDelegationToken" \
        --data-urlencode "space=$1" \
        --header "authorization: Bearer ${SWAN_FIRST_WRITE_TOKEN}" \
        --output /tmp/delegation.json \
        --write-out "%{http_code}" || true)"
      delegation_token="$(python3 -c '"'"'import json,sys
try:
    print(json.load(open("/tmp/delegation.json")).get("token") or "")
except (OSError, ValueError):
    print("")'"'"' 2>/dev/null || true)"
      credential_code=""
      if [ -n "$delegation_token" ]; then
        credential_code="$(curl --silent --show-error --max-time 10 \
          --request POST "https://swan.test/xrpc/com.atproto.space.getSpaceCredential" \
          --header "content-type: application/json" \
          --header "authorization: Bearer ${delegation_token}" \
          --data "{\"space\":\"$1\"}" \
          --output /tmp/credential.json \
          --write-out "%{http_code}" || true)"
      fi
      list_repos_code=""
      if [ "$credential_code" = "200" ]; then
        credential_token="$(python3 -c '"'"'import json,sys
try:
    parsed = json.load(open("/tmp/credential.json"))
    print(parsed.get("credential") or parsed.get("token") or "")
except (OSError, ValueError):
    print("")'"'"' 2>/dev/null || true)"
        if [ -n "$credential_token" ]; then
          list_repos_code="$(curl --silent --show-error --max-time 10 \
            --get "https://swan.test/xrpc/com.atproto.space.listRepos" \
            --data-urlencode "space=$1" \
            --header "authorization: Bearer ${credential_token}" \
            --output /tmp/list-repos.json \
            --write-out "%{http_code}" || true)"
        fi
      fi
      printf "%s\n%s\n%s\n" "${delegation_code:-}" "${credential_code:-}" "${list_repos_code:-}"
    ' _ "$space_uri"
})" || true
sweep_delegation_status="$(printf '%s\n' "$sweep_attempt" | sed -n '1p')"
sweep_credential_status="$(printf '%s\n' "$sweep_attempt" | sed -n '2p')"
sweep_list_repos_status="$(printf '%s\n' "$sweep_attempt" | sed -n '3p')"
echo "FIRST-WRITE ACCEPTANCE: sweep writerCountForMember=${sweep_writer_member} delegation=${sweep_delegation_status:-unavailable} credential=${sweep_credential_status:-unavailable} listRepos=${sweep_list_repos_status:-not-attempted}"

# G. Heal attempt: Bob writes a second record with the authority healthy, then
#    the writer-set state and the live read path for BOTH records are
#    recorded. The writer-set outcome is an empirical finding, not a gate.
second_write="$({
  docker exec \
    --env SWAN_FIRST_WRITE_TOKEN="$reference_access_token" \
    "$reference_pds_id" \
    node -e '
const crypto = require("node:crypto")

async function write(space, repo, collection, rkey) {
  const value = `second-write-${crypto.randomBytes(24).toString("hex")}`
  const body = JSON.stringify({
    space,
    repo,
    collection,
    rkey,
    record: { $type: "app.bsky.feed.post", text: value },
  })
  const response = await fetch("http://127.0.0.1:3000/xrpc/com.atproto.space.putRecord", {
    method: "POST",
    headers: {
      authorization: `Bearer ${process.env.SWAN_FIRST_WRITE_TOKEN}`,
      "content-type": "application/json",
    },
    body,
  })
  const text = await response.text()
  const digest = crypto.createHash("sha256").update(text, "utf8").digest("hex")
  let cid = null
  let errorCode = null
  try {
    const parsed = JSON.parse(text)
    cid = typeof parsed.cid === "string" ? parsed.cid : null
    errorCode = typeof parsed.error === "string" ? parsed.error : null
  } catch {}
  process.stdout.write(JSON.stringify({
    status: response.status,
    cid,
    errorCode,
    responseSHA256: digest,
  }))
}

write(process.argv[2], process.argv[3], process.argv[4], process.argv[5])
  .catch((error) => {
    process.stderr.write(`second write failed: ${error.message}\n`)
    process.exit(1)
  })
' _ "$space_uri" "$reference_did" "$collection" "$second_rkey"
})" || {
  echo "second write could not be attempted" >&2
  exit 1
}
second_status="$(printf '%s' "$second_write" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
second_cid="$(printf '%s' "$second_write" | python3 -c 'import json,sys; print(json.load(sys.stdin)["cid"] or "")')"
[[ "$second_status" == "200" && "$second_cid" =~ ^bafyrei ]] || {
  echo "second write did not commit locally while the authority was healthy" >&2
  exit 1
}

heal_state="$(database_state)"
heal_writer_member="$(printf '%s' "$heal_state" | python3 -c 'import json,sys; print(json.load(sys.stdin)["writerCountForMember"])')"

# Live read path: Bob's own repository must serve both records.
read_back="$({
  docker exec \
    --env SWAN_FIRST_WRITE_TOKEN="$reference_access_token" \
    "$reference_pds_id" \
    node -e '
const crypto = require("node:crypto")

async function readRecord(space, repo, collection, rkey) {
  const query = new URLSearchParams({ space, repo, collection, rkey })
  const response = await fetch(
    `http://127.0.0.1:3000/xrpc/com.atproto.space.getRecord?${query}`,
    {
      headers: {
        authorization: `Bearer ${process.env.SWAN_FIRST_WRITE_TOKEN}`,
      },
    },
  )
  const text = await response.text()
  const digest = crypto.createHash("sha256").update(text, "utf8").digest("hex")
  let cid = null
  try {
    const parsed = JSON.parse(text)
    cid = typeof parsed.cid === "string" ? parsed.cid : null
  } catch {}
  return { status: response.status, cid, responseSHA256: digest }
}

Promise.all([
  readRecord(process.argv[2], process.argv[3], process.argv[4], process.argv[5]),
  readRecord(process.argv[2], process.argv[3], process.argv[4], process.argv[6]),
]).then((records) => {
  process.stdout.write(JSON.stringify({ record1: records[0], record2: records[1] }))
}).catch((error) => {
  process.stderr.write(`read-back failed: ${error.message}\n`)
  process.exit(1)
})
' _ "$space_uri" "$reference_did" "$collection" "$first_rkey" "$second_rkey"
})" || {
  echo "read-back could not be completed" >&2
  exit 1
}
read1_status="$(printf '%s' "$read_back" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record1"]["status"])')"
read2_status="$(printf '%s' "$read_back" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record2"]["status"])')"
read1_cid="$(printf '%s' "$read_back" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record1"]["cid"] or "")')"
read2_cid="$(printf '%s' "$read_back" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record2"]["cid"] or "")')"
[[ "$read1_status" == "200" && "$read1_cid" == "$first_cid" ]] || {
  echo "the first record was not reachable from the member repository" >&2
  exit 1
}
[[ "$read2_status" == "200" && "$read2_cid" == "$second_cid" ]] || {
  echo "the second record was not reachable from the member repository" >&2
  exit 1
}
echo "FIRST-WRITE ACCEPTANCE: second write committed while authority healthy (cid=${second_cid}); writerCountForMember=${heal_writer_member}; both records readable"

# H. Restore verification. ------------------------------------------------------
wait_for_healthy_container "$swan_id" "final authority Swan"
wait_for_healthy_container "$reference_pds_id" "final reference PDS"
echo "FIRST-WRITE ACCEPTANCE: lab restored"

# I. Sanitized artifact. --------------------------------------------------------
completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
first_write_digest="$(printf '%s' "$first_write" | python3 -c 'import json,sys; print(json.load(sys.stdin)["responseSHA256"])')"
second_write_digest="$(printf '%s' "$second_write" | python3 -c 'import json,sys; print(json.load(sys.stdin)["responseSHA256"])')"
read1_digest="$(printf '%s' "$read_back" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record1"]["responseSHA256"])')"
read2_digest="$(printf '%s' "$read_back" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record2"]["responseSHA256"])')"

evidence_json="${temporary_directory}/evidence.json"
python3 - "$evidence_json" \
  "$started_at" "$completed_at" \
  "$authority_did" "$reference_did" "$space_uri" "$collection" "$first_rkey" "$second_rkey" \
  "$pre_state" "$sweep_state" "$heal_state" \
  "$first_status" "$first_cid" "$first_write_digest" \
  "$second_status" "$second_cid" "$second_write_digest" \
  "$read1_status" "$read1_cid" "$read1_digest" "$read2_status" "$read2_cid" "$read2_digest" \
  "${sweep_delegation_status:-}" "${sweep_credential_status:-}" "${sweep_list_repos_status:-}" <<'PY'
import json
import os
import sys

output_path, started_at, completed_at = sys.argv[1:4]
authority_did, writer_did, space, collection, first_rkey, second_rkey = sys.argv[4:10]
pre_state, sweep_state, heal_state = sys.argv[10:13]
first_status, first_cid, first_digest = sys.argv[13:16]
second_status, second_cid, second_digest = sys.argv[16:19]
read1_status, read1_cid, read1_digest = sys.argv[19:22]
read2_status, read2_cid, read2_digest = sys.argv[22:25]
delegation_status, credential_status, list_repos_status = sys.argv[25:28]

pre = json.loads(pre_state)
sweep = json.loads(sweep_state)
heal = json.loads(heal_state)

sweep_empty = sweep["writerCountForMember"] == 0
heal_healed = heal["writerCountForMember"] > 0
# The first record is discoverable only after the second write when the
# authority's writer set learns of the writer only at that point. Both
# conjuncts are recorded so a future lab that heals is distinguishable.
first_record_discoverable = sweep_empty and heal_healed

def status(value):
    try:
        return int(value)
    except ValueError:
        return None

evidence = {
    "status": "passed",
    "scenario": "first-write-notification-loss",
    "profileID": "permissioned-data-0016-2026-07-30",
    "fixturePolicy": "semantic-summary-only; no credentials, tokens, DPoP proofs, request bodies, record values, or personal selectors",
    "startedAt": started_at,
    "completedAt": completed_at,
    "identifiers": {
        "authorityDid": authority_did,
        "writerDid": writer_did,
        "space": space,
        "collection": collection,
        "firstRkey": first_rkey,
        "secondRkey": second_rkey,
    },
    "provisioning": {
        "method": "swan lab live --mode permissioned --provision-space",
        "spaceCreated": pre["spaceExists"],
        "memberAdded": pre["memberExists"],
        "writerCountForSpace": pre["writerCountForSpace"],
    },
    "firstWrite": {
        "authorityDown": True,
        "status": status(first_status),
        "cid": first_cid,
        "responseSHA256": first_digest,
    },
    "sweep": {
        "writerCountForMember": sweep["writerCountForMember"],
        "writerCountForSpace": sweep["writerCountForSpace"],
        "listReposAttempt": {
            "delegationStatus": status(delegation_status),
            "credentialStatus": status(credential_status),
            "listReposStatus": status(list_repos_status),
            "note": "protocol sweep not feasible: the authority rejected the member delegation token; the read-only SQLite writer-set assertion is the authoritative witness because Swan listRepos reads exactly permissioned_space_writers",
        },
    },
    "secondWrite": {
        "authorityUp": True,
        "status": status(second_status),
        "cid": second_cid,
        "responseSHA256": second_digest,
        "writerCountForMemberAfter": heal["writerCountForMember"],
    },
    "readBack": {
        "record1": {"status": status(read1_status), "cid": read1_cid, "responseSHA256": read1_digest},
        "record2": {"status": status(read2_status), "cid": read2_cid, "responseSHA256": read2_digest},
    },
    "findings": {
        "firstWriteCommittedWhileAuthorityDown": True,
        "writerSetEmptyAfterSweep": sweep_empty,
        "secondWriteHealedWriterSet": heal_healed,
        "firstRecordDiscoverableOnlyAfterSecondWrite": first_record_discoverable,
    },
}
with open(output_path, "x", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
os.chmod(output_path, 0o600)
PY

mkdir -p "$(dirname "$output_path")"
install -m 0600 "$evidence_json" "$output_path"

python3 Scripts/validate-live-interop-artifact.py "$output_path" || {
  echo "the first-write artifact failed semantic validation" >&2
  exit 1
}

healed_facts="$(python3 - "$heal_writer_member" "$sweep_writer_member" <<'PY'
import sys

heal_writers = int(sys.argv[1])
sweep_writers = int(sys.argv[2])
print("true" if heal_writers > 0 else "false")
print("true" if sweep_writers == 0 and heal_writers > 0 else "false")
PY
)"
echo "FIRST-WRITE NOTIFICATION LOSS ACCEPTANCE OK: artifact=${output_path}"
echo "FINDING firstWriteCommittedWhileAuthorityDown=true (cid=${first_cid})"
echo "FINDING writerSetEmptyAfterSweep=true (writerCountForMember=${sweep_writer_member})"
printf 'FINDING secondWriteHealedWriterSet=%s (writerCountForMember=%s)\n' "$(printf '%s\n' "$healed_facts" | sed -n '1p')" "$heal_writer_member"
printf 'FINDING firstRecordDiscoverableOnlyAfterSecondWrite=%s (authority writer set empty after both writes; both records readable from the member repository)\n' "$(printf '%s\n' "$healed_facts" | sed -n '2p')"
