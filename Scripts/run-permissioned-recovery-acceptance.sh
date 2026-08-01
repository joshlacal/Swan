#!/usr/bin/env bash
set -euo pipefail

# Live, disposable acceptance for a real permissioned compaction gap.  This
# deliberately attaches to an already-running Compose project: it never calls
# Compose lifecycle commands, and it replaces only the resolved Swan process
# while retaining the project's data volume, network, Caddy, and trust root.
# All write bodies, passwords, OAuth material, PLC documents, and the pruned
# wire TID remain in a runner tmpfs.  Only the CLI's sanitized artifact leaves
# the runner.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"

project_name="${SWAN_PERMISSIONED_RECOVERY_PROJECT:-}"
output_path="${SWAN_PERMISSIONED_RECOVERY_OUTPUT:-${root}/artifacts/live/permissioned-recovery.json}"
wait_timeout="${SWAN_PERMISSIONED_RECOVERY_TIMEOUT:-180}"
image_tag=""
normal_swan_id=""
normal_stopped=0
recovery_container=""
temporary_directory=""
data_volume=""
runtime_secrets_volume=""
bootstrap_secrets_volume=""
caddy_trust_volume=""
network_name=""
caddy_id=""
swan_ip=""

[[ "$project_name" =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ ]] || {
  echo "SWAN_PERMISSIONED_RECOVERY_PROJECT must be a lowercase Compose project name" >&2
  exit 64
}
[[ "$output_path" = /* ]] || {
  echo "SWAN_PERMISSIONED_RECOVERY_OUTPUT must be an absolute path" >&2
  exit 64
}
if [[ ! "$wait_timeout" =~ ^[1-9][0-9]*$ ]] || ((wait_timeout > 600)); then
  echo "SWAN_PERMISSIONED_RECOVERY_TIMEOUT must be an integer from 1 through 600" >&2
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
docker version >/dev/null

SWAN_INTEROP_SECRETS_DIR="$(
  ./interop/verify-secret-source.sh "$root" "$SWAN_INTEROP_SECRETS_DIR"
)"
export SWAN_INTEROP_SECRETS_DIR

container_id_for_service() {
  local service="$1"
  local ids
  local count
  ids="$(docker ps --all \
    --filter "label=com.docker.compose.project=${project_name}" \
    --filter "label=com.docker.compose.service=${service}" \
    --format '{{.ID}}')"
  count="$(printf '%s\n' "$ids" | awk 'NF { count += 1 } END { print count + 0 }')"
  if [[ "$count" != 1 ]]; then
    echo "expected exactly one ${service} container in ${project_name}" >&2
    return 1
  fi
  printf '%s\n' "$ids"
}

mount_name() {
  local container="$1"
  local destination="$2"
  docker inspect \
    --format '{{range .Mounts}}{{if eq .Destination "'"$destination"'"}}{{.Name}}{{end}}{{end}}' \
    "$container"
}

wait_for_loopback_health() {
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
    local state
    state="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)"
    if [[ "$state" == "exited" || "$state" == "dead" ]]; then
      echo "${label} exited before its loopback health endpoint became ready" >&2
      return 1
    fi
    sleep 1
  done
  echo "${label} did not expose loopback /health before the bounded timeout" >&2
  return 1
}

wait_for_caddy_health() {
  local label="$1"
  local deadline=$((SECONDS + wait_timeout))
  while ((SECONDS < deadline)); do
    if docker run --rm \
      --network "$network_name" \
      --read-only \
      --tmpfs /tmp:size=16m,mode=1777 \
      --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
      --entrypoint curl \
      "$image_tag" \
      --fail --silent --show-error --max-time 2 \
      --cacert /etc/ssl/certs/caddy-local-root.crt \
      https://swan.test/health >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  echo "${label} did not become healthy through Caddy before the bounded timeout" >&2
  return 1
}

restore_normal_swan() {
  if [[ -n "$recovery_container" ]]; then
    docker rm --force "$recovery_container" >/dev/null 2>&1 || true
    recovery_container=""
  fi
  local normal_running
  normal_running="$(docker inspect --format '{{.State.Running}}' "$normal_swan_id" 2>/dev/null || true)"
  if [[ "$normal_running" != "true" ]]; then
    docker start "$normal_swan_id" >/dev/null
  fi
  normal_stopped=0
  wait_for_loopback_health "$normal_swan_id" "restored normal Swan"
  wait_for_caddy_health "restored normal Swan"
}

cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  set +e
  if [[ -n "$recovery_container" || $normal_stopped -eq 1 ]]; then
    if ! restore_normal_swan; then
      echo "failed to restore the exact normal Swan container ${normal_swan_id}" >&2
      result=1
    fi
  fi
  if [[ -n "$temporary_directory" && -d "$temporary_directory" ]]; then
    if ((result != 0)) && [[ -f "${temporary_directory}/stage.txt" ]]; then
      local diagnostic_directory
      local diagnostic_temporary
      diagnostic_directory="$(dirname "$output_path")"
      mkdir -p "$diagnostic_directory"
      diagnostic_temporary="$(mktemp "${diagnostic_directory}/.permissioned-recovery-failure.XXXXXX")"
      install -m 0600 "${temporary_directory}/stage.txt" "$diagnostic_temporary"
      mv -f "$diagnostic_temporary" "${output_path}.failed"
    fi
    rm -rf "$temporary_directory"
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

normal_swan_id="$(container_id_for_service swan)"
bootstrap_id="$(container_id_for_service swan-bootstrap)"
caddy_id="$(container_id_for_service caddy)"
caddy_trust_id="$(container_id_for_service caddy-ca-ready)"

[[ "$(docker inspect --format '{{.State.Running}}' "$normal_swan_id")" == "true" ]] || {
  echo "the resolved normal Swan container is not running" >&2
  exit 1
}
wait_for_loopback_health "$normal_swan_id" "normal Swan"

read_lab_value() {
  local name="$1"
  tr -d '\r\n' < "${SWAN_INTEROP_SECRETS_DIR}/${name}"
}

json_string_field() {
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

authority_handle="$(read_lab_value authority.handle)"
member_handle="$(read_lab_value member.handle)"
authority_metadata="$(docker exec "$normal_swan_id" /usr/local/bin/swan account show \
  --data-directory /var/lib/swan/data --handle "$authority_handle")" || {
  echo "the current project has no managed authority account" >&2
  exit 1
}
member_metadata="$(docker exec "$normal_swan_id" /usr/local/bin/swan account show \
  --data-directory /var/lib/swan/data --handle "$member_handle")" || {
  echo "the current project has no managed member account" >&2
  exit 1
}
authority_did="$(printf '%s' "$authority_metadata" | json_string_field did)" || exit 1
member_did="$(printf '%s' "$member_metadata" | json_string_field did)" || exit 1
authority_handle="$(printf '%s' "$authority_metadata" | json_string_field canonicalHandle)" || exit 1
member_handle="$(printf '%s' "$member_metadata" | json_string_field canonicalHandle)" || exit 1
if [[ ! "$authority_did" =~ ^did:[a-z0-9:._-]+$ ]] \
  || [[ ! "$member_did" =~ ^did:[a-z0-9:._-]+$ ]] \
  || [[ "$authority_did" == "$member_did" ]]; then
  echo "managed account metadata did not yield two distinct canonical DIDs" >&2
  exit 1
fi

data_volume="$(mount_name "$normal_swan_id" /var/lib/swan)"
runtime_secrets_volume="$(mount_name "$normal_swan_id" /run/secrets/swan-runtime)"
bootstrap_secrets_volume="$(mount_name "$bootstrap_id" /run/secrets/swan-bootstrap)"
caddy_trust_volume="$(mount_name "$caddy_trust_id" /prepared-trust)"
network_name="$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s" $name}}{{end}}' "$normal_swan_id")"
swan_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$normal_swan_id")"
caddy_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$caddy_id")"
for required_value in \
  "$data_volume" "$runtime_secrets_volume" "$bootstrap_secrets_volume" \
  "$caddy_trust_volume" "$network_name" "$swan_ip" "$caddy_ip"
do
  [[ -n "$required_value" ]] || {
    echo "the current project has an incomplete Swan runtime boundary" >&2
    exit 1
  }
done

# Keep this image name project-scoped without using Compose lifecycle/build
# commands. The fast path is deliberately strict: a missing current tag is a
# configuration error, not an excuse to silently run the normal service image.
image_tag="${project_name}-swan:task45-recovery"
if [[ "${SWAN_PERMISSIONED_RECOVERY_NO_BUILD:-0}" == "1" ]]; then
  docker image inspect "$image_tag" >/dev/null 2>&1 || {
    echo "SWAN_PERMISSIONED_RECOVERY_NO_BUILD=1 requires ${image_tag}" >&2
    exit 1
  }
else
  docker build --tag "$image_tag" --file "$root/Dockerfile" "$root/.."
fi

temporary_root="${root}/.interop-live"
mkdir -p "$temporary_root"
chmod 700 "$temporary_root"
temporary_directory="$(mktemp -d "${temporary_root}/permissioned-recovery.XXXXXX")"
chmod 700 "$temporary_directory"
runner_artifact="${temporary_directory}/artifact.json"
printf '%s\n' 'temporary-server-starting' > "${temporary_directory}/stage.txt"
recovery_container="${project_name}-permissioned-recovery-${PPID}-$$"

# No host port is published. Reusing the exact former Swan IP makes Caddy's
# already-resolved upstream target deterministic while the normal container is
# stopped, and the container name/alias preserves normal Compose DNS routing.
# Establish restoration intent before the mutating stop. Cleanup also inspects
# the original container's actual state, covering a signal in this command.
normal_stopped=1
docker stop --time 10 "$normal_swan_id" >/dev/null

docker run --detach \
  --name "$recovery_container" \
  --network "$network_name" \
  --ip "$swan_ip" \
  --network-alias swan \
  --read-only \
  --tmpfs /tmp:size=32m,mode=1777 \
  --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
  --mount "type=volume,src=${runtime_secrets_volume},dst=/run/secrets/swan-runtime,readonly" \
  "$image_tag" \
  serve \
  --host 0.0.0.0 \
  --port 3000 \
  --public-url https://swan.test \
  --profile /usr/local/share/swan/Profiles/permissioned-data-0016-2026-07-30.json \
  --data-directory /var/lib/swan/data \
  --space-oplog-retention 2 \
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
  --notification-config /etc/swan/interop/notification-config.json \
  --managing-service-audience did:web:interop-swan-managing-service \
  --enable-email-recovery \
  --email-proof-key-file /run/secrets/swan-runtime/email-proof-key \
  --email-sender no-reply@swan.local \
  --email-smtp-host mailpit \
  --email-smtp-port 1025 \
  >/dev/null
wait_for_loopback_health "$recovery_container" "retention-2 Swan"
wait_for_caddy_health "retention-2 Swan"
printf '%s\n' 'temporary-server-healthy' > "${temporary_directory}/stage.txt"
echo "permissioned recovery acceptance: temporary retention-2 Swan is healthy"

# The runner derives the repository author's public P-256 key from the live
# PLC DID document. It checks base58btc canonicality and the exact uncompressed
# X9.63 shape before exposing a base64url public verification key only to the
# recovery CLI environment. No account-key envelope or private scalar is read.
# A fresh bounded key makes a retained Compose volume repeatable without
# retaining a selector in the artifact or diagnostic marker. The authority
# DID remains derived from account show; only this non-secret selector varies.
space_skey="permissioned-recovery-$(python3 -c '
import secrets
print("".join(secrets.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(16)))
')"
space_uri="at://${authority_did}/space/app.bsky.bookmarks/${space_skey}"
collection="app.bsky.feed.post"
client_id="http://localhost?scope=atproto%20space%3Aapp.bsky.bookmarks%3Fauthority%3D${authority_did}%26skey%3D${space_skey}%26action%3Dread%20space%3Aapp.bsky.bookmarks%3Fauthority%3D${authority_did}%26skey%3D${space_skey}%26action%3Dcreate%26collection%3D${collection}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback"

docker run --rm -i \
  --network "$network_name" \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
  --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${temporary_directory},dst=/run/acceptance" \
  --entrypoint /bin/bash \
  "$image_tag" \
  -s -- \
  "$space_uri" "$member_did" "$collection" "$client_id" \
  "$member_handle" "$authority_handle" "$authority_did" "$space_skey" <<'RUNNER'
set -euo pipefail
umask 077
export HOME=/tmp
export SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt

space_uri="$1"
member_did="$2"
collection="$3"
client_id="$4"
member_handle="$5"
authority_handle="$6"
authority_did="$7"
space_skey="$8"
read_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${space_skey}&action=read"
create_scope="space:app.bsky.bookmarks?authority=${authority_did}&skey=${space_skey}&action=create&collection=${collection}"
export SWAN_LAB_PRODUCER_HANDLE="$member_handle"
export SWAN_LAB_CONSUMER_HANDLE="$authority_handle"
SWAN_LAB_PRODUCER_PASSWORD="$(tr -d '\r\n' < /run/secrets/swan-bootstrap/member.password)"
SWAN_LAB_CONSUMER_PASSWORD="$(tr -d '\r\n' < /run/secrets/swan-bootstrap/authority.password)"
export SWAN_LAB_PRODUCER_PASSWORD SWAN_LAB_CONSUMER_PASSWORD
stage() { printf '%s\n' "$1" > /run/acceptance/stage.txt; }
diagnostic_code() {
  case "$1" in
    HTTP[1-5][0-9][0-9]|InvalidURL|ResponseTooLarge|UnexpectedRedirect|UnexpectedContentType|TransportFailure|FileFailure|InteropFailure|UnknownError)
      printf '%s\n' "$1"
      ;;
    *)
      printf '%s\n' unknown
      ;;
  esac
}
stage key-derivation-start

curl --fail --silent --show-error --max-time 10 \
  "http://reference-plc:2582/${member_did}" >/tmp/member-plc.json
SWAN_LAB_PERMISSIONED_COMMIT_KEY="$(swift - <<'SWIFT'
import Foundation

let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
let index = Dictionary(uniqueKeysWithValues: alphabet.enumerated().map { ($0.element, $0.offset) })
func decode(_ text: String) -> [UInt8]? {
    var bytes: [UInt8] = []
    let leadingZeroes = text.utf8.prefix { $0 == alphabet[0] }.count
    for scalar in text.utf8 {
        guard let value = index[scalar] else { return nil }
        var carry = value
        for offset in bytes.indices.reversed() {
            let combined = Int(bytes[offset]) * 58 + carry
            bytes[offset] = UInt8(combined & 0xff)
            carry = combined >> 8
        }
        while carry > 0 { bytes.insert(UInt8(carry & 0xff), at: 0); carry >>= 8 }
    }
    bytes.insert(contentsOf: repeatElement(0, count: leadingZeroes), at: 0)
    return bytes
}
func encode(_ input: [UInt8]) -> String {
    var value = input
    var output: [UInt8] = []
    var start = 0
    while start < value.count && value[start] == 0 { start += 1 }
    let zeroes = start
    while start < value.count {
        var remainder = 0
        for offset in start..<value.count {
            let combined = remainder * 256 + Int(value[offset])
            value[offset] = UInt8(combined / 58)
            remainder = combined % 58
        }
        output.append(alphabet[remainder])
        while start < value.count && value[start] == 0 { start += 1 }
    }
    output.append(contentsOf: repeatElement(alphabet[0], count: zeroes))
    return String(bytes: output.reversed(), encoding: .utf8)!
}
let root = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "/tmp/member-plc.json")))
guard let object = root as? [String: Any],
      let methods = object["verificationMethod"] as? [[String: Any]],
      let encoded = methods.first?["publicKeyMultibase"] as? String,
      encoded.first == "z",
      let bytes = decode(String(encoded.dropFirst())),
      bytes.count == 65, bytes.first == 0x04,
      encode(bytes) == String(encoded.dropFirst()) else { exit(1) }
let b64 = Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
print("ES256:" + b64)
SWIFT
 )"
case "$SWAN_LAB_PERMISSIONED_COMMIT_KEY" in ES256:*) ;; *) exit 1;; esac
export SWAN_LAB_PERMISSIONED_COMMIT_KEY
stage key-derived

write_one() {
  local index="$1"
  local rkey="retention-${index}"
  local private_value
  private_value="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  printf '{"space":"%s","repo":"%s","collection":"%s","rkey":"%s","record":{"$type":"app.bsky.feed.post","text":"%s"}}\n' \
    "$space_uri" "$member_did" "$collection" "$rkey" "$private_value" >/tmp/record.json
  local -a command=(
    /usr/local/bin/swan lab live
    --mode permissioned --name "retention-write-${index}"
    --producer-url https://swan.test --consumer-url https://swan.test
    --producer-auth oauth --consumer-auth oauth
    --producer-client-id "$client_id" --producer-redirect-uri http://127.0.0.1/callback
    --consumer-client-id "$client_id" --consumer-redirect-uri http://127.0.0.1/callback
    --scope atproto --scope "$read_scope" --scope "$create_scope"
    --space "$space_uri" --body-file /tmp/record.json
    --read-query "space=$space_uri" "repo=$member_did" "collection=$collection" "rkey=$rkey"
    --output "/tmp/write-${index}.json"
  )
  if [[ "$index" == 1 ]]; then
    command+=(--provision-space --permissioned-list-ops --permissioned-list-ops-exclude-values)
  fi
  stage "write-${index}-start"
  if ! "${command[@]}" >/tmp/live.log 2>&1; then
    error_code="$(sed -n 's/.*"errorCode":"\([A-Za-z0-9_]*\)".*/\1/p' "/tmp/write-${index}.json" || true)"
    if [[ -n "$error_code" ]]; then
      stage "write-${index}-failed-$(diagnostic_code "$error_code")"
    elif grep -q 'permissioned space creation failed' /tmp/live.log; then
      stage "write-${index}-failed-space-create"
    elif grep -q 'permissioned space membership failed' /tmp/live.log; then
      stage "write-${index}-failed-space-member"
    elif grep -q 'OAuth' /tmp/live.log; then
      stage "write-${index}-failed-oauth"
    else
      stage "write-${index}-failed-pre-artifact"
    fi
    exit 1
  fi
  grep -q '"status":"passed"' "/tmp/write-${index}.json"
  if grep -F -- "$private_value" "/tmp/write-${index}.json" >/dev/null; then
    exit 1
  fi
  stage "write-${index}-passed"
}

write_one 1
earliest_tid="$(python3 - /tmp/write-1.json <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8")).get("syncOperationRevision")
if not isinstance(value, str) or not re.fullmatch(r"[a-z2-7]{13}", value):
    raise SystemExit(1)
print(value)
PY
)"
case "$earliest_tid" in [a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7][a-z2-7]) ;; *) exit 1;; esac
stage earliest-tid-pruned
write_one 2
write_one 3
echo "permissioned recovery acceptance: earliest wire TID was pruned"

stage recovery-start
if ! /usr/local/bin/swan lab recover-permissioned \
  --receiver-did "$authority_did" --repository "$member_did" --space "$space_uri" \
  --data-directory /var/lib/swan/data --name permissioned-retention-recovery \
  --source-url https://swan.test --authority-url https://swan.test \
  --source-auth oauth --source-client-id "$client_id" \
  --source-redirect-uri http://127.0.0.1/callback \
  --scope atproto --scope "$read_scope" --scope "$create_scope" \
  --since "$earliest_tid" --output /run/acceptance/artifact.json \
  --request-timeout-seconds 20 --no-fail-on-failure >/tmp/recovery.log 2>&1
then
  if grep -q 'OAuth' /tmp/recovery.log; then
    stage recovery-command-failed-oauth
  elif grep -q 'permissioned commit public key' /tmp/recovery.log; then
    stage recovery-command-failed-key
  elif grep -q 'receiver account' /tmp/recovery.log; then
    stage recovery-command-failed-receiver
  else
    stage recovery-command-failed-pre-artifact
  fi
  exit 1
fi
chmod 0600 /run/acceptance/artifact.json
stage "$(python3 - /run/acceptance/artifact.json <<'PY'
import json
import sys

allowed = {
    "CARBlockCIDMismatch", "RecoveryFailed", "RecoveryInvalidBinding",
    "RecoveryInvalidTimestamp", "RecoveryReceiverMismatch",
    "RecoveryUnknownSession", "RecoveryExpiredSession",
    "RecoveryImportInProgress", "RecoveryPoisonedSession",
    "RecoveryConflictingRequestReuse", "RecoveryBindingMismatch",
    "RecoveryVerificationRequired", "RecoveryInvalidStatus",
    "RetentionGapMissing", "CorruptRecoveryAccepted",
}
artifact = json.load(open(sys.argv[1], encoding="utf-8"))
if artifact.get("status") == "passed":
    print("recovery-artifact-passed")
else:
    code = artifact.get("errorCode")
    print("recovery-artifact-failed-" + (code if code in allowed else "unknown"))
PY
)"
unset earliest_tid SWAN_LAB_PERMISSIONED_COMMIT_KEY SWAN_LAB_PRODUCER_PASSWORD SWAN_LAB_CONSUMER_PASSWORD
RUNNER

if ! artifact_validation="$(python3 - "$runner_artifact" <<'PY'
import json
import os
import re
import stat
import sys

path = sys.argv[1]
def fail(code):
    print(code)
    raise SystemExit(1)

if stat.S_IMODE(os.stat(path).st_mode) != 0o600:
    fail("mode")
with open(path, encoding="utf-8") as source:
    artifact = json.load(source)
expected = {
    "scenario", "profileID", "gapStatus", "gapErrorCode", "priorHeadPresent",
    "validHeadGeneration", "validHeadRevision", "validCommitment", "validRecordCount",
    "corruptionRejected", "corruptErrorCode", "finalHeadGeneration", "finalHeadRevision",
    "finalCommitment", "lastValidHeadPreserved", "status", "errorCode", "fixturePolicy",
}
required = {
    "scenario", "profileID", "priorHeadPresent", "corruptionRejected",
    "lastValidHeadPreserved", "status", "fixturePolicy",
}
if not set(artifact).issubset(expected) or not required.issubset(artifact):
    fail("fields")
if artifact["status"] != "passed" or artifact["gapStatus"] != 409:
    fail("status")
if artifact["gapErrorCode"] != "full_repo_recovery_required":
    fail("gap")
if artifact["corruptErrorCode"] != "CARBlockCIDMismatch" or not artifact["corruptionRejected"]:
    fail("corruption")
if not artifact["lastValidHeadPreserved"]:
    fail("preserved")
if artifact["validHeadGeneration"] != artifact["finalHeadGeneration"] \
        or artifact["validHeadRevision"] != artifact["finalHeadRevision"] \
        or artifact["validCommitment"] != artifact["finalCommitment"]:
    fail("head")
if not isinstance(artifact["validRecordCount"], int) or artifact["validRecordCount"] < 1:
    fail("records")
if not re.fullmatch(r"[0-9a-f]{64}", artifact["validCommitment"] or ""):
    fail("commitment")
if not re.fullmatch(r"[a-z2-7]{13}", artifact["validHeadRevision"] or ""):
    fail("revision")
if artifact.get("errorCode") is not None:
    fail("error")
if artifact["fixturePolicy"] != "semantic-summary-only; no DIDs, space URIs, paths, request identities, verifier material, credentials, tokens, DPoP proofs, record values, or raw LtHash state":
    fail("policy")
PY
 )"; then
  case "$artifact_validation" in
    mode|fields|status|gap|corruption|preserved|head|records|commitment|revision|error|policy)
      printf 'host-artifact-validation-%s\n' "$artifact_validation" > "${temporary_directory}/stage.txt"
      ;;
    *)
      printf '%s\n' 'host-artifact-validation-unknown' > "${temporary_directory}/stage.txt"
      ;;
  esac
  exit 1
fi

output_directory="$(dirname "$output_path")"
mkdir -p "$output_directory"
output_temporary="$(mktemp "${output_directory}/.permissioned-recovery.XXXXXX")"
install -m 0600 "$runner_artifact" "$output_temporary"
mv -f "$output_temporary" "$output_path"
rm -f "${output_path}.failed"
[[ "$(stat -f '%Lp' "$output_path" 2>/dev/null || stat -c '%a' "$output_path")" == "600" ]] || {
  echo "final recovery artifact mode is not 0600" >&2
  exit 1
}

restore_normal_swan

echo "PERMISSIONED RECOVERY ACCEPTANCE OK: artifact=${output_path} normal_swan=${normal_swan_id}"
