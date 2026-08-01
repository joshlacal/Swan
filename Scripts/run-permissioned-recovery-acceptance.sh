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
runner_container=""
runner_id=""
runner_id_file=""
runner_cleanup_armed=0
runner_pid=""
operation_deadline=0
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
  local deadline="${3:-$((SECONDS + wait_timeout))}"
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
  local deadline="${2:-$((SECONDS + wait_timeout))}"
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

capture_runner_id() {
  local candidate
  if [[ -n "$runner_id" ]]; then
    return 0
  fi
  [[ -n "$runner_id_file" && -f "$runner_id_file" ]] || return 1
  candidate="$(tr -d '\r\n' < "$runner_id_file")"
  [[ "$candidate" =~ ^[a-f0-9]{64}$ ]] || return 1
  runner_id="$candidate"
}

remove_runner() {
  # `docker create` writes the exact ID to an owner-only file before the
  # attach client can exist. Do not resolve by name, and never wait for that
  # client here: Docker tears down its attached stream when this remove wins.
  if capture_runner_id; then
    docker rm --force "$runner_id" >/dev/null 2>&1 || true
  fi
  runner_id=""
  runner_pid=""
  runner_cleanup_armed=0
}

restore_normal_swan() {
  local restore_deadline=$((SECONDS + wait_timeout))
  if ((runner_cleanup_armed == 1)); then
    remove_runner
  fi
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
  wait_for_loopback_health "$normal_swan_id" "restored normal Swan" "$restore_deadline"
  wait_for_caddy_health "restored normal Swan" "$restore_deadline"
}

cleanup() {
  local result=$?
  # Once cleanup begins, follow-on termination signals must not interrupt the
  # restoration of the exact original Swan container.
  trap - EXIT
  trap '' INT TERM HUP
  set +e
  if ((runner_cleanup_armed == 1)) || [[ -n "$recovery_container" ]] || ((normal_stopped == 1)); then
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
runner_container="${project_name}-permissioned-recovery-runner-${PPID}-$$"
# This deadline covers the disruptive replacement and the named runner. It is
# derived directly from the user-bounded 1...600 second timeout; cleanup gets
# its own equally bounded restoration window after the runner is stopped.
operation_deadline=$((SECONDS + wait_timeout))

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
wait_for_loopback_health "$recovery_container" "retention-2 Swan" "$operation_deadline"
wait_for_caddy_health "retention-2 Swan" "$operation_deadline"
printf '%s\n' 'temporary-server-healthy' > "${temporary_directory}/stage.txt"
echo "permissioned recovery acceptance: temporary retention-2 Swan is healthy"

# The runner obtains the repository author's public P-256 key from Swan's
# durable signed PLC history through `account recovery-commit-key`. That narrow
# command verifies the DID/controller, CID chain, rotations, and exact atproto
# method binding before it prints public verification bytes; it never opens an
# account-key envelope or exposes private signing material.
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

wait_for_runner() {
  [[ -n "$runner_pid" ]] || return 1
  while kill -0 "$runner_pid" >/dev/null 2>&1; do
    if ((SECONDS >= operation_deadline)); then
      printf '%s\n' 'runner-timeout' > "${temporary_directory}/stage.txt"
      remove_runner
      return 124
    fi
    sleep 1
  done
  if ! wait "$runner_pid"; then
    remove_runner
    return 1
  fi
  remove_runner
}

# Arm cleanup before Docker can create the runner. The created ID is redirected
# to an owner-only file, so cleanup can remove the exact object even if a
# signal lands between `docker create` and shell assignment/start.
runner_script="${temporary_directory}/runner.sh"
runner_id_file="${temporary_directory}/runner.id"
install -m 0700 "$root/Scripts/permissioned-recovery-runner.sh" "$runner_script"
runner_cleanup_armed=1
docker create --name "$runner_container" -i \
  --network "$network_name" \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  --mount "type=volume,src=${data_volume},dst=/var/lib/swan" \
  --mount "type=volume,src=${bootstrap_secrets_volume},dst=/run/secrets/swan-bootstrap,readonly" \
  --mount "type=volume,src=${caddy_trust_volume},dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${temporary_directory},dst=/run/acceptance" \
  --entrypoint /bin/bash \
  "$image_tag" \
  /run/acceptance/runner.sh \
  "$space_uri" "$member_did" "$collection" "$client_id" \
  "$member_handle" "$authority_handle" "$authority_did" "$space_skey" \
  > "$runner_id_file"
capture_runner_id || {
  echo "Docker did not return a canonical runner ID" >&2
  exit 1
}

# The create is synchronous and the attach client's PID is assigned as the
# immediate next shell action. A failure between create and start is safe:
# cleanup already owns the exact `runner_id` and removes it without waiting.
docker start --attach --interactive "$runner_id" &
runner_pid=$!
if ! wait_for_runner; then
  [[ -f "${temporary_directory}/stage.txt" ]] || \
    printf '%s\n' 'runner-failed-pre-artifact' > "${temporary_directory}/stage.txt"
  exit 1
fi

if ! artifact_validation="$(python3 "$root/Scripts/validate-permissioned-recovery-artifact.py" "$runner_artifact")"; then
  case "$artifact_validation" in
    mode|fields|scenario|profile|status|gap|corruption|preserved|generation|prior|head|records|commitment|revision|error|policy)
      printf 'host-artifact-validation-%s\n' "$artifact_validation" > "${temporary_directory}/stage.txt"
      ;;
    *)
      printf '%s\n' 'host-artifact-validation-unknown' > "${temporary_directory}/stage.txt"
      ;;
  esac
  exit 1
fi

# `remove_runner` clears the lifecycle state only after Docker has received
# the exact created ID. There is deliberately no cleanup-time client wait.
runner_pid=""

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
