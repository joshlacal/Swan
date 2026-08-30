#!/usr/bin/env bash
set -euo pipefail

# Focused reproduction for the `swan lab forum thread` syncer stall. Reuses
# the durable forum state from the last live demo run (space, members, posts)
# and runs ONLY the syncer against the normal Swan container with the
# recovery-qualified reference PDS, so the instrumented stage markers on
# stderr reveal exactly where the command stalls.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

project_name="${SWAN_FORUM_PROJECT:-swan-alpha-current-20260801}"
space_uri="${SWAN_FORUM_SPACE:-at://did:plc:dmwv2txmmakxe2u47adghce4/space/blue.catbird.lab.forum/forum-demo-d5143f80}"
receiver_did="${SWAN_FORUM_RECEIVER:-did:plc:tiu5zkymbgotqpoxll55ccyy}"
alice_did="did:plc:dmwv2txmmakxe2u47adghce4"
bob_did="did:plc:4ooojm4wsr23c6irj4t6mfrp"
alice_key="did:key:zDnaeTxCz368LjuGz4vEM1h5nUh8BGdBmRwCwuQKT7Q9rAiUt"
carol_key="did:key:zDnaewBUwFWXBz2owyKFbwui1cPn4VKRCXWaqNhkcFZGHtJza"
bob_key="did:key:zQ3shhKi5zALomKznrL9bZgZwFUT7HUu3XwgPALrhDyuCDRdw"
wait_timeout="${SWAN_FORUM_TIMEOUT:-300}"
[[ "$project_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$ ]] || exit 64
[[ -n "${SWAN_INTEROP_SECRETS_DIR:-}" ]] || {
  echo "SWAN_INTEROP_SECRETS_DIR is required" >&2
  exit 64
}

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

wait_for_health() {
  local container="$1"
  local label="$2"
  local deadline=$((SECONDS + wait_timeout))
  while ((SECONDS < deadline)); do
    local state
    state="$(
      docker inspect \
        --format '{{if .State.Running}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}{{.State.Status}}{{end}}' \
        "$container" 2>/dev/null || true
    )"
    if [[ "$state" == "healthy" || "$state" == "running" ]]; then
      return 0
    fi
    if [[ "$state" == "exited" || "$state" == "dead" ]]; then
      echo "$label exited" >&2
      exit 1
    fi
    sleep 1
  done
  echo "$label did not become healthy" >&2
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
    sleep 1
  done
  echo "$label did not expose its HTTP listener" >&2
  exit 1
}

normal_swan_id="$(container_id swan)"
reference_pds_id="$(container_id reference-pds)"
caddy_trust_id="$(container_id caddy-ca-ready)"
bootstrap_id="$(container_id swan-bootstrap)"
for required_id in "$normal_swan_id" "$reference_pds_id" "$caddy_trust_id" "$bootstrap_id"; do
  [[ -n "$required_id" ]] || exit 1
done
wait_for_health "$normal_swan_id" "Swan"
wait_for_health "$reference_pds_id" "reference PDS"

data_volume="$(mount_name "$normal_swan_id" /var/lib/swan)"
bootstrap_secrets_volume="$(mount_name "$bootstrap_id" /run/secrets/swan-bootstrap)"
caddy_trust_volume="$(mount_name "$caddy_trust_id" /prepared-trust)"
network_name="$(
  docker inspect \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s" $name}}{{end}}' \
    "$normal_swan_id"
)"
for required_value in "$data_volume" "$bootstrap_secrets_volume" "$caddy_trust_volume" "$network_name"; do
  [[ -n "$required_value" ]] || exit 1
done

temporary_directory="$(mktemp -d "${root}/.interop-live/forum-thread-debug.XXXXXX")"
recovery_deployed=0

cleanup() {
  local result=$?
  trap - EXIT INT TERM HUP
  if ((recovery_deployed)); then
    compose build reference-pds >/dev/null 2>&1 || true
    compose up -d reference-pds >/dev/null 2>&1 || true
  fi
  rm -rf "$temporary_directory"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat > "$temporary_directory/tls-override.yml" <<EOF
services:
  reference-pds:
    build:
      dockerfile: Swan/interop/Dockerfile.reference-pds-recovery
volumes: {}
EOF

compose \
  --file "$root/docker-compose.yml" \
  --file "$root/interop/docker-compose.reference-recovery.yml" \
  --file "$temporary_directory/tls-override.yml" \
  build reference-pds >/dev/null 2>&1
compose \
  --file "$root/docker-compose.yml" \
  --file "$temporary_directory/tls-override.yml" \
  up -d reference-pds >/dev/null 2>&1
recovery_deployed=1
reference_pds_id="$(container_id reference-pds)"
wait_for_health "$reference_pds_id" "reference PDS"

skey="${space_uri##*/}"
authority_did="${alice_did}"
read_scope="space:blue.catbird.lab.forum?authority=${authority_did}&skey=${skey}&action=read"
create_scope="space:blue.catbird.lab.forum?authority=${authority_did}&skey=${skey}&action=create&collection=blue.catbird.lab.post"
scope_client_id="$(python3 - "$read_scope" "$create_scope" <<'PY'
import sys
from urllib.parse import quote

print("http://localhost?scope=" + quote("atproto " + sys.argv[1] + " " + sys.argv[2], safe="") +
      "&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")
PY
)"

echo "FORUM THREAD DEBUG: running syncer for $space_uri"
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
  --env SWAN_SYNC_STAGE_LOG=1 \
  --entrypoint /bin/sh \
  "${project_name}-swan:latest" \
  -ec '
    umask 077
    SWAN_LAB_AUTHORITY_HANDLE="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/authority.handle)"
    SWAN_LAB_CONSUMER_HANDLE="$(tr -d "\r\n" < /run/secrets/swan-bootstrap/member.handle)"
    export SWAN_LAB_AUTHORITY_HANDLE
    export SWAN_LAB_CONSUMER_HANDLE
    exec /usr/local/bin/swan lab forum thread \
      --consumer-url https://swan.test \
      --authority-url https://swan.test \
      --space "$1" \
      --receiver-did "$2" \
      --data-directory /var/lib/swan/data \
      --consumer-auth oauth \
      --consumer-password-file /run/secrets/swan-bootstrap/member.password \
      --consumer-client-id "$3" \
      --consumer-redirect-uri http://127.0.0.1/callback \
      --plc-origin http://reference-plc:2582 \
      --plc-laboratory \
      --plc-laboratory-allowlisted-host reference-plc \
      --writer-host "$4=https://swan.test:$5" \
      --writer-host "$6=https://swan.test:$7" \
      --writer-host "$8=https://pds.test:$9" \
      --request-timeout-seconds 30 \
      --output /run/forum/thread.json
  ' _ \
  "$space_uri" \
  "$receiver_did" \
  "$scope_client_id" \
  "$alice_did" "$alice_key" \
  "$receiver_did" "$carol_key" \
  "$bob_did" "$bob_key"

echo "FORUM THREAD DEBUG: syncer exited with $?"
if [[ -f "$temporary_directory/thread.json" ]]; then
  python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); print("status:", a.get("status"), "writers:", len(a.get("writers", [])), "posts:", a.get("postCount"), "replies:", a.get("replyCount"))' \
    "$temporary_directory/thread.json"
fi
