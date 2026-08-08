#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

override_names=(
  SWAN_INTEROP_COMPOSE_FILE
  SWAN_INTEROP_NOTIFICATION_CONFIG_FILE
  SWAN_INTEROP_NOTIFICATION_RESTART_SCENARIO
  SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE
  SWAN_INTEROP_REFERENCE_PLC_DOCKERFILE
  SWAN_INTEROP_CADDYFILE
  SWAN_INTEROP_SWAN_DOCKERIGNORE
  SWAN_INTEROP_REFERENCE_PDS_DOCKERIGNORE
  SWAN_INTEROP_REFERENCE_PLC_DOCKERIGNORE
)
for override_name in "${override_names[@]}"; do
  if [[ -n "${!override_name:-}" ]] \
    && [[ "${SWAN_INTEROP_VERIFIER_TEST_MODE:-0}" != "1" ]]
  then
    echo "verifier input overrides require mutation-test mode" >&2
    exit 64
  fi
done

compose_file="${SWAN_INTEROP_COMPOSE_FILE:-docker-compose.yml}"
notification_config_file="${SWAN_INTEROP_NOTIFICATION_CONFIG_FILE:-interop/notification-config.json}"
notification_restart_scenario="${SWAN_INTEROP_NOTIFICATION_RESTART_SCENARIO:-Scripts/run-notification-restart-acceptance.sh}"
reference_pds_dockerfile="${SWAN_INTEROP_REFERENCE_PDS_DOCKERFILE:-interop/Dockerfile.reference-pds}"
reference_plc_dockerfile="${SWAN_INTEROP_REFERENCE_PLC_DOCKERFILE:-interop/Dockerfile.reference-plc}"
toxiproxy_dockerfile="interop/Dockerfile.toxiproxy"
toxiproxy_config="interop/toxiproxy.json"
caddyfile="${SWAN_INTEROP_CADDYFILE:-interop/Caddyfile}"
swan_dockerignore="${SWAN_INTEROP_SWAN_DOCKERIGNORE:-Dockerfile.dockerignore}"
reference_pds_dockerignore="${SWAN_INTEROP_REFERENCE_PDS_DOCKERIGNORE:-interop/Dockerfile.reference-pds.dockerignore}"
reference_plc_dockerignore="${SWAN_INTEROP_REFERENCE_PLC_DOCKERIGNORE:-interop/Dockerfile.reference-plc.dockerignore}"
recovery_compose_file="interop/docker-compose.reference-recovery.yml"
recovery_compose_script="interop/compose-recovery.sh"
recovery_pds_dockerfile="interop/Dockerfile.reference-pds-recovery"
recovery_overlay_profile="interop/reference-pds-overlay/profile.json"
recovery_overlay_patch="interop/reference-pds-overlay/reference-pds-recovery.patch"
recovery_overlay_apply="interop/reference-pds-overlay/apply-reference-pds-overlay.sh"
recovery_overlay_test="interop/reference-pds-overlay/test-reference-pds-overlay.sh"

for required_file in \
  "$compose_file" \
  "$notification_config_file" \
  "$notification_restart_scenario" \
  "$reference_pds_dockerfile" \
  "$reference_plc_dockerfile" \
  "$toxiproxy_dockerfile" \
  "$toxiproxy_config" \
  "$caddyfile" \
  "$swan_dockerignore" \
  "$reference_pds_dockerignore" \
  "$reference_plc_dockerignore" \
  "$recovery_compose_file" \
  "$recovery_compose_script" \
  "$recovery_pds_dockerfile" \
  "$recovery_overlay_profile" \
  "$recovery_overlay_patch" \
  "$recovery_overlay_apply" \
  "$recovery_overlay_test"
do
  if [[ ! -f "$required_file" ]]; then
    echo "interop verifier input is missing: ${required_file}" >&2
    exit 1
  fi
done
if [[ ! -x "$notification_restart_scenario" ]]; then
  echo "notification restart scenario must be executable" >&2
  exit 1
fi
if [[ ! -x "Scripts/test-bootstrap-local-space.sh" ]]; then
  echo "bootstrap fail-closed regression must be executable" >&2
  exit 1
fi
for recovery_script in \
  "$recovery_compose_script" \
  "$recovery_overlay_apply" \
  "$recovery_overlay_test"
do
  if [[ ! -x "$recovery_script" ]]; then
    echo "recovery overlay script must be executable: ${recovery_script}" >&2
    exit 1
  fi
done

# The recovery image is a qualified disposable variant, not an unpinned fork.
# Bind its Compose entry, source archive, and patch to the active immutable
# profile so a green stateful run cannot silently drift to another source.
python3 - \
  "$recovery_overlay_profile" \
  "Profiles/permissioned-data-0016-2026-07-30.json" \
  "$recovery_overlay_patch" <<'PY'
import hashlib
import json
import pathlib
import sys

overlay_path, active_path, patch_path = map(pathlib.Path, sys.argv[1:])
with overlay_path.open(encoding="utf-8") as handle:
    overlay = json.load(handle)
with active_path.open(encoding="utf-8") as handle:
    active = json.load(handle)

for key in ("referenceImplementationCommit", "referenceArchiveSHA256"):
    if overlay.get(key) != active.get(key):
        raise SystemExit(f"recovery overlay profile is not bound to active profile: {key}")
if overlay.get("overlayPatch") != patch_path.name:
    raise SystemExit("recovery overlay profile points to the wrong patch")
actual = hashlib.sha256(patch_path.read_bytes()).hexdigest()
if overlay.get("overlayPatchSHA256") != actual:
    raise SystemExit("recovery overlay patch checksum does not match its profile")
PY
rg -q '^  reference-pds:$' "$recovery_compose_file"
rg -q '^      context: \.\.$' "$recovery_compose_file"
rg -q '^      dockerfile: Swan/interop/Dockerfile\.reference-pds-recovery$' \
  "$recovery_compose_file"
rg -q -- 'docker-compose.reference-recovery.yml' "$recovery_compose_script"
rg -q -- './interop/verify-reference.sh' "$recovery_compose_script"
rg -q '^COPY Swan/\.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354\.tar\.gz /tmp/reference\.tar\.gz$' \
  "$recovery_pds_dockerfile"
rg -q '^COPY Swan/interop/reference-pds-overlay/reference-pds-recovery\.patch /tmp/reference-pds-recovery\.patch$' \
  "$recovery_pds_dockerfile"
rg -q '^RUN apk add --no-cache patch' "$recovery_pds_dockerfile"
rg -q 'patch --batch --forward -p1' "$recovery_pds_dockerfile"
if rg -n '^[[:space:]]*RUN .*(curl|git clone|git fetch)' "$recovery_pds_dockerfile"; then
  echo "recovery reference image Dockerfile must not fetch source from the network" >&2
  exit 1
fi
rg -q 'overlay patch checksum mismatch' "$recovery_overlay_apply"
rg -q 'pinned reference checkout' "$recovery_overlay_test"

./interop/verify-reference.sh

service_block() {
  service="$1"
  awk -v service="$service" '
    $0 == "  " service ":" { capture=1; next }
    capture && /^  [[:alnum:]][[:alnum:]-]*:/ { capture=0 }
    capture { print }
  ' "$compose_file"
}

require_contains() {
  block="$1"
  expected="$2"
  message="$3"
  if [[ "$block" != *"$expected"* ]]; then
    echo "$message" >&2
    exit 1
  fi
}

reject_contains() {
  block="$1"
  forbidden="$2"
  message="$3"
  if [[ "$block" == *"$forbidden"* ]]; then
    echo "$message" >&2
    exit 1
  fi
}

for service in \
  swan-secrets-init \
  swan-data-init \
  swan-bootstrap \
  swan \
  reference-pds \
  reference-plc \
  caddy \
  caddy-ca-ready \
  mailpit \
  toxiproxy \
  toxiproxy-setup \
  scenario-runner
do
  if ! rg -q "^  ${service}:" "$compose_file"; then
    echo "required interop service is missing: ${service}" >&2
    exit 1
  fi
done

secrets_init_block="$(service_block swan-secrets-init)"
data_init_block="$(service_block swan-data-init)"
bootstrap_block="$(service_block swan-bootstrap)"
swan_block="$(service_block swan)"
reference_block="$(service_block reference-pds)"
caddy_block="$(service_block caddy)"
ca_ready_block="$(service_block caddy-ca-ready)"
mailpit_block="$(service_block mailpit)"
toxiproxy_block="$(service_block toxiproxy)"
runner_block="$(service_block scenario-runner)"

# Compose may interpolate the external directory path, never secret values.
interpolations="$(rg -o '\$\{[^}]+\}' "$compose_file" || true)"
interpolation_count="$(printf '%s\n' "$interpolations" | awk 'NF { count += 1 } END { print count + 0 }')"
# shellcheck disable=SC2016 # Compare the literal Compose interpolation form.
if [[ "$interpolation_count" -ne 1 ]] \
  || [[ "$interpolations" != '${SWAN_INTEROP_SECRETS_DIR:?set the owner-only lab interop secret directory path}' ]]; then
  echo "Compose interpolation is limited to the external secret directory path" >&2
  exit 1
fi
if rg -n '^[[:space:]]*(SWAN_OAUTH_SERVER_KEY|PDS_(DPOP_SECRET|JWT_SECRET|ADMIN_PASSWORD|REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX|PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX)):' "$compose_file"; then
  echo "Compose must not inject secret values through environment entries" >&2
  exit 1
fi

# A root-only copier handles host/container UID mismatch. It never invokes the
# Swan executable, has no network, and produces least-privilege named volumes.
require_contains "$secrets_init_block" 'user: root' "secret preparation must run as root"
require_contains "$secrets_init_block" 'entrypoint: ["/usr/local/bin/swan-interop-prepare-secrets"]' "secret preparation wrapper is missing"
require_contains "$secrets_init_block" ':/external-secrets:ro' "external secrets must be mounted read-only"
require_contains "$secrets_init_block" 'swan-runtime-secrets:/prepared/swan-runtime' "runtime secret output is missing"
require_contains "$secrets_init_block" 'swan-bootstrap-secrets:/prepared/swan-bootstrap' "bootstrap secret output is missing"
require_contains "$secrets_init_block" 'reference-pds-secrets:/prepared/reference-pds' "PDS secret output is missing"
require_contains "$secrets_init_block" 'network_mode: "none"' "secret preparation must be network-isolated"
reject_contains "$secrets_init_block" 'entrypoint: ["/usr/local/bin/swan"]' "root secret preparation must not run Swan"
reject_contains "$secrets_init_block" 'privileged:' "secret preparation must not be privileged"

require_contains "$data_init_block" 'user: root' "data preparation must run as root"
require_contains "$data_init_block" 'network_mode: "none"' "data preparation must be network-isolated"
require_contains "$data_init_block" 'install -d -o swan -g swan -m 0700 /var/lib/swan/data' "data preparation ownership contract is missing"
reject_contains "$data_init_block" 'entrypoint: ["/usr/local/bin/swan"]' "root data preparation must not run Swan"
reject_contains "$data_init_block" 'privileged:' "data preparation must not be privileged"

require_contains "$bootstrap_block" 'user: swan' "bootstrap must run as swan"
require_contains "$bootstrap_block" 'entrypoint: ["/usr/local/bin/swan-interop-bootstrap"]' "bootstrap wrapper is missing"
require_contains "$bootstrap_block" 'swan-bootstrap-secrets:/run/secrets/swan-bootstrap:ro' "bootstrap secrets must be read-only"
require_contains "$bootstrap_block" $'swan-secrets-init:\n        condition: service_completed_successfully' "bootstrap must wait for prepared secrets"
require_contains "$bootstrap_block" $'swan-data-init:\n        condition: service_completed_successfully' "bootstrap must wait for prepared data"
reject_contains "$bootstrap_block" 'user: root' "bootstrap must not run as root"
reject_contains "$bootstrap_block" 'privileged:' "bootstrap must not be privileged"
# shellcheck disable=SC2016 # Reject the literal interpolation prefix.
reject_contains "$bootstrap_block" '${SWAN_INTEROP_SECRETS_DIR' "bootstrap must not mount host secrets directly"

# The long-running runtime is explicitly unprivileged and receives only the
# two-file runtime volume, never bootstrap passwords/operator material.
require_contains "$swan_block" 'user: swan' "Swan runtime must explicitly run as swan"
require_contains "$swan_block" 'read_only: true' "Swan runtime root filesystem must be read-only"
require_contains "$swan_block" '/tmp:size=16m,mode=1777' "Swan runtime must have only a bounded writable temporary filesystem"
reject_contains "$swan_block" 'user: root' "Swan runtime must not run as root"
reject_contains "$swan_block" 'privileged:' "Swan runtime must not be privileged"
reject_contains "$swan_block" 'cap_add:' "Swan runtime must not add capabilities"
reject_contains "$swan_block" '/var/run/docker.sock' "Swan runtime must not mount the Docker socket"
require_contains "$swan_block" 'swan-runtime-secrets:/run/secrets/swan-runtime:ro' "runtime secrets must use the read-only prepared volume"
reject_contains "$swan_block" 'swan-bootstrap-secrets' "runtime must not receive bootstrap-only secrets"
reject_contains "$swan_block" 'operator-secret' "runtime must not receive the operator secret"
reject_contains "$swan_block" '.password' "runtime must not receive account passwords"
# shellcheck disable=SC2016 # Reject the literal interpolation prefix.
reject_contains "$swan_block" '${SWAN_INTEROP_SECRETS_DIR' "runtime must not mount host secrets directly"
require_contains "$swan_block" '--oauth-server-key-file' "file-backed OAuth server key flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/oauth-server-key' "OAuth server key path is wrong"
require_contains "$swan_block" '--enable-oauth-authorization-server' "Compose must enable the complete OAuth authorization server"
require_contains "$swan_block" '--oauth-allow-localhost-development-client' "Compose must declare its localhost client metadata exception"
require_contains "$swan_block" '--login-trusted-proxy-peer' "Compose must declare its exact login trusted proxy"
require_contains "$swan_block" '"172.30.0.2"' "Compose login trusted proxy must match Caddy's fixed peer"
require_contains "$swan_block" '--notification-config' "Compose must load the checked-in lab notification configuration"
require_contains "$swan_block" '/etc/swan/interop/notification-config.json' "Compose notification configuration path is wrong"
require_contains "$swan_block" '--enable-notification-delivery' "Compose must enable durable notification delivery and restart recovery"
require_contains "$swan_block" '--enable-email-recovery' "Compose must enable durable account-email recovery"
require_contains "$swan_block" '--email-proof-key-file' "Compose email proof key flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/email-proof-key' "Compose email proof key path is wrong"
require_contains "$swan_block" '--email-smtp-host' "Compose email SMTP host flag is missing"
require_contains "$swan_block" 'mailpit' "Compose email delivery must target the isolated Mailpit service"
reject_contains "$swan_block" './interop/notification-config.json:' "Compose must not use a host file bind for notification configuration"
require_contains "$swan_block" '--managing-service-audience' "Compose must enable checkUserAccess service verification"
reject_contains "$swan_block" '--enable-localhost-oauth' "Compose must not use the narrower localhost-only OAuth bridge"
require_contains "$swan_block" '--enable-local-space-interop' "local-space interop flag is missing"
require_contains "$swan_block" '--space-account-kek-file' "account KEK file flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/account-kek' "account KEK path is wrong"
require_contains "$swan_block" '--enable-public-repository-mutations' "public mutation capability must be explicitly enabled"
require_contains "$swan_block" '--public-account-kek-file' "public mutation account KEK flag is missing"
require_contains "$swan_block" 'https://swan.test' "Swan public URL must use Caddy TLS"
require_contains "$swan_block" $'swan-bootstrap:\n        condition: service_completed_successfully' "Swan must wait for successful bootstrap"

# Reference PDS secrets are loaded from its read-only, UID-adjusted volume by
# an unprivileged wrapper. No secret value appears in Compose.
require_contains "$reference_block" 'reference-pds-secrets:/run/secrets/reference-pds:ro' "PDS secrets must use the read-only prepared volume"
require_contains "$reference_block" 'REFERENCE_PDS_SECRETS_DIR: /run/secrets/reference-pds' "PDS file-secret directory is missing"
require_contains "$reference_block" $'swan-secrets-init:\n        condition: service_completed_successfully' "PDS must wait for prepared secrets"
# shellcheck disable=SC2016 # Reject any literal Compose interpolation.
reject_contains "$reference_block" '${' "PDS must not interpolate environment values"
reject_contains "$reference_block" 'PDS_DPOP_SECRET:' "PDS DPoP secret must not be in Compose environment"
reject_contains "$reference_block" 'PDS_JWT_SECRET:' "PDS JWT secret must not be in Compose environment"
reject_contains "$reference_block" 'PDS_ADMIN_PASSWORD:' "PDS administrator password must not be in Compose environment"
reject_contains "$reference_block" 'PDS_REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX:' "PDS signing key must not be in Compose environment"
reject_contains "$reference_block" 'PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX:' "PDS rotation key must not be in Compose environment"

# Caddy is the only host ingress. Its health is the deterministic CA creation
# gate, and its upstream dependencies must be genuinely ready before TLS can
# report healthy. A root shell then copies only the public CA to an
# unprivileged volume.
require_contains "$swan_block" 'curl --fail --silent --show-error --max-time 2 http://127.0.0.1:3000/health' "Swan healthcheck must probe the live HTTP listener"
require_contains "$reference_block" "fetch('http://127.0.0.1:3000/xrpc/_health')" "reference PDS healthcheck must probe the live HTTP listener"
require_contains "$(service_block reference-plc)" "fetch('http://127.0.0.1:2582/_health')" "reference PLC healthcheck must probe the live HTTP listener"
require_contains "$(service_block reference-plc)" 'PLC_DATA_DIRECTORY: /plc' "reference PLC state directory is missing"
require_contains "$(service_block reference-plc)" 'reference-plc-data:/plc' "reference PLC state volume is missing"
rg -q '^COPY Swan/interop/reference-plc-server\.mjs /reference/reference-plc-server\.mjs$' \
  "$reference_plc_dockerfile" || {
  echo "reference PLC must use the persistent wrapper" >&2
  exit 1
}
rg -q '^CMD \["node", "/reference/reference-plc-server\.mjs"\]$' \
  "$reference_plc_dockerfile" || {
  echo "reference PLC command must use the persistent wrapper" >&2
  exit 1
}
test -x "${root}/interop/test-reference-plc-persistence.sh" || {
  echo "reference PLC persistence acceptance script is missing or not executable" >&2
  exit 1
}
require_contains "$reference_block" $'reference-plc:\n        condition: service_healthy' "reference PDS must wait for a healthy PLC"
require_contains "$(service_block toxiproxy-setup)" $'reference-pds:\n        condition: service_healthy' "Toxiproxy setup must wait for a healthy reference PDS"
require_contains "$caddy_block" $'swan:\n        condition: service_healthy' "Caddy must wait for a healthy Swan listener"
require_contains "$caddy_block" '"127.0.0.1:443:443"' "Caddy must be the loopback-only host ingress"
require_contains "$caddy_block" 'test -s /data/caddy/pki/authorities/local/root.crt' "Caddy CA healthcheck is missing"
require_contains "$caddy_block" 'aliases:' "Caddy TLS aliases are missing"
require_contains "$caddy_block" 'ipv4_address: 172.30.0.2' "Caddy must have the fixed login-proxy peer address"
require_contains "$toxiproxy_block" 'ipv4_address: 172.30.0.8' "Toxiproxy must reserve an address distinct from Caddy"
require_contains "$toxiproxy_block" 'dockerfile: Swan/interop/Dockerfile.toxiproxy' "Toxiproxy must use the pinned checked-in config image"
require_contains "$toxiproxy_block" '-config=/etc/toxiproxy/config.json' "Toxiproxy must load its restart-safe proxy configuration"
require_contains "$caddy_block" 'dockerfile: Swan/interop/Dockerfile.caddy' "Caddy must use the pinned checked-in config image"
reject_contains "$caddy_block" './interop/Caddyfile:' "Caddy must not use a host file bind"
require_contains "$caddy_block" 'swan.test' "Caddy must own the swan.test network alias"
require_contains "$caddy_block" 'pds.test' "Caddy must own the pds.test network alias"
reject_contains "$mailpit_block" 'ports:' "Mailpit must not publish a host port"
require_contains "$mailpit_block" 'healthcheck:' "Mailpit must expose a readiness healthcheck"
require_contains "$mailpit_block" '8025/api/v1/info' "Mailpit healthcheck must use its local HTTP API"
require_contains "$swan_block" $'mailpit:\n        condition: service_healthy' "Swan must wait for Mailpit readiness"
reject_contains "$toxiproxy_block" 'ports:' "Toxiproxy must not publish a host port"
if ! rg -q '^[[:space:]]+- subnet: 172\.30\.0\.0/24$' "$compose_file"; then
  echo "interop network must use the fixed login-proxy subnet" >&2
  exit 1
fi
published_port_count="$(rg -c '^[[:space:]]+ports:' "$compose_file" || true)"
if [[ "$published_port_count" -ne 1 ]]; then
  echo "Caddy must be the only service with a published host port" >&2
  exit 1
fi
require_contains "$ca_ready_block" 'user: root' "CA trust preparation ownership is missing"
require_contains "$ca_ready_block" 'entrypoint: ["/usr/local/bin/swan-interop-caddy-trust"]' "CA trust preparation wrapper is missing"
require_contains "$ca_ready_block" 'caddy-data:/caddy-data:ro' "CA source must be read-only"
require_contains "$ca_ready_block" 'caddy-trust:/prepared-trust' "CA trust destination is missing"
require_contains "$ca_ready_block" 'network_mode: "none"' "CA trust preparation must be network-isolated"
require_contains "$ca_ready_block" $'caddy:\n        condition: service_healthy' "CA trust preparation must wait for Caddy health"
reject_contains "$ca_ready_block" 'entrypoint: ["/usr/local/bin/swan"]' "root CA preparation must not run Swan"
reject_contains "$ca_ready_block" 'privileged:' "CA trust preparation must not be privileged"

# The Task 28 runner is genuinely inert: opt-in profile, no network, no Swan
# invocation, no probes/faults, and only a read-only prepared trust mount.
require_contains "$runner_block" 'profiles: ["planned-not-executed"]' "scenario runner must remain opt-in and planned"
require_contains "$runner_block" 'user: swan' "scenario runner must be unprivileged"
require_contains "$runner_block" 'network_mode: "none"' "planned runner must be network-isolated"
require_contains "$runner_block" 'caddy-trust:/etc/ssl/certs:ro' "runner trust mount must be read-only"
require_contains "$runner_block" 'SSL_CERT_FILE=/etc/ssl/certs/caddy-local-root.crt' "runner trust environment is missing"
require_contains "$runner_block" 'planned-not-executed: CA trust prepared; no probes or faults were run' "runner planned status is missing"
require_contains "$runner_block" $'caddy-ca-ready:\n        condition: service_completed_successfully' "runner must wait for prepared CA trust"
reject_contains "$runner_block" 'user: root' "scenario runner must not run as root"
reject_contains "$runner_block" '/usr/local/bin/swan' "planned runner must not invoke Swan"
reject_contains "$runner_block" 'lab matrix' "planned runner must not execute the matrix"
reject_contains "$runner_block" 'curl ' "planned runner must not send requests"
reject_contains "$runner_block" 'http://' "planned runner must not name a live endpoint"
reject_contains "$runner_block" 'https://' "planned runner must not name a live endpoint"
reject_contains "$runner_block" 'toxiproxy' "planned runner must not mutate Toxiproxy"
reject_contains "$runner_block" 'privileged:' "scenario runner must not be privileged"

rg -q 'permissioned-data-0016-2026-07-30' Sources/SwanInterop/SwanInterop.swift
rg -q '1caad93dbb1f445396f6abf3b97eb4040345e78e' Sources/SwanInterop/SwanInterop.swift
rg -q '3f6c96d5d2d25438bd40fa89d6ecc37865f8e354' "$reference_pds_dockerfile"
rg -q '1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea' "$reference_pds_dockerfile"
rg -q 'tls internal' "$caddyfile"
rg -q 'reverse_proxy toxiproxy:8666' "$caddyfile"
delete_client_header_count="$(
  rg -c '^[[:space:]]*header_up -X-Swan-Client-IP$' "$caddyfile" || true
)"
if [[ "${delete_client_header_count:-0}" -ne 0 ]]; then
  echo "Caddy must not delete its replacement login client identity header" >&2
  exit 1
fi
set_client_header_count="$(
  rg -c '^[[:space:]]*header_up X-Swan-Client-IP \{http\.request\.remote\.host\}$' \
    "$caddyfile" || true
)"
if [[ "${set_client_header_count:-0}" -ne 1 ]]; then
  echo "Caddy must set the login client identity from its direct peer exactly once" >&2
  exit 1
fi
rg -q '^FROM caddy:2\.10\.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d$' interop/Dockerfile.caddy
rg -q '^COPY Swan/interop/Caddyfile /etc/caddy/Caddyfile$' interop/Dockerfile.caddy
rg -q '^FROM ghcr\.io/shopify/toxiproxy:2\.12\.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e$' "$toxiproxy_dockerfile"
rg -q '^COPY Swan/interop/toxiproxy\.json /etc/toxiproxy/config\.json$' "$toxiproxy_dockerfile"
if rg -n '^[[:space:]]*RUN .*(curl|wget|git clone|git fetch)' "$toxiproxy_dockerfile"; then
  echo "Toxiproxy image Dockerfile must not fetch source from the network" >&2
  exit 1
fi
python3 - "$toxiproxy_config" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
configuration = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(configuration, list) or len(configuration) != 1:
    raise SystemExit("Toxiproxy config must contain exactly one proxy")
proxy = configuration[0]
if not isinstance(proxy, dict) or set(proxy) != {"name", "listen", "upstream", "enabled"}:
    raise SystemExit("Toxiproxy config must contain only the reference-pds proxy")
if proxy != {
    "name": "reference-pds",
    "listen": "0.0.0.0:8666",
    "upstream": "reference-pds:3000",
    "enabled": True,
}:
    raise SystemExit("Toxiproxy reference-pds proxy is not the pinned topology")
PY

rg -qx 'FROM swift:6\.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e AS build' Dockerfile
rg -q 'libsodium-dev pkg-config' Dockerfile
# The runtime keeps the Swift 6.1 standard-library surface alongside the
# release executable. A minimal Ubuntu runtime would omit those libraries and
# fail only after the container passes image build.
rg -qx 'FROM swift:6\.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e' Dockerfile
rg -q 'libsodium23' Dockerfile
rg -q 'COPY Swan/interop/bootstrap-local-space\.sh /usr/local/bin/swan-interop-bootstrap' Dockerfile
rg -q 'COPY Swan/interop/prepare-interop-secrets\.sh /usr/local/bin/swan-interop-prepare-secrets' Dockerfile
rg -q 'COPY Swan/interop/prepare-caddy-trust\.sh /usr/local/bin/swan-interop-caddy-trust' Dockerfile
rg -q 'COPY Swan/interop/run-reference-pds\.sh /usr/local/bin/reference-pds-with-file-secrets' "$reference_pds_dockerfile"
rg -q '^CMD \["/usr/local/bin/reference-pds-with-file-secrets",' "$reference_pds_dockerfile"
node_image='node:24.15-alpine3.23@sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f'
pnpm_sha512='71c631e382066efc25625d5cf029075de07b61b37f6e27350fbd84b1bda5864c8c1967adc280776b45c30a715c0359a3be08fef42d5bb09e2b99029979692916'
for reference_dockerfile in \
  "$reference_pds_dockerfile" \
  "$reference_plc_dockerfile" \
  "$recovery_pds_dockerfile"; do
  node_from_count="$(rg -c "^FROM ${node_image}( AS build)?$" "$reference_dockerfile" || true)"
  if [[ "$node_from_count" != "2" ]]; then
    echo "reference image Dockerfiles must use the exact pinned Node digest in both stages" >&2
    exit 1
  fi
  if rg -q '^FROM node:[^@[:space:]]+( AS build)?$' "$reference_dockerfile"; then
    echo "reference image Dockerfiles must pin Node by digest" >&2
    exit 1
  fi
  if ! rg -q "${pnpm_sha512}  /tmp/pnpm-11\\.5\\.2\\.tgz" "$reference_dockerfile" \
      || ! rg -q 'npm install --global /tmp/pnpm-11\.5\.2\.tgz' "$reference_dockerfile" \
      || ! rg -q 'test "\$\(pnpm --version\)" = "11\.5\.2"' "$reference_dockerfile"; then
    echo "reference image Dockerfiles must verify the pinned pnpm bootstrap" >&2
    exit 1
  fi
done
rg -q 'account show' interop/bootstrap-local-space.sh
rg -q 'account not found' interop/bootstrap-local-space.sh
rg -q 'could not inspect existing account' interop/bootstrap-local-space.sh
rg -q 'expected_did' interop/bootstrap-local-space.sh
rg -q 'authority\.did' interop/bootstrap-local-space.sh
rg -q 'member\.did' interop/bootstrap-local-space.sh
rg -q 'prepared PLC DID does not match' interop/bootstrap-local-space.sh
rg -q 'find "\$source" -perm /077' interop/prepare-interop-secrets.sh
rg -q 'install -o "\$owner" -g "\$group" -m 0400' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$runtime_directory" swan swan' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$pds_directory" 1000 1000' interop/prepare-interop-secrets.sh
rg -q 'source_certificate="/caddy-data/caddy/pki/authorities/local/root\.crt"' interop/prepare-caddy-trust.sh
rg -q 'install -o swan -g swan -m 0444' interop/prepare-caddy-trust.sh
rg -q 'verify-secret-source\.sh "\$root" "\$SWAN_INTEROP_SECRETS_DIR"' interop/compose.sh

# The checked-in notification configuration is intentionally lab-only public
# material. It must not be a hidden private-key or secret input channel.
python3 - "$notification_config_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])


class DuplicateField(ValueError):
    pass


def reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateField(key)
        result[key] = value
    return result


try:
    configuration = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
    )
except DuplicateField as error:
    raise SystemExit(
        "checked-in notification configuration has a duplicate field: "
        f"{error}"
    ) from error

secret_field_tokens = ("private", "secret", "password", "token")


def reject_secret_fields(value, location="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SystemExit(
                    f"checked-in notification configuration has a non-string field at {location}"
                )
            child_location = f"{location}.{key}"
            if any(token in key.lower() for token in secret_field_tokens):
                raise SystemExit(
                    "checked-in notification configuration contains a "
                    f"secret-like field: {child_location}"
                )
            reject_secret_fields(child, child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{location}[{index}]")


def require_object(value, location, allowed, required):
    if not isinstance(value, dict):
        raise SystemExit(
            f"checked-in notification configuration expected an object at {location}"
        )
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SystemExit(
            "checked-in notification configuration has unknown fields "
            f"at {location}: {', '.join(unknown)}"
        )
    missing = sorted(required - set(value))
    if missing:
        raise SystemExit(
            "checked-in notification configuration is missing fields "
            f"at {location}: {', '.join(missing)}"
        )


def require_array(value, location):
    if not isinstance(value, list):
        raise SystemExit(
            f"checked-in notification configuration expected an array at {location}"
        )
    if len(value) > 128:
        raise SystemExit(
            f"checked-in notification configuration has too many entries at {location}"
        )


def require_string(value, location):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 2_048:
        raise SystemExit(
            f"checked-in notification configuration expected a bounded string at {location}"
        )


reject_secret_fields(configuration)
required_root = {
    "credentialPublicKeys",
    "servicePublicKeys",
    "authorityDestinations",
    "registrationDestinations",
    "recipientServiceBindings",
    "managingServiceAudience",
    "credentialKeyPLC",
}
allowed_root = required_root | {"delegationPublicKeys", "delegationKeyPLC"}
require_object(configuration, "$", allowed_root, required_root)

credential_fields = {
    "issuer",
    "keyID",
    "generation",
    "algorithm",
    "publicKey",
    "p256X963",
    "secp256k1",
}
service_fields = credential_fields - {"keyID"}
string_key_fields = {
    "issuer",
    "keyID",
    "algorithm",
    "publicKey",
    "p256X963",
    "secp256k1",
}

for collection_name in ("credentialPublicKeys", "delegationPublicKeys"):
    entries = configuration.get(collection_name, [])
    require_array(entries, f"$.{collection_name}")
    for index, entry in enumerate(entries):
        location = f"$.{collection_name}[{index}]"
        require_object(entry, location, credential_fields, {"issuer", "generation"})
        for field in string_key_fields & set(entry):
            require_string(entry[field], f"{location}.{field}")
        generation = entry["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise SystemExit(
                f"checked-in notification configuration has an invalid generation at {location}"
            )
        if not any(entry.get(field) for field in ("publicKey", "p256X963", "secp256k1")):
            raise SystemExit(
                f"checked-in notification configuration has no public key at {location}"
            )

service_entries = configuration["servicePublicKeys"]
require_array(service_entries, "$.servicePublicKeys")
for index, entry in enumerate(service_entries):
    location = f"$.servicePublicKeys[{index}]"
    require_object(entry, location, service_fields, {"issuer", "generation"})
    for field in string_key_fields & set(entry):
        require_string(entry[field], f"{location}.{field}")
    generation = entry["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise SystemExit(
            f"checked-in notification configuration has an invalid generation at {location}"
        )
    if not any(entry.get(field) for field in ("publicKey", "p256X963", "secp256k1")):
        raise SystemExit(
            f"checked-in notification configuration has no public key at {location}"
        )

destination_fields = {"key", "endpoint", "audience", "finalPeer"}
for collection_name in ("authorityDestinations", "registrationDestinations"):
    destinations = configuration[collection_name]
    require_array(destinations, f"$.{collection_name}")
    for index, destination in enumerate(destinations):
        location = f"$.{collection_name}[{index}]"
        require_object(
            destination,
            location,
            destination_fields,
            destination_fields,
        )
        for field in destination_fields:
            require_string(destination[field], f"{location}.{field}")
        if (
            destination["endpoint"] != "http://localhost:3001"
            or destination["finalPeer"] != "127.0.0.1"
        ):
            raise SystemExit(
                "checked-in notification destination is not loopback-lab-only"
            )

expected_authority = "did:plc:abcdefghijklmnopqrstuvwx"
if configuration["authorityDestinations"] != [
    {
        "key": expected_authority,
        "endpoint": "http://localhost:3001",
        "audience": expected_authority,
        "finalPeer": "127.0.0.1",
    }
]:
    raise SystemExit(
        "checked-in notification authority route is not the fixed restart laboratory"
    )
if configuration["registrationDestinations"]:
    raise SystemExit(
        "checked-in notification configuration must not contain registration routes"
    )

bindings = configuration["recipientServiceBindings"]
require_array(bindings, "$.recipientServiceBindings")
binding_fields = {"serviceIdentity", "recipientAccount"}
for index, binding in enumerate(bindings):
    location = f"$.recipientServiceBindings[{index}]"
    require_object(binding, location, binding_fields, binding_fields)
    for field in binding_fields:
        require_string(binding[field], f"{location}.{field}")
if bindings:
    raise SystemExit(
        "checked-in notification configuration must not contain recipient bindings"
    )
if (
    configuration["credentialPublicKeys"]
    or configuration.get("delegationPublicKeys", [])
    or configuration["servicePublicKeys"]
):
    raise SystemExit(
        "checked-in notification configuration must not contain static key material"
    )

require_string(configuration["managingServiceAudience"], "$.managingServiceAudience")
if configuration["managingServiceAudience"] != "did:web:interop-swan-managing-service":
    raise SystemExit("checked-in notification configuration is not lab-scoped")
plc = configuration["credentialKeyPLC"]
plc_fields = {"origin", "laboratory", "allowlistedHost"}
require_object(plc, "$.credentialKeyPLC", plc_fields, plc_fields)
if plc != {
    "origin": "http://reference-plc:2582",
    "laboratory": True,
    "allowlistedHost": "reference-plc",
}:
    raise SystemExit("checked-in notification PLC resolver is not the pinned lab origin")

if "delegationKeyPLC" in configuration:
    delegation_plc = configuration["delegationKeyPLC"]
    delegation_plc_fields = {
        "origin",
        "laboratory",
        "allowlistedHost",
        "allowedIssuers",
    }
    require_object(
        delegation_plc,
        "$.delegationKeyPLC",
        delegation_plc_fields,
        delegation_plc_fields,
    )
    if delegation_plc["origin"] != "http://reference-plc:2582":
        raise SystemExit(
            "checked-in notification delegation PLC is not the pinned lab origin"
        )
    if delegation_plc["laboratory"] is not True or delegation_plc["allowlistedHost"] != "reference-plc":
        raise SystemExit(
            "checked-in notification delegation PLC is not loopback-lab-only"
        )
    issuers = delegation_plc["allowedIssuers"]
    require_array(issuers, "$.delegationKeyPLC.allowedIssuers")
    if not issuers:
        raise SystemExit(
            "checked-in notification delegation PLC issuer allowlist is empty"
        )
    for index, issuer in enumerate(issuers):
        require_string(issuer, f"$.delegationKeyPLC.allowedIssuers[{index}]")
        if not issuer.startswith("did:plc:"):
            raise SystemExit(
                "checked-in notification delegation PLC issuer is not a PLC DID"
            )
    if len(set(issuers)) != len(issuers):
        raise SystemExit(
            "checked-in notification delegation PLC issuer allowlist has duplicates"
        )
PY

# The live closure is opt-in, but its proof contract is checked offline. It
# must crash the delivery-disabled seed, make the proxy ready before recovery,
# force a lost acknowledgement, start normal Compose after convergence, and
# correlate one durable receipt without reading a record table or retaining the
# generated permissioned value.
bash -n "$notification_restart_scenario"
for required_contract in \
  'docker kill --signal KILL' \
  'permissioned_space_outbox' \
  'permissioned_space_notification_receipts' \
  'WHERE issuer = ? AND event_id = ? AND space_uri = ?' \
  'readonly: true' \
  'successfulForwards' \
  'uniqueRequestDigests' \
  'droppedAcknowledgements' \
  'returnedAcknowledgements' \
  'NOTIFICATION RESTART OUTBOX CONVERGENCE OK: successful_forwards=2 receiver_effects=1'
do
  if ! rg -Fq "$required_contract" "$notification_restart_scenario"; then
    echo "notification restart scenario is missing its durable convergence contract" >&2
    exit 1
  fi
done
python3 - "$notification_restart_scenario" <<'PY'
import sys
from pathlib import Path

scenario = Path(sys.argv[1]).read_text(encoding="utf-8")
anchors = (
    'proxy_id="$(',
    'until [[ -f "$temporary_directory/ready" ]]',
    'recovery_id="$(',
    'wait_for_swan_http "$recovery_container" "recovery-enabled Swan"',
)
positions = [scenario.find(anchor) for anchor in anchors]
if any(position < 0 for position in positions) or positions != sorted(positions):
    raise SystemExit(
        "notification restart scenario must make the loopback proxy ready "
        "before recovery starts"
    )
PY
if rg -n \
  'set[[:space:]]+-x|docker[[:space:]]+logs|cat[[:space:]].*permissioned-record|tee[[:space:]].*permissioned-record' \
  "$notification_restart_scenario"
then
  echo "notification restart scenario contains a value-bearing log path" >&2
  exit 1
fi

for reference_dockerfile in "$reference_pds_dockerfile" "$reference_plc_dockerfile"; do
  if rg -q '^ARG[[:space:]]+REFERENCE_ARCHIVE_SHA256' "$reference_dockerfile"; then
    echo "reference image Dockerfiles must not accept an archive checksum build argument" >&2
    exit 1
  fi
  rg -q '^RUN echo "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea  /tmp/reference\.tar\.gz" \| sha256sum -c -' "$reference_dockerfile"
done

# Every build context is an allowlist and excludes secret/state paths. The
# pinned reference builds expose only the verified archive exception.
for ignore_file in \
  "$swan_dockerignore" \
  "$reference_pds_dockerignore" \
  "$reference_plc_dockerignore"
do
  rg -qx '\*\*' "$ignore_file"
  rg -qx '!Swan/' "$ignore_file"
  rg -qx '!Petrel/' "$ignore_file"
  rg -qx '\*\*/\.env\*' "$ignore_file"
  rg -qx '\*\*/\.swan-data/' "$ignore_file"
  rg -qx '\*\*/\*\.sqlite' "$ignore_file"
  rg -qx '\*\*/\*\.key' "$ignore_file"
  rg -qx '\.swan-interop-secrets/' "$ignore_file"
  rg -qx '\*\*/\.swan-interop-secrets/' "$ignore_file"
  rg -qx '\*\*/\.swan-interop-secrets/\*\*' "$ignore_file"
done
rg -qx 'Swan/\.interop-cache/\*\*' "$swan_dockerignore"
python3 - "$swan_dockerignore" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
allowed_parent = (
    "!Swan/.interop-cache/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de"
)
allowed_archive = (
    "!Swan/.interop-cache/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/"
    "indigo-8b43a326dbbb394f63b6d68761553cdfe25532de.tar.gz"
)
rules = [
    line.strip()
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]
exceptions = {
    line for line in rules if line.startswith("!") and "/.interop-cache/" in line
}
if exceptions != {allowed_parent, allowed_archive}:
    raise SystemExit(
        "the Swan image build context must allow only the pinned Indigo source archive"
    )
if rules[-2:] != [allowed_parent, allowed_archive]:
    raise SystemExit(
        "the Swan image build context must allow only the pinned Indigo source archive"
    )

# Evaluate ordered membership for the exact allowed archive and representative
# forbidden cache paths. A later broad negation such as !Swan/** must not undo
# the cache exclusion without naming .interop-cache itself.
import fnmatch

def is_ignored(candidate):
    ignored = False
    for rule in rules:
        negated = rule.startswith("!")
        pattern = rule[1:] if negated else rule
        pattern = pattern.lstrip("/")
        if pattern.endswith("/"):
            pattern += "**"
        if fnmatch.fnmatchcase(candidate, pattern):
            ignored = not negated
    return ignored

pinned_parent = allowed_parent[1:]
pinned = allowed_archive[1:]
for candidate, expected_ignored in (
    (pinned_parent, False),
    (pinned, False),
    (
        "Swan/.interop-cache/indigo-8b43a326dbbb394f63b6d68761553cdfe25532de/"
        "source/go.mod",
        True,
    ),
    ("Swan/.interop-cache/atproto-unpinned.tar.gz", True),
    ("Swan/.interop-cache/indigo-unpinned/archive.tar.gz", True),
):
    if is_ignored(candidate) != expected_ignored:
        raise SystemExit(
            "the Swan image build context must allow only the pinned Indigo source archive"
        )
PY
for ignore_file in "$reference_pds_dockerignore" "$reference_plc_dockerignore"; do
  rg -qx 'Swan/\.interop-cache/\*\*' "$ignore_file"
  rg -qx '!Swan/\.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354\.tar\.gz' "$ignore_file"
done

if rg -n '^[[:space:]]*RUN .*\b(curl|git clone|git fetch)\b' \
  "$reference_pds_dockerfile" "$reference_plc_dockerfile"
then
  echo "reference image Dockerfiles must not fetch source from the network" >&2
  exit 1
fi

verify_effective_compose() {
  local effective_secret_source="/var/empty/swan-interop-verifier-secrets"
  local effective_json=""
  effective_json="$(mktemp "${TMPDIR:-/tmp}/swan-effective-compose.XXXXXX")"

  if ! SWAN_INTEROP_SECRETS_DIR="$effective_secret_source" \
    docker compose \
      --profile planned-not-executed \
      -f "$compose_file" \
      config --format json >"$effective_json"
  then
    rm -f "$effective_json"
    echo "effective Compose configuration could not be rendered" >&2
    exit 1
  fi

  if python3 - "$effective_json" "$effective_secret_source" <<'PY'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
effective_secret_source = sys.argv[2]


def fail(message):
    raise SystemExit(message)


services = configuration.get("services")
if not isinstance(services, dict):
    fail("effective Compose configuration has no service map")

required_services = {
    "swan-secrets-init",
    "swan-data-init",
    "swan-bootstrap",
    "swan",
    "reference-pds",
    "reference-plc",
    "caddy",
    "caddy-ca-ready",
    "mailpit",
    "toxiproxy",
    "toxiproxy-setup",
    "scenario-runner",
}
if set(services) != required_services:
    fail("effective Compose service set does not match the laboratory profile")

swan = services["swan"]
if swan.get("user") != "swan":
    fail("effective Compose Swan runtime must run as swan")
if swan.get("read_only") is not True:
    fail("effective Compose Swan runtime root filesystem must be read-only")
if swan.get("privileged") not in (None, False):
    fail("effective Compose Swan runtime must not be privileged")
if swan.get("cap_add"):
    fail("effective Compose Swan runtime must not add capabilities")
if swan.get("depends_on", {}).get("swan-bootstrap", {}).get("condition") != (
    "service_completed_successfully"
):
    fail("effective Compose Swan runtime must wait for successful bootstrap")
command = swan.get("command", [])
if (
    not isinstance(command, list)
    or command.count("--enable-notification-delivery") != 1
    or command.count("--notification-config") != 1
    or command.count("/etc/swan/interop/notification-config.json") != 1
):
    fail("effective Compose Swan runtime must enable pinned notification recovery")
if (
    command.count("--enable-email-recovery") != 1
    or command.count("--email-proof-key-file") != 1
    or command.count("/run/secrets/swan-runtime/email-proof-key") != 1
    or command.count("--email-smtp-host") != 1
    or command.count("mailpit") != 1
):
    fail("effective Compose Swan runtime must enable Mailpit account-email recovery")
if swan.get("depends_on", {}).get("mailpit", {}).get("condition") != "service_healthy":
    fail("effective Compose Swan runtime must wait for healthy Mailpit")
mailpit = services["mailpit"]
if "healthcheck" not in mailpit or "8025/api/v1/info" not in str(mailpit["healthcheck"]):
    fail("effective Compose Mailpit readiness healthcheck is missing")
if (
    command.count("--login-trusted-proxy-peer") != 1
    or command.count("172.30.0.2") != 1
):
    fail("effective Compose Swan runtime must trust only the fixed Caddy login peer")

runtime_secret_mounts = [
    volume
    for volume in swan.get("volumes", [])
    if volume.get("target") == "/run/secrets/swan-runtime"
]
if (
    len(runtime_secret_mounts) != 1
    or runtime_secret_mounts[0].get("type") != "volume"
    or runtime_secret_mounts[0].get("source") != "swan-runtime-secrets"
    or runtime_secret_mounts[0].get("read_only") is not True
):
    fail("effective Compose Swan runtime secret mount is not least privilege")

secret_init = services["swan-secrets-init"]
if secret_init.get("user") != "root" or secret_init.get("network_mode") != "none":
    fail("effective Compose secret preparation boundary is invalid")
external_mounts = [
    volume
    for volume in secret_init.get("volumes", [])
    if volume.get("target") == "/external-secrets"
]
if (
    len(external_mounts) != 1
    or external_mounts[0].get("type") != "bind"
    or external_mounts[0].get("source") != effective_secret_source
    or external_mounts[0].get("read_only") is not True
):
    fail("effective Compose external secret mount is not read-only and isolated")

safe_secret_directory_variables = {
    "EXTERNAL_SECRETS_DIR",
    "REFERENCE_PDS_SECRETS_DIR",
    "SWAN_BOOTSTRAP_SECRETS_DIR",
    "SWAN_INTEROP_SECRETS_DIR",
    "SWAN_RUNTIME_SECRETS_DIR",
}
for service_name, service in services.items():
    if service.get("privileged") not in (None, False):
        fail(f"effective Compose service is privileged: {service_name}")
    if service.get("cap_add"):
        fail(f"effective Compose service adds capabilities: {service_name}")
    for environment_key in service.get("environment", {}):
        lowered_key = environment_key.lower()
        if (
            any(
                token in lowered_key
                for token in ("private", "secret", "password", "token")
            )
            and environment_key not in safe_secret_directory_variables
        ):
            fail(
                "effective Compose contains a secret-like environment key: "
                f"{service_name}.{environment_key}"
            )
    for volume in service.get("volumes", []):
        if volume.get("type") != "bind":
            continue
        if (
            service_name != "swan-secrets-init"
            or volume.get("target") != "/external-secrets"
        ):
            fail("effective Compose exposes an unexpected host bind mount")

published = []
for service_name, service in services.items():
    for port in service.get("ports", []):
        published.append((service_name, port))
if len(published) != 1:
    fail("effective Compose Caddy ingress is not the sole loopback publication")
published_service, published_port = published[0]
if (
    published_service != "caddy"
    or published_port.get("host_ip") != "127.0.0.1"
    or published_port.get("target") != 443
    or str(published_port.get("published")) != "443"
    or published_port.get("protocol") != "tcp"
):
    fail("effective Compose Caddy ingress is not the sole loopback publication")

caddy = services["caddy"]
if caddy.get("depends_on", {}).get("swan", {}).get("condition") != "service_healthy":
    fail("effective Compose Caddy must wait for a healthy Swan listener")
caddy_network = caddy.get("networks", {}).get("swan", {})
if caddy_network.get("ipv4_address") != "172.30.0.2":
    fail("effective Compose Caddy must use the fixed login-proxy peer address")
aliases = caddy_network.get("aliases", [])
if set(aliases) != {"swan.test", "pds.test"}:
    fail("effective Compose Caddy aliases do not match the laboratory hosts")
network = configuration.get("networks", {}).get("swan", {})
ipam_config = network.get("ipam", {}).get("config", [])
if (
    not isinstance(ipam_config, list)
    or len(ipam_config) != 1
    or ipam_config[0].get("subnet") != "172.30.0.0/24"
):
    fail("effective Compose interop network must use the fixed login-proxy subnet")

reference = services["reference-pds"]
if reference.get("depends_on", {}).get("reference-plc", {}).get("condition") != (
    "service_healthy"
):
    fail("effective Compose reference PDS must wait for a healthy PLC")
for forbidden in (
    "PDS_DPOP_SECRET",
    "PDS_JWT_SECRET",
    "PDS_ADMIN_PASSWORD",
    "PDS_REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX",
    "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX",
):
    if forbidden in reference.get("environment", {}):
        fail("effective Compose reference PDS contains a secret environment key")

runner = services["scenario-runner"]
if runner.get("profiles") != ["planned-not-executed"]:
    fail("effective Compose scenario runner profile is not inert")
if runner.get("user") != "swan" or runner.get("network_mode") != "none":
    fail("effective Compose scenario runner privilege boundary is invalid")
if runner.get("depends_on", {}).get("caddy-ca-ready", {}).get("condition") != (
    "service_completed_successfully"
):
    fail("effective Compose scenario runner must wait for prepared CA trust")
runner_trust = [
    volume
    for volume in runner.get("volumes", [])
    if volume.get("target") == "/etc/ssl/certs"
]
if len(runner_trust) != 1 or runner_trust[0].get("read_only") is not True:
    fail("effective Compose scenario runner trust mount must be read-only")
PY
  then
    :
  else
    rm -f "$effective_json"
    exit 1
  fi
  rm -f "$effective_json"
  echo "INTEROP LAB EFFECTIVE COMPOSE INVARIANTS OK"
}

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  verify_effective_compose
elif [[ "${SWAN_INTEROP_REQUIRE_EFFECTIVE_COMPOSE:-0}" == "1" ]]; then
  echo "Docker Compose is required for effective interop verification" >&2
  exit 1
else
  echo "INTEROP LAB EFFECTIVE COMPOSE INVARIANTS SKIPPED: Docker Compose unavailable" >&2
fi

echo "INTEROP LAB STATIC INVARIANTS OK"
