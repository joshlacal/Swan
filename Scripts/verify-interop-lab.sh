#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

compose_file="${SWAN_INTEROP_COMPOSE_FILE:-docker-compose.yml}"
if [[ ! -f "$compose_file" ]]; then
  echo "interop Compose file is missing" >&2
  exit 1
fi

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
reject_contains "$bootstrap_block" '${SWAN_INTEROP_SECRETS_DIR' "bootstrap must not mount host secrets directly"

# The long-running runtime is explicitly unprivileged and receives only the
# two-file runtime volume, never bootstrap passwords/operator material.
require_contains "$swan_block" 'user: swan' "Swan runtime must explicitly run as swan"
reject_contains "$swan_block" 'user: root' "Swan runtime must not run as root"
reject_contains "$swan_block" 'privileged:' "Swan runtime must not be privileged"
reject_contains "$swan_block" 'cap_add:' "Swan runtime must not add capabilities"
reject_contains "$swan_block" '/var/run/docker.sock' "Swan runtime must not mount the Docker socket"
require_contains "$swan_block" 'swan-runtime-secrets:/run/secrets/swan-runtime:ro' "runtime secrets must use the read-only prepared volume"
reject_contains "$swan_block" 'swan-bootstrap-secrets' "runtime must not receive bootstrap-only secrets"
reject_contains "$swan_block" 'operator-secret' "runtime must not receive the operator secret"
reject_contains "$swan_block" '.password' "runtime must not receive account passwords"
reject_contains "$swan_block" '${SWAN_INTEROP_SECRETS_DIR' "runtime must not mount host secrets directly"
require_contains "$swan_block" '--oauth-server-key-file' "file-backed OAuth server key flag is missing"
require_contains "$swan_block" '/run/secrets/swan-runtime/oauth-server-key' "OAuth server key path is wrong"
require_contains "$swan_block" '--enable-oauth-authorization-server' "Compose must enable the complete OAuth authorization server"
require_contains "$swan_block" '--oauth-allow-localhost-development-client' "Compose must declare its localhost client metadata exception"
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
require_contains "$reference_block" $'reference-plc:\n        condition: service_healthy' "reference PDS must wait for a healthy PLC"
require_contains "$(service_block toxiproxy-setup)" $'reference-pds:\n        condition: service_healthy' "Toxiproxy setup must wait for a healthy reference PDS"
require_contains "$caddy_block" $'swan:\n        condition: service_healthy' "Caddy must wait for a healthy Swan listener"
require_contains "$caddy_block" '"127.0.0.1:443:443"' "Caddy must be the loopback-only host ingress"
require_contains "$caddy_block" 'test -s /data/caddy/pki/authorities/local/root.crt' "Caddy CA healthcheck is missing"
require_contains "$caddy_block" 'aliases:' "Caddy TLS aliases are missing"
require_contains "$caddy_block" 'swan.test' "Caddy must own the swan.test network alias"
require_contains "$caddy_block" 'pds.test' "Caddy must own the pds.test network alias"
reject_contains "$mailpit_block" 'ports:' "Mailpit must not publish a host port"
reject_contains "$toxiproxy_block" 'ports:' "Toxiproxy must not publish a host port"
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

rg -q 'permissioned-data-0016-2026-07-03' Sources/SwanInterop/SwanInterop.swift
rg -q '1caad93dbb1f445396f6abf3b97eb4040345e78e' Sources/SwanInterop/SwanInterop.swift
rg -q '3f6c96d5d2d25438bd40fa89d6ecc37865f8e354' interop/Dockerfile.reference-pds
rg -q '1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea' interop/Dockerfile.reference-pds
rg -q 'tls internal' interop/Caddyfile
rg -q 'reverse_proxy toxiproxy:8666' interop/Caddyfile

rg -qx 'FROM swift:6\.1-jammy AS build' Dockerfile
rg -q 'libsodium-dev pkg-config' Dockerfile
# The runtime keeps the Swift 6.1 standard-library surface alongside the
# release executable. A minimal Ubuntu runtime would omit those libraries and
# fail only after the container passes image build.
rg -qx 'FROM swift:6\.1-jammy' Dockerfile
rg -q 'libsodium23' Dockerfile
rg -q 'COPY Swan/interop/bootstrap-local-space\.sh /usr/local/bin/swan-interop-bootstrap' Dockerfile
rg -q 'COPY Swan/interop/prepare-interop-secrets\.sh /usr/local/bin/swan-interop-prepare-secrets' Dockerfile
rg -q 'COPY Swan/interop/prepare-caddy-trust\.sh /usr/local/bin/swan-interop-caddy-trust' Dockerfile
rg -q 'COPY Swan/interop/run-reference-pds\.sh /usr/local/bin/reference-pds-with-file-secrets' interop/Dockerfile.reference-pds
rg -q '^CMD \["/usr/local/bin/reference-pds-with-file-secrets",' interop/Dockerfile.reference-pds
rg -q 'find "\$source" -perm /077' interop/prepare-interop-secrets.sh
rg -q 'install -o "\$owner" -g "\$group" -m 0400' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$runtime_directory" swan swan' interop/prepare-interop-secrets.sh
rg -q 'prepare_directory "\$pds_directory" 1000 1000' interop/prepare-interop-secrets.sh
rg -q 'source_certificate="/caddy-data/caddy/pki/authorities/local/root\.crt"' interop/prepare-caddy-trust.sh
rg -q 'install -o swan -g swan -m 0444' interop/prepare-caddy-trust.sh
rg -q 'verify-secret-source\.sh "\$root" "\$SWAN_INTEROP_SECRETS_DIR"' interop/compose.sh

for reference_dockerfile in interop/Dockerfile.reference-pds interop/Dockerfile.reference-plc; do
  ! rg -q '^ARG[[:space:]]+REFERENCE_ARCHIVE_SHA256' "$reference_dockerfile"
  rg -q '^RUN echo "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea  /tmp/reference\.tar\.gz" \| sha256sum -c -' "$reference_dockerfile"
done

# Every build context is an allowlist and excludes secret/state paths. The
# pinned reference builds expose only the verified archive exception.
for ignore_file in Dockerfile.dockerignore interop/Dockerfile.reference-pds.dockerignore interop/Dockerfile.reference-plc.dockerignore; do
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
rg -qx 'Swan/\.interop-cache/\*\*' Dockerfile.dockerignore
! rg -q '^!Swan/\.interop-cache/atproto-' Dockerfile.dockerignore
for ignore_file in interop/Dockerfile.reference-pds.dockerignore interop/Dockerfile.reference-plc.dockerignore; do
  rg -qx 'Swan/\.interop-cache/\*\*' "$ignore_file"
  rg -qx '!Swan/\.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354\.tar\.gz' "$ignore_file"
done

if rg -n '^[[:space:]]*RUN .*\b(curl|git clone|git fetch)\b' interop/Dockerfile.reference-pds interop/Dockerfile.reference-plc; then
  echo "reference image Dockerfiles must not fetch source from the network" >&2
  exit 1
fi

echo "INTEROP LAB STATIC INVARIANTS OK"
