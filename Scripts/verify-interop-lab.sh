#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

./interop/verify-reference.sh

for service in swan swan-data-init swan-bootstrap reference-pds reference-plc caddy mailpit toxiproxy scenario-runner scenario-artifacts-init; do
  rg -q "^  ${service}:" docker-compose.yml
done
rg -q 'permissioned-data-0016-2026-07-03' Sources/SwanInterop/SwanInterop.swift
rg -q '1caad93dbb1f445396f6abf3b97eb4040345e78e' Sources/SwanInterop/SwanInterop.swift
rg -q '3f6c96d5d2d25438bd40fa89d6ecc37865f8e354' interop/Dockerfile.reference-pds
rg -q '1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea' interop/Dockerfile.reference-pds
rg -q 'tls internal' interop/Caddyfile
rg -q 'reverse_proxy toxiproxy:8666' interop/Caddyfile

rg -qx 'FROM swift:6\.1-jammy AS build' Dockerfile
rg -q 'libsodium-dev pkg-config' Dockerfile
rg -qx 'FROM ubuntu:24\.04' Dockerfile
rg -q 'libsodium23' Dockerfile

# New seed/secret contract and startup ordering.
swan_block="$(awk '/^  swan:/{capture=1; next} capture && /^  [[:alnum:]][[:alnum:]-]*:/{capture=0} capture {print}' docker-compose.yml)"
init_block="$(awk '/^  swan-data-init:/{capture=1; next} capture && /^  [[:alnum:]][[:alnum:]-]*:/{capture=0} capture {print}' docker-compose.yml)"
bootstrap_block="$(awk '/^  swan-bootstrap:/{capture=1; next} capture && /^  [[:alnum:]][[:alnum:]-]*:/{capture=0} capture {print}' docker-compose.yml)"
reference_block="$(awk '/^  reference-pds:/{capture=1; next} capture && /^  [[:alnum:]][[:alnum:]-]*:/{capture=0} capture {print}' docker-compose.yml)"
runner_block="$(awk '/^  scenario-runner:/{capture=1; next} capture && /^  [[:alnum:]][[:alnum:]-]*:/{capture=0} capture {print}' docker-compose.yml)"
artifact_init_block="$(awk '/^  scenario-artifacts-init:/{capture=1; next} capture && /^  [[:alnum:]][[:alnum:]-]*:/{capture=0} capture {print}' docker-compose.yml)"

[[ "$init_block" == *'user: root'* ]]
[[ "$init_block" == *'network_mode: "none"'* ]]
[[ "$init_block" == *'install -d -o swan -g swan -m 0700 /var/lib/swan/data'* ]]
[[ "$init_block" == *'swan-data:/var/lib/swan'* ]]

[[ "$bootstrap_block" == *'user: swan'* ]]
[[ "$bootstrap_block" == *'swan-interop-bootstrap'* ]]
[[ "$bootstrap_block" == *'SWAN_INTEROP_SECRETS_DIR'* ]]

[[ "$swan_block" == *'--oauth-server-key-file'* ]]
[[ "$swan_block" == *'--notification-config'* ]]
[[ "$swan_block" == *'--enable-local-space-interop'* ]]
[[ "$swan_block" == *'--space-account-kek-file'* ]]
[[ "$swan_block" == *'/swan-interoperability-secrets/account-kek'* ]]
[[ "$swan_block" == *'https://swan.test'* ]]
[[ "$swan_block" == *'aliases:'* ]]
[[ "$swan_block" == *'swan.test'* ]]

[[ "$reference_block" == *'aliases:'* ]]
[[ "$reference_block" == *'pds.test'* ]]

[[ "$runner_block" == *'find /caddy-data -type f -name root.crt | head -n 1'* ]]
[[ "$runner_block" == *'/usr/local/bin/swan lab matrix'* ]]
[[ "$runner_block" == *'caddy-data:/caddy-data:ro'* ]]
[[ "$runner_block" == *'SSL_CERT_FILE'* ]]
[[ "$runner_block" == *'condition: service_completed_successfully'* ]]

[[ "$artifact_init_block" == *'user: root'* ]]
[[ "$artifact_init_block" == *'install -d -o swan -g swan -m 0700 /artifacts'* ]]
[[ "$artifact_init_block" == *'scenario-artifacts:/artifacts'* ]]

if rg -q 'SWAN_OAUTH_SERVER_KEY' docker-compose.yml; then
  echo "swan compose must use --oauth-server-key-file" >&2
  exit 1
fi

[[ -f interop/notification-config.json ]]

if command -v jq >/dev/null 2>&1; then
  jq -e '
    . as $config |
    ( $config | type == "object" ) and
    ( $config.authorityDestinations | type == "array" ) and
    ( $config.registrationDestinations | type == "array" ) and
    ( $config.credentialPublicKeys | type == "array" ) and
    ( $config.servicePublicKeys | type == "array" ) and
    ( $config.recipientServiceBindings | type == "array" or . == null ) and
    ( $config.managingServiceAudience | type == "string" or . == null )
  ' interop/notification-config.json >/dev/null
elif command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import json
import sys

with open("interop/notification-config.json", encoding="utf-8") as file:
    config = json.load(file)

if not isinstance(config, dict):
    sys.exit("notification-config is not a JSON object")
for key in [
    "authorityDestinations",
    "registrationDestinations",
    "credentialPublicKeys",
    "servicePublicKeys",
]:
    if not isinstance(config.get(key), list):
        sys.exit(f"notification-config key {key!r} is not an array")

recipient_bindings = config.get("recipientServiceBindings")
if recipient_bindings is not None and not isinstance(recipient_bindings, list):
    sys.exit("'recipientServiceBindings' is not an array when present")

managing_audience = config.get("managingServiceAudience")
if managing_audience is not None and not isinstance(managing_audience, str):
    sys.exit("'managingServiceAudience' is not a string when present")
PY
else
  echo "notification-config validation requires jq or python3, neither is available" >&2
  exit 1
fi

for reference_dockerfile in interop/Dockerfile.reference-pds interop/Dockerfile.reference-plc; do
  ! rg -q '^ARG[[:space:]]+REFERENCE_ARCHIVE_SHA256' "$reference_dockerfile"
  rg -q '^RUN echo "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea  /tmp/reference\.tar\.gz" \| sha256sum -c -' "$reference_dockerfile"
done

# Compose uses the repository root as its context. The generic and
# Dockerfile-specific controls must be allowlists with the sensitive cache
# excluded, except for the one archive explicitly needed by reference builds.
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
  rg -qx '\*\*/\.swan-interop-secrets/**' "$ignore_file"
done
for ignore_file in Dockerfile.dockerignore; do
  rg -qx 'Swan/\.interop-cache/\*\*' "$ignore_file"
  ! rg -q '^!Swan/\.interop-cache/atproto-' "$ignore_file"
done
for ignore_file in interop/Dockerfile.reference-pds.dockerignore interop/Dockerfile.reference-plc.dockerignore; do
  rg -qx 'Swan/\.interop-cache/\*\*' "$ignore_file"
  rg -qx '!Swan/\.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354\.tar\.gz' "$ignore_file"
done

if rg -n '^[[:space:]]*RUN .*\b(curl|git clone|git fetch)\b' interop/Dockerfile.reference-pds interop/Dockerfile.reference-plc; then
  echo "reference image Dockerfiles must not fetch source from the network" >&2
  exit 1
fi

echo "INTEROP LAB STATIC INVARIANTS OK"
