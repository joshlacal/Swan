#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

./interop/verify-reference.sh

for service in swan reference-pds reference-plc caddy mailpit toxiproxy scenario-runner; do
  rg -q "^  ${service}:" docker-compose.yml
done
rg -q 'permissioned-data-0016-2026-07-03' Sources/SwanInterop/SwanInterop.swift
rg -q '1caad93dbb1f445396f6abf3b97eb4040345e78e' Sources/SwanInterop/SwanInterop.swift
rg -q '3f6c96d5d2d25438bd40fa89d6ecc37865f8e354' interop/Dockerfile.reference-pds
rg -q '1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea' interop/Dockerfile.reference-pds
rg -q 'tls internal' interop/Caddyfile
rg -q 'reverse_proxy toxiproxy:8666' interop/Caddyfile

if rg -n '^[[:space:]]*RUN .*\b(curl|git clone|git fetch)\b' interop/Dockerfile.reference-pds interop/Dockerfile.reference-plc; then
  echo "reference image Dockerfiles must not fetch source from the network" >&2
  exit 1
fi

echo "INTEROP LAB STATIC INVARIANTS OK"
