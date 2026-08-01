#!/usr/bin/env bash
set -euo pipefail

# Run the reproducibility gates without reusing Swan's normal SwiftPM build
# directory or reference-source cache. The macOS workload validates a fresh
# SwiftPM scratch path. The Linux-container workload also copies the source
# into a disposable directory, fetches the pinned reference archive there, and
# rebuilds Compose with no Docker layers. Running that workload through Docker
# Desktop is not Linux-host evidence.
#
# This script never creates secrets. Linux mode requires the same external,
# owner-only SWAN_INTEROP_SECRETS_DIR accepted by interop/compose.sh.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_root="$(dirname "$root")"
host_kernel="$(uname -s)"
mode=""
scratch_path=""
wait_timeout="240"
reference_variant="pinned"

# Docker Compose accepts several ambient variables that can silently redirect
# a run to a caller-selected file, project, or profile. This gate owns its
# topology and cleanup, so any such routing input is a hard failure.
for compose_variable in COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR; do
  if [[ -n "${!compose_variable:-}" ]]; then
    echo "${compose_variable} must be unset for clean-cache acceptance" >&2
    exit 64
  fi
done

usage() {
  cat >&2 <<'EOF'
usage: Scripts/run-clean-cache-acceptance.sh [--mode macos|linux] [--scratch-path <directory>] [--wait-timeout <seconds>] [--reference-variant pinned|recovery]

macos: run static verification and swift test with a fresh --scratch-path.
linux: additionally use a copied disposable source tree, fetch its pinned
       reference archive, then build Linux containers and run Compose health
       gates. This is Linux-host evidence only when the host itself is Linux.
reference-variant recovery: apply the checked-in recovery overlay only to the
       disposable reference image; the pinned cache remains immutable.
EOF
  exit 64
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || usage
      mode="$2"
      shift 2
      ;;
    --scratch-path)
      [[ $# -ge 2 ]] || usage
      scratch_path="$2"
      shift 2
      ;;
    --wait-timeout)
      [[ $# -ge 2 ]] || usage
      wait_timeout="$2"
      shift 2
      ;;
    --reference-variant)
      [[ $# -ge 2 ]] || usage
      reference_variant="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

if [[ -z "$mode" ]]; then
  case "$(uname -s)" in
    Darwin) mode="macos" ;;
    Linux) mode="linux" ;;
    *) echo "set --mode explicitly on this platform" >&2; exit 64 ;;
  esac
fi
case "$mode" in macos|linux) ;; *) usage ;; esac
[[ "$wait_timeout" =~ ^[1-9][0-9]*$ ]] || usage
case "$reference_variant" in pinned|recovery) ;; *) usage ;; esac

canonical_path() {
  python3 - "$1" <<'PY'
import os
import sys

print(os.path.realpath(os.path.abspath(sys.argv[1])))
PY
}

path_is_within() {
  python3 - "$1" "$2" <<'PY'
import os
import sys

candidate = os.path.realpath(os.path.abspath(sys.argv[1]))
boundary = os.path.realpath(os.path.abspath(sys.argv[2]))
try:
    inside = os.path.commonpath((candidate, boundary)) == boundary
except ValueError:
    inside = False
raise SystemExit(0 if inside else 1)
PY
}

validate_scratch_boundary() {
  local candidate="$1"
  if path_is_within "$candidate" "$workspace_root"; then
    echo "scratch path must be outside the source workspace: $candidate" >&2
    exit 64
  fi
  if [[ -n "${SWAN_INTEROP_SECRETS_DIR:-}" ]]; then
    local secret_boundary=""
    secret_boundary="$(canonical_path "$SWAN_INTEROP_SECRETS_DIR")"
    if path_is_within "$candidate" "$secret_boundary"; then
      echo "scratch path must be outside the interop secret directory: $candidate" >&2
      exit 64
    fi
  fi
}

if [[ -z "$scratch_path" ]]; then
  scratch_parent="$(canonical_path "${TMPDIR:-/tmp}")"
  validate_scratch_boundary "$scratch_parent"
  scratch_path="$(mktemp -d "${TMPDIR:-/tmp}/swan-clean-cache.XXXXXX")"
else
  scratch_path="$(canonical_path "$scratch_path")"
  validate_scratch_boundary "$scratch_path"
  [[ ! -e "$scratch_path" ]] || { echo "scratch path already exists: $scratch_path" >&2; exit 64; }
  mkdir -p "$scratch_path"
fi
scratch_path="$(cd "$scratch_path" && pwd -P)"
validate_scratch_boundary "$scratch_path"
echo "CLEAN-CACHE SCRATCH: $scratch_path"
echo "CLEAN-CACHE HOST: $host_kernel"

run_static_and_swift() {
  local working_root="$1"
  (
    cd "$working_root"
    ./Scripts/verify-profile.sh
    ./Scripts/verify-interop-lab.sh
    ./Scripts/test-verify-interop-lab.sh
    # CLI subprocess tests intentionally clear their inherited environment.
    # Always build the executable from this same isolated scratch tree and
    # pass its absolute path explicitly so a stale .build/debug/swan can
    # neither create false failures nor mask a source/profile mismatch.
    swift build \
      --scratch-path "$scratch_path/swiftpm-build" \
      --jobs 1 \
      --product swan
    cli_bin="$(swift build \
      --scratch-path "$scratch_path/swiftpm-build" \
      --jobs 1 \
      --show-bin-path)/swan"
    [[ -x "$cli_bin" ]] || {
      echo "clean acceptance could not locate built swan executable" >&2
      exit 1
    }
    export SWAN_TEST_EXECUTABLE="$cli_bin"
    if [[ "$working_root" != "$root" ]]; then
      # Keep a source-tree fallback for test helpers that predate the explicit
      # override. SwiftPM dependency/build state remains isolated, and no
      # normal build cache is reused.
      mkdir -p "$working_root/.build/debug"
      cp "$cli_bin" "$working_root/.build/debug/swan"
      chmod 0755 "$working_root/.build/debug/swan"
    fi
    swift test --scratch-path "$scratch_path/swiftpm-build" --jobs 1
  )
}

if [[ "$mode" == "macos" ]]; then
  run_static_and_swift "$root"
  if [[ "$host_kernel" == "Darwin" ]]; then
    echo "CLEAN-CACHE MACOS BUILD/TEST GATE OK: $scratch_path"
  else
    echo "CLEAN-CACHE BUILD/TEST GATE OK ON ${host_kernel}: $scratch_path"
    echo "--mode macos selected the Swift-only workload; it did not change the host platform"
  fi
  echo "LIVE CROSS-HOST SEMANTIC MATRIX NOT RUN; ALPHA INTEROP ACCEPTANCE REMAINS OPEN"
  exit 0
fi

[[ -n "${SWAN_INTEROP_SECRETS_DIR:-}" ]] || {
  echo "SWAN_INTEROP_SECRETS_DIR is required for the Linux-container Compose gate" >&2
  exit 64
}
command -v docker >/dev/null 2>&1 || {
  echo "Docker is required for the Linux-container Compose gate" >&2
  exit 69
}
docker compose version >/dev/null

workspace_copy="$scratch_path/worktree"
source_root="$workspace_copy/Swan"
mkdir -p "$workspace_copy"
(
  cd "$workspace_root"
  # The workspace contains large unrelated Petrel history, Kotlin, atproto,
  # documentation, and scratch trees. Copy only the inputs consumed by the
  # clean Swift/Compose gate so an unrelated cache cannot turn this into an
  # ENOSPC test failure.
  tar -cf - \
    Swan/Package.swift Swan/Package.resolved \
    Swan/PetrelManifest.json Swan/PublicPetrelManifest.json \
    Swan/Profiles Swan/Sources Swan/Tests Swan/Scripts Swan/fixtures \
    Swan/interop Swan/docker-compose.yml Swan/Dockerfile \
    Swan/Dockerfile.dockerignore \
    Petrel/Package.swift Petrel/Sources
  ) | tar -xf - -C "$workspace_copy"

prepare_compose_network_override() {
  # The checked-in Compose file intentionally uses a fixed subnet and fixed
  # addresses: the Caddy peer address is part of the trusted-proxy contract
  # and the static verifier must continue to inspect those exact values. A
  # clean acceptance run, however, must also be safe to execute while another
  # disposable lab project is still running. In that case generate an
  # untracked Compose override for this run only. The source Compose file and
  # its static invariants are never mutated.
  local network_ids
  network_ids="$(docker network ls -q)"
  local configured_subnets=""
  if [[ -n "$network_ids" ]]; then
    configured_subnets="$(
      printf '%s\n' "$network_ids" \
        | xargs docker network inspect \
            --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' \
            2>/dev/null || true
    )"
  fi
  local network_prefix
  network_prefix="$(python3 - "$configured_subnets" <<'PY'
import ipaddress
import sys

configured = []
for raw in sys.argv[1].splitlines():
    raw = raw.strip()
    if not raw:
        continue
    try:
        configured.append(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        pass

# Keep the first candidate equal to the checked-in network when it is free.
# The remaining candidates are private /24s reserved for this disposable
# harness and are selected only when a live Docker network overlaps it.
for third_octet in [30, *range(31, 255)]:
    candidate = ipaddress.ip_network(f"172.{third_octet}.0.0/24")
    if any(candidate.overlaps(existing) for existing in configured):
        continue
    # Keep the first three octets as the reusable address prefix.  The
    # checked-in Compose file uses 172.30.0.x, so a generated run must retain
    # that same shape rather than producing the malformed 172.30.x form.
    print(f"172.{third_octet}.0")
    break
else:
    raise SystemExit("no unused 172.x.0.0/24 subnet is available")
PY
  )"
  [[ "$network_prefix" =~ ^172\.[0-9]+\.0$ ]] || {
    echo "clean acceptance could not choose an isolated Compose subnet" >&2
    exit 1
  }

  local published_port
  published_port="$(python3 - <<'PY'
import socket

for port in range(443, 5000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    print(port)
    break
else:
    raise SystemExit("no loopback port is available for Caddy")
PY
  )"
  [[ "$published_port" =~ ^[0-9]+$ ]] || {
    echo "clean acceptance could not choose a loopback Caddy port" >&2
    exit 1
  }

  local override="$scratch_path/compose-network-override.yml"
  local reference_build_block=""
  if [[ "$reference_variant" == "recovery" ]]; then
    reference_build_block=$'    build:\n      context: ..\n      dockerfile: Swan/interop/Dockerfile.reference-pds-recovery'
  fi
  cat > "$override" <<EOF
services:
  swan-bootstrap:
    networks:
      swan:
        ipv4_address: ${network_prefix}.6
  swan:
    command:
      - serve
      - --host
      - "0.0.0.0"
      - --port
      - "3000"
      - --public-url
      - "https://swan.test"
      - --profile
      - /usr/local/share/swan/Profiles/permissioned-data-0016-2026-07-30.json
      - --data-directory
      - /var/lib/swan/data
      - --enable-local-space-interop
      - --space-account-kek-file
      - /run/secrets/swan-runtime/account-kek
      - --space-account-kek-id
      - primary
      - --enable-public-repository-mutations
      - --public-account-kek-file
      - /run/secrets/swan-runtime/account-kek
      - --public-account-kek-id
      - primary
      - --oauth-server-key-file
      - /run/secrets/swan-runtime/oauth-server-key
      - --enable-oauth-authorization-server
      - --oauth-allow-localhost-development-client
      - --login-trusted-proxy-peer
      - "${network_prefix}.2"
      - --notification-config
      - /etc/swan/interop/notification-config.json
      - --enable-notification-delivery
      - --managing-service-audience
      - did:web:interop-swan-managing-service
      - --enable-email-recovery
      - --email-proof-key-file
      - /run/secrets/swan-runtime/email-proof-key
      - --email-sender
      - no-reply@swan.local
      - --email-smtp-host
      - mailpit
      - --email-smtp-port
      - "1025"
    networks:
      swan:
        ipv4_address: ${network_prefix}.5
  reference-pds:
${reference_build_block}
    networks:
      swan:
        ipv4_address: ${network_prefix}.4
  reference-plc:
    networks:
      swan:
        ipv4_address: ${network_prefix}.3
  caddy:
    ports: !override
      - "127.0.0.1:${published_port}:443"
    networks:
      swan:
        ipv4_address: ${network_prefix}.2
  mailpit:
    networks:
      swan:
        ipv4_address: ${network_prefix}.7
  toxiproxy:
    networks:
      swan:
        ipv4_address: ${network_prefix}.8
  toxiproxy-setup:
    networks:
      swan:
        ipv4_address: ${network_prefix}.9
networks:
  swan:
    ipam:
      config:
        - subnet: ${network_prefix}.0/24
EOF
  compose_override="$override"
  echo "CLEAN-CACHE COMPOSE OVERRIDE: subnet=${network_prefix}.0/24 caddy=127.0.0.1:${published_port} reference=${reference_variant}" >&2
}

compose_override=""
compose() {
  local compose_files=(--file "$source_root/docker-compose.yml")
  if [[ -n "$compose_override" ]]; then
    compose_files+=(--file "$compose_override")
  fi
  ./interop/compose.sh "${compose_files[@]}" "$@"
}

(
  cd "$source_root"
  ./interop/fetch-reference.sh
  run_static_and_swift "$source_root"
  prepare_compose_network_override
  project_name="swan-clean-cache-$(python3 - <<'PY'
import secrets

print(secrets.token_hex(12))
PY
)"
  echo "CLEAN-CACHE COMPOSE PROJECT: $project_name"
  if [[ -n "$(docker ps --all --filter "label=com.docker.compose.project=${project_name}" --quiet)" ]] \
    || [[ -n "$(docker network ls --filter "label=com.docker.compose.project=${project_name}" --quiet)" ]] \
    || [[ -n "$(docker volume ls --filter "label=com.docker.compose.project=${project_name}" --quiet)" ]]; then
    echo "clean acceptance project name unexpectedly already owns Docker resources" >&2
    exit 1
  fi
  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
  cleanup() {
    compose --project-name "$project_name" down --volumes --remove-orphans >/dev/null 2>&1 || true
  }
  trap cleanup EXIT
  compose --project-name "$project_name" build --no-cache
  if ! compose --project-name "$project_name" up --detach --wait --wait-timeout "$wait_timeout"; then
    # Compose v2 reports a successful one-shot service as an error from
    # `up --wait` once all long-running healthchecks are ready. Accept that
    # known lifecycle result only after inspecting every service explicitly;
    # a real startup or health failure remains fatal.
    status_lines="$(compose \
      --project-name "$project_name" \
      ps --all --format '{{.Service}} {{.State}} {{.ExitCode}} {{.Health}}' \
      | awk '$1 != "REFERENCE" { print }')"
    for service in swan reference-pds reference-plc caddy mailpit; do
      line="$(printf '%s\n' "$status_lines" | awk -v service="$service" '$1 == service { print; exit }')"
      [[ "$line" == "$service running 0 healthy" ]] || {
        echo "clean acceptance service is not healthy: $line" >&2
        exit 1
      }
    done
    line="$(printf '%s\n' "$status_lines" | awk '$1 == "toxiproxy" { print; exit }')"
    [[ "$line" =~ ^toxiproxy[[:space:]]+running[[:space:]]+0[[:space:]]*$ ]] || {
      echo "clean acceptance Toxiproxy is not running: $line" >&2
      exit 1
    }
    for service in swan-secrets-init swan-data-init swan-bootstrap toxiproxy-setup caddy-ca-ready; do
      line="$(printf '%s\n' "$status_lines" | awk -v service="$service" '$1 == service { print; exit }')"
      [[ "$line" =~ ^${service}[[:space:]]+exited[[:space:]]+0[[:space:]]*$ ]] || {
        echo "clean acceptance init service did not complete successfully: $line" >&2
        exit 1
      }
    done
    echo "Compose --wait completed with expected successful one-shot services" >&2
  fi
)

if [[ "$host_kernel" == "Linux" ]]; then
  echo "CLEAN-CACHE LINUX-HOST COMPOSE BUILD/HEALTH GATE OK: $scratch_path"
else
  echo "CLEAN-CACHE DOCKER-LINUX COMPOSE BUILD/HEALTH GATE OK ON ${host_kernel}: $scratch_path"
  echo "THIS IS NOT LINUX-HOST EVIDENCE"
fi
echo "LIVE CROSS-HOST SEMANTIC MATRIX NOT RUN; ALPHA INTEROP ACCEPTANCE REMAINS OPEN (reference=${reference_variant})"
