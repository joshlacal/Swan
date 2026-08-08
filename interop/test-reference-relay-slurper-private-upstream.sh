#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

for command in docker rg; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "${command} is required for the reference relay Slurper proof" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required for the reference relay Slurper proof" >&2
  exit 1
fi

./interop/verify-reference-indigo.sh
./interop/verify-reference-indigo-vendor.sh

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-relay-slurper-proof.XXXXXX")"
readonly temporary_directory
readonly compose_file="interop/docker-compose.reference-relay-slurper-proof.yml"
active_project=""
created_network=""
proof_network=""

cleanup() {
  if [[ -n "$active_project" ]]; then
    SWAN_SLURPER_PROOF_NETWORK="$proof_network" docker compose \
      -p "$active_project" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "$created_network" ]]; then
    docker network rm "$created_network" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

while IFS= read -r candidate; do
  subnet="$(docker network inspect "$candidate" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')"
  if [[ "$subnet" == "172.30.0.0/24" ]]; then
    if [[ -n "$proof_network" ]]; then
      echo "multiple Docker networks claim the required 172.30.0.0/24 proof subnet" >&2
      exit 1
    fi
    proof_network="$candidate"
  fi
done < <(docker network ls --filter driver=bridge --format '{{.Name}}')

if [[ -n "$proof_network" ]]; then
  attached="$(docker network inspect "$proof_network" --format '{{len .Containers}}')"
  if [[ "$attached" != "0" ]]; then
    echo "the required 172.30.0.0/24 proof subnet is occupied by ${attached} container(s)" >&2
    exit 1
  fi
else
  created_network="swan-relay-slurper-proof-network-$$"
  docker network create --driver bridge --subnet 172.30.0.0/24 "$created_network" >/dev/null
  proof_network="$created_network"
fi
readonly proof_network

run_case() {
  target="$1"
  log_file="$2"
  active_project="swan-relay-slurper-proof-${target//[^a-z0-9]/-}-$$"

  set +e
  SWAN_SLURPER_PROOF_NETWORK="$proof_network" SWAN_SLURPER_PROOF_TARGET="$target" docker compose \
    -p "$active_project" \
    -f "$compose_file" \
    up --build --pull never --abort-on-container-exit --exit-code-from slurper-proof \
    2>&1 | tee "$log_file"
  status="${PIPESTATUS[0]}"
  set -e

  SWAN_SLURPER_PROOF_NETWORK="$proof_network" docker compose \
    -p "$active_project" -f "$compose_file" down --volumes --remove-orphans >/dev/null
  active_project=""
  return "$status"
}

mutation_log="${temporary_directory}/public-only.log"
if run_case public-only "$mutation_log"; then
  echo "production Slurper proof accepted ssrf.PublicOnlyDialer on the private upstream path" >&2
  exit 1
fi
if ! rg -Fq '172.30.0.8 is not a public IP address' "$mutation_log"; then
  echo "production Slurper mutation failed for the wrong reason" >&2
  exit 1
fi
if ! rg -Fq 'timed out waiting for production Slurper subscribeRepos request' "$mutation_log"; then
  echo "production Slurper mutation did not fail on the unobserved private WSS connection" >&2
  exit 1
fi
echo "REFERENCE RELAY SLURPER PUBLIC-ONLY MUTATION REJECTED"

patched_log="${temporary_directory}/patched.log"
if ! run_case patched "$patched_log"; then
  echo "patched production Slurper did not establish the private WSS path" >&2
  exit 1
fi
if ! rg -Fq 'REFERENCE RELAY SLURPER PRIVATE WSS PROOF OK' "$patched_log"; then
  echo "patched production Slurper exited without the observed WSS proof" >&2
  exit 1
fi
echo "REFERENCE RELAY SLURPER MUTATION AND PRIVATE WSS PROOF OK"
