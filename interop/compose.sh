#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
cd "$root"

./interop/verify-reference.sh
if [[ -z "${SWAN_INTEROP_SECRETS_DIR:-}" ]]; then
  echo "SWAN_INTEROP_SECRETS_DIR must name an external owner-only directory" >&2
  exit 1
fi
SWAN_INTEROP_SECRETS_DIR="$(
  ./interop/verify-secret-source.sh "$root" "$SWAN_INTEROP_SECRETS_DIR"
)"
export SWAN_INTEROP_SECRETS_DIR
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required after the pinned reference cache check" >&2
  exit 1
fi

for compose_variable in COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR; do
  if [[ -n "${!compose_variable:-}" ]]; then
    echo "${compose_variable} must be unset; pass Compose topology explicitly" >&2
    exit 64
  fi
done

has_explicit_file=0
for argument in "$@"; do
  if [[ "$argument" == "--file" || "$argument" == "-f" \
    || "$argument" == --file=* || "$argument" == -f* ]]; then
    has_explicit_file=1
  fi
done

if ((has_explicit_file)); then
  exec docker compose "$@"
else
  exec docker compose --file "$root/docker-compose.yml" "$@"
fi
