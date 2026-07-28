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

exec docker compose "$@"
