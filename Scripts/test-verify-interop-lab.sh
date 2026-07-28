#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/swan-interop-verifier.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

mutate_and_require_rejection() {
  name="$1"
  old="$2"
  new="$3"
  candidate="${temporary_directory}/${name}.yml"
  cp docker-compose.yml "$candidate"

  python3 - "$candidate" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
contents = path.read_text(encoding="utf-8")
if contents.count(old) != 1:
    raise SystemExit(
        f"mutation fixture expected exactly one occurrence, found {contents.count(old)}"
    )
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY

  if SWAN_INTEROP_COMPOSE_FILE="$candidate" ./Scripts/verify-interop-lab.sh >/dev/null 2>&1; then
    echo "verifier accepted unsafe mutation: ${name}" >&2
    exit 1
  fi
}

mutate_and_require_rejection \
  root-swan-runtime \
  $'  swan:\n    build:' \
  $'  swan:\n    user: root\n    build:'

mutate_and_require_rejection \
  writable-runtime-secret \
  '/run/secrets/swan-runtime:ro' \
  '/run/secrets/swan-runtime:rw'

mutate_and_require_rejection \
  missing-bootstrap-success-dependency \
  $'      swan-bootstrap:\n        condition: service_completed_successfully' \
  $'      swan-bootstrap:\n        condition: service_started'

mutate_and_require_rejection \
  compose-secret-environment-value \
  $'      PDS_HOSTNAME: pds.test' \
  $'      PDS_HOSTNAME: pds.test\n      PDS_JWT_SECRET: ${PDS_JWT_SECRET}'

mutate_and_require_rejection \
  live-scenario-command \
  'echo "planned-not-executed: CA trust prepared; no probes or faults were run"' \
  '/usr/local/bin/swan lab matrix --fail-on-failure'

mutate_and_require_rejection \
  root-scenario-runner \
  $'  scenario-runner:\n    profiles:' \
  $'  scenario-runner:\n    user: root\n    profiles:'

mutate_and_require_rejection \
  caddy-started-not-ready \
  $'      caddy-ca-ready:\n        condition: service_completed_successfully' \
  $'      caddy:\n        condition: service_started'

mutate_and_require_rejection \
  overbroad-runtime-secret-source \
  'swan-runtime-secrets:/run/secrets/swan-runtime:ro' \
  '${SWAN_INTEROP_SECRETS_DIR}:/run/secrets/swan-runtime:ro'

echo "INTEROP LAB VERIFIER MUTATION TESTS OK"
