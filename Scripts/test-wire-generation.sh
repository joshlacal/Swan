#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

[[ -n "${PETREL_GENERATOR_ROOT:-}" ]] || {
  echo "test-wire-generation: PETREL_GENERATOR_ROOT is required" >&2
  exit 2
}

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-wire-generation-test.XXXXXX")"
trap 'rm -rf "${temporary_root}"' EXIT
before="${temporary_root}/before.sha256"
after="${temporary_root}/after.sha256"

(
  cd Sources/SwanSpacesWire/Generated
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256
) >"${before}"

# A deliberately invalid explicit root must be rejected before the real output
# is touched. This test does not consult a machine-global ../Petrel checkout.
if PETREL_GENERATOR_ROOT="${temporary_root}/missing-generator" ./Scripts/regenerate-wire.sh; then
  echo "test-wire-generation: invalid generator root unexpectedly succeeded" >&2
  exit 1
fi

(
  cd Sources/SwanSpacesWire/Generated
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256
) >"${after}"
cmp -- "${before}" "${after}"

PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" ./Scripts/verify-wire-generation.sh
echo "wire generation rejection-before-mutation and deterministic verification passed"
