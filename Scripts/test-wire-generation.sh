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
snapshot_generated() {
  (
    cd Sources/SwanSpacesWire/Generated
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -n 1 "${root}/Scripts/sha256.sh"
  ) >"$1"
}
assert_unchanged() {
  snapshot_generated "${after}"
  cmp "${before}" "${after}"
}

snapshot_generated "${before}"

# A deliberately invalid explicit root must be rejected before the real output
# is touched. This test does not consult a machine-global ../Petrel checkout.
if PETREL_GENERATOR_ROOT="${temporary_root}/missing-generator" ./Scripts/regenerate-wire.sh; then
  echo "test-wire-generation: invalid generator root unexpectedly succeeded" >&2
  exit 1
fi
assert_unchanged

# The capability check must run only after the pinned workspace identity has
# passed. Shadow rg for this invocation so the real immutable workspace is
# selected but advertises neither required server-contract capability.
capability_bin="${temporary_root}/capability-bin"
mkdir "${capability_bin}"
printf '#!/usr/bin/env sh\nexit 1\n' >"${capability_bin}/rg"
chmod +x "${capability_bin}/rg"
if PATH="${capability_bin}:${PATH}" PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" ./Scripts/regenerate-wire.sh; then
  echo "test-wire-generation: missing server-contract capability unexpectedly succeeded" >&2
  exit 1
fi
assert_unchanged

# An editable profile cannot retarget the immutable generator SHA. Exercise
# this preflight directly with a throwaway profile while retaining the same
# generated-output inventory assertion.
bad_profile="${temporary_root}/profile.json"
python3 - "Profiles/permissioned-data-0016-2026-08-15.json" "${bad_profile}" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    profile = json.load(source)
profile["petrelGeneratorCommit"] = "0" * 40
with open(sys.argv[2], "w", encoding="utf-8") as destination:
    json.dump(profile, destination)
PY
if bash -c 'set -euo pipefail; source "$1"; wire_generation_profile="$2"; PETREL_GENERATOR_ROOT="$3"; wire_generation_require_pinned_generator' -- \
  "${root}/Scripts/wire-generation-common.sh" "${bad_profile}" "${PETREL_GENERATOR_ROOT}"; then
  echo "test-wire-generation: mutable profile generator SHA unexpectedly succeeded" >&2
  exit 1
fi
assert_unchanged

# A structurally wrong jj workspace must not pass as the pinned generator. The
# synthetic root carries the expected entrypoint names but no usable repository;
# the actual pinned workspace remains read-only during this test.
wrong_generator="${temporary_root}/wrong-petrel"
mkdir "${wrong_generator}"
(cd "${PETREL_GENERATOR_ROOT}" && tar -cf - .jj run.py generator/main.py) | (cd "${wrong_generator}" && tar -xf -)
if PETREL_GENERATOR_ROOT="${wrong_generator}" ./Scripts/regenerate-wire.sh; then
  echo "test-wire-generation: wrong jj generator workspace unexpectedly succeeded" >&2
  exit 1
fi
assert_unchanged

# The immutable source manifest must reject a lexicon Petrel would otherwise
# discover during recursive traversal. Test it against a copied cache only.
reference_copy="${temporary_root}/reference"
mkdir -p "${reference_copy}"
(cd .interop-cache/atproto-bddc99fb24c34b4078b9bf65837283f37b49ab66 && tar -cf - lexicons) | (cd "${reference_copy}" && tar -xf -)
printf '{"lexicon":1,"id":"com.atproto.space.injected","defs":{"main":{"type":"query"}}}\n' >"${reference_copy}/lexicons/com/atproto/space/injected.json"
if ./Scripts/verify-profile.sh "${reference_copy}"; then
  echo "test-wire-generation: injected source lexicon unexpectedly succeeded" >&2
  exit 1
fi
assert_unchanged

# The generated output manifest is an exact file-set too, so a stale or
# injected Swift file cannot survive a successful postcondition check.
output_copy="${temporary_root}/output-copy"
mkdir -p "${output_copy}/Sources/SwanSpacesWire"
(cd . && tar -cf - Sources/SwanSpacesWire) | (cd "${output_copy}" && tar -xf -)
printf '// injected test source\n' >"${output_copy}/Sources/SwanSpacesWire/Generated/injected.swift"
if bash -c 'set -euo pipefail; source "$1"; wire_generation_verify_checked_in_manifest "$2"' -- \
  "${root}/Scripts/wire-generation-common.sh" "${output_copy}"; then
  echo "test-wire-generation: injected generated Swift file unexpectedly succeeded" >&2
  exit 1
fi
assert_unchanged

PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" ./Scripts/verify-wire-generation.sh
echo "wire generation rejection-before-mutation and deterministic verification passed"
