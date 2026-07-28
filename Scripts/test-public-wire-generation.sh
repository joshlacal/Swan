#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root}/Scripts/public-wire-generation-common.sh"
[[ -n "${PETREL_GENERATOR_ROOT:-}" ]] || public_wire_die "PETREL_GENERATOR_ROOT is required"

public_wire_verify_checked_in_manifest

capability_bin="${temporary_root:-${TMPDIR:-/tmp}}/swan-public-capability-bin"
mkdir -p "${capability_bin}"
printf '#!/usr/bin/env sh\nexit 1\n' >"${capability_bin}/rg"
chmod +x "${capability_bin}/rg"
if PATH="${capability_bin}:${PATH}" PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" \
  "${root}/Scripts/regenerate-public-wire.sh"; then
  public_wire_die "generator without server-contract capability unexpectedly succeeded"
fi
public_wire_verify_checked_in_manifest

if PETREL_GENERATOR_ROOT="${TMPDIR:-/tmp}/missing-swan-public-generator" "${root}/Scripts/regenerate-public-wire.sh"; then
  public_wire_die "missing generator unexpectedly succeeded"
fi
public_wire_verify_checked_in_manifest

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-public-rejections.XXXXXX")"
wrong_generator="${temporary_root}/wrong-generator"
jj git init --colocate "${wrong_generator}" >/dev/null
mkdir -p "${wrong_generator}/generator"
cp "${PETREL_GENERATOR_ROOT}/run.py" "${wrong_generator}/run.py"
cp "${PETREL_GENERATOR_ROOT}/generator/main.py" "${wrong_generator}/generator/main.py"
wrong_parent_diagnostic=""
if wrong_parent_diagnostic="$(
  PETREL_GENERATOR_ROOT="${wrong_generator}" "${root}/Scripts/regenerate-public-wire.sh" 2>&1
)"; then
  public_wire_die "wrong jj parent unexpectedly succeeded"
fi
grep -F "Petrel generator parent is not pinned" <<<"${wrong_parent_diagnostic}" >/dev/null || {
  echo "${wrong_parent_diagnostic}" >&2
  public_wire_die "wrong-parent fixture did not reach the parent-pin rejection"
}
public_wire_verify_checked_in_manifest

reference_copy="${temporary_root}/reference"
mkdir -p "${reference_copy}"
cp -R "${public_wire_reference_root}/lexicons" "${reference_copy}/lexicons"

printf '{"lexicon":1,"id":"com.atproto.repo.applyWrites","defs":{}}\n' \
  >"${reference_copy}/lexicons/com/atproto/repo/applyWrites.json"
if PUBLIC_WIRE_REFERENCE_ROOT="${reference_copy}" PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" \
  "${root}/Scripts/regenerate-public-wire.sh"; then
  public_wire_die "modified selected lexicon unexpectedly succeeded"
fi
public_wire_verify_checked_in_manifest
cp "${public_wire_reference_root}/lexicons/com/atproto/repo/applyWrites.json" \
  "${reference_copy}/lexicons/com/atproto/repo/applyWrites.json"

# An extra unselected lexicon must never enter the staged generation surface.
printf '{"lexicon":1,"id":"com.atproto.repo.importRepo","defs":{"main":{"type":"procedure"}}}\n' \
  >"${reference_copy}/lexicons/com/atproto/repo/importRepo.json"
printf '{"lexicon":1,"id":"com.atproto.sync.subscribeRepos","defs":{"main":{"type":"subscription"}}}\n' \
  >"${reference_copy}/lexicons/com/atproto/sync/subscribeRepos.json"
PUBLIC_WIRE_REFERENCE_ROOT="${reference_copy}" PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" \
  "${root}/Scripts/verify-public-wire-generation.sh"
public_wire_verify_checked_in_manifest

output_copy="${temporary_root}/output"
mkdir -p "${output_copy}/Sources"
cp -R "${root}/Sources/SwanPublicWire" "${output_copy}/Sources/SwanPublicWire"
printf '// stale generated source\n' >"${output_copy}/Sources/SwanPublicWire/Generated/Injected.swift"
if ( public_wire_verify_checked_in_manifest "${output_copy}" ); then
  public_wire_die "injected generated source unexpectedly succeeded"
fi
public_wire_verify_checked_in_manifest

PETREL_GENERATOR_ROOT="${PETREL_GENERATOR_ROOT}" "${root}/Scripts/verify-public-wire-generation.sh"
echo "public wire generation rejection and deterministic verification passed"
