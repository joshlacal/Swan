#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

source "${root}/Scripts/wire-generation-common.sh"

# Every condition below is read-only. In particular, do not invoke Petrel until
# both the pinned lexicon tree and the explicitly selected generator have been
# checked: an ordinary ../Petrel checkout predates server contracts and would
# otherwise delete them from the checked-in output.
wire_generation_verify_profile_lexicons
# Reject stale or injected checked-in Swift files before Petrel ever receives
# the real output path. The same immutable inventory/checksum runs again as
# the postcondition after generation.
wire_generation_verify_checked_in_manifest
wire_generation_require_pinned_generator

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-wire-regeneration.XXXXXX")"
trap 'rm -rf "${temporary_root}"' EXIT
temporary_manifest="${temporary_root}/PetrelManifest.json"
wire_generation_materialize_manifest \
  "${temporary_manifest}" \
  "${root}/Sources/SwanSpacesWire/Generated"

(
  cd "${PETREL_GENERATOR_ROOT}"
  PYTHONDONTWRITEBYTECODE=1 python3 "${PETREL_GENERATOR_ENTRYPOINT}" \
  --manifest "${temporary_manifest}" \
  --language swift
)

wire_generation_assert_server_contracts "${root}/Sources/SwanSpacesWire/Generated"
wire_generation_verify_checked_in_manifest

echo "pinned Swan wire sources regenerated"
