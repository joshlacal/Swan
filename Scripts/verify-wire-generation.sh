#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

source "${root}/Scripts/wire-generation-common.sh"

# This command never points Petrel at checked-in output. It is suitable for CI
# after it has materialized the profile's reference archive and pinned Petrel
# workspace locally: all generated files live under this private temp tree.
wire_generation_verify_profile_lexicons
wire_generation_require_pinned_generator
wire_generation_verify_checked_in_manifest

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-wire-generation.XXXXXX")"
trap 'rm -rf "${temporary_root}"' EXIT
temporary_manifest="${temporary_root}/PetrelManifest.json"
temporary_output="${temporary_root}/Generated"
wire_generation_materialize_manifest "${temporary_manifest}" "${temporary_output}"

(
  cd "${PETREL_GENERATOR_ROOT}"
  PYTHONDONTWRITEBYTECODE=1 python3 "${PETREL_GENERATOR_ENTRYPOINT}" \
    --manifest "${temporary_manifest}" \
    --language swift
)

wire_generation_assert_server_contracts "${temporary_output}"

if ! diff -ru "${root}/Sources/SwanSpacesWire/Generated" "${temporary_output}"; then
  echo "wire generation: pinned regeneration differs from checked-in Swift sources" >&2
  exit 1
fi

echo "pinned Swan wire generation verified without worktree mutation"
