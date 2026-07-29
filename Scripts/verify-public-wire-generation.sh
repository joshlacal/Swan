#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root}/Scripts/public-wire-generation-common.sh"

public_wire_verify_source_manifest
public_wire_require_pinned_generator
public_wire_verify_checked_in_manifest

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-public-verify.XXXXXX")"
trap 'find "${temporary_root}" -depth -delete' EXIT
staged="${temporary_root}/lexicons"
output="${temporary_root}/Generated"
manifest="${temporary_root}/PublicPetrelManifest.json"
public_wire_stage_lexicons "${staged}"
public_wire_materialize_manifest "${staged}" "${output}" "${manifest}"
(
  cd "${PETREL_GENERATOR_ROOT}"
  PYTHONDONTWRITEBYTECODE=1 python3 "${PETREL_GENERATOR_ENTRYPOINT}" --manifest "${manifest}" --language swift
)
public_wire_normalize_generated_sources "${output}"
public_wire_assert_contracts "${output}"
diff -ru "${root}/Sources/SwanPublicWire/Generated" "${output}" >/dev/null || public_wire_die "pinned regeneration differs from checked-in public wire"
public_wire_verify_legacy_profile_immutable
echo "pinned Swan public wire generation verified without worktree mutation"
