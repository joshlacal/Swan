#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${root}/Scripts/public-wire-generation-common.sh"

public_wire_verify_source_manifest
public_wire_verify_checked_in_manifest
public_wire_require_pinned_generator

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/swan-public-regenerate.XXXXXX")"
trap 'find "${temporary_root}" -depth -delete' EXIT
staged="${temporary_root}/lexicons"
manifest="${temporary_root}/PublicPetrelManifest.json"
public_wire_stage_lexicons "${staged}"
public_wire_materialize_manifest "${staged}" "${root}/Sources/SwanPublicWire/Generated" "${manifest}"
(
  cd "${PETREL_GENERATOR_ROOT}"
  PYTHONDONTWRITEBYTECODE=1 python3 "${PETREL_GENERATOR_ENTRYPOINT}" --manifest "${manifest}" --language swift
)
public_wire_normalize_generated_sources "${root}/Sources/SwanPublicWire/Generated"
public_wire_assert_contracts "${root}/Sources/SwanPublicWire/Generated"
public_wire_verify_checked_in_manifest
public_wire_verify_legacy_profile_immutable
echo "pinned Swan public wire sources regenerated"
