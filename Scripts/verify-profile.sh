#!/usr/bin/env bash
set -euo pipefail

readonly profile_root="Profiles"
readonly manifest="${profile_root}/permissioned-data-0016-2026-07-03.lexicons.sha256"
readonly expected_manifest_sha256="9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
readonly reference_root="${1:-.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354}"

if [[ ! -d "${reference_root}/lexicons" ]]; then
  echo "missing pinned source at ${reference_root}; run interop/fetch-reference.sh" >&2
  exit 1
fi

actual_manifest_sha256="$(shasum -a 256 "${manifest}" | awk '{print $1}')"
if [[ "${actual_manifest_sha256}" != "${expected_manifest_sha256}" ]]; then
  echo "checked-in lexicon manifest checksum mismatch" >&2
  exit 1
fi

(
  cd "${reference_root}/lexicons"
  shasum -a 256 -c "../../../${manifest}"
)

echo "profile lexicons verified"
