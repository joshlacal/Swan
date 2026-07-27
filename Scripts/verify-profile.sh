#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly profile_root="${root}/Profiles"
readonly manifest="${profile_root}/permissioned-data-0016-2026-07-03.lexicons.sha256"
readonly expected_manifest_sha256="9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
readonly reference_root="${1:-${root}/.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354}"
readonly sha256="${root}/Scripts/sha256.sh"

if [[ ! -d "${reference_root}/lexicons" ]]; then
  echo "missing pinned source at ${reference_root}; run interop/fetch-reference.sh" >&2
  exit 1
fi

actual_manifest_sha256="$("${sha256}" "${manifest}" | awk '{print $1}')"
if [[ "${actual_manifest_sha256}" != "${expected_manifest_sha256}" ]]; then
  echo "checked-in lexicon manifest checksum mismatch" >&2
  exit 1
fi

(
  cd "${reference_root}/lexicons"
  "${sha256}" --check "${manifest}"
)

# Petrel traverses the source tree rather than the manifest. A checksum-only
# check would therefore permit an injected JSON lexicon to be generated. The
# profile's manifest is also the exact allowed file-set for both namespaces.
expected_files="$(mktemp "${TMPDIR:-/tmp}/swan-profile-expected.XXXXXX")"
actual_files="$(mktemp "${TMPDIR:-/tmp}/swan-profile-actual.XXXXXX")"
trap 'rm -f "${expected_files}" "${actual_files}"' EXIT
awk '{print $2}' "${manifest}" | LC_ALL=C sort >"${expected_files}"
(
  cd "${reference_root}/lexicons"
  find com/atproto/space com/atproto/simplespace -type f -name '*.json' -print | LC_ALL=C sort
) >"${actual_files}"
if ! diff -u "${expected_files}" "${actual_files}"; then
  echo "pinned lexicon file-set differs from the immutable profile manifest" >&2
  exit 1
fi

echo "profile lexicons verified"
