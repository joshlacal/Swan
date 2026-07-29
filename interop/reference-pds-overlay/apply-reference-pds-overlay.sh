#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly overlay_root="${root}/interop/reference-pds-overlay"
readonly profile="${overlay_root}/profile.json"
readonly commit="3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
readonly source="${root}/.interop-cache/atproto-${commit}"
readonly patch_file="${overlay_root}/reference-pds-recovery.patch"
readonly archive_sha="1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [destination]" >&2
  exit 64
fi

(
  cd "${root}"
  ./interop/verify-reference.sh
) >/dev/null

expected_patch_sha="$(python3 - "${profile}" "${commit}" "${archive_sha}" "$(basename "${patch_file}")" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    profile = json.load(handle)
expected = {
    "referenceImplementationCommit": sys.argv[2],
    "referenceArchiveSHA256": sys.argv[3],
    "overlayPatch": sys.argv[4],
}
for key, value in expected.items():
    if profile.get(key) != value:
        raise SystemExit(f"reference overlay profile mismatch: {key}")
digest = profile.get("overlayPatchSHA256")
if not isinstance(digest, str) or len(digest) != 64 or any(
    character not in "0123456789abcdef" for character in digest
):
    raise SystemExit("reference overlay profile has an invalid patch digest")
print(digest)
PY
)"
actual_patch_sha="$(shasum -a 256 "${patch_file}" | awk '{print $1}')"
if [[ "${actual_patch_sha}" != "${expected_patch_sha}" ]]; then
  echo "reference PDS overlay patch checksum mismatch" >&2
  exit 1
fi

if [[ $# -eq 1 ]]; then
  destination="$1"
  if ! mkdir "${destination}"; then
    echo "overlay destination could not be created atomically: ${destination}" >&2
    exit 1
  fi
else
  destination="$(mktemp -d "${TMPDIR:-/tmp}/swan-reference-pds-overlay.XXXXXX")"
fi

# Do not clone the cache's 1+ GiB pnpm hard-link farm into every disposable
# overlay. A clean workspace install below recreates only the dependencies
# needed by the build, while the source archive and its generated artifacts
# remain immutable.
(
  cd "${source}"
  tar -cf - --exclude=node_modules --exclude=.git --exclude=.jj .
) | (
  cd "${destination}"
  tar -xf -
)
patch --batch --forward -d "${destination}" -p1 < "${patch_file}"
printf 'REFERENCE PDS OVERLAY READY: %s\n' "${destination}"
