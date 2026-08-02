#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly profile_root="${root}/Profiles"
readonly profile="${profile_root}/permissioned-data-0016-2026-07-30.json"
readonly manifest="${profile_root}/permissioned-data-0016-2026-07-30.lexicons.sha256"
readonly generated_manifest="${profile_root}/permissioned-data-0016-2026-07-30.generated-wire.sha256"
readonly petrel_manifest="${root}/PetrelManifest.json"
readonly expected_profile_sha256="431294d96a4a82f15fe5cd0807d89dbcd76d1768a1762d2a0c6a5905e8083988"
readonly expected_manifest_sha256="9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
readonly expected_generated_manifest_sha256="80f9f7b93127826d95d516a4a9d18b7ca245d82fc74f8fa484bbf3423d1f51db"
readonly expected_petrel_manifest_sha256="ac3c8b006e0e771f6e3cb0b5cbe6e93a78101dc49ce95ea9b3e1ed734a97636f"
readonly reference_root="${1:-${root}/.interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354}"
readonly sha256="${root}/Scripts/sha256.sh"
readonly legacy_profile_sha256="30a696e78f62b11f22dd669f6ebb9f7e08d6c1d3346ebd71ad5cf0cd49b3f4d0"
readonly legacy_lexicons_sha256="9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
readonly legacy_generated_sha256="c1d5697f351a4209c7f8a9faaf460d423f9f44f37845ae2c92e150e78c552609"

while read -r artifact expected; do
  [[ -f "${artifact}" && ! -L "${artifact}" ]] || {
    echo "successor profile artifact is missing or symlinked" >&2
    exit 1
  }
  actual="$("${sha256}" "${artifact}" | awk '{print $1}')"
  [[ "${actual}" == "${expected}" ]] || {
    echo "successor profile artifact checksum mismatch" >&2
    exit 1
  }
done <<EOF
${profile} ${expected_profile_sha256}
${manifest} ${expected_manifest_sha256}
${generated_manifest} ${expected_generated_manifest_sha256}
${petrel_manifest} ${expected_petrel_manifest_sha256}
EOF

python3 - "${profile}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    profile = json.load(source)
if profile.get("id") != "permissioned-data-0016-2026-07-30":
    raise SystemExit("successor profile ID mismatch")
if profile.get("petrelGeneratorCommit") != "c2a1cdbee8c621c7682416114700f032cc7e2b37":
    raise SystemExit("successor profile generator pin mismatch")
if profile.get("petrelManifest") != "PetrelManifest.json":
    raise SystemExit("successor profile Petrel manifest name mismatch")
if profile.get("petrelManifestSHA256") != "ac3c8b006e0e771f6e3cb0b5cbe6e93a78101dc49ce95ea9b3e1ed734a97636f":
    raise SystemExit("successor profile Petrel manifest pin mismatch")
if profile.get("lexiconManifest") != "permissioned-data-0016-2026-07-30.lexicons.sha256":
    raise SystemExit("successor profile lexicon manifest name mismatch")
if profile.get("lexiconManifestSHA256") != "9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f":
    raise SystemExit("successor profile lexicon manifest pin mismatch")
if profile.get("generatedWireManifest") != "permissioned-data-0016-2026-07-30.generated-wire.sha256":
    raise SystemExit("successor profile generated-wire manifest name mismatch")
if profile.get("generatedWireManifestSHA256") != "80f9f7b93127826d95d516a4a9d18b7ca245d82fc74f8fa484bbf3423d1f51db":
    raise SystemExit("successor profile generated-wire manifest pin mismatch")
PY

while read -r relative expected; do
  [[ -f "${root}/${relative}" && ! -L "${root}/${relative}" ]] || {
    echo "legacy profile artifact is missing or symlinked: ${relative}" >&2
    exit 1
  }
  actual="$("${sha256}" "${root}/${relative}" | awk '{print $1}')"
  [[ "${actual}" == "${expected}" ]] || {
    echo "legacy profile artifact changed: ${relative}" >&2
    exit 1
  }
done <<EOF
Profiles/permissioned-data-0016-2026-07-03.json ${legacy_profile_sha256}
Profiles/permissioned-data-0016-2026-07-03.lexicons.sha256 ${legacy_lexicons_sha256}
Profiles/permissioned-data-0016-2026-07-03.generated-wire.sha256 ${legacy_generated_sha256}
EOF

if [[ ! -d "${reference_root}/lexicons" ]]; then
  echo "missing pinned source at ${reference_root}; run interop/fetch-reference.sh" >&2
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
