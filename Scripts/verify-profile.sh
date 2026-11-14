#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly profile_root="${root}/Profiles"
readonly profile="${profile_root}/permissioned-data-0016-2026-11-12.json"
readonly manifest="${profile_root}/permissioned-data-0016-2026-11-12.lexicons.sha256"
readonly generated_manifest="${profile_root}/permissioned-data-0016-2026-11-12.generated-wire.sha256"
readonly petrel_manifest="${root}/PetrelManifest.json"
readonly expected_profile_sha256="94883aec91cc77c0151bd2fd6b496c2115a0e8bacbc8fca69b32ce865b63c681"
readonly expected_manifest_sha256="7183524dccbb66126f9fb3dafc2a436d46d6f885b8ad4b5d8defae2086222ed7"
readonly expected_generated_manifest_sha256="4fed431ea394fdd71b396a2aa67362e64bdcbd3d94ac9d337cd3c4e045fd897b"
readonly expected_petrel_manifest_sha256="c5845f5d1052cf3a683f32dbb4334f747ac5fd5aec9e14cd3c655f3c4ae2506b"
readonly reference_root="${1:-${root}/.interop-cache/atproto-d4def6e9f521896ed8222f576d54923d00b5fbeb}"
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
if profile.get("id") != "permissioned-data-0016-2026-11-12":
    raise SystemExit("successor profile ID mismatch")
if profile.get("referenceImplementationCommit") != "d4def6e9f521896ed8222f576d54923d00b5fbeb":
    raise SystemExit("successor profile reference pin mismatch")
if profile.get("petrelGeneratorCommit") != "baa8cf10199c049e5137b5f1d8fa3cfbd4563f29":
    raise SystemExit("successor profile generator pin mismatch")
if profile.get("petrelManifest") != "PetrelManifest.json":
    raise SystemExit("successor profile Petrel manifest name mismatch")
if profile.get("petrelManifestSHA256") != "c5845f5d1052cf3a683f32dbb4334f747ac5fd5aec9e14cd3c655f3c4ae2506b":
    raise SystemExit("successor profile Petrel manifest pin mismatch")
if profile.get("lexiconManifest") != "permissioned-data-0016-2026-11-12.lexicons.sha256":
    raise SystemExit("successor profile lexicon manifest name mismatch")
if profile.get("lexiconManifestSHA256") != "7183524dccbb66126f9fb3dafc2a436d46d6f885b8ad4b5d8defae2086222ed7":
    raise SystemExit("successor profile lexicon manifest pin mismatch")
if profile.get("generatedWireManifest") != "permissioned-data-0016-2026-11-12.generated-wire.sha256":
    raise SystemExit("successor profile generated-wire manifest name mismatch")
if profile.get("generatedWireManifestSHA256") != "4fed431ea394fdd71b396a2aa67362e64bdcbd3d94ac9d337cd3c4e045fd897b":
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
Profiles/permissioned-data-0016-2026-07-30.json 431294d96a4a82f15fe5cd0807d89dbcd76d1768a1762d2a0c6a5905e8083988
Profiles/permissioned-data-0016-2026-07-30.lexicons.sha256 9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f
Profiles/permissioned-data-0016-2026-07-30.generated-wire.sha256 80f9f7b93127826d95d516a4a9d18b7ca245d82fc74f8fa484bbf3423d1f51db
Profiles/permissioned-data-0016-2026-08-15.json b3edfc13675d4273cf036f1f74391795b3f1307d4b1fd24ad021f26fa60e4023
Profiles/permissioned-data-0016-2026-08-15.lexicons.sha256 873fb88439cadd447ee6a90f9fadb262fa84bdb6689735b53e667db13d7219c3
Profiles/permissioned-data-0016-2026-08-15.generated-wire.sha256 7e7fe09868a7fcda0c6ab824ebe19e7f64ba147db63fd02a27762ed538e02704
Profiles/permissioned-data-0016-2026-09-10.json 3214c31ab5c277f4958a2d3dd5ecd03331f348f869f35a5d3916ee59d9528acc
Profiles/permissioned-data-0016-2026-09-10.lexicons.sha256 7ecbc75972d592e349f0227ff3bc1f0841fe3fda83e16ff1d3c39bbfaeca9de8
Profiles/permissioned-data-0016-2026-09-10.generated-wire.sha256 9b3df8b2b04445a3c2a623fc556469b6aa430a0901ead90709abf3f4fd7af876
Profiles/permissioned-data-0016-2026-09-19.json ab41a971e868b924cec395887233e8ae9f0991029b14b7a7e4af4f7f615b6b75
Profiles/permissioned-data-0016-2026-09-19.lexicons.sha256 7ecbc75972d592e349f0227ff3bc1f0841fe3fda83e16ff1d3c39bbfaeca9de8
Profiles/permissioned-data-0016-2026-09-19.generated-wire.sha256 3f4efbc98fb24c7b6883f5255c5b2e59bc74c971dc7753da1da2a1e2ab1b667e
Profiles/permissioned-data-0016-2026-10-22.json 7fa8f20d84051e296e43fc39acd0ad34ecb4656a4bbf648c08182587e3452d60
Profiles/permissioned-data-0016-2026-10-22.lexicons.sha256 fbbf6e9b89507d24d8bffd3df78cd9c5a8d4aa8190f5bf8870bb53281d972bc3
Profiles/permissioned-data-0016-2026-10-22.generated-wire.sha256 1bd8bd00ee6c7beb620d0b72e4c6e25d99e1c0563f9958724512ec002606be9a
Profiles/permissioned-data-0016-2026-10-29.json 10066bf334b217e0f021e362805d9340da6a6a4053254674cf1ff93d1b3b84f0
Profiles/permissioned-data-0016-2026-10-29.lexicons.sha256 6c699f9dca3c5b08180f91f30a2275d409488e9cd29b380215277e0bc33364af
Profiles/permissioned-data-0016-2026-10-29.generated-wire.sha256 7fb57cdb9bfd067f0deae7fc19b62e481fd5622dc929401c1f5faaa5f3b9c573
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
# profile's manifest is also the exact allowed file-set for the four namespaces.
expected_files="$(mktemp "${TMPDIR:-/tmp}/swan-profile-expected.XXXXXX")"
actual_files="$(mktemp "${TMPDIR:-/tmp}/swan-profile-actual.XXXXXX")"
trap 'rm -f "${expected_files}" "${actual_files}"' EXIT
awk '{print $2}' "${manifest}" | LC_ALL=C sort >"${expected_files}"
(
  cd "${reference_root}/lexicons"
  find com/atproto/space com/atproto/memberspace com/atproto/managedspace com/atproto/personalspace -type f -name '*.json' -print | LC_ALL=C sort
) >"${actual_files}"
if ! diff -u "${expected_files}" "${actual_files}"; then
  echo "pinned lexicon file-set differs from the immutable profile manifest" >&2
  exit 1
fi

echo "profile lexicons verified"
