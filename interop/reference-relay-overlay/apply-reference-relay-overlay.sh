#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly overlay_root="${root}/interop/reference-relay-overlay"
readonly profile="${overlay_root}/profile.json"
readonly patch_file="${overlay_root}/reference-relay-private-upstream.patch"
readonly commit="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly source_bundle="${root}/.interop-cache/indigo-${commit}"
readonly vendor_bundle="${root}/.interop-cache/indigo-vendor-${commit}"
readonly required_patch_line='Transport: ssrf.PublicOnlyTransport(),'
readonly required_subscription_patch_line='netDialer := ssrf.PublicOnlyDialer()'

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [destination]" >&2
  exit 64
fi

(
  cd "$root"
  ./interop/verify-reference-indigo.sh --bundle-dir "$source_bundle"
  ./interop/verify-reference-indigo-vendor.sh --bundle-dir "$vendor_bundle" --source-bundle "$source_bundle"
) >/dev/null

expected_patch_sha="$(python3 - "$profile" "$patch_file" <<'PY'
import hashlib
import json
import pathlib
import sys

profile = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
patch = pathlib.Path(sys.argv[2])
expected = {
    "id": "reference-relay-private-upstream-overlay-2026-08-08",
    "indigoCommit": "8b43a326dbbb394f63b6d68761553cdfe25532de",
    "sourceArchiveSHA256": "bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b",
    "vendorArchiveSHA256": "8dc18074f7833f610c622fc698bed545511a32dd633c348825560ee9b2878b4e",
    "toolchainImageDigest": "sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56",
    "relayBuilderImageDigest": "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b",
    "relayBuilderManifestDigest": "sha256:b58a2431884c6dfc5ddcea953c7f426ad72c2ff9e94b4b8495fefa74e4dabcc0",
    "relayBuilderPlatform": "linux/arm64/v8",
    "relayBuilderGoVersion": "go1.26.4",
    "overlayPatch": patch.name,
}
if any(profile.get(key) != value for key, value in expected.items()):
    raise SystemExit("reference relay overlay profile is not bound to the Indigo pin")
digest = profile.get("overlayPatchSHA256")
if not isinstance(digest, str) or len(digest) != 64:
    raise SystemExit("reference relay overlay profile has an invalid patch digest")
print(digest)
PY
)"
actual_patch_sha="$(shasum -a 256 "$patch_file" | awk '{print $1}')"
if [[ "$actual_patch_sha" != "$expected_patch_sha" ]]; then
  echo "reference relay overlay patch checksum mismatch" >&2
  exit 1
fi

if [[ $# -eq 1 ]]; then
  destination="$1"
  mkdir "$destination" || { echo "overlay destination could not be created atomically: ${destination}" >&2; exit 1; }
else
  destination="$(mktemp -d "${TMPDIR:-/tmp}/swan-reference-relay-overlay.XXXXXX")"
fi

cp -R "${source_bundle}/source/." "$destination"
tar -xzf "${vendor_bundle}/indigo-${commit}.vendor.tar.gz" -C "$destination"
patch --batch --forward -d "$destination" -p1 < "$patch_file"
grep -Fq "$required_patch_line" "$patch_file"
grep -Fq "$required_subscription_patch_line" "$patch_file"
if rg -q 'ssrf\.PublicOnlyTransport' "$destination/cmd/relay/relay/host_checker.go"; then
  echo "reference relay overlay did not replace the private-upstream transport" >&2
  exit 1
fi
if rg -q 'ssrf\.PublicOnlyDialer' "$destination/cmd/relay/relay/slurper.go"; then
  echo "reference relay overlay did not replace the Slurper private-upstream dialer" >&2
  exit 1
fi
printf 'REFERENCE RELAY OVERLAY READY: %s\n' "$destination"
