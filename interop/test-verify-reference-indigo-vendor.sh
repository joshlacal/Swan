#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

readonly commit="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly verifier="./interop/verify-reference-indigo-vendor.sh"
readonly materializer="./interop/materialize-reference-indigo-vendor.sh"
readonly cache_dir="${SWAN_REFERENCE_INDIGO_CACHE_DIR:-.interop-cache}"
readonly bundle_name="indigo-vendor-${commit}"
readonly source_bundle="${cache_dir}/indigo-${commit}"
readonly vendor_bundle="${cache_dir}/${bundle_name}"
readonly pin_file="interop/reference-indigo-vendor-pin.json"

mkdir -p .interop-cache
# Colima shares the workspace path, while macOS's private TMPDIR is not a
# stable Docker bind-mount source. Keep fixtures in this ignored workspace
# cache so the real container retry test sees the exact files under test.
temporary_directory="$(mktemp -d ".interop-cache/.vendor-tests.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

fail() {
  echo "$*" >&2
  exit 1
}

require_rejection() {
  name="$1"
  expected="$2"
  shift 2
  output=""
  if output="$("$@" 2>&1)"; then
    fail "Indigo vendor verifier accepted unsafe mutation: ${name}"
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "Indigo vendor verifier rejected ${name} for the wrong reason" >&2
    echo "expected diagnostic: ${expected}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

for executable in "$verifier" "$materializer"; do
  [[ -x "$executable" ]] || fail "Indigo vendor harness is missing or not executable: ${executable}"
done
[[ -f "$pin_file" && ! -L "$pin_file" ]] || fail "Indigo vendor pin data is missing or unsafe"
[[ -d "$source_bundle" && ! -L "$source_bundle" ]] || fail "verified Indigo source bundle is unavailable"
[[ -d "$vendor_bundle" && ! -L "$vendor_bundle" ]] || fail "verified Indigo vendor bundle is unavailable; run the materializer"

baseline_output="$($verifier --cache-dir "$cache_dir")"
[[ "$baseline_output" == "REFERENCE INDIGO VENDOR OK: ${commit}" ]] \
  || fail "Indigo vendor verifier baseline did not report the pinned commit"

new_cache_fixture() {
  name="$1"
  fixture="${temporary_directory}/${name}"
  mkdir -p "$fixture"
  cp -R "$source_bundle" "$fixture/"
  cp -R "$vendor_bundle" "$fixture/"
  printf '%s\n' "$fixture"
}

mutated_pin() {
  name="$1"
  field="$2"
  value="$3"
  candidate="${temporary_directory}/${name}.json"
  python3 - "$pin_file" "$candidate" "$field" "$value" <<'PY'
import json
import pathlib
import sys

source, destination, field, value = sys.argv[1:]
document = json.loads(pathlib.Path(source).read_text(encoding="utf-8"))
if field not in document:
    raise SystemExit(f"missing pin field: {field}")
document[field] = value
pathlib.Path(destination).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
  printf '%s\n' "$candidate"
}

zero64="0000000000000000000000000000000000000000000000000000000000000000"
wrong_toolchain_pin="$(mutated_pin wrong-toolchain toolchainImageDigest "sha256:${zero64}")"
require_rejection wrong-toolchain "toolchain image digest mismatch" \
  env SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE=1 \
    SWAN_REFERENCE_INDIGO_VENDOR_PIN_FILE="$wrong_toolchain_pin" \
    "$verifier" --cache-dir "$cache_dir"

wrong_source_pin="$(mutated_pin wrong-source sourceArchiveSHA256 "$zero64")"
require_rejection wrong-source "source archive digest mismatch" \
  env SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE=1 \
    SWAN_REFERENCE_INDIGO_VENDOR_PIN_FILE="$wrong_source_pin" \
    "$verifier" --cache-dir "$cache_dir"

wrong_vendor_pin="$(mutated_pin wrong-vendor vendorArchiveSHA256 "$zero64")"
require_rejection wrong-vendor "vendor archive digest mismatch" \
  env SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE=1 \
    SWAN_REFERENCE_INDIGO_VENDOR_PIN_FILE="$wrong_vendor_pin" \
    "$verifier" --cache-dir "$cache_dir"

corrupt_fixture="$(new_cache_fixture corrupt-archive)"
printf 'not a gzip archive\n' >"${corrupt_fixture}/${bundle_name}/indigo-${commit}.vendor.tar.gz"
require_rejection corrupt-archive "vendor archive digest mismatch" \
  "$verifier" --cache-dir "$corrupt_fixture"

unexpected_fixture="$(new_cache_fixture unexpected-layout)"
printf 'unexpected\n' >"${unexpected_fixture}/${bundle_name}/unexpected"
require_rejection unexpected-layout "vendor bundle has unexpected layout" \
  "$verifier" --cache-dir "$unexpected_fixture"

mismatch_fixture="$(new_cache_fixture extracted-tree-mismatch)"
candidate_file="$(find "${mismatch_fixture}/${bundle_name}/vendor" -type f -print -quit)"
printf '\nmutation\n' >>"$candidate_file"
require_rejection extracted-tree-mismatch "vendor tree does not match its archive" \
  "$verifier" --cache-dir "$mismatch_fixture"

stale_fixture="$(new_cache_fixture stale-partial-cache)"
mkdir "${stale_fixture}/.${bundle_name}.staging"
require_rejection stale-partial-cache "unexpected Indigo vendor cache entry" \
  "$verifier" --cache-dir "$stale_fixture"

archive_mutation() {
  name="$1"
  kind="$2"
  fixture="$(new_cache_fixture "$name")"
  archive="${fixture}/${bundle_name}/indigo-${commit}.vendor.tar.gz"
  python3 - "$archive" "$kind" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

path = pathlib.Path(sys.argv[1])
kind = sys.argv[2]
with tarfile.open(path, "r:gz") as source:
    members = source.getmembers()
    payloads = {
        member.name: source.extractfile(member).read()
        for member in members if member.isfile()
    }
if kind == "symlink":
    member = tarfile.TarInfo("vendor/unsafe-link")
    member.type = tarfile.SYMTYPE
    member.linkname = "modules.txt"
else:
    member = tarfile.TarInfo("vendor/unsafe-device")
    member.type = tarfile.CHRTYPE
members.append(member)
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as output:
    for item in sorted(members, key=lambda candidate: candidate.name):
        output.addfile(item, io.BytesIO(payloads[item.name]) if item.isfile() else None)
with path.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        zipped.write(buffer.getvalue())
PY
  digest="$(shasum -a 256 "$archive" | awk '{print $1}')"
  candidate_pin="$(mutated_pin "${name}-pin" vendorArchiveSHA256 "$digest")"
  python3 - "${fixture}/${bundle_name}/metadata.json" "$digest" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["vendorArchiveSHA256"] = sys.argv[2]
path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  expected="vendor archive contains a symlink"
  [[ "$kind" == "nonregular" ]] && expected="vendor archive contains a non-regular entry"
  require_rejection "$name" "$expected" \
    env SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE=1 \
      SWAN_REFERENCE_INDIGO_VENDOR_PIN_FILE="$candidate_pin" \
      "$verifier" --cache-dir "$fixture"
}

archive_mutation symlink-archive symlink
archive_mutation nonregular-archive nonregular

atomic_cache="${temporary_directory}/atomic-cache"
mkdir -p "$atomic_cache"
cp -R "$source_bundle" "$atomic_cache/"
require_rejection injected-pre-install-failure "injected failure before Indigo vendor install" \
  env SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE=1 \
    SWAN_REFERENCE_INDIGO_CACHE_DIR="$atomic_cache" \
    SWAN_REFERENCE_INDIGO_VENDOR_FAIL_BEFORE_INSTALL=1 \
    "$materializer"
[[ ! -e "${atomic_cache}/${bundle_name}" ]] || fail "failed materialization published a vendor bundle"
[[ ! -e "${atomic_cache}/.${bundle_name}.staging" ]] || fail "failed materialization left staging state"
SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE=1 \
  SWAN_REFERENCE_INDIGO_CACHE_DIR="$atomic_cache" \
  "$materializer" >/dev/null
"$verifier" --cache-dir "$atomic_cache" >/dev/null

echo "REFERENCE INDIGO VENDOR MUTATIONS OK"
