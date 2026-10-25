#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

readonly commit="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly source_sha256="bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b"
readonly pin_file="interop/reference-indigo-vendor-pin.json"
readonly image="docker.io/library/golang@sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2"
readonly image_digest="sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2"
readonly platform="linux/arm64/v8"
readonly go_version="go1.27.3"
readonly archive_writer="${root}/interop/write-deterministic-vendor-archive.go"
readonly bundle_name="indigo-vendor-${commit}"
readonly archive_name="indigo-${commit}.vendor.tar.gz"
cache_dir=".interop-cache"

override_names=(
  SWAN_REFERENCE_INDIGO_CACHE_DIR
  SWAN_REFERENCE_INDIGO_VENDOR_FAIL_BEFORE_INSTALL
)
for override_name in "${override_names[@]}"; do
  if [[ -n "${!override_name:-}" ]] \
    && [[ "${SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE:-0}" != "1" ]]
  then
    echo "Indigo vendor materializer overrides require mutation-test mode" >&2
    exit 64
  fi
done
if [[ "${SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE:-0}" == "1" ]]; then
  cache_dir="${SWAN_REFERENCE_INDIGO_CACHE_DIR:-$cache_dir}"
fi

readonly cache_dir
readonly source_bundle="${cache_dir}/indigo-${commit}"
readonly destination="${cache_dir}/${bundle_name}"
readonly staging="${cache_dir}/.${bundle_name}.staging"
readonly work_tree="${staging}/.work"
readonly staged_archive="${staging}/${archive_name}"

for command_name in docker python3 shasum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Indigo vendor materialization requires ${command_name}" >&2
    exit 1
  }
done
docker info >/dev/null 2>&1 || {
  echo "Indigo vendor materialization requires a running Docker daemon" >&2
  exit 1
}
[[ -f "$pin_file" && ! -L "$pin_file" ]] || {
  echo "Indigo vendor pin data is missing or unsafe" >&2
  exit 1
}
[[ -f "$archive_writer" && ! -L "$archive_writer" ]] || {
  echo "deterministic Indigo vendor archive writer is missing or unsafe" >&2
  exit 1
}
./interop/verify-reference-indigo.sh --bundle-dir "$source_bundle" >/dev/null

python3 - "$pin_file" "$commit" "$source_sha256" "$image" "$image_digest" "$platform" "$go_version" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
commit, source_digest, image, image_digest, platform, go_version = sys.argv[2:]
document = json.loads(path.read_text(encoding="utf-8"))
task4_keys = {
    "schemaVersion", "indigoCommit", "sourceArchiveSHA256", "toolchainImage",
    "toolchainImageDigest", "toolchainPlatform", "goVersion",
    "vendorArchiveSHA256",
}
relay_builder_keys = {
    "relayBuilderImage", "relayBuilderImageDigest", "relayBuilderManifestDigest",
    "relayBuilderPlatform", "relayBuilderGoVersion",
}
if set(document) != (task4_keys | relay_builder_keys) or document.get("schemaVersion") != 1:
    raise SystemExit("Indigo vendor pin data has unexpected layout")
expected = {
    "indigoCommit": commit,
    "sourceArchiveSHA256": source_digest,
    "toolchainImage": image,
    "toolchainImageDigest": image_digest,
    "toolchainPlatform": platform,
    "goVersion": go_version,
}
for field, value in expected.items():
    if document.get(field) != value:
        raise SystemExit(f"Indigo vendor pin data has wrong {field}")
vendor_digest = document.get("vendorArchiveSHA256")
if not isinstance(vendor_digest, str) or not vendor_digest:
    raise SystemExit("Indigo vendor pin data has invalid vendorArchiveSHA256")
PY

mkdir -p "$cache_dir"
if [[ -e "$destination" ]]; then
  echo "pinned Indigo vendor cache already exists; remove or archive it explicitly before rematerializing" >&2
  exit 1
fi
if [[ -e "$staging" ]]; then
  echo "stale Indigo vendor staging directory exists; remove it explicitly before materializing" >&2
  exit 1
fi

mkdir -p "$work_tree"
trap 'rm -rf "$staging"' EXIT
cp -R "${source_bundle}/source/." "$work_tree/"
before_go_mod="$(shasum -a 256 "${work_tree}/go.mod" | awk '{print $1}')"
before_go_sum="$(shasum -a 256 "${work_tree}/go.sum" | awk '{print $1}')"

# Registry access and Go proxy/checksum-db access occur only in this explicitly
# platform-selected, digest-pinned container. GOTOOLCHAIN=local prevents Go's
# automatic toolchain downloader from escaping the pinned image contract.
docker run --rm \
  --platform "$platform" \
  --network bridge \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=4g \
  -e HOME=/tmp/home \
  -e GOCACHE=/tmp/go-build \
  -e GOMODCACHE=/tmp/go-mod \
  -e GOTOOLCHAIN=local \
  -v "${work_tree}:/workspace" \
  -v "${archive_writer}:/archive-writer.go:ro" \
  -w /workspace \
  "$image" \
  sh -ceu '
    mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
    test "$(go env GOVERSION)" = "go1.27.3"
    test "$(go env GOOS)/$(go env GOARCH)" = "linux/arm64"
    test "$(sed -n "s/^go //p" go.mod)" = "1.26"
    test "$(sed -n "s/^toolchain //p" go.mod)" = "go1.26.1"
    go mod vendor
    go build -o /workspace/.archive-writer /archive-writer.go
    /workspace/.archive-writer /workspace/vendor /workspace/.vendor.tar.gz
    rm /workspace/.archive-writer
  '

after_go_mod="$(shasum -a 256 "${work_tree}/go.mod" | awk '{print $1}')"
after_go_sum="$(shasum -a 256 "${work_tree}/go.sum" | awk '{print $1}')"
if [[ "$before_go_mod" != "$after_go_mod" || "$before_go_sum" != "$after_go_sum" ]]; then
  echo "go mod vendor mutated the pinned module contract" >&2
  exit 1
fi
[[ -f "${work_tree}/vendor/modules.txt" && ! -L "${work_tree}/vendor/modules.txt" ]] || {
  echo "go mod vendor did not produce a complete regular vendor tree" >&2
  exit 1
}
mv "${work_tree}/.vendor.tar.gz" "$staged_archive"

vendor_sha256="$(shasum -a 256 "$staged_archive" | awk '{print $1}')"
expected_vendor_sha256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vendorArchiveSHA256"])' "$pin_file")"
if [[ "$vendor_sha256" != "$expected_vendor_sha256" ]]; then
  echo "materialized Indigo vendor digest ${vendor_sha256} does not match pinned ${expected_vendor_sha256}" >&2
  exit 1
fi

mv "${work_tree}/vendor" "${staging}/vendor"
rm -rf "$work_tree"
python3 - "$staging/metadata.json" "$commit" "$source_sha256" "$image" "$image_digest" "$platform" "$go_version" "$vendor_sha256" <<'PY'
import json
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
commit, source_digest, image, image_digest, platform, go_version, vendor_digest = sys.argv[2:]
document = {
    "goVersion": go_version,
    "indigoCommit": commit,
    "schemaVersion": 1,
    "sourceArchiveSHA256": source_digest,
    "toolchainImage": image,
    "toolchainImageDigest": image_digest,
    "toolchainPlatform": platform,
    "vendorArchiveSHA256": vendor_digest,
}
destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

./interop/verify-reference-indigo-vendor.sh --bundle-dir "$staging" --source-bundle "$source_bundle" >/dev/null
if [[ "${SWAN_REFERENCE_INDIGO_VENDOR_FAIL_BEFORE_INSTALL:-0}" == "1" ]]; then
  echo "injected failure before Indigo vendor install" >&2
  exit 1
fi
python3 - "$staging" "$destination" <<'PY'
import os
import sys
os.rename(sys.argv[1], sys.argv[2])
PY
trap - EXIT
./interop/verify-reference-indigo-vendor.sh --cache-dir "$cache_dir"
echo "materialized ${destination}/${archive_name}"
