#!/usr/bin/env bash
set -euo pipefail

readonly default_pin_file="interop/reference-indigo-vendor-pin.json"
readonly commit="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly bundle_name="indigo-vendor-${commit}"
readonly archive_name="indigo-${commit}.vendor.tar.gz"
cache_dir=".interop-cache"
bundle_dir=""
source_bundle=""
scan_cache=1
pin_file="$default_pin_file"

if [[ -n "${SWAN_REFERENCE_INDIGO_VENDOR_PIN_FILE:-}" ]]; then
  if [[ "${SWAN_REFERENCE_INDIGO_VENDOR_TEST_MODE:-0}" != "1" ]]; then
    echo "Indigo vendor verifier input overrides require mutation-test mode" >&2
    exit 64
  fi
  pin_file="$SWAN_REFERENCE_INDIGO_VENDOR_PIN_FILE"
fi

case "${1:-}" in
  --cache-dir)
    [[ -n "${2:-}" && $# -eq 2 ]] || { echo "usage: interop/verify-reference-indigo-vendor.sh [--cache-dir <directory> | --bundle-dir <directory> --source-bundle <directory>]" >&2; exit 64; }
    cache_dir="$2"
    ;;
  --bundle-dir)
    [[ -n "${2:-}" && "${3:-}" == "--source-bundle" && -n "${4:-}" && $# -eq 4 ]] || { echo "usage: interop/verify-reference-indigo-vendor.sh [--cache-dir <directory> | --bundle-dir <directory> --source-bundle <directory>]" >&2; exit 64; }
    bundle_dir="$2"
    source_bundle="$4"
    scan_cache=0
    ;;
  "") ;;
  *) echo "usage: interop/verify-reference-indigo-vendor.sh [--cache-dir <directory> | --bundle-dir <directory> --source-bundle <directory>]" >&2; exit 64 ;;
esac

if [[ -z "$bundle_dir" ]]; then
  bundle_dir="${cache_dir}/${bundle_name}"
  source_bundle="${cache_dir}/indigo-${commit}"
fi
archive="${bundle_dir}/${archive_name}"
metadata="${bundle_dir}/metadata.json"
vendor_root="${bundle_dir}/vendor"

if [[ ! -f "$pin_file" || -L "$pin_file" ]]; then
  echo "Indigo vendor pin data is missing or unsafe" >&2
  exit 1
fi
if [[ ! -d "$bundle_dir" || -L "$bundle_dir" \
  || ! -f "$archive" || -L "$archive" \
  || ! -f "$metadata" || -L "$metadata" \
  || ! -d "$vendor_root" || -L "$vendor_root" ]]
then
  echo "pinned Indigo vendor cache is unavailable; run interop/materialize-reference-indigo-vendor.sh" >&2
  exit 1
fi
./interop/verify-reference-indigo.sh --bundle-dir "$source_bundle" >/dev/null

python3 - "$pin_file" "$metadata" "$cache_dir" "$bundle_dir" "$archive" "$vendor_root" "$commit" "$bundle_name" "$archive_name" "$scan_cache" <<'PY'
import gzip
import hashlib
import json
import os
import pathlib
import stat
import sys
import tarfile

(
    pin_path, metadata_path, cache_dir, bundle_dir, archive_path, vendor_root,
) = map(pathlib.Path, sys.argv[1:7])
commit, bundle_name, archive_name = sys.argv[7:10]
scan_cache = sys.argv[10] == "1"
expected_keys = {
    "schemaVersion", "indigoCommit", "sourceArchiveSHA256", "toolchainImage",
    "toolchainImageDigest", "toolchainPlatform", "goVersion",
    "vendorArchiveSHA256",
}
try:
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Indigo vendor metadata cannot be read: {error}") from error
if set(pin) != expected_keys or pin.get("schemaVersion") != 1:
    raise SystemExit("Indigo vendor pin data has unexpected layout")
if set(metadata) != expected_keys or metadata.get("schemaVersion") != 1:
    raise SystemExit("Indigo vendor metadata has unexpected layout")
immutable_pin = {
    "indigoCommit": commit,
    "sourceArchiveSHA256": "bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b",
    "toolchainImage": "docker.io/library/golang@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56",
    "toolchainImageDigest": "sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56",
    "toolchainPlatform": "linux/arm64/v8",
    "goVersion": "go1.26.4",
}
immutable_diagnostics = {
    "indigoCommit": "Indigo commit mismatch",
    "sourceArchiveSHA256": "source archive digest mismatch",
    "toolchainImage": "toolchain image mismatch",
    "toolchainImageDigest": "toolchain image digest mismatch",
    "toolchainPlatform": "toolchain platform mismatch",
    "goVersion": "Go version mismatch",
}
for field, value in immutable_pin.items():
    if pin.get(field) != value:
        raise SystemExit(immutable_diagnostics[field])
if pin.get("indigoCommit") != commit or metadata.get("indigoCommit") != commit:
    raise SystemExit("Indigo commit mismatch")
for field, diagnostic in (
    ("toolchainImageDigest", "toolchain image digest mismatch"),
    ("sourceArchiveSHA256", "source archive digest mismatch"),
    ("vendorArchiveSHA256", "vendor archive digest mismatch"),
    ("toolchainImage", "toolchain image mismatch"),
    ("toolchainPlatform", "toolchain platform mismatch"),
    ("goVersion", "Go version mismatch"),
):
    if pin.get(field) != metadata.get(field):
        raise SystemExit(diagnostic)

if scan_cache:
    if not cache_dir.is_dir() or cache_dir.is_symlink():
        raise SystemExit("pinned Indigo vendor cache is unavailable")
    for entry in cache_dir.iterdir():
        if (entry.name.startswith("indigo-vendor-") or entry.name.startswith(".indigo-vendor-")) and entry.name != bundle_name:
            raise SystemExit(f"unexpected Indigo vendor cache entry: {entry.name}")
expected_bundle_entries = {archive_name, "metadata.json", "vendor"}
if {entry.name for entry in bundle_dir.iterdir()} != expected_bundle_entries:
    raise SystemExit("vendor bundle has unexpected layout")

actual_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
if actual_digest != pin["vendorArchiveSHA256"]:
    raise SystemExit("vendor archive digest mismatch")

tree_files = {}
tree_directories = {"vendor"}
vendor_root = vendor_root.resolve(strict=True)
for directory, directory_names, file_names in os.walk(vendor_root, followlinks=False):
    directory_path = pathlib.Path(directory)
    for name in directory_names:
        path = directory_path / name
        relative = f"vendor/{path.relative_to(vendor_root).as_posix()}"
        if path.is_symlink():
            raise SystemExit(f"vendor tree contains a symlink: {relative}")
        if not path.is_dir():
            raise SystemExit(f"vendor tree contains a non-directory: {relative}")
        tree_directories.add(relative)
    for name in file_names:
        path = directory_path / name
        relative = f"vendor/{path.relative_to(vendor_root).as_posix()}"
        if path.is_symlink():
            raise SystemExit(f"vendor tree contains a symlink: {relative}")
        if not stat.S_ISREG(path.stat().st_mode):
            raise SystemExit(f"vendor tree contains a non-regular file: {relative}")
        tree_files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

archive_files = {}
archive_directories = set()
try:
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "vendor":
                raise SystemExit("vendor archive has unexpected layout")
            if member.issym() or member.islnk():
                raise SystemExit(f"vendor archive contains a symlink: {member.name}")
            if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
                raise SystemExit("vendor archive metadata is not deterministic")
            if member.isdir():
                if member.mode != 0o755:
                    raise SystemExit("vendor archive metadata is not deterministic")
                archive_directories.add(member.name.rstrip("/"))
            elif member.isfile():
                if member.mode != 0o644:
                    raise SystemExit("vendor archive metadata is not deterministic")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SystemExit("vendor archive cannot be read")
                archive_files[member.name] = hashlib.sha256(extracted.read()).hexdigest()
            else:
                raise SystemExit(f"vendor archive contains a non-regular entry: {member.name}")
except (tarfile.TarError, gzip.BadGzipFile, OSError) as error:
    raise SystemExit(f"vendor archive cannot be read: {error}") from error

if "vendor/modules.txt" not in archive_files:
    raise SystemExit("vendor archive is incomplete: missing vendor/modules.txt")
if tree_directories != archive_directories or tree_files != archive_files:
    raise SystemExit("vendor tree does not match its archive")
PY

echo "REFERENCE INDIGO VENDOR OK: ${commit}"
