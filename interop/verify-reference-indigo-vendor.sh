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
import zlib

(
    pin_path, metadata_path, cache_dir, bundle_dir, archive_path, vendor_root,
) = map(pathlib.Path, sys.argv[1:7])
commit, bundle_name, archive_name = sys.argv[7:10]
scan_cache = sys.argv[10] == "1"
task4_keys = {
    "schemaVersion", "indigoCommit", "sourceArchiveSHA256", "toolchainImage",
    "toolchainImageDigest", "toolchainPlatform", "goVersion",
    "vendorArchiveSHA256",
}
relay_builder_keys = {
    "relayBuilderImage", "relayBuilderImageDigest", "relayBuilderManifestDigest",
    "relayBuilderPlatform", "relayBuilderGoVersion",
}
try:
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Indigo vendor metadata cannot be read: {error}") from error
if set(pin) - (task4_keys | relay_builder_keys) or pin.get("schemaVersion") != 1:
    raise SystemExit("Indigo vendor pin data has unexpected layout")
if set(metadata) != task4_keys or metadata.get("schemaVersion") != 1:
    raise SystemExit("Indigo vendor metadata has unexpected layout")
immutable_pin = {
    "indigoCommit": commit,
    "sourceArchiveSHA256": "bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b",
    "toolchainImage": "docker.io/library/golang@sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2",
    "toolchainImageDigest": "sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2",
    "toolchainPlatform": "linux/arm64/v8",
    "goVersion": "go1.27.3",
    "relayBuilderImage": "docker.io/library/golang@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5",
    "relayBuilderImageDigest": "sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5",
    "relayBuilderManifestDigest": "sha256:d3f61539a5743b1f1815ba8dd3627202f55262fb09380feda1d585ccf5a9850e",
    "relayBuilderPlatform": "linux/arm64/v8",
    "relayBuilderGoVersion": "go1.27.3",
}
immutable_diagnostics = {
    "indigoCommit": "Indigo commit mismatch",
    "sourceArchiveSHA256": "source archive digest mismatch",
    "toolchainImage": "toolchain image mismatch",
    "toolchainImageDigest": "toolchain image digest mismatch",
    "toolchainPlatform": "toolchain platform mismatch",
    "goVersion": "Go version mismatch",
    "relayBuilderImage": "relay builder image mismatch",
    "relayBuilderImageDigest": "relay builder image digest mismatch",
    "relayBuilderManifestDigest": "relay builder manifest digest mismatch",
    "relayBuilderPlatform": "relay builder platform mismatch",
    "relayBuilderGoVersion": "relay builder Go version mismatch",
}
for field, value in immutable_pin.items():
    if pin.get(field) != value:
        raise SystemExit(immutable_diagnostics[field])
if set(pin) != (task4_keys | relay_builder_keys):
    raise SystemExit("Indigo vendor pin data has unexpected layout")
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

archive_bytes = archive_path.read_bytes()
canonical_gzip_header = bytes.fromhex("1f8b08000000000000ff")
if len(archive_bytes) < 18 or archive_bytes[:10] != canonical_gzip_header:
    raise SystemExit("vendor archive has a noncanonical gzip header")
try:
    decompressor = zlib.decompressobj(wbits=31)
    tar_bytes = decompressor.decompress(archive_bytes) + decompressor.flush()
    if not decompressor.eof or decompressor.unused_data:
        raise SystemExit("vendor archive has a noncanonical gzip stream")
except (gzip.BadGzipFile, OSError, EOFError, zlib.error) as error:
    raise SystemExit(f"vendor archive cannot be read: {error}") from error
if len(tar_bytes) % 512 != 0:
    raise SystemExit("vendor archive must use canonical USTAR")

def parse_octal(field, label):
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    try:
        return int(stripped or b"0", 8)
    except ValueError as error:
        raise SystemExit(f"vendor archive has invalid {label}") from error

def decode_name(field, label):
    raw = field.split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(f"vendor archive has invalid {label}") from error

archive_files = {}
archive_directories = set()
seen_names = set()
ordered_names = []
offset = 0
found_terminator = False
while offset < len(tar_bytes):
    header = tar_bytes[offset:offset + 512]
    if header == bytes(512):
        if tar_bytes[offset:] != bytes(1024):
            raise SystemExit("vendor archive must use canonical USTAR")
        found_terminator = True
        break
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        raise SystemExit("vendor archive must use canonical USTAR")
    stored_checksum = parse_octal(header[148:156], "checksum")
    checksum_header = header[:148] + (b" " * 8) + header[156:]
    if sum(checksum_header) != stored_checksum:
        raise SystemExit("vendor archive has invalid checksum")
    name = decode_name(header[0:100], "member name")
    prefix = decode_name(header[345:500], "member prefix")
    if prefix:
        name = f"{prefix}/{name}"
    if name in seen_names:
        raise SystemExit(f"vendor archive contains a duplicate member: {name}")
    seen_names.add(name)
    ordered_names.append(name)
    typeflag = header[156:157]
    if typeflag in (b"x", b"g", b"L", b"K"):
        raise SystemExit("vendor archive must use canonical USTAR")
    path = pathlib.PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "vendor":
        raise SystemExit("vendor archive has unexpected layout")
    if header[157:257].rstrip(b"\0"):
        raise SystemExit(f"vendor archive contains a symlink: {name}")
    if header[265:329].rstrip(b"\0"):
        raise SystemExit("vendor archive metadata is not deterministic")
    mode = parse_octal(header[100:108], "mode")
    uid = parse_octal(header[108:116], "uid")
    gid = parse_octal(header[116:124], "gid")
    size = parse_octal(header[124:136], "size")
    mtime = parse_octal(header[136:148], "mtime")
    devmajor = parse_octal(header[329:337], "device major")
    devminor = parse_octal(header[337:345], "device minor")
    if uid != 0 or gid != 0 or mtime != 0 or devmajor != 0 or devminor != 0:
        raise SystemExit("vendor archive metadata is not deterministic")
    data_start = offset + 512
    data_end = data_start + size
    padded_end = data_start + ((size + 511) // 512) * 512
    if padded_end > len(tar_bytes) or any(tar_bytes[data_end:padded_end]):
        raise SystemExit("vendor archive must use canonical USTAR")
    canonical_name = name.rstrip("/")
    if typeflag == b"5":
        if mode != 0o755 or size != 0:
            raise SystemExit("vendor archive metadata is not deterministic")
        archive_directories.add(canonical_name)
    elif typeflag in (b"0", b"\0"):
        if mode != 0o644:
            raise SystemExit("vendor archive metadata is not deterministic")
        archive_files[canonical_name] = hashlib.sha256(
            tar_bytes[data_start:data_end]
        ).hexdigest()
    elif typeflag in (b"1", b"2"):
        raise SystemExit(f"vendor archive contains a symlink: {name}")
    else:
        raise SystemExit(f"vendor archive contains a non-regular entry: {name}")
    offset = padded_end

if not found_terminator:
    raise SystemExit("vendor archive must use canonical USTAR")
if ordered_names != sorted(ordered_names):
    raise SystemExit("vendor archive members are not strictly sorted")

if "vendor/modules.txt" not in archive_files:
    raise SystemExit("vendor archive is incomplete: missing vendor/modules.txt")
if tree_directories != archive_directories or tree_files != archive_files:
    raise SystemExit("vendor tree does not match its archive")
PY

echo "REFERENCE INDIGO VENDOR OK: ${commit}"
