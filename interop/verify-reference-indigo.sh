#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly ARCHIVE_SHA256="bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b"
cache_dir=".interop-cache"

if [[ "${1:-}" == "--cache-dir" && -n "${2:-}" && $# -eq 2 ]]; then
  cache_dir="$2"
elif [[ $# -ne 0 ]]; then
  echo "usage: interop/verify-reference-indigo.sh [--cache-dir <directory>]" >&2
  exit 64
fi

archive="${cache_dir}/indigo-${COMMIT}.tar.gz"
source_root="${cache_dir}/indigo-${COMMIT}"
if [[ ! -f "$archive" || -L "$archive" || ! -d "$source_root" || -L "$source_root" ]]; then
  echo "pinned Indigo reference cache is unavailable; run interop/fetch-reference-indigo.sh" >&2
  exit 1
fi

actual_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$ARCHIVE_SHA256" ]]; then
  echo "pinned Indigo archive checksum mismatch; refuse to build the reference relay" >&2
  exit 1
fi

python3 - "$cache_dir" "$archive" "$source_root" "$COMMIT" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys
import tarfile

cache_dir, archive_path, source_root = map(pathlib.Path, sys.argv[1:4])
commit = sys.argv[4]
expected_prefix = f"indigo-{commit}"
allowed_cache_entries = {expected_prefix, f"{expected_prefix}.tar.gz"}

for entry in cache_dir.iterdir():
    is_indigo_entry = entry.name.startswith("indigo-") or entry.name.startswith(
        ".indigo-"
    )
    if is_indigo_entry and entry.name not in allowed_cache_entries:
        raise SystemExit(f"unexpected Indigo cache entry: {entry.name}")

required_files = (
    "go.mod",
    "go.sum",
    "cmd/relay/main.go",
    "cmd/relay/relay/slurper.go",
    "cmd/relay/relay/host_checker.go",
    "cmd/relay/Dockerfile",
    "cmd/relay/README.md",
    "cmd/relay/HACKING.md",
)
source_root = source_root.resolve(strict=True)
for required in required_files:
    candidate = source_root / required
    if candidate.is_symlink():
        raise SystemExit(f"pinned Indigo source contains a symlink: {required}")
    if not candidate.is_file():
        raise SystemExit(
            f"pinned Indigo source is incomplete: missing regular file {required}"
        )

tree_files = {}
tree_directories = set()
for directory, directory_names, file_names in os.walk(source_root, followlinks=False):
    directory_path = pathlib.Path(directory)
    for name in directory_names:
        path = directory_path / name
        relative = path.relative_to(source_root).as_posix()
        if path.is_symlink():
            raise SystemExit(f"pinned Indigo source contains a symlink: {relative}")
        if not path.is_dir():
            raise SystemExit(f"pinned Indigo source contains a non-directory: {relative}")
        tree_directories.add(relative)
    for name in file_names:
        path = directory_path / name
        relative = path.relative_to(source_root).as_posix()
        if path.is_symlink():
            raise SystemExit(f"pinned Indigo source contains a symlink: {relative}")
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            raise SystemExit(f"pinned Indigo source contains a non-regular file: {relative}")
        tree_files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

archive_files = {}
archive_directories = set()
try:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise SystemExit("pinned Indigo archive has unexpected layout")
            if path.parts[0] != expected_prefix:
                raise SystemExit("pinned Indigo archive has unexpected layout")
            if len(path.parts) == 1:
                if not member.isdir():
                    raise SystemExit("pinned Indigo archive has unexpected layout")
                continue
            relative = pathlib.PurePosixPath(*path.parts[1:]).as_posix()
            if member.issym() or member.islnk():
                raise SystemExit(f"pinned Indigo archive contains a link: {relative}")
            if member.isdir():
                archive_directories.add(relative)
            elif member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SystemExit("pinned Indigo archive cannot be read")
                archive_files[relative] = hashlib.sha256(extracted.read()).hexdigest()
            else:
                raise SystemExit(
                    f"pinned Indigo archive contains a non-regular entry: {relative}"
                )
except (tarfile.TarError, OSError) as error:
    raise SystemExit(f"pinned Indigo archive cannot be read: {error}") from error

for required in required_files:
    if required not in archive_files:
        raise SystemExit(
            f"pinned Indigo archive is missing required relay source: {required}"
        )

if tree_directories != archive_directories or tree_files != archive_files:
    raise SystemExit("pinned Indigo source does not match its archive")
PY

echo "REFERENCE INDIGO CACHE OK: ${COMMIT}"
