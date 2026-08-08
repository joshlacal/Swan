#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly ARCHIVE_SHA256="bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b"
readonly SOURCE_URL="https://github.com/bluesky-social/indigo/archive/${COMMIT}.tar.gz"
readonly CACHE_DIR=".interop-cache"
readonly DESTINATION="${CACHE_DIR}/indigo-${COMMIT}"
readonly ARCHIVE="${CACHE_DIR}/indigo-${COMMIT}.tar.gz"
readonly STAGING="${CACHE_DIR}/.indigo-${COMMIT}.staging"

mkdir -p "$CACHE_DIR"
if [[ -e "$DESTINATION" || -e "$ARCHIVE" ]]; then
  echo "pinned Indigo cache already exists; remove or archive it explicitly before refetching" >&2
  exit 1
fi
if [[ -e "$STAGING" ]]; then
  echo "stale Indigo staging directory exists; remove it explicitly before refetching" >&2
  exit 1
fi

mkdir -p "$STAGING"
trap 'rm -rf "$STAGING"' EXIT
staged_archive="${STAGING}/indigo-${COMMIT}.tar.gz"
staged_source="${STAGING}/indigo-${COMMIT}"

curl --fail --location --retry 3 "$SOURCE_URL" -o "$staged_archive"
actual_sha256="$(shasum -a 256 "$staged_archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$ARCHIVE_SHA256" ]]; then
  echo "reference Indigo archive checksum mismatch" >&2
  exit 1
fi

python3 - "$staged_archive" "$STAGING" "$COMMIT" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
staging = pathlib.Path(sys.argv[2])
commit = sys.argv[3]
expected_prefix = f"indigo-{commit}"
required_files = {
    "go.mod",
    "go.sum",
    "cmd/relay/main.go",
    "cmd/relay/relay/slurper.go",
    "cmd/relay/relay/host_checker.go",
    "cmd/relay/Dockerfile",
    "cmd/relay/README.md",
    "cmd/relay/HACKING.md",
}

try:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        regular_files = set()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise SystemExit("reference Indigo archive has unexpected top-level layout")
            if path.parts[0] != expected_prefix:
                raise SystemExit("reference Indigo archive has unexpected top-level layout")
            if len(path.parts) == 1:
                if not member.isdir():
                    raise SystemExit("reference Indigo archive has unexpected top-level layout")
                continue
            relative = pathlib.PurePosixPath(*path.parts[1:]).as_posix()
            if member.issym() or member.islnk():
                raise SystemExit(f"reference Indigo archive contains a link: {relative}")
            if member.isfile():
                regular_files.add(relative)
            elif not member.isdir():
                raise SystemExit(
                    f"reference Indigo archive contains a non-regular entry: {relative}"
                )
        missing = sorted(required_files - regular_files)
        if missing:
            raise SystemExit(
                "verified reference Indigo archive is missing required relay source: "
                + ", ".join(missing)
            )
        archive.extractall(staging, members=members)
except (tarfile.TarError, OSError) as error:
    raise SystemExit(f"reference Indigo archive cannot be read: {error}") from error
PY

./interop/verify-reference-indigo.sh --cache-dir "$STAGING"
mv "$staged_source" "$DESTINATION"
mv "$staged_archive" "$ARCHIVE"
rmdir "$STAGING"
trap - EXIT
./interop/verify-reference-indigo.sh
echo "verified ${ARCHIVE}"
