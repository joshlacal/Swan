#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="8b43a326dbbb394f63b6d68761553cdfe25532de"
readonly ARCHIVE_SHA256="bc6f57e6211560220ac49dc7d6b55c5a43291f1e1193113ce413ffe4478fdd0b"
readonly SOURCE_URL="https://github.com/bluesky-social/indigo/archive/${COMMIT}.tar.gz"
cache_dir=".interop-cache"

override_names=(
  SWAN_REFERENCE_INDIGO_CACHE_DIR
  SWAN_REFERENCE_INDIGO_SOURCE_ARCHIVE
  SWAN_REFERENCE_INDIGO_FAIL_BEFORE_INSTALL
)
for override_name in "${override_names[@]}"; do
  if [[ -n "${!override_name:-}" ]] \
    && [[ "${SWAN_REFERENCE_INDIGO_FETCH_TEST_MODE:-0}" != "1" ]]
  then
    echo "Indigo fetch overrides require mutation-test mode" >&2
    exit 64
  fi
done
if [[ "${SWAN_REFERENCE_INDIGO_FETCH_TEST_MODE:-0}" == "1" ]]; then
  cache_dir="${SWAN_REFERENCE_INDIGO_CACHE_DIR:-$cache_dir}"
fi

readonly CACHE_DIR="$cache_dir"
readonly DESTINATION="${CACHE_DIR}/indigo-${COMMIT}"
readonly STAGING="${CACHE_DIR}/.indigo-${COMMIT}.staging"
readonly STAGED_ARCHIVE="${STAGING}/indigo-${COMMIT}.tar.gz"

mkdir -p "$CACHE_DIR"
if [[ -e "$DESTINATION" ]]; then
  echo "pinned Indigo cache already exists; remove or archive it explicitly before refetching" >&2
  exit 1
fi
if [[ -e "$STAGING" ]]; then
  echo "stale Indigo staging directory exists; remove it explicitly before refetching" >&2
  exit 1
fi

mkdir -p "$STAGING"
trap 'rm -rf "$STAGING"' EXIT
if [[ -n "${SWAN_REFERENCE_INDIGO_SOURCE_ARCHIVE:-}" ]]; then
  cp "$SWAN_REFERENCE_INDIGO_SOURCE_ARCHIVE" "$STAGED_ARCHIVE"
else
  curl --fail --location --retry 3 "$SOURCE_URL" -o "$STAGED_ARCHIVE"
fi
actual_sha256="$(shasum -a 256 "$STAGED_ARCHIVE" | awk '{print $1}')"
if [[ "$actual_sha256" != "$ARCHIVE_SHA256" ]]; then
  echo "reference Indigo archive checksum mismatch" >&2
  exit 1
fi

python3 - "$STAGED_ARCHIVE" "$STAGING" "$COMMIT" <<'PY'
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
        extraction_root = staging / ".extract"
        extraction_root.mkdir()
        archive.extractall(extraction_root, members=members)
        (extraction_root / expected_prefix).replace(staging / "source")
        extraction_root.rmdir()
except (tarfile.TarError, OSError) as error:
    raise SystemExit(f"reference Indigo archive cannot be read: {error}") from error
PY

./interop/verify-reference-indigo.sh --bundle-dir "$STAGING"
if [[ "${SWAN_REFERENCE_INDIGO_FAIL_BEFORE_INSTALL:-0}" == "1" ]]; then
  echo "injected failure before Indigo cache install" >&2
  exit 1
fi
python3 - "$STAGING" "$DESTINATION" <<'PY'
import os
import sys

# Both paths are direct children of CACHE_DIR. rename(2) is therefore the one
# same-filesystem publication point and refuses an extant destination instead
# of nesting the staging directory inside it as mv may do.
os.rename(sys.argv[1], sys.argv[2])
PY
trap - EXIT
./interop/verify-reference-indigo.sh --cache-dir "$CACHE_DIR"
echo "verified ${DESTINATION}/indigo-${COMMIT}.tar.gz"
