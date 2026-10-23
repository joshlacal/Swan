#!/usr/bin/env bash
set -euo pipefail

# Historical Compose overlay verifier. Current-profile host proofs use
# verify-reference-oct22.sh and the isolated spaces-release laboratory.

readonly COMMIT="3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
readonly ARCHIVE_SHA256="1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"
cache_dir=".interop-cache"

if [[ "${1:-}" == "--cache-dir" && -n "${2:-}" && $# -eq 2 ]]; then
  cache_dir="$2"
elif [[ $# -ne 0 ]]; then
  echo "usage: interop/verify-reference.sh [--cache-dir <directory>]" >&2
  exit 64
fi

archive="${cache_dir}/atproto-${COMMIT}.tar.gz"
source_root="${cache_dir}/atproto-${COMMIT}"
if [[ ! -f "$archive" || ! -d "$source_root" ]]; then
  echo "pinned reference cache is unavailable; run interop/fetch-reference.sh before Compose" >&2
  exit 1
fi

actual_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$ARCHIVE_SHA256" ]]; then
  echo "pinned reference archive checksum mismatch; refuse to build Compose images" >&2
  exit 1
fi

for required in package.json pnpm-lock.yaml services/pds/Dockerfile packages/pds/package.json; do
  if [[ ! -f "${source_root}/${required}" ]]; then
    echo "pinned reference source is incomplete; rerun interop/fetch-reference.sh" >&2
    exit 1
  fi
done

if ! tar -tzf "$archive" >/dev/null; then
  echo "pinned reference archive cannot be read; refuse to build Compose images" >&2
  exit 1
fi

echo "REFERENCE CACHE OK: ${COMMIT}"
