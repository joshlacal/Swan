#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="ac0c9f15392f6f0298d71dc52aa88c05036150be"
readonly ARCHIVE_SHA256="eae029a70a3adf0f7d6241814d5a91d55bf6768e8f4cd00196870c911df57eb5"
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
