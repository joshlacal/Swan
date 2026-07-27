#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
readonly ARCHIVE_SHA256="1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"
readonly DESTINATION=".interop-cache/atproto-${COMMIT}"
readonly ARCHIVE=".interop-cache/atproto-${COMMIT}.tar.gz"
readonly STAGING=".interop-cache/.atproto-${COMMIT}.staging"

mkdir -p .interop-cache
if [[ -e "${DESTINATION}" ]]; then
  echo "${DESTINATION} already exists; remove or archive it explicitly before refetching" >&2
  exit 1
fi
curl --fail --location --retry 3 \
  "https://github.com/bluesky-social/atproto/archive/${COMMIT}.tar.gz" \
  -o "${ARCHIVE}"
actual_sha256="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
if [[ "${actual_sha256}" != "${ARCHIVE_SHA256}" ]]; then
  echo "reference archive checksum mismatch" >&2
  exit 1
fi
rm -rf "${STAGING}"
mkdir -p "${STAGING}"
trap 'rm -rf "${STAGING}"' EXIT
tar -xzf "${ARCHIVE}" --strip-components=1 -C "${STAGING}"
for required in package.json pnpm-lock.yaml services/pds/Dockerfile packages/pds/package.json; do
  if [[ ! -f "${STAGING}/${required}" ]]; then
    echo "verified reference archive is missing required PDS source" >&2
    exit 1
  fi
done
mv "${STAGING}" "${DESTINATION}"
trap - EXIT
echo "verified ${ARCHIVE}"
