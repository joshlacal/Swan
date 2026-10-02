#!/usr/bin/env bash
set -euo pipefail

# Five pinned reference archives coexist deliberately:
#  - 679724ad… is the wire/profile pin (permissioned-data-0016-2026-10-01,
#    the October 1 Spaces alpha): lexicons and contract tests read this tree.
#  - 907f41a7… is the historical September 19 profile pin.
#  - 9d787ebf… is the historical September 10 profile pin.
#  - bddc99fb… is the historical August profile pin (permissioned-data-0016-2026-08-15).
#  - 3f6c96d5… is the interop-lab pin: the dockerized reference PDS and its
#    overlay patches still build from this tree until the lab is re-pinned.
# Fetching is idempotent per pin; an already-materialized tree is left alone.
readonly PINS=(
  "679724ad62eb9a02f7f40429c3c4fdd65d3e4c79 4f326ac19b74773fec8fe2d1403978f20779a19670ace185129ae04f60cacaa8"
  "907f41a7b379a7e649a6c4842864946eef6eb757 418f7213539e2c8f0945a9f8e6e22643073dc1c3f3248115bc626e4c29c1c579"
  "9d787ebff231ff8f4e01c63717e9f5bcd6e1bc33 1ab99c2be340640f14b74c8c4d051f0a8963df061b939874db62d76205f434a6"
  "bddc99fb24c34b4078b9bf65837283f37b49ab66 84b9a245be65758c577020dbe68a78039ce2d8acb5ead052043ed30c314f4d7e"
  "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354 1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"
)

mkdir -p .interop-cache
for pin in "${PINS[@]}"; do
  commit="${pin%% *}"
  archive_sha256="${pin##* }"
  destination=".interop-cache/atproto-${commit}"
  archive=".interop-cache/atproto-${commit}.tar.gz"
  staging=".interop-cache/.atproto-${commit}.staging"

  if [[ -e "${destination}" ]]; then
    echo "${destination} already materialized"
    continue
  fi
  curl --fail --location --retry 3 \
    "https://github.com/bluesky-social/atproto/archive/${commit}.tar.gz" \
    -o "${archive}"
  actual_sha256="$(shasum -a 256 "${archive}" | awk '{print $1}')"
  if [[ "${actual_sha256}" != "${archive_sha256}" ]]; then
    echo "reference archive checksum mismatch for ${commit}" >&2
    exit 1
  fi
  rm -rf "${staging}"
  mkdir -p "${staging}"
  trap 'rm -rf "${staging}"' EXIT
  tar -xzf "${archive}" --strip-components=1 -C "${staging}"
  for required in package.json pnpm-lock.yaml services/pds/Dockerfile packages/pds/package.json; do
    if [[ ! -f "${staging}/${required}" ]]; then
      echo "verified reference archive is missing required PDS source" >&2
      exit 1
    fi
  done
  mv "${staging}" "${destination}"
  trap - EXIT
  echo "verified ${archive}"
done
