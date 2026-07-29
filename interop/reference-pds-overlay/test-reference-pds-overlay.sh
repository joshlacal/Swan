#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly overlay="${root}/interop/reference-pds-overlay/apply-reference-pds-overlay.sh"
readonly commit="3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
readonly pinned="${root}/.interop-cache/atproto-${commit}"

before="$(find "${pinned}" -type f -exec shasum -a 256 {} + | shasum -a 256 | awk '{print $1}')"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/swan-reference-pds-overlay-test.XXXXXX")"
trap 'rm -rf "${workspace}"' EXIT

"${overlay}" "${workspace}/atproto" >/dev/null
after="$(find "${pinned}" -type f -exec shasum -a 256 {} + | shasum -a 256 | awk '{print $1}')"
[[ "${before}" == "${after}" ]] || {
  echo "overlay test changed the pinned reference checkout" >&2
  exit 1
}

overlay_source="${workspace}/atproto"
grep -q "async countRepoRecords" \
  "${overlay_source}/packages/pds/src/actor-store/space/reader.ts"
grep -q "async getRepoRecordAfterCanonical" \
  "${overlay_source}/packages/pds/src/actor-store/space/reader.ts"
grep -q "async getRepoRecordAfterLexical" \
  "${overlay_source}/packages/pds/src/actor-store/space/reader.ts"
grep -q "space_record_oplog.space" \
  "${overlay_source}/packages/pds/src/actor-store/space/reader.ts"
grep -q "writeCarBlockHeader" "${overlay_source}/packages/repo/src/car.ts"
grep -q "handler: async ({ params, auth })" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "store.transact" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "createHash('sha256')" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "Permissioned record CID mismatch" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "INSERT OR IGNORE INTO seen_cid" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
if grep -qE "Object\\.fromEntries|listRepoRecords" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"; then
  echo "reference getRepo reintroduced an in-memory repository export" >&2
  exit 1
fi
grep -q "two-root recovery CAR" \
  "${overlay_source}/packages/pds/tests/spaces.test.ts"
grep -q "one stable snapshot" \
  "${overlay_source}/packages/pds/tests/spaces.test.ts"
grep -q "dist/actor-store/space/reader.js" \
  "${overlay_source}/packages/pds/tests/spaces.test.ts"
grep -q "message: 'Internal Server Error'" \
  "${overlay_source}/packages/pds/tests/spaces.test.ts"
grep -q "writes\\[1\\].cid.*writes\\[2\\].cid" \
  "${overlay_source}/packages/pds/tests/spaces.test.ts"
grep -q "Credential space mismatch" \
  "${overlay_source}/packages/pds/tests/spaces.test.ts"
echo "REFERENCE PDS OVERLAY SOURCE QUALIFICATION OK"
