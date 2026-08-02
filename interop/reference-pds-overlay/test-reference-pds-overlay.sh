#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly overlay="${root}/interop/reference-pds-overlay/apply-reference-pds-overlay.sh"
readonly commit="3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
readonly pinned="${root}/.interop-cache/atproto-${commit}"

source_digest() {
  # The pinned cache contains a pnpm hard-link farm under node_modules. A
  # recursive descriptor walk there is both unnecessary and capable of
  # exhausting the host while this otherwise read-only source test runs.
  # Hash exactly the files touched by the checked-in overlay instead.
  local relative
  for relative in \
    packages/pds/src/actor-store/space/reader.ts \
    packages/repo/src/car.ts \
    packages/pds/src/api/com/atproto/space/getRepo.ts \
    packages/pds/tests/spaces.test.ts \
    packages/pds/src/api/com/atproto/space/util.ts \
    packages/pds/src/api/com/atproto/space/createRecord.ts \
    packages/pds/src/api/com/atproto/space/putRecord.ts \
    packages/pds/src/api/com/atproto/space/applyWrites.ts
  do
    shasum -a 256 -- "${pinned}/${relative}"
  done | shasum -a 256 | awk '{print $1}'
}

before="$(source_digest)"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/swan-reference-pds-overlay-test.XXXXXX")"
trap 'rm -rf "${workspace}"' EXIT

"${overlay}" "${workspace}/atproto" >/dev/null
after="$(source_digest)"
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
grep -q "maximumAggregateRepoSpoolBytes" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "maximumConcurrentRepoSpools" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "releaseSpoolAdmission" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/getRepo.ts"
grep -q "reserveRepoArtifactBytes" \
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
grep -q "makeSpaceRecordBlobsPermanent" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/util.ts"
grep -q "makeSpaceRecordBlobsPermanent" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/createRecord.ts"
grep -q "makeSpaceRecordBlobsPermanent" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/putRecord.ts"
grep -q "makeSpaceRecordBlobsPermanent" \
  "${overlay_source}/packages/pds/src/api/com/atproto/space/applyWrites.ts"
echo "REFERENCE PDS OVERLAY SOURCE QUALIFICATION OK"
