# Swan public blob-reference isolation progress

Date: 2026-07-28

This note supersedes the earlier handoff wording that described public
mutation and blob routes as closed. The current checkout contains bounded
public upload/download routes and the public record-link isolation guard.

## Implemented

- `StreamingBlobStore.publicBlobExists(cid:)` performs a metadata-only public
  namespace reachability check. It never opens or materializes the payload.
- Public record conversion exposes deterministic, de-duplicated raw CID
  projection through `PublicRepositoryRecordCodec.publicBlobCIDs(in:)`.
- `repo.createRecord`, `repo.putRecord`, and `repo.applyWrites` reject a raw
  CID unless the target account already has a valid public CAS reference.
  Missing/private-only references return an invalid request; storage or
  integrity failures fail closed as temporarily unavailable.
- DAG-CBOR CIDs remain repository/block links and are not treated as blobs.
- The SQLite streaming test covers positive public reachability and negative
  permissioned-only reachability; the codec test covers nested links and
  duplicate elimination.
- Authenticated HTTP coverage now proves a public raw link commits, a
  permissioned-only raw link is rejected, and the public blob route streams
  only the public reference. The route registry also includes `applyWrites`
  in its installed-method filter so startup cannot register it twice.
- Lab scenario and matrix commands fail non-zero on failed artifacts by
  default. `--no-fail-on-failure` is diagnostic-only.

## Verification

Using the pinned Xcode toolchain with `--jobs 1`:

- `PublicRepositoryDomainTests`: 19 passed.
- `SwanSQLiteTests/testPublicStreamingBlobUploadUsesBoundedCASAndPublicNamespaceOnly`: passed.
- `PublicRepositoryMutationHTTPTests/testPublicRecordLinksRequirePublicBlobReachability`: passed.
- `PublicRepositoryReadHTTPTests`: 8 passed. The original filtered command
  completes when SwiftPM is given the Xcode toolchain explicitly and stale
  `SDKROOT`/`TOOLCHAINS` values are removed; the earlier apparent hang was
  dependency-resolution work in the default SwiftPM state, not a request
  handler deadlock.
- `PublicRepositoryReadDirectoryTests/testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS`:
  passed in 5.602 seconds with the 256 MiB gate enabled.
- Complete macOS `swift test --jobs 1 --quiet`: passed on a clean rerun after
  one intermittent PLC verifier assertion was confirmed green in isolation.
- `node interop/reference-public-repository-car.mjs`: pinned public CAR
  fixture verified.
- `Scripts/verify-profile.sh`, `Scripts/verify-interop-lab.sh`, and
  `Scripts/test-verify-interop-lab.sh`: passed.
- `git diff --check`: passed.
- `swift build`: passed.

## Deliberate boundary

The public upload endpoint establishes a public reference as part of the
upload transaction. Record writes do not implicitly promote a permissioned
reference into the public namespace. This avoids exposing a private-only blob
through a public record and leaves garbage collection of unreferenced public
uploads as a separate maintenance concern. A future staged-upload design may
add atomic record-linked promotion, but it must preserve this fail-closed
boundary.

## Remaining gates

- Exercise the durable PLC rotation service and `swan account rotate-plc`
  against a live/local PLC fixture; the service, CLI path, storage,
  verifier, and public-read slice are now implemented and covered locally.
- Replace the probe-only interop runner with semantic cross-host record/blob
  exchange and run the matrix under Docker on macOS and Linux.
- Run the complete suite after the next mutation slice; do not claim alpha
  completion until the live Compose/reference matrix and Linux gates pass.
