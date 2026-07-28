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
- The explicit private-transfer gates also pass with the pinned Xcode
  toolchain: the 256 MiB permissioned CAR spool, 256 MiB private CAS blob
  stream, and 256 MiB staged CAR import all complete with bounded chunks and
  no failures.
- The offline `swan lab semantic` command now runs two independent durable
  SQLite roots through incremental replay, duplicate/reordered delivery,
  retention-gap full recovery, two-root CAR verification/corruption rejection,
  credential enforcement, and public/private blob reachability. Its artifact
  is explicitly labeled `swan-durable-to-swan-durable` and contains only
  counts, commitments, and digests; it is local semantic evidence, not a
  TypeScript PDS interop result.

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
- Run the new stateful live runner against cross-host record/blob scenarios and
  execute the fault matrix under Docker on macOS and Linux. The Linux Compose
  public Swan-to-Swan record/blob scenario now passes: upload, public raw-link
  write, unauthenticated record read, and streamed blob read all converge with
  the blob bytes verified. The checked-in fixture is DID-independent through
  `{{REPOSITORY_DID}}` and `{{BLOB_CID}}` placeholders. A disposable
  reference-only TypeScript run also passes its typed-blob form: upload, a
  standard `app.bsky.feed.post` commit, unauthenticated record read, and
  streamed blob read all returned the expected status and bytes. This is not a
  Swan/TypeScript convergence result; Swan's current public codec deliberately
  accepts its raw-CID fixture form and still rejects the TypeScript typed blob
  object.
- Re-run the complete suite after any further mutation slice; do not claim
  alpha completion until the live Compose/reference matrix and Linux gates
  pass.

## 2026-07-28 public-key interoperability checkpoint

The public repository verifier now accepts canonical low-S secp256k1 commit
signatures in addition to Swan's P-256 writer format. PLC `did:key` decoding
validates both the P-256 and secp256k1 multicodec forms, and
`PLCPublicRepositoryCommitKeyResolver` can select the `atproto` key from a
PLC-backed document without retaining private material. Focused tests cover
the pinned TypeScript secp256k1 `did:key` form, resolver selection, invalid
identities, and missing signing keys. The CLI importer still requires an
explicit verification key; wiring remote discovery into a live import remains
a separate gate.

## 2026-07-28 runtime and harness checkpoint

The next execution slice is now checkpointed in the Swan jj history:

- `e6e4692f` isolates public repository mutation keys behind the explicit
  `--enable-public-repository-mutations` capability and adds separate
  mounted-KEK/key-directory options. Permissioned-space interop no longer
  implicitly enables public writes. DID and canonical local-handle selectors
  resolve through the startup control registry only.
- `e6e4692f` also rejects a supplied `swapRecord` when the selected put path is
  absent and abandons a no-swap reservation before a bounded CAS retry.
- `cd92f9df` adds a stateful `SwanInterop` public put/read round-trip runner.
  It compares producer and consumer CIDs and records only endpoint paths,
  statuses, sizes, and response digests. Query selector values are removed
  from fixture paths.
- `d484298b` extends that seam with permissioned delegation/credential
  exchange, selector-bound public and permissioned writes, per-request OAuth
  DPoP authorization, and the callable `swan lab live` command. Its artifacts
  carry commitments and digests only.

Focused put/delete/no-op/swap HTTP tests, the separate CLI opt-in guard,
stateful interop fixture-sanitization tests, the complete macOS Swift suite,
profile verification, interop topology verification, and `git diff --check`
are green with the pinned Xcode toolchain. Docker/Compose, Linux, and a live
Swan-to-TypeScript run remain unexecuted because those runtimes are not
available in this environment; they must be run before alpha completion is
claimed.

## 2026-07-28 stateful live-runner checkpoint

The interop seam now supports a callable `swan lab live` command. Public mode
performs a producer `repo.putRecord` followed by a consumer `repo.getRecord`;
permissioned mode obtains a member delegation, exchanges it for a space
credential, then performs `space.createRecord` and `space.getRecord`. Both
modes compare returned record CIDs, and reject a request body whose selectors
do not match the requested record before any network request. OAuth mode uses
the in-memory `SwanOAuthLabClient` and creates a fresh method/target-bound DPoP
proof for each request; bearer mode reads only a named environment variable.

Artifacts contain only sanitized endpoint events, statuses, commitments, and
response digests. A CLI test exercises the failure path against an unavailable
loopback endpoint and verifies that the private record value is absent from
the artifact. This is a runnable harness, not live matrix evidence: Docker,
Linux, and the pinned TypeScript cross-host run remain required external gates.

## 2026-07-28 live-client correctness checkpoint

The live runner now constructs the actual `/xrpc/<nsid>` path rather than a
literal placeholder. A direct test covers the NSID and canonical query
ordering, which is important because OAuth DPoP proofs bind to that exact
request target. The fix is committed as `0ec5467e` in the Swan jj history.
