# Swan Spaces Interoperability Alpha

## Frozen inputs

- Proposal 0016: `1caad93dbb1f445396f6abf3b97eb4040345e78e`
- TypeScript implementation: `3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`
- Petrel runtime baseline: `db84b2c9788aa38000ee3f134e21feffa8f351cd`
- Isolated Petrel generator revision: `c2a1cdbee8c621c7682416114700f032cc7e2b37`
- Active successor profile: `Profiles/permissioned-data-0016-2026-07-30.json`
- Legacy profile `permissioned-data-0016-2026-07-03` remains checked in byte-exact
  but is not selected for new builds or exports.

The profile pins the TypeScript source archive and a complete checksum manifest
for the `com.atproto.space` and `com.atproto.simplespace` lexicons. Normal
builds use checked-in sources. `interop/fetch-reference.sh` is the explicit,
checksum-verified way to populate the ignored reference cache.

## Sequenced work

1. Freeze profile and land Petrel’s isolated `space` declaration / server
   contract generator change without altering existing output by default.
2. Complete pure wire primitives: cross-language vectors, signed reader
   envelopes, canonical record DAG-CBOR/CIDs, two-root CAR writer/reader.
3. Make per-account SQLite authoritative for public/space records, LtHash,
   revision CAS, oplog, blobs, and atomic notification outbox; prove recovery.
4. Add account keys/PLC, Argon2id password verification, OAuth PAR/PKCE/DPoP,
   strict metadata fetch, and the loopback management listener.
5. Wire every pinned space/simplespace endpoint, stream CAR/blob payloads, and
   enforce account-state/public-private isolation.
6. Run the Compose matrix against the pinned TypeScript PDS under normal,
   delayed, duplicated, reordered, offline, and corrupted traffic.

## Current evidence

- Exact six-segment space record URIs are parsed.
- Checked-in Swift wire sources are regenerated from every verified pinned
  lexicon with the opt-in typed async `ServerHandler` contracts enabled.
- LtHash is 1,024 little-endian UInt16 lanes with modular add/remove; its empty
  commitment is checked against the pinned TypeScript test vector.
- Commit contexts use the proposal domain prefix, big-endian TLS vector lengths,
  ES256 context signatures, and the pinned one-block HKDF-Expand/HMAC-SHA256
  content binding (the 32-byte IKM is the Expand PRK, matching TypeScript).
  A fixed cross-language vector protects this distinction from regression.
- Full-recovery CARs use the required ordered two roots (signed commit then
  index), validate root/record CIDs, recompute LtHash from the index, and reject
  an altered record block before recovery data is returned.
- A batch is atomic in the in-memory repository; a SQLite WAL test proves
  oplog/outbox insertion and outbox recovery operations share one transaction.
- The local simple authority covers member-list, managing-app, public, and app
  allow-list decisions without granting credentials write power.
- `28c35493` installs a locally provisioned account only after its verified
  empty public-repository genesis is durable. The immutable public commit CID
  binds the separate control-plane row; interrupted installation recovers,
  legacy unbound control rows fail closed, and independent SQLite connections
  race to one registration without persisting password or private-key bytes.
- `aa1c6cc5` records a sanitized fixed public-genesis vector under this
  profile. Swift verifies the pinned TypeScript CAR and the TypeScript
  `verifyRepoCar` path verifies Swan's CAR. This also enforces canonical
  low-S ES256 repository signatures, because the pinned verifier rejects the
  mathematically valid high-S encoding accepted by Swift Crypto.
- The Compose laboratory now has a separate, cache-gated topology: Swan,
  source-pinned reference PDS and PLC images, Caddy local TLS, Mailpit,
  Toxiproxy, and a Swift scenario-runner. `interop/fetch-reference.sh` is the
  only source-population path; both image Dockerfiles verify the archive SHA
  before unpacking it and contain no source clone or curl. `swan lab validate`
  checks the same archive/source prerequisites without starting containers; `swan
  lab scenario --output ...` probes pinned profile endpoints on both hosts and
  records per-endpoint request/response summaries under a fixture policy that
  intentionally carries no credential, token, key, account, or blob payload data.
- The first non-authority record-read slice is live only behind the durable
  resource capability: `com.atproto.space.getRecord` and
  `com.atproto.space.listRecords` use generated server contracts, fixed-route
  DPoP validation, self-only OAuth subject/repository matching, and the
  startup-preopened SQLite directory. It implements the pinned list ordering,
  cursor, and `excludeValues` behavior, plus the credential-reader path and
  write/apply-writes flows. Cross-host behavior remains defined by the live
  interop matrix for end-to-end confidence. A profile-specific qualified
  `space:<type>?authority=...&skey=...&action=...` OAuth scope can now be
  issued as a narrow resource grant without adding the broad `atproto` token
  scope. Bare/default type scopes are rejected; the domain policy remains the
  exact space/collection authorization decision.
- The six authority-owned `com.atproto.simplespace` lifecycle/membership
  routes now use checked-in generated server contracts and the same
  startup-preopened DPoP/OAuth capability. They are available for local-authority
  lifecycle and membership workflows with managing-app and credential-aware policy
  checks; notifications and repository sync are available via their dedicated
  capability slices. SQLite migration v3 rebuilds legacy simple-space authority
  CHECK constraints and preserves all FK child facts,
  so a policy-only patch retains its omitted managing-app value and an empty
  wire value clears it. This is not evidence of cross-host SimpleSpace
  interoperability.
- Authority-issued space credentials now have a closed core/storage boundary.
  Swan locally issues ES256 compact JWTs with
  `typ=atproto-space-credential+jwt`, a fresh opaque bounded JTI, and a
  two-hour maximum lifetime. Verification also accepts the pinned TypeScript
  ES256K compact low-S form and the permitted `#atproto` account-key fallback
  when no `#atproto_space` key is published. Issuance first runs the durable
  startup-preopened `authorizeSimpleSpaceRead` policy, then resolves the
  active authority signing material only through `AccountKeyStore`; neither
  private key bytes nor reader-specific credential artifacts enter SQLite.
  Verification performs bounded compact-JWT inspection, exact issuer/space
  binding, pinned/local public-key selection, low-S signature validation, and
  clock checks before creating `AuthorizationContext.spaceCredential`. Remote
  DID/PLC key lookup and client-attestation JWKS validation are explicitly
  unavailable, so unverified app identity and unknown remote keys fail closed.
- `com.atproto.space.getSpaceCredential` now exchanges a bounded signed
  case-insensitive `Authorization: Bearer` delegation JWT for an
  authority-issued credential. Delegations require the proposal type,
  supported ES256 or ES256K algorithm, `#atproto` key ID, issuer, authority
  service audience, space subject, bounded opaque JTI, lifetime, low-S
  signature, and a local or pinned public key; unknown keys never trigger
  DID/PLC/DNS/HTTP resolution. The authority HMAC-binds and atomically reserves
  each verified JTI in `control.sqlite` before policy or signing, so a replay
  cannot mint a second credential even after restart. The exchange uses only
  the startup-preopened authority policy directory, then the existing durable
  credential authority.
  `getRecord` and `listRecords` accept either their existing DPoP OAuth path
  or an exact Bearer space credential. Credential reads are cross-repository
  only within their bound space and remain read-only; Bearer tokens never
  satisfy the DPoP OAuth authorizer. `getDelegationToken` is separately
  capability-gated: the local `serve` composition installs it only with
  durable DPoP OAuth, a startup-preopened account, and an account-key signer;
  the default/incomplete server remains closed.
- PLC identity history is now durable per account: genesis and signed
  rotations are stored as a linear CID-bound chain, verified fail-closed, and
  used by public repository description reads to expose the authenticated
  terminal DID document. Rotation records the pending operation before PLC
  network I/O and promotes control key generations with a compare-and-swap;
  local tests cover restart, idempotency, tampering, and rotated public reads.
- `swan lab semantic` and `LocalSemanticInteropRunner` now provide an offline
  Swan-to-Swan durable semantic gate. Two independent account roots exchange
  real oplog batches, reject duplicate and unordered delivery, force a
  retention-gap full snapshot, authenticate/corruption-test a two-root CAR,
  enforce a bound space credential, and verify public/private blob namespace
  isolation. The artifact is summary-only and explicitly does not claim that
  the pinned TypeScript PDS participated.
- The callable `swan lab live` runner now drives selector-bound public
  `repo.putRecord`/`repo.getRecord` and permissioned delegation/credential
  `space.createRecord`/`space.getRecord` flows. It keeps OAuth DPoP proofs and
  bearer credentials out of artifacts and compares returned record CIDs. Its
  XRPC path construction is covered directly, including DPoP-bound query
  ordering. `--permissioned-list-ops` additionally verifies a terminal
  incremental page, LtHash commitment, deniable content binding, and the
  author context signature using an explicit public-key pin.
- Task 43's independent rereview is recorded under
  `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-rereview-2026-07-28.md`.
  Its scoped public-read verdict is PASS: `PublicRepositoryReadHTTPTests`
  executes 8/8, the opt-in 256 MiB production-directory RSS gate passes, and
  the serialized macOS suite passes.
- The explicit 256 MiB bounded-transfer gates pass for the permissioned CAR
  spool, private blob CAS stream, and staged CAR import. These are local
  memory/streaming gates; they do not replace Docker or Linux evidence.
- The 2026-07-31 adversarial rereview scoped notification receipts by space,
  added the single-record public-read SQLite length preflight, and put
  `describeRepo` behind the shared anonymous JSON response admission. The
  focused suites passed 6/6, 14/14, and 12/12 respectively (the opt-in 256
  MiB directory test remains skipped). A malformed default `swan serve
  --host` now returns a validation error instead of crashing, and malformed
  public-mutation reservation digests fail closed instead of trapping the
  process. These harden boundedness and operator availability but do not close
  the native-Linux, cross-host recovery, or reverse-authority gates.
- Public-read startup admission and the optional public-blob promoter now have
  explicit index ceilings. Admission rejects more than 100,000 retained index
  rows, 100,000 distinct collections, or 8 MiB of collection-name bytes before
  the full projection validator; promotion rejects the same row ceiling,
  scans in 256-row keyset pages, and caps unique raw CIDs at 100,000. The
  synthetic oversized-index regression passed as part of
  `PublicRepositoryReadDirectoryTests` (15/15, with the opt-in 256 MiB RSS
  test skipped); the opt-in RSS test also passed 1/1 when enabled explicitly.
  This is macOS source-level boundedness evidence; a native Linux
  hostile-index/RSS run remains open.
- The pinned TypeScript source cache was booted in a disposable localhost
  smoke runtime. Account creation, authenticated public record creation,
  record read/list, and `sync.getRepo` succeeded. Blob upload remained staged
  until a valid record reference; the smoke result is reference-host evidence,
  not Swan/TypeScript convergence evidence.
- A disposable TypeScript member account completed the cross-host permissioned
  path on 2026-07-28: the reference PDS wrote the member repository, Swan's
  authority verified the delegation with an operator-supplied static public-key
  pin and issued a space credential, and the reference member host accepted
  that credential for `space.getRecord` with a matching CID. The new
  `--permissioned-read-host member` runner option makes the repository-host
  boundary explicit. This is a real credential/read interop proof, but it does
  not claim public repository import, dynamic remote DID/PLC/JWKS discovery,
  or the complete TypeScript semantic matrix.
- A fresh disposable TypeScript member account also completed the
  cross-host `space.listRepoOps` boundary on 2026-07-28. With
  `--permissioned-list-ops-exclude-values`, the reference member host returned
  one operation and a terminal signed commit; Swan matched the write/read CID,
  recomputed the commitment, verified the proposal content binding, and
  verified the ES256K context signature against the operator-supplied public
  The sanitized artifact reported `syncStatus: 200`,
  `syncCommitVerified: true`, and `syncValuesIncluded: false`. The ordinary
  value-including TypeScript request was separately observed to fail with
  `InternalServerError` (`ambiguous column name: space`) in the pinned branch;
  Swan does not mutate that cache and exposes the metadata-only workaround as
  an explicit CLI option.
- The Linux Compose laboratory was run from a clean disposable Swan data
  volume with the pinned PLC/PDS cache, Caddy TLS, Mailpit, and Toxiproxy
  healthy. Bootstrap now creates real PLC-backed Swan accounts through the
  prepare/activate lifecycle and stores their signed public genesis before
  traffic is accepted. The stateful public Swan-to-Swan round trip passed with
  matching write/read CIDs. The stateful permissioned round trip passed with a
  member OAuth write, authority delegation/credential exchange, and authority
  credential read returning the same CID; credentials remained read-only.
- Public/private isolation was checked against the live Linux host: the public
  authority list contained the public CID and no permissioned CID, the member
  public list was empty, a permissioned record returned `RecordNotFound` from
  the public record endpoint, and the member public CAR contained neither the
  permissioned record nor the authority's public record. The sanitized fault
  matrix covered offline, disconnected, delayed, duplicated, reordered, and
  corrupted traffic across both Swan and the pinned reference host (156
  convergence comparisons, 416 endpoint events); it is transport/profile
  evidence and does not claim full TypeScript semantic convergence.
- The proposal-0016 content-binding profile is pinned as
  `HKDF-Expand/HMAC-SHA-256`, with a fixed cross-language vector and a live
  TypeScript `space.listRepoOps` proof that verifies the LtHash, deniable MAC,
  and ES256K context signature. The pinned values-including TypeScript form is
  recorded as an explicit upstream SQLite ambiguity and is exercised only via
  the explicit `excludeValues=true` compatibility path.
- The interop runner now has two bounded recovery seams. `swan lab live
  --permissioned-get-repo` streams and verifies a Swan two-root permissioned
  CAR after the credential read, recording only status, record count, and the
  commitment. `swan lab import-public` streams a remote
  `com.atproto.sync.getRepo` CAR into per-account SQLite import staging and
  publishes it only after commit-signature, MST, CID, and revision-CAS checks.
  The public importer accepts an explicitly supplied P-256 or secp256k1
  verification key; it does not silently resolve a remote DID/PLC key.
- The rebuilt Linux Compose Swan image passes a live public blob round trip on
  2026-07-28: OAuth-authenticated `repo.uploadBlob` returned a validated raw
  CID, `repo.putRecord` committed a record containing that public raw link,
  unauthenticated `repo.getRecord` returned the same record CID, and streamed
  `sync.getBlob` returned the same 25 bytes. The sanitized artifact records
  HTTP 200 for upload/read/download, `blobVerified: true`, and no request body,
  credential, or record value. Disposable public fixtures use
  `{{REPOSITORY_DID}}` and `{{BLOB_CID}}` placeholders; the runner materializes
  them only after selector/blob validation. The public codec accepts both the
  legacy raw-CID link form and the modern typed `blob` object, but validates
  the latter strictly (raw SHA-256 CID, bounded size, safe MIME type, and exact
  shape) before the HTTP layer checks public-namespace reachability.
- The rebuilt Linux Compose Swan image also passes the modern typed-blob
  fixture: OAuth-authenticated upload, typed `repo.putRecord`, unauthenticated
  `repo.getRecord`, and streamed `sync.getBlob` all return HTTP 200, matching
  record CIDs, and the original 25 bytes. The sanitized artifact is
  `artifacts/live-typed-blob.json`; the initial failure was a stale bootstrap
  DID selector, not a protocol or storage failure.
- A disposable pinned-TypeScript reference-only probe also passed the standard
  typed-blob path: account provisioning, blob upload, an
  `app.bsky.feed.post` commit, unauthenticated record retrieval, and streamed
  blob retrieval all returned the expected status and bytes. This is evidence
  for the reference host's own public behavior, not Swan/TypeScript
  convergence. A follow-up live reference account was imported into a fresh
  managed Swan account through `com.atproto.sync.getRepo`: HTTP 200, one
  record, three reachable blocks, and a verified imported commit were recorded
  in the sanitized `artifacts/reference-public-import-live.json` artifact. The importer
  initially opened the target as a read-only portable-export source; the CLI
  now uses the managed account mode required for durable staging. Receiver-side
  public-blob byte promotion after CAR import remains a separate gate.
- Public repository verification now accepts canonical low-S secp256k1
  signatures emitted by the pinned TypeScript implementation while retaining
  P-256-only local signing. PLC `did:key` decoding and
  `PLCPublicRepositoryCommitKeyResolver` provide a tested, fail-closed
  PLC-backed key-discovery seam; the importer still requires an explicit key
  until the remote discovery path is wired into a live CAR import.
- Final macOS verification after the rereview passes the serialized Swift
  suite with zero failures, profile verification, the 18-check semantic lab,
  static/mutation interop checks, and `PublicRepositoryReadHTTPTests` 8/8. The
  rebuilt Linux Compose Swan image is healthy behind Caddy local TLS.

## Completion gates

Completion still requires the full pinned XRPC surface, delegation minting at
the user PDS, durable repositories/CARs/blobs, OAuth and account
lifecycle, and Compose reference PDS/PLC/Caddy matrix, plus macOS/Linux verification.
The public-genesis vector is a narrow cross-language gate; it is not evidence
that the complete live interop matrix has passed.

## Compose laboratory evidence and live gates

- `Scripts/verify-interop-lab.sh` is an offline structural verifier for the
  cache SHA, source shape, topology membership, local-TLS/Toxiproxy route, and
  the no-network-source-fetch Dockerfile boundary. `SwanInteropTests` also
  covers cache-pin rejection and the sanitized scenario schema.
- The laboratory does not expose PLC, Mailpit, or Toxiproxy publicly. Caddy
  has only local-CA TLS routes for `swan.test` and `pds.test`; PDS traffic goes
  through its named Toxiproxy listener. No permissioned route gains a public
  fallback.
- Compose startup now uses real readiness probes: Swan must answer
  `GET /health`, the pinned reference PDS must answer `GET /xrpc/_health`, and
  the pinned PLC must answer `GET /_health`. The reference PDS waits for a
  healthy PLC, Toxiproxy setup waits for a healthy reference PDS, and Caddy
  waits for a healthy Swan listener before creating the TLS trust handoff.
- The Linux live gates are now verified with Docker Compose v2, disposable
  owner-only secrets outside the repository, and an explicit Caddy CA trust
  handoff. `artifacts/linux-compose-matrix.json` records only sanitized
  transport/profile summaries. Stateful Swan-to-Swan public, permissioned, and
  isolation evidence is recorded separately in ignored local artifacts; no
  secret, token, proof, or recoverable record value is committed. The pinned
  TypeScript service was included in the endpoint/fault matrix, its local
  smoke runtime passed reference-only account/public operations, and the
  cross-host permissioned credential/read smoke passed with a static operator
  key pin. A complete Swan-to-TypeScript semantic convergence run, including a
  live public repository import, blob transfer, compaction-gap recovery, and
  dynamic remote key discovery, remains a distinct follow-up gate.

## 2026-07-29 live public CAR and blob-promotion checkpoint

The rebuilt Swan image passed a disposable reference-to-Swan public handoff
with dynamic PLC key resolution enabled explicitly for the lab. A fresh
managed receiver imported the pinned TypeScript repository over Caddy TLS:
HTTP 200, one record, three reachable blocks, and a verified commit. With
`--promote-public-blobs`, the receiver then called the reference
`com.atproto.sync.getBlob` endpoint using both the repository DID and raw blob
CID, streamed the response into a bounded temporary file, verified the
content-addressed SHA-256 CID, and adopted one blob in the receiver's public
namespace. The ignored sanitized artifact is
`artifacts/reference-public-import-live.json` and records
`promotedBlobCount: 1`; no credentials, values, proofs, or private key
material are present.

This closes the live public CAR-import and receiver-side public-blob
promotion seams. It does not close the broader alpha: complete TypeScript
semantic convergence, value-bearing incremental updates, compaction-gap
recovery, reverse authority placement, and the full OAuth/security/lifecycle/
export matrix remain required.

## 2026-07-29 account-bound promotion and reverse-authority boundary

Receiver-side public-blob promotion now checks that the supplied repository DID
matches the managed SQLite account before fetching `sync.getBlob`. The mismatch
path is covered by a no-network regression test and preserves the stable
`BlobInvalidRepositoryDID` artifact code. The focused public-read suite, full
macOS suite, explicit 256 MiB RSS gate, semantic lab, profile verification, and
static interop verifier all pass after this change.

The reverse-authority Compose probe now passes with explicit trust material:
after resolving the current Swan member DID (rather than stale external DID
files), the pinned TypeScript authority issued a credential, Swan wrote on the
member host, and a temporary `credentialPublicKeys` pin for the authority's
PLC `#atproto` secp256k1 key made the member-host read return HTTP 200 with the
same CID. The sanitized result is kept only in the ignored
`artifacts/reverse-authority-pinned-20260729.json` artifact.

The ordinary checked-in notification configuration still has no remote key
pin, so this is not yet a turnkey reverse-host matrix: an operator must supply
the authority key explicitly, or Swan must gain a profile-approved DID/JWKS
resolver. Separately, the reference OAuth authorization page uses a
client-side CSRF/API contract that the current minimal Swan form driver does
not implement. Reverse key provisioning and the cross-implementation OAuth
matrix remain explicit alpha gates rather than being inferred from this one
controlled proof.

## 2026-07-31 cross-host recovery-qualified checkpoint

The disposable Compose lab now has a fresh real TypeScript member account and
has exercised the opposite-host permissioned path. With an owner-only pin for
the member's public `#atproto` key, Swan authority issued a credential for a
reference-PDS delegation; the member wrote on the TypeScript host and the
credential-authenticated read was served by that same remote host with a
matching CID. Removing the pin was also exercised and failed closed with HTTP
401 before any write or read.

The recovery-qualified reference image (the immutable pinned archive plus the
checked-in, checksum-verified overlay) then passed the stateful matrix with
value-bearing `listRepoOps` and two-root `getRepo`: operation and commit
revisions matched, LtHash commitments matched, the expected record was present
in the recovered CAR, and the sync/CAR verifier accepted the final state. This
is qualified overlay evidence only; the stock pinned TypeScript image remains
the source of truth for normal compatibility and still lacks those recovery
surfaces. Dynamic remote key discovery against a configured Swan peer,
reverse authority placement, full
cross-implementation OAuth/browser/lifecycle coverage, corrupted-operation and
compaction-gap fault runs, and a native Linux host run remain open.

Reverse authority placement was subsequently exercised as well: the reference
PDS acted as authority while Swan hosted the member repository. With the
reference authority's public credential key pinned at the Swan member, the
stateful matrix passed credential issuance, member write/read, value-bearing
incremental sync, signed commitment verification, and two-root CAR recovery.
The pin is operator-supplied disposable evidence, not automatic remote-key
discovery.

## 2026-07-31 live dynamic delegation-key checkpoint

The dynamic PLC delegation resolver was exercised against the running
Compose network with no static delegation-key pin. A disposable Swan process
was started with a startup-only `delegationKeyPLC` allowlist containing the
current member DID and the laboratory PLC origin. The member's PLC
`#atproto` key was fetched and verified through the bounded PLC state/audit
path; the same run then completed OAuth/DPoP, space credential exchange,
permissioned write/read, value-bearing `listRepoOps`, and two-root `getRepo`
CAR verification with matching CID, revision, and commitment. The evidence
artifact is sanitized and ignored under `artifacts/live/`; the temporary
configuration was removed after the run and the normal checked-in Compose
configuration was restored.

This closes the live dynamic-resolver capability for a configured Swan peer,
but not the full alpha: dynamic discovery against a TypeScript member,
reverse-authority OAuth/browser/lifecycle coverage, corrupted-operation and
compaction-gap recovery, and a native Linux-host run remain required.

## 2026-08-01 TypeScript-member dynamic delegation-key checkpoint

The dynamic PLC resolver was subsequently exercised against a fresh account on
the pinned TypeScript PDS, again with no static delegation-key pin. The
repeatable
`Scripts/run-reference-member-dynamic-delegation-acceptance.sh` harness created
the reference account, restricted `delegationKeyPLC.allowedIssuers` to its DID,
and ran Swan as the authority on the existing disposable Compose network. The
TypeScript member wrote a permissioned record, Swan resolved and authenticated
the member's `#atproto` key from the pinned laboratory PLC, issued the bound
space credential, and the TypeScript repository host accepted that credential
for the read. The sanitized artifact reported `status: passed`,
`credentialIssued: true`, `converged: true`, and matching write/read CIDs; its
mode was `0600` and it retained no permissioned record value.

The harness controls the existing Swan container directly during the temporary
replacement. This avoids letting a caller's missing historical Compose subnet
environment recreate or detach the running project network, and the
success/failure trap restores the original container by ID. Static shell
validation and ShellCheck pass, and the normal Swan service was healthy through
Caddy after the live run.

This closes dynamic delegation-key discovery against a pinned TypeScript
member. It does not close stock value-bearing TypeScript `listRepoOps`/`getRepo`,
reverse-authority OAuth/browser/lifecycle coverage, live corrupted-operation or
compaction-gap recovery, strict password-reset contention/cancellation gates,
or native Linux-host acceptance.

## 2026-07-31 notification crash/restart acceptance

The disposable Compose notification acceptance completed against the pinned
Swan image. A real OAuth permissioned write was committed with delivery
disabled, the seed process was terminated, and a recovery-enabled process
forwarded the same outbox event twice while the proxy dropped the first
acknowledgement. The receiver applied exactly one effect and the sender
outbox converged to empty. The scenario retained only bounded counts and
digests; no credentials, tokens, request bodies, or permissioned values were
written to the repository.

The acceptance harness now falls back to a normal pinned build when a fresh
project name has no project-scoped Docker image tags, so `NO_BUILD=1` cannot
fail before service startup merely because the cache was built under another
disposable project name.

The notification receipt table was also hardened for cross-space replay
isolation. Receipt uniqueness and duplicate lookup now include `space_uri`,
with a transactional migration for existing account databases. The focused
SQLite notification suite passes 6/6, including reuse of one writer JTI across
two spaces without suppressing either writer hint.

## 2026-07-31 local acceptance checkpoint after adversarial rereview

Commit `229d90b9` bounds permissioned JSON record projection with a keyset SQL
page and aggregate byte admission, performs metadata-only write authorization,
seeds the permissioned TID allocator from the durable write revision, and
narrowed public OAuth low-level issuance/redemption APIs so production callers
cannot disable active-account enforcement. Focused suites passed 13/13 for
permissioned record reads/writes, 104/104 for OAuth, and 12/12 for public
repository read HTTP behavior.

A fresh dependency-cache macOS acceptance passed the complete XCTest graph with
zero failures. The explicit bounded-transfer gates also passed: public
production `getRepo` RSS, permissioned near-256 MiB CAR RSS, public CAR-spool
RSS, 256 MiB staged CAR import, private CAS streaming, and the private CAR
spool stress test. This is local macOS evidence only. The acceptance wrapper
still reports the live cross-host semantic matrix as not run; native Linux,
stock pinned TypeScript recovery/value interoperability, reverse-authority
OAuth/browser/lifecycle coverage, and the corruption/compaction fault matrix
remain required before calling the alpha complete.

## 2026-08-01 reference OAuth provider and public write/read witness

`SwanOAuthLabClient` now supports the pinned TypeScript provider's
same-origin JSON sign-in/consent contract, including its CSRF cookie, ephemeral
session bearer, and issuer-local `/oauth/authorize/redirect` browser hop. The
hop is bounded to one GET and one 303, with strict issuer/path/query/referrer
validation and redirect following disabled. The focused adapter test and the
serialized `SwanInteropTests` selection pass with zero failures.

A disposable account on the pinned TypeScript PDS completed a live OAuth/PKCE/
DPoP public round trip through the current Caddy/Toxiproxy Compose network.
With `atproto` plus collection-specific create/update repository scope, the
reference host accepted `com.atproto.repo.putRecord` (HTTP 200) and
`com.atproto.repo.getRecord` (HTTP 200) returned the same CID. The sanitized
ignored artifact is
`.interop-live/reference-oauth-public.SMYhmU/artifact.json`; it contains only
statuses, endpoint labels, byte counts, and digests. The public fixture's
record key is the valid TID `3jzfcwq7jrs2a`.

This closes the reference OAuth/public write-read witness, but not the
remaining stock TypeScript incremental/full-CAR gap, cross-host corruption and
compaction recovery, reverse-authority browser/account lifecycle, strict
password-reset race, or native-Linux current-profile live gates.

## 2026-08-01 lab restart image and descriptor-pressure correction

After the lab restart, the active reference-PDS service was checked by its
container contents, not its Compose tag. It was initially recovery-qualified;
the disposable current project was restored to the stock pinned image and
only `reference-pds` was recreated with its existing data volume. The stock
source marker and the Caddy/Toxiproxy HTTPS route were then verified.

The recovery overlay source test was also hardened to hash only its four
patched files. Recursive hashing of the pinned checkout's pnpm dependency
farm was unnecessary and could trigger the host descriptor-pressure failure.
The overlay source qualification passes after the bounded check.

## 2026-08-02 qualified stateful member witness and data-volume selection

With the current rebuilt Swan image and the explicit recovery-qualified
reference overlay, the member-direction stateful matrix passed all 26
sanitized assertions: credential exchange, permissioned write/read CID
convergence, value-bearing incremental sync, signed commit verification, and
two-root full-CAR recovery with equal commitments and revisions. The ignored
artifact is `/private/tmp/swan-qualified-stateful-member-20260802.json` and
contains no credentials or permissioned values.

The overlay was removed afterward and the stock pinned reference image was
restored. The active Compose project now selects its existing encrypted
`swan-data-v2` volume through
`interop/docker-compose.external-data-volume.yml`; the older volume remains
untouched and is not accepted as current evidence.

The same qualified stateful matrix also passed with authority placement
reversed: 26/26 assertions covered dynamic credential/key resolution,
value-bearing incremental sync, signed commit verification, full-CAR recovery,
and equal sync/full-CAR commitments and revisions. The reference service was
restored to its stock image after the run.

## 2026-08-02 cross-host full-CAR fallback witness

The pinned TypeScript `listRepoOps` implementation returns a successful page
for an old cursor rather than the proposal's `409 full_repo_recovery_required`
response. Swan's recovery command therefore keeps the strict 409 behavior by
default and adds an explicit `--allow-full-car-fallback` compatibility flag for
this known reference limitation. The flag is recorded as
`gapFallbackUsed: true` and is rejected by the strict retention-gap artifact
validator; it cannot be promoted to compaction-gap evidence.

With that flag enabled only for the checksummed recovery overlay, the
rebuilt-Swan/reference-PDS cross-host run passed all 26 sanitized assertions.
The artifact `/private/tmp/swan-qualified-cross-host-recovery-fallback-20260802.json`
was mode 0600, reported `gapStatus: 200` and `gapFallbackUsed: true`, installed
and verified the two-root full CAR, rejected a corrupted CAR as
`CARBlockCIDMismatch`, and preserved the last valid receiver head. No secret or
permissioned value was recorded. The reference service was restored to the
stock pinned image and the current Swan service was recreated from the rebuilt
image using the explicit `swan-data-v2` volume.

This closes a qualified cross-host full-CAR transfer witness, not stock
TypeScript retention-gap interoperability. Native Linux, stock value-bearing
and gap semantics, cross-host fault ordering/compaction, reverse lifecycle,
and final security gates remain open.

## 2026-08-02 active-profile and stock-fault receipts

Adding the pinned TypeScript retention-gap behavior to the active successor
profile exposed and closed the associated deterministic-pin seam: the profile,
Swift verifier, shell verifier, and wire-generation preflight now use the same
SHA-256 for `permissioned-data-0016-2026-07-30.json`. Pinned Swift and
public-wire regeneration, their mutation suites, `SwanInteropTests` (92/92),
and `PublicRepositoryReadHTTPTests` (13/13) pass on the current macOS
checkout.

The current rebuilt Swan image was then exercised against the stock reference
PDS after the lab restart. Credential issuance, permissioned write, and
credential-authenticated read all returned HTTP 200 with matching record CIDs;
the pinned member host returned HTTP 500 for value-bearing `listRepoOps` and
HTTP 501 for `getRepo`. The failure was retained as a mode-0600 sanitized
artifact at `/private/tmp/swan-stock-member-current-20260802.json.failed` and
is recorded as the profile's upstream compatibility boundary, not relabeled as
Swan success.

A disposable CA-trusted Swan runner also executed the live profile endpoint
fault matrix through the current Caddy/Toxiproxy topology for normal, delayed,
duplicated, reordered, offline, disconnected, and corrupted modes. Each
sanitized matrix cell completed with status `passed`; both Caddy routes remained
HTTP 200 and all long-running services were healthy afterward. This is
transport/profile fault evidence, not a claim that the stock TypeScript host
implements value-bearing incremental or full-CAR permissioned recovery.
