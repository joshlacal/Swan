# Swan adversarial review — 2026-07-30

## Status

This review covers the uncommitted interoperability, PLC key-discovery,
Mailpit recovery, fixture-sanitization, reference-overlay, and clean-cache
acceptance work layered on parent change `a2ea4782`.

It is a security and acceptance review, not evidence that the alpha is
complete. In particular, a green Swift suite or healthy Compose deployment
does not substitute for the live Swan/TypeScript semantic and fault matrix.

Latest checkpoint: the live account-email XRPC surface is now composed into
`SwanHTTPServer`, with a lifecycle-owned Mailpit worker, owner-only proof-key
loading, and a healthy-Mailpit Compose dependency. A disposable Caddy/Mailpit
run has now delivered a seeded password-recovery message, and the durable
notification worker has passed a real SIGKILL/restart/lost-ack convergence
run. The operator restore path
now restores the PLC preparation journal, submitted intent, and genesis
history, and activation admission retries discard rejected closed transfers.
Public-read generations now retain and cross-check an exact SQLite descriptor,
and OAuth authorization-code/token-family/access/refresh rows have hard
transactional live caps. Focused route, restore, concurrency, retry,
descriptor-replacement, and cap tests are green, and the serialized macOS
suite is green. Live Compose SIGKILL/restart, cross-host semantic matrix, and
Linux-host gate remain open.

## Review judgment

The new work contains useful production-shaped controls, but the first version
overstated several gates. The most important adversarial findings were:

1. the stateful matrix could pass without value-bearing incremental sync;
2. reflected opaque authorization material could survive fixture recording;
3. email proof tokens were not bound to the address and account lifecycle;
4. arbitrary PLC issuer misses could amplify unauthenticated outbound work;
5. PLC rollback protection did not survive process restart;
6. permissioned CAR transfer was streamed, but CAR verification still
   materialized payload-sized state;
7. the reference overlay exported an unbounded, non-snapshot-stable recovery
   repository;
8. the clean-cache Compose runner proved build/startup health while printing an
   acceptance-shaped success result;
9. portable operator restore can publish an active account whose public
   admission journal and PLC intent were never restored;
10. the selected/generated profile IDs drifted from the mandated immutable
    `permissioned-data-0016-2026-07-03` profile, breaking the portable export
    contract and the serialized suite;
11. an activation admission failure closes the transferred database while the
    preparation opener retains the same closed actor for every exact retry;
12. Mailpit verification/recovery storage existed without a safe live
   HTTP/CLI, delivery, throttling, and OAuth-revocation composition.
13. Compose bootstrap treated every failed account lookup as an absent account,
   so a control-database/storage failure could fall through into PLC preparation
   and mutate bootstrap state instead of failing closed.

## Finding ledger

| ID | Priority | Finding | Current disposition |
|---|---|---|---|
| ADV-01 | P1 | Stateful evaluator accepted `syncValuesIncluded: false` and weak revision witnesses. | Remediated; value presence, canonical DAG-CBOR/CID matching, TIDs, terminal revision, and evaluator assertions are required. |
| ADV-02 | P1 | Live stateful verification lacked the correct host key and was curve-specific. | Remediated; both placements receive an explicitly tagged ES256/ES256K verification key and recovery verification is algorithm-bound. |
| ADV-03 | P1 | An upstream host could reflect an opaque token into a persisted error field. | Remediated; remote error strings are reduced to a fixed code allowlist and recursive fixture sentinels cover opaque values. |
| ADV-04 | P1 | Email tokens could verify a reassociated address or reset a non-active account. | Remediated at storage/service boundaries; tokens bind the exact address, reassociation and non-active transitions revoke them, consumption is atomic, and deletion purges email PII. |
| ADV-05 | P1 | Request-selected PLC issuers could cause unbounded misses and same-issuer duplicate fetches. | Remediated; operator authority allowlist, single-flight, concurrency ceiling, new-issuer budget, negative cache, and bounded retention are enforced. |
| ADV-06 | P1 | A valid historical PLC audit prefix could restore a retired credential key after restart. | Remediated and focused tests are green: durable key-continuity state must commit before the resolved key is returned, and the exact terminal audit CID is required. |
| ADV-07 | P1 | Swift CAR verification maps and copies the full recovery payload. | Remediated and green on macOS: the live path uses a bounded streaming parser and staged record sink; corruption, oversize, cleanup, staged-CAR RSS, and public-export RSS gates pass. Cross-host recovery remains open. |
| ADV-08 | P1 | Reference `getRepo` loads all records, builds a full index, and does not hold one read snapshot. | Remediated in the checksummed disposable overlay with bounded traversal and one read transaction. The exact pinned source remains immutable; the live cross-host recovery matrix remains open. |
| ADV-09 | P1 | Clean-cache Compose “acceptance” did not execute semantic interop. | The false claim is remediated: the runner now labels build/health evidence honestly. The live semantic matrix itself remains open. |
| ADV-10 | P1 | Mailpit verification/recovery was not a complete runtime flow. | Superseded by ADV-56. The standalone transport/storage concerns are now composed and focused-tested; live through-Caddy delivery, restart recovery, and SIGKILL acceptance remain open there. |
| ADV-11 | P2 | Lab verifier negated `rg` checks could fail open under `set -e`. | Remediated with explicit branches and mutation tests. |
| ADV-12 | P2 | Notification configuration checks were shallow and could ignore nested unknown/secret-like keys. | Remediated in both the lab verifier and runtime decoder with recursive exact-key validation. |
| ADV-13 | P2 | Overlay temporary-path reservation, copy fallback, and profile binding were unsafe or inconsistent. | Remediated with retained/atomic directories, consistent tar copy, and profile/source/archive/patch cross-checks. |
| ADV-14 | P2 | Base and utility container tags were mutable. | Remediated for Swift, Caddy, Mailpit, Toxiproxy, and curl with multi-architecture manifest digests. |
| ADV-15 | P2 | Test barriers could lose a release and hang indefinitely. | Remediated with a latched release. |
| ADV-16 | P2 | The stable-snapshot CAR test did not inspect the generated CAR. | Remediated; the test reconstructs and cryptographically verifies the CAR and exact old record set. |
| ADV-17 | P1 | The public 256 MiB RSS gate measured only after seeding, while production drained the spool with Foundation `FileHandle.read(upToCount:)`; allocator retention could therefore be hidden by the baseline. | Remediated and verified in the working copy with a fresh measurement process and fixed-buffer POSIX `pread`: 270,049,433 bytes streamed with 16,564,224 bytes peak RSS growth. |
| ADV-18 | P1 | Active public databases were published at bootstrap and live activation before full projection verification. Public JSON reads then repeated whole-repository verification inside `BEGIN IMMEDIATE`, allowing unauthenticated reads to reserve the SQLite writer. | The admission and writer-reservation cases are remediated and green. Whole-repository request-time verification is split into ADV-26 and remains open. |
| ADV-19 | P1 | Concurrent exact-URL OAuth metadata cache misses each performed their own DNS/GET, and canceling one waiter canceled its transport rather than only that waiter. The production transport also creates a new event-loop thread for each GET. | Coalescing, prompt waiter-only cancellation, and the shared eight-flight metadata/JWKS admission are green. Shared transport lifecycle remains open. |
| ADV-20 | P1 | `AccountOperatorService.delete` still calls the generic `.deleted` transition, which the lifecycle policy explicitly rejects so deletion cannot reach the resumable coordinator. | Remediated and green in the serialized macOS suite: the operator boundary delegates only to the permanent-deletion capability; the CLI/runtime injects concrete PLC/data adapters, resumes pending work before listeners, and fails closed if recovery is required but unavailable. |
| ADV-21 | P1 | Full-CAR recovery evidence is verified but discarded; no durable atomic installer retains verified record bodies, rejects rollback/equivocation against last-good state, and replaces a remote replica. | Storage installer is remediated and green in the serialized macOS suite with descriptor-backed staging, authenticated freshness witnesses, atomic generation publication, rollback/equivocation rejection, and crash cleanup. Production cross-host orchestration still must bind the authorized origin/DID/key/freshness to this installer. |
| ADV-22 | P1 | Checked-in Compose loaded notification configuration but did not enable outbound delivery or the startup recovery service. Duplicate/reorder scenarios exercised endpoint probes, not durable convergence. | Static remediation and adversarial rereview are complete: delivery is enabled, the proxy is ready before recovery, and the claim is correctly scoped to two successful forwards/one receiver effect. The live SIGKILL/lost-ack Compose run is still required. |
| ADV-23 | P1 | Portable export/restore accepted a permissioned blob whose space had no matching space CAR. With no restored closure or repository-existence check, the published account could stream that orphan through `getBlob`. | Remediated and green: restore requires matching repository state before persistence, request reads check state/closure/tombstones/exact reference in one snapshot, and the legitimate closed operator-restore path remains supported. |
| ADV-24 | P1 | Password login has no durable per-account/source failure admission, and PAR/replay persistence has no live-row cardinality cap. Argon work and unbounded expiry deletes can monopolize the process-local queue and serialized control database. | Login admission and the OAuth storage ceilings are remediated in source: metadata/PAR/replay plus authorization-code, token-family, access-token, and refresh-token rows now use transactional hard caps. Focused cap tests are green; the serialized suite remains the execution gate. |
| ADV-25 | P2 | Unknown/inactive login identities return before Argon verification, while an active account with a wrong password performs expensive work. Uniform HTTP status/body therefore still exposes a remote timing oracle. | Remediated and focused login tests are green: unknown, inactive, stale-PHC, and wrong-password cases use the same admitted configured-cost verification path. |
| ADV-26 | P1 | `getRecord`, `listRecords`, and `describeRepo` still walk and materialize the full MST and record index on every unauthenticated request; the HTTP get/list handlers ordinarily trigger that validation twice. | Bounded lazy pages, trusted authenticated generations, aggregate body budgets, and process admission are green in the serialized macOS suite and explicit 256 MiB gates. The remaining concern is request-time JSON/index materialization beyond the bounded response budget. |
| ADV-27 | P1 | Public admission validates structural commit/MST/index consistency but does not authenticate the current commit signature or bind the admitted state to the PLC terminal signing key. Admission is also split across separate read snapshots. | Current-head authentication is remediated and green for P-256 and secp256k1 DID keys; a canonical wrong-key head is rejected before publication. The single authenticated generation/snapshot optimization remains part of ADV-26. |
| ADV-28 | P1 | OAuth metadata single-flight is keyed only by exact URL and mode, with no process-wide or per-origin permit bound. An attacker can use many distinct valid client IDs to create unbounded detached DNS/HTTP/JWKS work. | Remediated and green with one process-wide nonqueueing eight-flight budget held across metadata plus remote JWKS; excess work fails typed unavailable before network I/O. Per-origin fairness and bounded blocking-DNS execution remain follow-up hardening. |
| ADV-29 | P1 | Cached-load and revalidation flights for one OAuth client can run concurrently and unconditionally overwrite the same cache row. A delayed older response can replace newly rotated JWKS and re-enable a retired client key. | Remediated and green with durable per-client monotonic fetch tickets and CAS publication. Freshness watermarks intentionally survive cache expiry; bounded safe compaction remains follow-up work. |
| ADV-30 | P2 | `SQLiteActivatedAccountAdmission` is copyable. Replaying an already-admitted value closes the same database actor that remains stored in the live directory. | Remediated and green: replay of the exact installed actor is idempotent and never closes it; a different actor for an occupied DID fails closed. |
| ADV-31 | P2 | Live activation checks that the expected account path exists but does not bind the transferred database actor to that DID, root, or open inode. | DID, managed-root, and retained-descriptor inode binding are remediated and green for wrong-DID, same-DID/foreign-root, and regular-file replacement attacks. |
| ADV-32 | P2 | The new OAuth concurrency tests wait on unbounded continuations and release the transport before awaiting the canceled waiter. A regression before transport admission can hang the suite, and non-prompt cancellation is masked. | Remediated: all gates have bounded deadlines and deferred release, and the canceled waiter must finish while the shared transport remains blocked. |
| ADV-33 | P1 | Compose terminates TLS at Caddy, while password-login admission keys only the accepted socket peer. Every lab user therefore shares Caddy's five-minute peer bucket and roughly 100 hostile attempts can globally lock out login. | Remediated and green in the serialized macOS suite plus static verifier: exact trusted peers require one strict Caddy-overwritten internal client-IP header; direct/untrusted peers ignore forwarding input; malformed or multi-hop input fails before Argon work. |
| ADV-34 | P1 | Stored Argon2 PHC parameters could differ from the boot dummy, preserving a known-versus-unknown timing oracle even when every path performed one verification. | Remediated and green in the serialized macOS suite: login accepts only the configured exact Argon2id algorithm/version/time/memory/parallelism policy and substitutes the equal-cost dummy for a verifier requiring migration. |
| ADV-35 | P1 | The first durable login limiter schema had no safe legacy-column migration, could retain a requested expired row behind the 512-row cleanup batch, and allocated attacker-varied keys after another dimension was already limited. | Remediated and green in the serialized macOS suite with an atomic legacy-table rebuild, exact-key expiry reclamation, fixed invalid-handle sentinel, denial-before-allocation, trigger-maintained capacity, and WAL/SHM secret regressions. |
| ADV-36 | P1 | OAuth metadata, PAR, DPoP, client-assertion, and delegation replay persistence has no complete hard cardinality policy; most request-time expiry purges are unbounded and most expiry columns are unindexed. | Remediated in source: cleanup is indexed and limited to 512 rows, and metadata/PAR/replay plus authorization-code, token-family, access-token, and refresh-token families have transactional insertion ceilings. Focused hard-cap coverage is green; serialized execution remains. |
| ADV-37 | P2 | OAuth login, consent, and error HTML lacks CSP frame denial, `X-Frame-Options`, `Referrer-Policy`, and `nosniff`. A same-site sibling origin can frame a host-cookie consent page for UI redress. | Remediated and green in the serialized macOS suite with one strict browser-header policy applied to localhost and remote success/error HTML. |
| ADV-38 | P2 | The new bounded control-SQLite connection gate has no deterministic capacity/cancellation/handoff regression. Its correctness currently rests on source inspection. | Remediated and green in the serialized macOS suite with deterministic capacity, cancellation, replenishment, handoff-race, and exactly-once settlement tests. |
| ADV-39 | P1 | Anonymous `listRecords` can load, decode, and re-encode up to 100 near-1-MiB values without an aggregate JSON byte budget or process admission lease. Concurrent reads can consume hundreds of MiB each. | Remediated and green in the serialized macOS suite with 8 MiB get / 16 MiB list reservations, a 64 MiB process ceiling, and leases held until the streamed response body drains or fails. |
| ADV-40 | P1 | `describeRepo` always labels the verification method P-256 even though admission supports secp256k1 DID keys. | Remediated and green in the serialized macOS suite; the response derives P-256 versus secp256k1 verification-method type from the admitted DID key. |
| ADV-41 | P1 | An active account can be admitted with neither PLC genesis nor a valid empty public repository, leaving its public surface unavailable despite the account lifecycle claiming active. | Remediated and green in the serialized macOS suite: production admission requires authenticated genesis and valid repository state; explicit nil-verifier mode disables public reads and all bootstrap call sites now choose deliberately. |
| ADV-42 | P1 | The first durable remote-replica installer refactor was frozen mid-slice with undefined helpers, an always-expired placeholder timestamp, generation-mixing record reads, unbounded startup deletion, and no SQLite crash/tamper/idempotency tests. | Remediated and green in the serialized macOS suite with real-time expiry, generation-qualified reads, bounded preparation/install/cleanup, startup recovery, corruption mapping, and crash/tamper/idempotency tests. Cross-host orchestration remains open. |
| ADV-43 | P1 | Permanent deletion used one lifecycle lock filename per two-character DID hash prefix and materialized/sorted the entire blob-CAS directory before deletion. | Remediated and green in the serialized macOS suite with full-DID hash-qualified lock files, descriptor-relative 256-entry deletion passes, sticky drain retry, and collision/multi-batch/startup-race regressions. |
| ADV-44 | P2 | Peer-pinned OAuth GET/POST transports construct a new event-loop group and TLS context per request; timeout handlers can also race a late response without atomically completing and closing the channel. | Remediated and green in the serialized macOS suite with configuration-owned event-loop/TLS resources, one-shot timeout completion, and channel close on every terminal path. |
| ADV-45 | P2 | Public-read generation tokens bind `lstat(path)` rather than a retained descriptor for the SQLite file actually opened, so a same-principal rename/replacement can validate one inode while SQLite reads another. | Remediated in source and focused green: every account database retains an `O_NOFOLLOW` descriptor, and public admission requires its `fstat` identity to match the current directory entry. Regular replacement and symlink replacement both fail closed. |
| ADV-46 | P2 | Atomic public-read outcome methods have default multi-`await` compositions, and HTTP fakes exercise those unsafe fallbacks rather than the production atomic generation path. | Remediated and green in the serialized macOS suite: atomic outcomes are required at the protocol boundary, fakes implement the same contract, and lifecycle mutation is covered. |
| ADV-47 | P1 | `OAuthBoundedJSONPoster` validates DNS before a notification but does not pass that approved peer set into the POST transport. A stale or misconfigured static pin can therefore receive the service JWT and body before the post-response DNS comparison rejects it. | Remediated and green in the serialized macOS suite: the approved peer set is passed into the POST transport and checked before connect/write; the postflight DNS intersection remains, with a zero-accept/no-body regression. |
| ADV-48 | P1 | A malicious interop peer can reflect a bearer or space credential as an arbitrary `cid`; failed artifacts persist that peer-controlled string, and matching reflected values can appear converged. | Remediated in source and focused `InteropArtifactBoundaryTests` are green: canonical CID validation and recursive artifact-boundary checks reject reflected opaque material. Live cross-host artifact recording remains part of ADV-56/interop closure. |
| ADV-49 | P1 | Password-recovery rate limits use only the accepted socket peer. Once routed through Caddy, one attacker can consume the shared 15/hour proxy bucket and deny recovery to every user. | Standalone trusted-proxy policy and focused HTTP tests are green. Through-Caddy recovery/rate-limit behavior is composed in source but not exercised live; that runtime gate remains tracked by ADV-56. |
| ADV-50 | P2 | Known password-reset mailboxes perform token/outbox writes while unknown mailboxes return early; known-only storage failures can also produce a distinct error response. | Partially remediated in source and focused tests: every canonical request now records a keyed, account-free blind-work marker; request-dependent storage/delivery failures collapse to the no-store empty success; and a 50 ms response floor bounds the direct timing signal. The known-account path still performs additional token/outbox writes, so strict constant-work equivalence under arbitrary SQLite contention remains an explicit follow-up. |
| ADV-51 | P2 | New 256 MiB RSS helpers inherit the entire parent environment and relay unbounded child output into XCTest failures. | Remediated in source and focused helper tests are green: child environment is allowlisted and diagnostics are bounded/redacted. |
| ADV-52 | P2 | Password-reset tests assert access-token revocation but discard the seeded refresh digest, so refresh-family regressions could pass unnoticed. | Remediated and focused refresh-family tests are green: the target family is revoked while an unrelated subject can still rotate. |
| ADV-53 | P2 | Permanent-deletion outbox coverage is vacuous because the fixture asserts an empty outbox without ever seeding one. | Remediated and focused deletion-outbox tests are green with retained target rows and exact scoped-purge assertions. |
| ADV-54 | P2 | Account-data deletion fixtures label blobs private but seed only the public namespace, so permissioned and equal-CID namespace isolation are unproved. | Remediated and focused namespace tests are green with `.public` and `.space` equal-CID references across same-shard accounts. |
| ADV-55 | P1 | Permanent deletion can delete an already-claimed email outbox lease while its worker is paused before SMTP; the worker then sends after deletion has begun and only discovers the missing row while acknowledging. | Remediated in source and focused race tests are green: the persistent send-start fence now also rejects an expired lease before the network boundary, and serializes deletion against that boundary. Live worker/Mailpit exposure remains blocked by ADV-56. |
| ADV-56 | P1 | The generated email/recovery XRPC handlers, proof codec, SMTP delivery, durable worker, and Mailpit service were not composed into `swan serve`; the live PDS exposed unavailable gates for these operations. | Remediated for the lab composition: the routes register on `SwanHTTPServer`, a lifecycle-owned worker drains the durable outbox and shuts down Mailpit, the proof key is owner-only file-backed, and Compose waits for Mailpit health. Focused route/worker/deletion tests are green. A live Compose run delivered a seeded password-recovery message through Mailpit after a Swan restart, and the notification acceptance passed real SIGKILL/restart/lost-ack convergence (`successful_forwards=2`, `receiver_effects=1`). Full browser-driven reset/revocation and cross-host semantic coverage remain separate gates. |
| ADV-57 | P1 | Operator restore verified and installed the public CAR, repositories, blobs, keys, and active control row, but did not restore the PLC preparation journal in the account database or the matching preparation intent in `control.sqlite`. Startup public admission therefore rejected the restored active account as unavailable. | Remediated in source and focused backup test: authenticated preparation journal/intent, submitted PLC genesis history, and public genesis state are restored transactionally; a fresh `SQLitePreMigratedAccountDirectory.bootstrap` reopens the account and describes its public repository. |
| ADV-58 | P1 | Luna-era profile selection changed `OfflineProtocolProfileVerifier.stableProfileID`, `PermissionedData0016.profileID`, and CLI defaults from the original `permissioned-data-0016-2026-07-03` to `permissioned-data-0016-2026-07-30` (and public `2026-07-27` to `2026-07-30`). Existing portable export/restore fixtures still targeted 07-03, so the serialized suite exited with 15 `invalidManifest` failures. | Remediated as an explicit successor boundary: 07-30 is the active immutable profile with regenerated checksums and current generator SHA; the original 07-03 profile remains checked in byte-exact and unsupported for new exports. Portable tests now use `PermissionedData0016.profileID`. The subsequent serialized macOS suite is green; Linux/profile-cache evidence remains open. |
| ADV-59 | P1 | Concurrent PLC preparation retries could install a journal while the winner had already advanced it to `submitted`; the retry compared the entire record, treated monotonic stage/CID progress as a conflict, and failed (or leaked its SQLite connection during error cleanup). | Remediated in source: create-only replay now compares immutable identity/operation/key fields and returns the already-advanced journal; the fixture has async teardown. Repeated focused concurrency and continuity tests are green. |
| ADV-60 | P1 | If `admitActivatedAccount` rejects a transferred database after the activation service has made the control row active, it closes the database actor but `SQLitePLCAccountPreparationStoreOpener` retains it in `transferredDatabases`. An exact management retry receives the same closed actor and cannot recover without a process restart. | Remediated in source and focused retry test: failed live-directory admission now discards the transferred actor before returning the error, so the exact retry opens a fresh database/journal actor rather than reusing a closed connection. |
| ADV-61 | P2 | The clean-cache acceptance runner did not pin the CLI subprocess executable for the root checkout. Its child tests clear their environment, so an old `.build/debug/swan` could create false failures or accidentally exercise stale profile behavior. | Remediated in `Scripts/run-clean-cache-acceptance.sh`: every run builds `swan` in the isolated scratch tree and exports `SWAN_TEST_EXECUTABLE`; the fresh macOS clean-cache gate passed 858 XCTest cases, 8 explicit skips, and zero failures. |
| ADV-62 | P1 | The live OAuth client used `URLComponents.queryItems` for the authorization redirect. Foundation leaves `?` and `&` from a nested `client_id` metadata URL unescaped, so Swan saw a truncated client binding and returned an opaque authorization error before the login form. The Compose Caddy bridge also deleted the replacement `X-Swan-Client-IP` after setting it, so browser login POSTs failed with a misleading missing-CSRF error. | Remediated in source with RFC 3986 component encoding and a regression test that round-trips the nested localhost metadata URL. The Caddy rule now overwrites the caller header from `{http.request.remote.host}` without a delete-after-set or append operation; a disposable echo upstream proved forged input is replaced. Direct and proxied PAR/login GETs now reach the server. A fresh cross-host semantic run remains blocked at the expected unpinned TypeScript delegation-key boundary. |
| ADV-63 | P1 | Compose bootstrap treated an existing account as valid when its handle matched, without checking the owner-only DID identity. Reusing a persistent `swan-data` volume with a different secret directory therefore let the OAuth subject diverge from the configured space authority and produced misleading `SpaceNotFound`/401 failures. | Remediated in `bootstrap-local-space.sh`: existing accounts now fail closed unless the durable DID exactly matches `authority.did`/`member.did`; static verifier coverage requires the check. A reused mismatched volume now exits before Swan starts. Fresh-volume provisioning still needs an explicit identity-source workflow because PLC genesis creates a DID rather than accepting one as an input. |
| ADV-64 | P1 | The checked-in notification configuration has no pinned TypeScript user delegation key. The real cross-host run can obtain a delegation token from the pinned PDS, but Swan rejects `getSpaceCredential` with HTTP 401 when neither a pin nor an explicit remote resolver is configured. | The resolver now supports an optional startup-bound `delegationKeyPLC` with an issuer allowlist, bounded/audited PLC state, continuity, and SSRF-safe transport; the checked-in lab still deliberately uses no remote delegation resolver. The live dynamic-PLC run and value-bearing member-read/full-CAR matrix remain open; a disposable operator pin is still a valid controlled proof path. |
| ADV-65 | P1 | Bootstrap treated any nonzero `account show` result as "not found". A locked/unavailable/corrupt control database could therefore fall through to PLC preparation and write an identity journal during an infrastructure failure. | Remediated in `bootstrap-local-space.sh`: only the exact sanitized `account not found` diagnostic permits preparation; all other lookup failures fail closed before mutation. The static lab verifier requires both branches. |
| ADV-66 | P1 | The local `#atproto` delegation-key resolver returned `nil` for a managed account whenever it was deactivated/deleted, had an unsupported or missing generation, or had unavailable key material. The composite resolver interprets `nil` as an unknown issuer and could then accept a configured operator pin or remote PLC key for that same DID, bypassing the account lifecycle gate. | Remediated in `LocalAccountSpaceDelegationPublicKeyResolver`: only proven local absence returns `nil`; every managed lifecycle, generation, key-store, corruption, and read-race failure throws an opaque terminal error. Added deactivation/deletion, unsupported/missing/corrupt-key, lifecycle-race, startup-pin, and unknown-issuer regression coverage; the focused OAuth/composition selection passed 23/23. |
| ADV-67 | P2 | The bounded PLC resolver retained expired positive cache entries in its issuer-capacity set. After a bounded burst filled `maximumEntries`, later issuers could remain rejected forever even after the value TTL elapsed, despite durable continuity state being independent of the cache. | Remediated by pruning expired positive entries during lookup admission while preserving the “previously authenticated issuer” budget exemption and the durable terminal-CID checkpoint. A one-entry cache test now proves a second issuer resolves after expiry; the PLC resolver selection passed 13/13. |
| ADV-68 | P2 | A holder of a valid read credential could register an unbounded number of distinct notification endpoints for one space. Space deletion copied every active endpoint into one transaction, so endpoint churn could grow the database and turn a later lifecycle operation into an unbounded fanout/lockout workload even though outbound delivery was SSRF-safe. | Remediated with a transactional per-space cap of 1,024 active registrations. Expired rows are pruned before admission, existing endpoints remain replaceable at capacity, and the capacity/expiry regression covers the read-credential path. The complete `SpaceNotificationSQLiteTests` class passed 5/5 in a serialized rerun. |

### Provenance limitation

The repository does not preserve per-agent attribution for these changes.
There are no `Luna` markers or trailers in the checked-in reports or commit
metadata, and Task 43 commit `66bf469bf53b` is authored as the repository
owner. The review therefore treats "Luna-era" as a time/surface boundary and
does not claim that a particular agent introduced a particular defect.

## Evidence already obtained

- `swift test --jobs 1 --filter
  'PLCSpaceCredentialPublicKeyResolverTests|SwanSQLiteTests/testEmailProof|SwanSQLiteTests/testFullCARSpoolUsesOneStableSQLiteReadTransaction'`
  passed 16 tests with zero failures.
- `swift test --jobs 1 --filter
  ServePermissionedRuntimeCompositionTests/testNotificationConfigurationRejectsUnknownKeysRecursively`
  passed.
- `Scripts/verify-interop-lab.sh` passed static and effective Compose checks.
- `Scripts/test-verify-interop-lab.sh` passed its adversarial mutation suite.
- `interop/reference-pds-overlay/test-reference-pds-overlay.sh` passed source
  qualification without mutating the pinned cache.
- The second-pass RED command ran five exact tests. All five failed for the
  intended production reasons:
  - corrupt public projection accepted at bootstrap;
  - corrupt public projection exposed by live activation;
  - public record/description read failed with `database is locked` while
    another connection held `BEGIN IMMEDIATE`;
  - eight concurrent exact-URL OAuth metadata loads caused eight GETs;
  - canceling one waiter canceled the transport, caused a second GET, and
    returned a wrapped availability error instead of `CancellationError`.
- The corresponding narrow GREEN run passed the three public admission/lock
  tests and both exact-URL OAuth single-flight tests.
- The fresh-process public CAR spool gate streamed 270,049,433 bytes with a
  baseline RSS of 83,214,336 bytes, peak RSS of 99,778,560 bytes, and
  16,564,224-byte growth.
- The complete `PublicRepositoryReadDirectoryTests` and
  `PublicRepositoryReadHTTPTests` selection passed 20 tests with one explicit
  opt-in skip.
- The orphan permissioned-blob RED selection produced only the intended
  failures: restore accepted/persisted an orphan and a staged orphan was
  readable; its active-repository control passed. After remediation, all three
  cases passed.
- The existing operator deletion test failed with `invalidTransition`, proving
  that the user-facing delete path cannot invoke the durable coordinator.
- The active-profile backup adversary initially failed because its test helper
  hard-coded the legacy profile ID into AES-GCM AAD. Reading the authenticated
  manifest's profile ID instead restored the intended swapped-secret and
  noncanonical-plaintext rejection test.
- Notification restart scripts pass shell/static/mutation verification and a
  second adversarial inspection. No Compose lifecycle was run, so this is not
  yet runtime convergence evidence.
- The third adversarial RED run reproduced all intended failures: four public
  admission attacks, prompt OAuth cancellation, distinct-client metadata and
  JWKS amplification, and stale cache-miss overwrite after revalidation.
- The corresponding serialized GREEN run passed all four public-admission
  tests, all six OAuth remote-fetch tests, and all four permanent-deletion
  coordinator tests. This proves the narrow boundaries only; it is not a
  substitute for the full suite or live interop matrix.
- Focused follow-up regressions passed after this review: public mutation/CAR
  error-ordering and namespace tests (4), concurrent PLC preparation, and the
  authenticated legacy continuity-backup rejection. The PLC concurrency test
  previously failed nondeterministically with a journal-stage conflict and a
  `SQLiteConnection` deinitialization assertion; the source/test lifecycle
  fixes remove both failure modes.
- An earlier serialized full suite exited 1 with 15 failures, all in
  portable export/restore tests constructing the legacy 07-03 manifest against
  the selected 07-30 `PermissionedData0016.profileID`; that profile drift was
  then fixed as the explicit successor boundary.
- The operator-backup restore regression now writes and reopens the verified
  PLC preparation journal/intent and genesis history, then passes a fresh
  public-admission bootstrap. This closes ADV-57 without weakening admission.
- Activation admission now discards a rejected transferred database before
  returning the control-plane failure. A focused rejection/exact-retry test
  proves the next attempt receives a fresh actor; this closes ADV-60.
- The serialized macOS suite was rerun after the profile, email composition,
  restore, activation, descriptor, OAuth-cap, and expired-email-lease changes
  with one SwiftPM worker and a unique scratch path: 858 XCTest cases
  executed, 8 explicit
  opt-in/reference-cache skips, and zero failures. The 256 MiB public-export
  stress tests remain intentionally opt-in in the normal suite.
- The formerly hanging targeted command also completed with the serialized
  invocation (`SWIFTPM_MAX_CONCURRENT_OPERATIONS=1`, `--jobs 1`, unique
  scratch path): `PublicRepositoryReadHTTPTests` executed 12 tests with zero
  failures in 0.18 seconds.
- Public-read descriptor admission now has a focused regular-file replacement
  regression in addition to the symlink case. OAuth live-cap coverage now
  proves authorization-code and access/refresh token ceilings, not only
  metadata/PAR/replay ceilings.
- Explicit macOS 256 MiB gates also pass: public `getRepo` RSS, public CAR
  spool RSS (270,049,433 bytes streamed with 17,924,096 bytes peak growth),
  staged-CAR streaming, and the private CAS bounded-chunk stream. These remain
  opt-in rather than part of the default suite.
- The post-change focused adversarial selections are compile/runtime green in
  one serialized scratch tree: artifact-boundary (5), account-email outbox
  (9), account-email HTTP (11), permanent-deletion SQLite (5), password
  recovery completion (5), OAuth storage caps (4), public-read directory (13
  with one opt-in skip), public-read HTTP (12), stateful interop evidence (7),
  permissioned CAR streaming (8 with two opt-in skips), and legacy artifact
  sanitization (2). The exact formerly hanging `PublicRepositoryReadHTTPTests`
  filter remains green under the same `SWIFTPM_MAX_CONCURRENT_OPERATIONS=1`,
  `--jobs 1`, unique-scratch invocation.
- The consolidated macOS suite was rerun after those focused checks with
  `SWAN_TEST_EXECUTABLE` pointed at the same scratch-tree `swan` binary (the
  CLI child-process tests intentionally clear their environment, so omitting
  this override makes them execute a stale `.build/debug/swan` if one exists).
  That run completed with 858 XCTest cases, 8 explicit opt-in/reference-cache
  skips, and zero failures. Profile verification, both interop lab verifier
  scripts, and `git diff --check` also pass.
- The clean-cache runner was then exercised from the root checkout after
  pinning that executable internally. Its fresh scratch build/test gate passed
  with 858 XCTest cases, 8 explicit opt-in/reference-cache skips, and zero
  failures; it still prints the deliberate "LIVE CROSS-HOST SEMANTIC MATRIX
  NOT RUN" boundary.
- A bare full `swift test` without `SWAN_TEST_EXECUTABLE` reproduced the known
  stale-child-CLI failure mode (backup/restore/profile-manifest cases). With
  `SWAN_TEST_EXECUTABLE` pointed at the same scratch-tree `swan` binary, the
  full serialized suite passed with zero failures; the unpinned invocation is
  not accepted as test evidence.
- The live notification restart acceptance was rerun after the harness privacy
  check was tightened. The disposable Compose path passed a real committed
  notification through a loopback proxy across authority SIGKILL/restart and a
  lost acknowledgement, converging with two successful forwards and one
  receiver effect. The script now emits no container-log path, because the
  artifact boundary deliberately forbids value-bearing diagnostic logs.
- The account-email recovery worker was exercised against the live Compose
  Mailpit service after a durable outbox/token seed and Swan restart. Mailpit
  received exactly one reset message, and the message body contained only the
  one-time proof token; no host-side artifact retained the token or mailbox.
- Password-recovery enumeration hardening is now covered by focused SQLite and
  HTTP tests: unknown requests leave only a 32-byte keyed marker with no DID or
  email columns, known requests still enqueue exactly one delivery, and a
  simulated delivery failure returns the same empty no-store success. The
  HTTP adapter applies the configured 50 ms minimum response duration after
  successful syntax/auth/rate-limit admission.
- A disposable Caddy echo upstream proved the login identity bridge's exact
  overwrite semantics: a forged inbound `X-Swan-Client-IP` is replaced by the
  Caddy peer-derived value. The earlier delete-plus-set rule silently removed
  the header from the upstream request.
- Reusing the existing Compose data volume with the current owner-only secret
  directory exposed a DID mismatch between durable accounts and bootstrap
  identities. After the bootstrap check was rebuilt into the dependency image,
  the stack failed closed with `interop account DID does not match the
  owner-only bootstrap identity` before starting Swan.
- The bootstrap lookup regression exercises both an absent-account success path
  and an unavailable-control-database failure path. Only the former reaches PLC
  preparation; the latter leaves no identity journal or temporary output.
- A fresh live run with the corrected proxy completed OAuth and space
  provisioning, then stopped at the intended unpinned remote delegation-key
  boundary: `getDelegationToken` returned 200 and
  `getSpaceCredential` returned 401. This is not recorded as cross-host
  convergence evidence.
- A fresh Compose adversarial run initially exposed a P1 OAuth harness defect:
  the nested localhost `client_id` query was not percent-encoded when the
  authorization URL was assembled, producing a misleading missing-CSRF error.
  The harness now encodes every query component from UTF-8 bytes, and its
  focused URL regression passes. The rebuilt rerun reaches OAuth and space
  provisioning; its remaining 401 is the separately tracked delegation-key
  pin gate above.
- The clean-cache macOS workload was rerun after the final harness and
  diagnostic-hook cleanup. Profile verification, effective/static/mutation
  interop checks, a fresh SwiftPM build, and the full test suite completed with
  zero failures (the expected opt-in CAR stress skip remains explicit). The
  output still honestly marks the live cross-host semantic matrix as not run.
- Historical note: the first post-rereview serialized compiler pass stopped
  before the intended PLC RED assertions because the remote-replica import
  status switch omitted the newly added `preparing` case. That source issue was
  subsequently remediated; the green serialized suite above supersedes this
  intermediate failure.

These are focused regression receipts plus the green serialized macOS suite.
The remaining closure work is live Compose/interoperability, Linux, and the
explicitly open security/availability items above.

## Remaining closure plan

1. Exercise the restored PLC journal/intent path and failed activation retry
   through the management HTTP path on macOS and Linux (ADV-57/60).
2. Replace any remaining live permissioned CAR materialization with bounded
   streaming verification and prove corruption, oversize, cleanup, and opt-in
   256 MiB RSS behavior.
3. Make the reference overlay recovery export snapshot-stable and
   bounded-memory; regenerate the checked-in patch digest.
4. Exercise the composed Mailpit runtime through Caddy, including SIGKILL,
   restart, durable outbox recovery, enumeration resistance, per-account/IP
   rate limits, and OAuth token-family revocation after password reset.
5. Replace request-time whole-repository JSON validation with bounded
   proofs/trusted projections where the current lazy pages still materialize
   more than the response budget (ADV-26).
6. Finish the full-CAR installer caller binding to authorized origin/DID/key/
   freshness and run the remote-replica cross-host path (ADV-21).
7. Tighten the remaining known/unknown password-reset work-shape gap under
   contention and decide whether to promote the current blind-marker/floor
   mitigation to a fully equivalent asynchronous design (ADV-50).
8. Run the complete serialized Swift suite and both lab verifier suites.
9. Run the real cross-host value-bearing, reverse-authority, compaction-gap,
   corruption, lifecycle/OAuth, and recovery matrix under Toxiproxy faults.
10. Run clean-cache acceptance on an actual Linux host. Docker-Linux on macOS
    is useful build evidence but is not Linux-host evidence.
11. Generate a disposable operator pin for the TypeScript member's `#atproto`
    key, exercise `getSpaceCredential`/member read/list-ops/full-CAR, and then
    remove the pin and confirm the same request fails closed.
12. Exercise bootstrap identity rotation/replacement across fresh and reused
    data volumes, proving that the secret directory, PLC document, account row,
    and space authority cannot drift independently.
13. Exercise bootstrap lookup failures (unavailable/corrupt control database)
    and prove they fail before PLC preparation or identity-file mutation
    (ADV-65).
14. Record sanitized artifacts and only then reassess alpha readiness.

## Non-findings and retained boundaries

- Public/private blob references remain separate and public retrieval is
  DID-bound.
- Incremental replica installation remains atomic: candidate state is
  validated before actor state changes.
- OAuth metadata fetching already has meaningful HTTPS, address, redirect,
  size, and replay controls.
- The exact pinned TypeScript cache remains immutable; the recovery work is a
  checksummed disposable overlay, not an upstream replacement.
- Permissioned data remains access-controlled rather than end-to-end
  encrypted; this review does not change that declared trust model.

## Adversarial remediation addendum: 2026-07-31

The Luna-era follow-up was rechecked against the current working copy rather
than relying on the historical green-suite receipts above.

- **ADV-50 recovery-marker admission:** the account-free password-recovery
  marker table now has a non-configurable per-control-database ceiling of
  4,096 rows. Migration trims legacy overflow; enqueue rejects a new digest
  once the ceiling is full; request-time and background expiry cleanup are
  both batch-limited to 256 rows. The regression fills the ceiling with
  non-expired markers, proves a new digest fails closed, proves an existing
  digest can still refresh without increasing the count, and proves a full
  expired table cannot be mass-deleted by one request. Control timestamps are
  seeded in the database's microsecond unit.
- **ADV-55 email deletion/send race:** crossing the durable SMTP fence now
  extends a short claim lease through the bounded five-minute network-attempt
  contract. Deletion and reclaim remain blocked throughout that window, and a
  stale worker can acknowledge only its original delivery. The focused
  SQLite selection passed the short-lease, deletion-before-fence,
  deletion-after-fence, expired-lease, and restart/retry cases.
- **ADV-63/65 bootstrap identity binding:** an owner-supplied expected DID is
  validated against the staged identity and any existing preparation intent
  before intent reservation, account-store activation, or PLC submission. The
  CLI and local bootstrap script pass this value, and a valid-but-wrong DID
  regression proves PLC submission count remains zero. The fail-closed lookup
  shell checks and interop static/effective checks pass.
- **Public-read hang recheck:** with
  `SWIFTPM_MAX_CONCURRENT_OPERATIONS=1`, a unique scratch path, and
  `--jobs 1`, the formerly hanging `PublicRepositoryReadHTTPTests` filter
  completed 12/12 in 0.190 seconds after its clean dependency build. The
  opt-in `SWAN_RUN_256MIB_PUBLIC_GET_REPO=1` production-directory RSS test
  also passed in 5.830 seconds. This identifies the earlier symptom as
  SwiftPM/Xcode-beta dependency/build contention, not an HTTP route deadlock.

These remediations close the reviewed local boundaries, but they do not close
the alpha. The following remain explicitly unproven and must not be described
as complete: value-bearing TypeScript incremental sync and compaction-gap
full-CAR recovery, corrupted-operation/CAR rejection with durable last-good
state across hosts, a reproducible remote delegation-key provisioning path,
the cross-implementation OAuth/browser and lifecycle matrix, and clean-cache
Linux acceptance. The pinned TypeScript cache and its known unsupported
value-bearing behavior remain unchanged.

## Live adversarial addendum: 2026-07-31

The disposable reference account and PLC document were exercised against the
running Compose network rather than fixture-only credentials. An operator-only
pin for the member DID's real PLC `#atproto` key was supplied outside the
repository. With that pin in place, the cross-host credential path is now
proven: the TypeScript member returned `getDelegationToken` 200, Swan returned
`getSpaceCredential` 200, the member `createRecord` returned 200, and the
credential-authenticated member `getRecord` returned 200 with a matching CID.
This closes the credential-resolution portion of ADV-64, but not the
stateful alpha gate.

The corrected stateful run remains failed for two reference-host reasons. The
default pinned TypeScript image returned HTTP 500 for value-bearing
`com.atproto.space.listRepoOps`; its enabled log records SQLite's
`ambiguous column name: space` from the joined value query. The same endpoint
returned 200 for `excludeValues=true` after the verifier was given the actual
actor repository key. The default image returned HTTP 501
`MethodNotImplemented` for `com.atproto.space.getRepo`. The checked-in
reference overlay contains a qualification patch for those recovery surfaces,
but `Dockerfile.reference-pds` and the default Compose service do not apply
that patch. Therefore a clean Compose run cannot claim value-bearing
incremental-sync or full-CAR recovery until the overlay is explicitly built
and exercised as a separate pinned lab image.

The review also caught a harness-key provenance error: the first disposable
`ts-repo-author-key.txt` did not match the actor key at
`/pds/actors/d6/did:plc:czvbc6dpzwve7eh4niqmj2dg/key`, producing a misleading
`ContextSignatureMismatch` on the metadata-only run. Re-deriving the public
key from that actor-specific key file made metadata-only sync pass. Future
fixtures must derive the repository verification key from the actor store and
record only the public-key provenance, never from the PDS-global secret.

Finally, replaying the fixed disposable record key against the reference PDS
returns HTTP 500 (`Record already exists`) rather than a typed conflict. Live
scenarios must use a fresh rkey or delete the disposable record before retry;
otherwise a failed-looking replay can be mistaken for a Swan write or
transport failure. This is an upstream reference behavior, not a Swan
authorization result.

Removing the operator pin was also exercised against a fresh no-pin Swan
container: the same real TypeScript delegation request still returned 200, but
Swan rejected the credential exchange with HTTP 401 before any write or read.
The resolver therefore fails closed as intended; the remaining ADV-64 work is
the reference overlay/full-CAR and fault-matrix proof, not broadening remote
key discovery.

## Live recovery and clean-cache addendum: 2026-07-31

The explicit checksummed reference-recovery overlay was rebuilt and exercised
against the disposable existing reference-PDS data volume. The first full-CAR
attempt exposed a real wire-compatibility defect in Swan: the TypeScript
`com.atproto.space.defs#signedCommit` block carries its `$type` field, while
Swan's encoder had omitted it. Swan consequently rejected an otherwise valid
reference CAR as `CARMalformedFrame`. `SpaceCommitCodec` now emits and requires
that lexicon type, and the verifier keeps the concrete CAR error code in the
sanitized interop result.

After the correction, the live stateful path passed with a fresh record key:
the TypeScript member delegated to the Swan authority, Swan issued the space
credential, the member write and credential-authenticated read returned 200
with the same CID, value-bearing `listRepoOps` returned 200 with commit
verification, and `getRepo` returned a two-root CAR whose record count,
commitment, and TID revision matched the incremental page. No token, private
key, CAR, record value, or recoverable personal data was retained in the
repository; the diagnostic artifacts were removed after classification.

The notification crash/restart acceptance also passed on the composed lab:
two forwards produced one receiver effect, demonstrating durable outbox
recovery and idempotent delivery after the forced stop. The run started only
after reclaiming disposable Docker build/container space; the earlier
`SQLITE_IOERR_SHMSIZE`/`SQLITE_FULL` result was a 100%-full Docker VM, not a
protocol failure. Data volumes were preserved.

The clean-cache macOS gate then completed from a new scratch directory with
profile verification, static/mutation lab checks, a fresh SwiftPM resolution,
and the full test graph green. The explicit 256 MiB private-CAR stress test
remains opt-in and was not part of that default run. This is stronger local
evidence, but it is not Linux-host evidence and does not close the remaining
reverse-authority, compaction-gap/fault, cross-implementation OAuth/lifecycle,
or clean-cache Linux gates. The default pinned TypeScript image still does not
implement `getRepo`; full-CAR/stateful recovery therefore requires the
checked-in overlay and must remain labeled as such.

As an additional portability check, `Scripts/run-clean-cache-acceptance.sh
--mode linux` completed from a copied source tree: its isolated Linux
containers built from the pinned archive, the full Swift test graph passed,
and Compose reached the expected healthy/exited service topology. The host
kernel was macOS, so this is Docker-Linux build/health evidence only; a native
Linux-host run remains required before the platform gate can be called green.

## Adversarial rereview: 2026-07-31

The Luna-era changes were rechecked from a fresh serialized SwiftPM scratch
build and against the current pinned reference cache. No new reportable
authorization, public/private isolation, CAR-integrity, credential, or
recovery defect was reproduced.

Evidence from this rereview:

- `PublicRepositoryReadHTTPTests` passed 12/12 after dependency resolution with
  `SWIFTPM_MAX_CONCURRENT_OPERATIONS=1`, `--jobs 1`, and a unique scratch path.
  The larger focused boundary selection passed 68/68, covering permissioned
  reads, repository sync/recovery, credential exchange, lifecycle, public blob
  binding, login admission, and selected remote OAuth-fetch cases.
- The fresh-process public CAR spool gate streamed 270,049,433 bytes with a
  18,726,912-byte peak RSS increase. The permissioned near-256 MiB CAR gate
  streamed 267,396,722 bytes in 64 KiB chunks with a 21,299,200-byte peak
  increase, verified integrity, and rejected an over-limit record without
  creating a spool.
- `verify-profile.sh`, `verify-interop-lab.sh`, its mutation suite, and the
  checked-in reference overlay qualification all passed without mutating the
  pinned cache. The complete Swift test graph also passed when the CLI child
  process was explicitly pinned to the same scratch-built `swan` executable.

One reproducibility trap was confirmed and closed as a harness issue, not a
source regression: invoking `swift test` directly with a scratch path but
without `SWAN_TEST_EXECUTABLE` makes CLI subprocess tests select a stale
`.build-task21`/`.build` binary. That produced false failures in backup,
restore, and export success tests. Re-running those tests with the scratch
binary passed, and `Scripts/run-clean-cache-acceptance.sh` already exports the
override after building the product.

Two suspected scope/timing concerns were also classified rather than silently
promoted to findings. `getSpace` intentionally requires an authority
`atproto` token; qualified space scopes are enforced on record/repository
operations, matching Swan's documented pinned-TypeScript exception. Recovery
marker cleanup is now bounded both by the 4,096-row invariant and the
256-row-per-request purge batch; strict constant-work behavior under arbitrary
SQLite contention remains an ADV-50 follow-up. The request-time JSON/index
materialization concern remains ADV-26 follow-up work even though response-size
and process-admission gates are green.

The review is not an alpha-completion sign-off. The remaining closure gates are
the native-Linux host run, reverse-authority and cross-implementation
OAuth/browser/lifecycle coverage, the value-bearing TypeScript incremental and
compaction-gap matrix using the explicit recovery overlay, corrupted
cross-host operation/CAR recovery, and an operator-supplied disposable
TypeScript delegation-key pin. The dedicated Codex Security launcher was also
unavailable in this environment because its bundled Python helper failed to
start; this document is therefore a bounded manual adversarial review, not an
official security-scan report.

## Live cross-host adversarial evidence: 2026-07-31

The disposable Compose network was then exercised with a real reference-PDS
account, not a checked-in fixture. The stock pinned TypeScript image served as
the member host and Swan served as the authority. Swan rejected the first
exchange with HTTP 401 when no remote delegation key was configured. Supplying
the reference account's public PLC `#atproto` key through the existing
owner-controlled notification pin made the same path pass: delegation minting,
credential exchange, member write, and credential-authenticated member-host
read all returned HTTP 200 with matching record CIDs. No private key, token, or
record value entered the repository.

The checksummed reference-recovery overlay was built separately from the
immutable cache and used only for qualified recovery evidence. Its stateful
cross-host run passed every assertion: value-bearing `listRepoOps`, operation
CID/revision, signed LtHash commitment, two-root `getRepo` CAR, expected-record
membership, CAR commitment/revision equality, and final convergence. This is
not evidence that the unmodified pinned TypeScript image supports those two
recovery endpoints; the stock image still returns the documented 500/501
responses. The remote delegation key was operator-pinned for this disposable
run, so dynamic PLC/DID key discovery and reverse-authority placement remain
open alpha gates.

The email-recovery review candidates were reconciled against the current tree:
the account-free marker table has a 4,096-row admission ceiling, migration
trimming, and a 256-row expiry purge batch, so the earlier unbounded-cardinality
candidate does not reproduce at the reviewed head. A separate pre-existing
SMTP lease-boundary concern remains a follow-up: a network attempt that outlives
the five-minute fence needs explicit cancellation/heartbeat semantics before
production claims. It is outside the current interop alpha acceptance gates.

Reverse authority placement was also exercised with the same disposable
network. The reference PDS acted as authority, Swan hosted the member
repository, and the reference authority's public credential key was pinned at
the Swan member. The stateful run passed credential issuance, member write,
member-host read, value-bearing incremental sync, signed commitment checks, and
two-root CAR recovery, with sync/CAR commitment and revision equality. This is
controlled pinned-key evidence; it does not turn the checked-in configuration
into an automatic remote-key discovery policy.

## Follow-up implementation review: 2026-07-31

The remaining delegation-key gap was addressed as an explicit configuration
boundary rather than by allowing request-time DID/PLC discovery. Notification
configuration now accepts an optional `delegationKeyPLC` object with a
duplicate-free allowlist of canonical `did:plc:` issuers. Its resolver reuses
the bounded PLC state/audit verifier, durable terminal-CID continuity store,
negative cache, and process-wide lookup admission already used for credential
keys. Local account keys and operator pins are checked first; the remote
resolver is consulted only when both decline, and the request supplies no
origin, issuer allowlist, or transport choice. Malformed shapes, duplicate or
non-DID issuers, production host allowlists, and invalid origins fail at
startup.

The focused composition test proves remote delegation fallback and local-key
precedence; notification-shape tests cover nested unknown fields. The same
review also removed a request-derived `try!` and result-CID force unwrap from
public `repo.applyWrites`, mapping invariant violations to a bounded
`temporarily_unavailable` response instead of a process crash.

After those changes, the serialized cached macOS graph completed 864 tests
with 8 explicit skips and zero failures. The focused public read and mutation
targets completed 12/12 and 3/3 respectively; profile, lab, mutation, and
reference-overlay qualification scripts also passed. This is host-local
evidence only and does not substitute for the outstanding Linux and live
dynamic-PLC gates below.

This does not close the alpha sign-off. The stock pinned TypeScript image still
lacks the value-bearing recovery surfaces, and the native-Linux host,
reverse-authority OAuth/browser/lifecycle matrix, corrupted/compaction-gap
recovery, and live dynamic-PLC cross-host run remain required evidence.

## Managed delegation lifecycle rereview: 2026-07-31

The delegation resolver added for the dynamic PLC path was reviewed as a
separate trust-boundary surface. Its local implementation returned `nil` when a
known account was inactive or when its generation/key projection could not be
read. `CompositeSpaceDelegationPublicKeyResolver` intentionally treats `nil`
as "unmanaged issuer" and therefore proceeded to an operator pin or the
startup-configured remote PLC resolver. A DID that Swan still managed locally
could consequently present a valid delegation signed by a pinned or PLC
published key after local deactivation/deletion.

The local resolver now mirrors the credential resolver's terminal-negative
contract: it looks up the account first, permits fallback only for a proven
local absence, checks active lifecycle and matching signing/rotation
generations, reads the authenticated public projection, validates the key, and
re-reads the complete account before returning it. All other failures map to a
non-descriptive `SpaceDelegationPublicKeyResolutionError.unavailable`, so
composition cannot reach another authority for a managed DID.

Regression coverage includes deactivated and deleted issuers, unsupported
key IDs, missing and corrupt public keys, a lifecycle change during the key
read, startup pin preflight, and the preserved unknown-issuer remote fallback.
The serialized focused run completed 23 tests with zero failures. This closes
the lifecycle portion of the dynamic delegation resolver review, but does not
close the outstanding dynamic-PLC live run or the other alpha gates listed
above.

The same pass found a separate availability defect in PLC admission. Expired
positive cache entries were never removed from the issuer-capacity set, so a
bounded stream of distinct issuers could make the resolver reject every new
issuer until restart. The resolver now prunes expired value entries before
capacity accounting; durable PLC terminal-CID continuity remains in the
control store and is not evicted with the value cache. The new expiry/capacity
test and the complete PLC resolver selection passed 13/13.

The post-remediation serialized full SwiftPM run was repeated with the
scratch-built `swan` executable explicitly pinned. Every XCTest bundle and the
Swift Testing wire bundle passed with zero failures; eight opt-in stress/cache
tests remained intentionally skipped (including the 256 MiB gates and the
uncached reference-lab check). `verify-profile.sh`, `verify-interop-lab.sh`,
the verifier mutation suite, and reference-overlay qualification also passed.

## Notification-cardinality follow-up: 2026-07-31

The notification registry was independently reviewed as a lower-privilege
availability boundary. Registration requires a space read credential and
endpoint syntax is validated; nevertheless, the schema had no per-space row
limit and deletion materialized all active recipients into one transaction.
The implementation now deletes expired rows for the target space, counts
active rows in the same transaction, rejects a new endpoint at 1,024 rows with
`SwanError.unavailable`, and still permits an existing endpoint to be
replaced. A storage regression fills the budget through the public API,
proves replacement and rejection, then proves expiry returns capacity.

The first post-change focused build did not reach test execution: the fresh
scratch path exhausted the host data volume during XCTest bundle code signing.
The explicitly created scratch directory was removed, and a stale one-hour
`swan-recovery-marker` test process from the earlier hung run was terminated.
A rerun using the existing serialized scratch tree then built successfully;
the capacity regression passed in 0.51 seconds and the complete notification
SQLite class passed 5/5 with zero failures. The disk-space failure remains a
reproducibility warning for clean scratch runs, not a code/test failure.
