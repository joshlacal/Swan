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

The latest rereview additionally added a caller-bound HTTP provider for durable
permissioned full-CAR recovery, shared spool admission for public blob upload,
remote public CAR import, and optional blob promotion, plus an IPv6 loopback
origin regression. A fresh clean-cache macOS build and full serialized test
graph passed after those changes; the first clean-cache attempt failed only
because the host data volume was full, then passed after explicitly removing
the generated scratch caches.

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
| ADV-18 | P1 | Active public databases were published at bootstrap and live activation before full projection verification. Public JSON reads then repeated whole-repository verification inside `BEGIN IMMEDIATE`, allowing unauthenticated reads to reserve the SQLite writer. | The admission and writer-reservation cases are remediated and green. Public requests use the admitted generation; the remaining index-projection risk is covered by ADV-26's bounded preflight and explicit ceilings. |
| ADV-19 | P1 | Concurrent exact-URL OAuth metadata cache misses each performed their own DNS/GET, and canceling one waiter canceled its transport rather than only that waiter. The production transport also creates a new event-loop thread for each GET. | Coalescing, prompt waiter-only cancellation, and the shared eight-flight metadata/JWKS admission are green. Shared transport lifecycle remains open. |
| ADV-20 | P1 | `AccountOperatorService.delete` still calls the generic `.deleted` transition, which the lifecycle policy explicitly rejects so deletion cannot reach the resumable coordinator. | Remediated and green in the serialized macOS suite: the operator boundary delegates only to the permanent-deletion capability; the CLI/runtime injects concrete PLC/data adapters, resumes pending work before listeners, and fails closed if recovery is required but unavailable. |
| ADV-21 | P1 | Full-CAR recovery evidence is verified but discarded; no durable atomic installer retains verified record bodies, rejects rollback/equivocation against last-good state, and replaces a remote replica. | Storage installer is remediated and green in the serialized macOS suite with descriptor-backed staging, authenticated freshness witnesses, atomic generation publication, rollback/equivocation rejection, and crash cleanup. A caller-bound HTTP provider and `LiveInterop` recovery helper now bind the authorized origin/DID/key/freshness to this installer; the live cross-host command/Compose matrix still must exercise that API end to end. |
| ADV-22 | P1 | Checked-in Compose loaded notification configuration but did not enable outbound delivery or the startup recovery service. Duplicate/reorder scenarios exercised endpoint probes, not durable convergence. | Static remediation and adversarial rereview are complete: delivery is enabled, the proxy is ready before recovery, and the claim is correctly scoped to two successful forwards/one receiver effect. The live SIGKILL/lost-ack Compose run is still required. |
| ADV-23 | P1 | Portable export/restore accepted a permissioned blob whose space had no matching space CAR. With no restored closure or repository-existence check, the published account could stream that orphan through `getBlob`. | Remediated and green: restore requires matching repository state before persistence, request reads check state/closure/tombstones/exact reference in one snapshot, and the legitimate closed operator-restore path remains supported. |
| ADV-24 | P1 | Password login has no durable per-account/source failure admission, and PAR/replay persistence has no live-row cardinality cap. Argon work and unbounded expiry deletes can monopolize the process-local queue and serialized control database. | Login admission and the OAuth storage ceilings are remediated in source: metadata/PAR/replay plus authorization-code, token-family, access-token, and refresh-token rows now use transactional hard caps. Focused cap tests are green; the serialized suite remains the execution gate. |
| ADV-25 | P2 | Unknown/inactive login identities return before Argon verification, while an active account with a wrong password performs expensive work. Uniform HTTP status/body therefore still exposes a remote timing oracle. | Remediated and focused login tests are green: unknown, inactive, stale-PHC, and wrong-password cases use the same admitted configured-cost verification path. |
| ADV-26 | P1 | Public-read admission and the optional blob promoter can materialize large MST/index projections, and the anonymous JSON handlers can encode a large collection list. | Remediated in source and focused tests: startup admission now performs a bounded keyset preflight (100,000 index rows, 100,000 collections, 8 MiB collection names), while the blob promoter rejects oversized indexes and scans records in 256-row pages with a 100,000-unique-CID ceiling. Anonymous JSON routes retain their aggregate body budgets and process-wide admission. Native-Linux/RSS evidence for hostile large indexes remains an open platform gate. |
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
| ADV-64 | P1 | The checked-in notification configuration has no pinned TypeScript user delegation key. The real cross-host run can obtain a delegation token from the pinned PDS, but Swan rejects `getSpaceCredential` with HTTP 401 when neither a pin nor an explicit remote resolver is configured. | Remediated and live-tested without a static pin. The optional startup-bound `delegationKeyPLC` uses an issuer allowlist, bounded/audited PLC state, continuity, and SSRF-safe transport. A fresh pinned-TypeScript member wrote permissioned data, Swan dynamically resolved its PLC `#atproto` key and issued the credential, and the reference host returned the same CID to that credential. The checked-in lab remains closed by default; stock value-bearing incremental/full-recovery TypeScript behavior is tracked separately. |
| ADV-65 | P1 | Bootstrap treated any nonzero `account show` result as "not found". A locked/unavailable/corrupt control database could therefore fall through to PLC preparation and write an identity journal during an infrastructure failure. | Remediated in `bootstrap-local-space.sh`: only the exact sanitized `account not found` diagnostic permits preparation; all other lookup failures fail closed before mutation. The static lab verifier requires both branches. |
| ADV-66 | P1 | The local `#atproto` delegation-key resolver returned `nil` for a managed account whenever it was deactivated/deleted, had an unsupported or missing generation, or had unavailable key material. The composite resolver interprets `nil` as an unknown issuer and could then accept a configured operator pin or remote PLC key for that same DID, bypassing the account lifecycle gate. | Remediated in `LocalAccountSpaceDelegationPublicKeyResolver`: only proven local absence returns `nil`; every managed lifecycle, generation, key-store, corruption, and read-race failure throws an opaque terminal error. Added deactivation/deletion, unsupported/missing/corrupt-key, lifecycle-race, startup-pin, and unknown-issuer regression coverage; the focused OAuth/composition selection passed 23/23. |
| ADV-67 | P2 | The bounded PLC resolver retained expired positive cache entries in its issuer-capacity set. After a bounded burst filled `maximumEntries`, later issuers could remain rejected forever even after the value TTL elapsed, despite durable continuity state being independent of the cache. | Remediated by pruning expired positive entries during lookup admission while preserving the “previously authenticated issuer” budget exemption and the durable terminal-CID checkpoint. A one-entry cache test now proves a second issuer resolves after expiry; the PLC resolver selection passed 13/13. |
| ADV-68 | P2 | A holder of a valid read credential could register an unbounded number of distinct notification endpoints for one space. Space deletion copied every active endpoint into one transaction, so endpoint churn could grow the database and turn a later lifecycle operation into an unbounded fanout/lockout workload even though outbound delivery was SSRF-safe. | Remediated with a transactional per-space cap of 1,024 active registrations. Expired rows are pruned before admission, existing endpoints remain replaceable at capacity, and the capacity/expiry regression covers the read-credential path. The complete `SpaceNotificationSQLiteTests` class passed 5/5 in a serialized rerun. |
| ADV-69 | P3 | Inbound notification replay receipts were keyed only by issuer and event ID, so a writer JTI reused across spaces could suppress a valid hint in a second space. | Remediated with migration 7 and a space-scoped duplicate lookup; `SpaceNotificationSQLiteTests` passed 6/6, including cross-space JTI reuse. Availability-only; no authorization or data exposure was demonstrated. |
| ADV-70 | P3 | The single-record public read path selected a SQLite BLOB before checking its scalar length, leaving a corrupt/hostile index able to force one over-budget body allocation before rejection. | Remediated by preflighting `length(bytes)` and checking the selected byte count before decode; `PublicRepositoryReadDirectoryTests` passed 14/14 (one opt-in RSS test skipped). Startup projection and optional whole-index promotion paths remain separate boundedness follow-ups. |
| ADV-71 | P3 | `swan serve` force-unwrapped the default URL assembled from operator-supplied `--host`/`--port`, turning malformed configuration into a process crash. | Remediated with `ValidationError` mapping and a child CLI regression using the scratch-built executable. Operator availability only; no remote request path was involved. |
| ADV-72 | P2 | Anonymous `describeRepo` encoded a potentially large admitted collection list without reserving the process-wide JSON response lease used by `getRecord` and `listRecords`, allowing concurrent callers to multiply response allocations. | Remediated by reserving the same 16 MiB response lease and releasing it on handler, encoding, and body-drain failures. `PublicRepositoryReadHTTPTests` passed 12/12, including a regression that blocks `describeRepo` behind an active list lease. |
| ADV-73 | P2 | `abandonPublicRepositoryReservation` force-unwrapped the persisted request digest and did not enforce its 32-byte invariant, so a corrupt reservation row could crash the process or be abandoned with an invalid integrity input. | Remediated with checked blob decoding and an exact 32-byte guard; malformed rows now return `corruptRepository`. `PublicRepositoryMutationStoreTests/testAbandonReservationRejectsMalformedPersistedDigest` covers the failure. |
| ADV-74 | P1 | The new HTTP recovery provider opened a bounded CAR file and held a spool lease before durable-session creation, but the orchestrator returned early on idempotent replay or pre-staging rejection without closing that source. Repeated failed/replayed requests could therefore pin temporary files and exhaust the receiver's recovery admission budget. | Remediated: every pre-staging terminal path closes the source session; the close callback is idempotent and the regression covers expiry rejection. The provider also binds the source origin, repository DID, exact verifier fingerprint, signed current-head witness, and CAR spool to the durable import. Live cross-host recovery remains an acceptance gate. |
| ADV-75 | P2 | `swan lab import-public` and optional public-blob promotion created temporary CAR/blob files outside the shared public-repository spool admission. A lab operator could therefore bypass the same disk budget enforced by public reads and uploads. | Remediated fail-closed: both helpers require an admission lease, and the CLI uses an explicit two-spool budget for CAR import plus blob adoption. Response-file cleanup runs before lease release. Focused build and the clean-cache macOS graph pass; a large hostile remote import remains a live lab exercise. |
| ADV-76 | P2 | Canonicalizing a valid `http://[::1]` laboratory origin through `URLComponents` dropped the required IPv6 brackets and rejected the source binding. This made a supported loopback recovery path fail closed and could have encouraged an unsafe workaround. | Remediated by rebuilding the bracketed literal and adding a regression for `http://[::1]:3000/`. Non-loopback HTTP, credentials, paths, queries, and fragments remain rejected. |
| ADV-77 | P2 | `PermissionedRemoteReplicaSourceSession` allowed callers to omit cleanup, and the orchestrator invoked a caller-supplied cleanup closure from multiple terminal paths without enforcing idempotence. A custom file-backed source could leak a descriptor/spool or double-release an external lease. | Remediated in the working copy: cleanup is now mandatory at session construction and an actor-backed close gate executes it exactly once. Verification-failure and preflight-rejection regressions pass; the HTTP provider remains the owner of the file/lease callback. |
| ADV-78 | P2 | The durable replay result stores only `base_generation`, while the orchestrator's request digest historically omitted the remaining expected-base fields. A direct caller of the storage protocol could reuse a request ID/digest with a forged same-generation base and receive a committed replay instead of a conflicting-reuse error. The production orchestrator obtains the base from the receiver database, so this is a storage-boundary integrity hardening issue rather than an HTTP bypass. | Remediated in migration 8: the result projection stores a domain-separated digest of the complete expected-base binding and replay requires an exact match; legacy rows without the digest fail closed. |
| ADV-79 | P3 | Three public `sync` read routes force-unwrapped the request-derived `did` query entry. The strict parser currently guarantees the key, but a future parser change or bypass could turn malformed input into a process trap instead of `InvalidRequest`. | Remediated with explicit key guards and one typed `DID` parse per route. `PublicRepositoryReadHTTPTests` passed 12/12; no authorization or privacy bypass was reproduced. |
| ADV-97 | P1 | Deactivation followed by reactivation updates `control.sqlite` but leaves the preopened public-read generation bound to the old `AccountControlAccount` (including its `updatedAt`). Public reads therefore remain unavailable after lifecycle reactivation. | Remediated with an existing-database-only async generation refresh that revalidates PLC identity, preparation intent, path identity, and the exact active control row before publication. A permanent regression covers status, description, record, and CAR reads after reactivation. |
| ADV-98 | P2 | Portable archive verification bounded manifest/payload bytes but recursively materialized every filesystem entry into `String`/`Set` collections without a count or depth bound. An untrusted restore archive could exhaust memory or the call stack with extra empty entries before the expected-path mismatch was reported. | Remediated with a manifest file-count ceiling, exact expected-entry admission, bounded per-directory enumeration, and a 256-level recursion ceiling. The new archive-inventory regression passes. |
| ADV-99 | P1 | Public-read admission bounded the SQLite index with a keyset preflight but then retained the full validated MST and leaf projection in Swift, allowing a valid near-policy-ceiling repository to create a large startup/generation-refresh allocation. | Remediated with `validateProjection` and a connection-local SQLite TEMP projection sink; the storage-level verifier now applies the same preflight. macOS and native Linux public-directory/HTTP selections plus the native-Linux opt-in transfer/RSS gates pass; the full Linux receipt is recorded below. |

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
build and against the current pinned reference cache. Two bounded availability
defects were reproduced and remediated (ADV-72 and ADV-73); no new
authorization, public/private isolation, CAR-integrity, credential, or
recovery bypass was reproduced.

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
materialization concern remains an ADV-26 follow-up for startup projection and
the optional whole-index promoter, although all anonymous JSON endpoints now
reserve the response-size/process-admission budget and the focused HTTP gate is
green.

The review is not an alpha-completion sign-off. The remaining closure gates are
the native-Linux host run, reverse-authority and cross-implementation
OAuth/browser/lifecycle coverage, the value-bearing TypeScript incremental and
compaction-gap matrix using the explicit recovery overlay, corrupted
cross-host operation/CAR recovery, and stock-TypeScript delegation-key
provisioning or dynamic discovery without a disposable operator pin. The
dedicated Codex Security launcher was also
unavailable in this environment because its bundled Python helper failed to
start; this document is therefore a bounded manual adversarial review, not an
official security-scan report.

## Request-boundary hardening follow-up: 2026-07-31

Additional availability edges were closed during the rereview. The
permissioned notification receipt table now scopes replay uniqueness by
`(issuer, event_id, space_uri)` through migration 7; a reused writer JTI in one
space can no longer suppress a valid hint in another. `SpaceNotificationSQLiteTests`
passed 6/6, including the cross-space replay regression.

The single-record public repository read now asks SQLite for the scalar BLOB
length before selecting the record body and rejects a length/count mismatch
before canonical decoding. `PublicRepositoryReadDirectoryTests` passed 14/14
(with its one opt-in 256 MiB test intentionally skipped), including an
over-budget-body regression. This closes the request-time scalar-body gap for
that endpoint; startup projection verification and the optional
`publicRepositoryBlobCIDs()` promotion helper still have separate whole-index
materialization follow-ups.

The anonymous `describeRepo` route now participates in the same process-wide
JSON admission as `getRecord` and `listRecords`. Its lease is held through
response-body drain and is released on handler, encoding, and writer failures.
The HTTP regression holds a list lease open and confirms a concurrent
`describeRepo` receives `temporarily_unavailable`; the focused
`PublicRepositoryReadHTTPTests` selection passed 12/12.

The `swan serve` default URL construction also maps a malformed `--host` value
to `ValidationError` instead of force-unwrapping `URL(string:)`. The child CLI
regression passed with the scratch-built executable pinned. This is an
operator-availability fix, not a protocol or authorization change.

Finally, public mutation reservation abandonment now validates the persisted
32-byte request digest before computing the terminal integrity digest. A
deliberately malformed SQLite row returns `corruptRepository` rather than
trapping the process; the full `PublicRepositoryMutationStoreTests` class
passed 12/12.

The remaining ADV-26 index materialization seam was then closed with an
explicit availability policy. Startup public-read admission performs a scalar
SQLite preflight before the retained-block validator or collection projection:
the alpha refuses more than 100,000 index rows, more than 100,000 distinct
collections, or more than 8 MiB of collection-name bytes. The optional
`publicRepositoryBlobCIDs()` promoter first applies the same 100,000-row
ceiling, then walks the index in 256-row `(collection, rkey)` pages and caps
the unique raw-CID result at 100,000 entries. An oversized synthetic index is
rejected before record decoding by
`testPublicReadAdmissionAndBlobPromotionRejectOversizedIndexBeforeWalk`;
`PublicRepositoryReadDirectoryTests` passed 15/15 with its one opt-in 256 MiB
RSS test intentionally skipped, and that RSS test passed 1/1 when explicitly
enabled with `SWAN_RUN_256MIB_PUBLIC_GET_REPO=1`. This closes the unbounded-
index policy gap in the macOS source/test path; native-Linux execution and a
hostile large-index RSS measurement remain platform acceptance evidence, not
silently claimed here.

The post-remediation serialized SwiftPM graph was also rerun with the
scratch-built `swan` executable explicitly pinned (`--jobs 1`, one scratch
path, no SDK/toolchain overrides inherited). XCTest and Swift Testing both
completed with exit code 0; the focused public-read selections above remain
the more specific evidence for the new index policy. This is macOS evidence
only and does not close the native-Linux or cross-host semantic gates.

The same route pass removed the last request-derived dictionary force
unwraps from the public `describeRepo`, `getRecord`, and `listRecords` JSON
constructors. Missing required values now take the bounded `InvalidRequest`
response path before a generated handler is called; the existing malformed
parameter suite remains green.

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
recovery, and live dynamic-PLC cross-host run remain required evidence. The
configured-Swan dynamic resolver capability is recorded separately below.

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
the lifecycle portion of the dynamic delegation resolver review; the live
configured-Swan exercise is recorded below, while the cross-implementation
dynamic-PLC and other alpha gates remain open.

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

## Live dynamic delegation rereview: 2026-07-31

The optional PLC-backed delegation resolver was exercised against the running
Compose network without a static delegation-key pin. A disposable Swan
container used a startup-only `delegationKeyPLC` allowlist for the current
member DID and the lab PLC origin. The member `#atproto` key was fetched and
authenticated through the PLC state/audit and continuity path; OAuth/DPoP,
credential exchange, permissioned write/read, value-bearing `listRepoOps`,
and two-root `getRepo` verification then passed with matching CID, revision,
and commitment. The artifact retained only sanitized status, digest, CID,
and endpoint summaries, and the normal checked-in Compose container was
restored afterward.

This is live dynamic-resolver evidence for a configured Swan peer, not a
claim of automatic discovery for arbitrary issuers or of TypeScript OAuth
convergence. Dynamic discovery against a TypeScript member, reverse-authority
browser/lifecycle coverage, corrupted-operation and compaction-gap recovery,
and native-Linux execution remain open. No new reportable authorization,
public/private-isolation, credential, CAR-integrity, or resolver-lifecycle
bypass was reproduced in this rereview; the bounded availability findings are
tracked as ADV-72 and ADV-73 above.

## Notification crash/restart acceptance rereview: 2026-07-31

The live disposable notification scenario passed with the pinned Compose
image: a delivery-disabled seed committed one permissioned write, survived a
forced process stop with one opaque pending outbox row, and a recovery process
forwarded the event twice after the proxy discarded the first acknowledgement.
The authority retained one receipt and one writer effect, while the sender
outbox converged to empty. The result contained only transport counts and
digests.

The run also exposed and corrected a harness-only reproducibility trap. A
fresh project name cannot use `up --no-build` unless its project-scoped image
tags already exist. The acceptance script now detects that condition and
falls back to the normal pinned build, preserving the fast path when cached
tags are present. This was not a Swan protocol or authorization failure.

## Notification receipt scope hardening: 2026-07-31

The rereview found that inbound writer receipts were keyed only by
`(issuer,event_id)`, even though the service JTI is consumed in a specific
space. A writer reusing a valid JTI across two spaces could therefore suppress
the second writer hint. This was an availability-only defense-in-depth issue:
it did not grant access or expose records, and normal Swan senders use fresh
UUID-backed JTIs.

The account migration now rebuilds the receipt table with
`(issuer,event_id,space_uri)` uniqueness, scopes the duplicate lookup to the
space, and preserves existing receipts transactionally. A regression creates
two spaces under one authority and proves the same writer JTI advances both
writer sets. `SpaceNotificationSQLiteTests` passed 6/6 after the migration.

## Caller-bound recovery and public spool rereview: 2026-07-31

The durable recovery boundary was rechecked for resource ownership, not only
cryptographic correctness. The HTTP provider now obtains and verifies a signed
current-head witness before opening `getRepo`, derives the persisted source
identity from the exact selected public key, and holds one admission lease for
the bounded CAR spool. The orchestrator closes that source on successful
publication, verification failure, idempotent replay, and every pre-staging
rejection. A focused regression verifies closure when expiry rejects the
request before SQLite staging begins.

The public replication helpers received the same disk-boundary treatment.
Remote CAR import now fails closed without a shared admission lease, and blob
promotion reserves a deliberate two-spool budget for the response file plus
SQLite adoption stream. The `swan lab import-public` command supplies the
larger explicit budget required by that two-spool case; leases and owner-only
temporary files are cleaned up in the reverse order. IPv6 loopback origin
canonicalization is covered by a regression.

Evidence for this pass:

- `PermissionedRemoteReplicaRecoveryOrchestratorTests` passed 4/4 after the
  source-closure change.
- The public import fail-closed regression, the concurrent spool-admission
  reservation test, and the four recovery-orchestrator tests passed together
  as a 6-test focused selection; the existing mutation HTTP selection remained
  green at 5/5.
- The clean-cache macOS script passed its fresh SwiftPM build and full test
  graph with zero failures (the opt-in 256 MiB stress test remained skipped).
- `git diff --check`, profile verification, Compose invariant verification,
  verifier mutation tests, and reference-overlay qualification passed.

These changes close bounded local availability defects, but they do not close
the native-Linux, cross-implementation browser/OAuth/lifecycle, corrupted
operation/compaction-gap, or stock-TypeScript full-CAR evidence gates.

## Independent source-boundary rereview: 2026-07-31

The current working copy was reread independently of the historical Luna-era
ledger. No new P1 authorization, public/private-isolation, credential, CAR
integrity, or recovery bypass was reproduced. Two lower-priority boundaries
were separated from that conclusion:

- **ADV-77 was remediated in code.** Source sessions now require an explicit
  cleanup action, and the private close gate makes repeated orchestrator
  cleanup calls harmless and exactly-once. The focused recovery selection now
  passes 5/5, including a malformed-CAR path that reaches both the staging and
  outer error handlers while observing one close callback.
- **ADV-78 is closed.** The result migration persists and compares a
  domain-separated digest over the receiver's complete expected-base state;
  direct storage callers now receive the same fail-closed replay guarantee as
  orchestrated callers.

The current focused command completed 17 selected tests with zero failures:
five recovery-orchestrator tests and twelve public-read HTTP tests. This is
macOS evidence only. The profile successor boundary (07-30 versus the frozen
07-03 plan input), stock TypeScript recovery endpoint gap, semantic fault and
compaction-gap matrix, dynamic TypeScript key discovery, reverse OAuth/browser
lifecycle coverage, native Linux execution, and the unavailable official
security launcher remain release blockers.

## Replay, delivery, origin, and live-public follow-up: 2026-07-31

The next adversarial pass closed four remaining local boundaries:

- **ADV-78 persistence hardening is now versioned.** Migration 8 adds a
  domain-separated digest of the complete expected-base binding to durable
  remote-replica results. Replay now requires the request ID, canonical body
  digest, source/target/profile/verifier identity, expected generation, commit
  CID, revision, LtHash commitment, and witness fields to match; legacy rows
  without the binding digest fail closed. A forged same-generation replay
  regression passes.
- **Remote origins are checked before network work.** The HTTP provider now
  rejects an unsafe or malformed source origin in its initializer, before
  creating a request or opening a response file. The orchestrator test covers
  this preflight boundary.
- **Email delivery has a bounded cancellation window.** The runtime delivery
  wrapper uses a 240-second maximum attempt deadline and cancels the SMTP task
  before entering the durable deletion fence. The timeout regression proves a
  stalled delivery cannot cross that fence after cancellation.
- **Live public mutation targets retain streaming blob capability.** The
  startup generation-refreshing wrapper now delegates the narrow streaming
  blob methods instead of allowing `uploadBlob`/`getBlob` to fail with a false
  404 while direct unit fixtures pass. The live runner also accepts an explicit
  lab CA trust root for the Caddy certificate while retaining normal trust
  roots.

Focused Swift evidence after these changes:

- `AccountEmailOutboxSQLiteTests` 12/12, `PermissionedRemoteReplicaRecoverySQLiteTests`
  7/7, `PermissionedRemoteReplicaRecoveryOrchestratorTests` 5/5, and
  `AccountEmailOutboxRuntimeTests` 6/6 (30 selected tests, zero failures).
- `SwanInteropTests` 82/82 and `PublicRepositoryMutationHTTPTests` 6/6.
- The serialized scratch-executable macOS graph passed 889 XCTest cases with
  8 explicit skips and zero failures, plus the four Swift Testing profile
  cases. The command must export `SWAN_TEST_EXECUTABLE` from the same scratch
  tree; invoking CLI tests with a stale normal `.build/debug/swan` produces a
  deterministic profile-mismatch `invalidManifest`, not a source failure.
- `verify-profile.sh`, `verify-interop-lab.sh`, reference-overlay qualification,
  and `git diff --check` passed.

A fresh isolated Compose Swan-to-Swan run now proves the public path over
trusted local TLS: OAuth/DPoP, public blob upload (200), `putRecord` (200),
 `getRecord` (200), `getBlob` (200), CID equality, and blob-byte verification
 all pass. The checked-in `public-live-blob-placeholder.json` fixture passed;
 the sanitized artifact contains no request body, token, password, or record
 value. The earlier live 400 was a harness selector error caused by reading the
 bootstrap marker `generate` from an owner-only `authority.did` file; the
 runner correctly rejected that non-DID selector. The actual PLC DID run is
 green.

The same fresh Compose project previously passed the strict Swan-to-Swan
 permissioned stateful matrix: credential issuance, member write/read,
 value-bearing incremental sync, signed commitment verification, two-root
 full-CAR recovery, expected-record verification, and convergence. This is
 configured-Swan evidence only. The pinned TypeScript branch still lacks the
 required `getRepo` implementation and has the known value-bearing
 `listRepoOps` SQLite ambiguity, so cross-implementation recovery and the
 fault/compaction matrix remain open.

## Current release boundary after this pass

Swan is ready for repeatable local public and permissioned data testing on the
macOS/Docker laboratory path, including public blob-linked records and the
 configured Swan-to-Swan permissioned recovery path. It is not yet an alpha
 completion claim. Native Linux execution, unmodified pinned TypeScript
 semantic/recovery interoperability, reverse-authority OAuth/browser and
 lifecycle coverage, corrupted-operation and compaction-gap traffic, and the
 official security launcher remain release gates. The active immutable profile
is `permissioned-data-0016-2026-07-30`; the frozen 07-03 plan input remains a
documented predecessor rather than an interchangeable profile.

## Reference PLC restart-boundary hardening: 2026-07-31

The checked-in PLC service previously selected the pinned server's in-memory
`Database.mock()` whenever `DATABASE_URL` was absent. Recreating a Compose
project could therefore erase every PLC DID while Swan's account databases
survived. The lab now keeps the same pinned PLC HTTP implementation and
validator behind a narrow file-backed adapter. Accepted operation bodies are
serialized with an owner-only temporary file, `fsync`, and atomic rename into
the named `reference-plc-data` volume; startup replays them through the pinned
validator and rejects malformed or tampered state before binding the listener.

`interop/test-reference-plc-persistence.sh` now proves write, restart/read,
and tampered-state fail-closed behavior. `verify-interop-lab.sh` requires the
volume, wrapper command, and executable acceptance script. This closes the
Compose PLC restart/reprovisioning availability gap; native Linux and the
cross-implementation semantic/fault gates remain separate release evidence.

## Fresh recovery-qualified stateful run: 2026-07-31

After rebuilding the recovery-qualified Compose project from the working
copy, the Swan-to-Swan permissioned stateful matrix passed with the persistent
PLC wrapper active. The sanitized artifact is retained outside the repository
at `/private/tmp/permissioned-recovery-20260731c.json`. It records credential
issuance, member write and authority read at HTTP 200, matching write/read
record CIDs, a value-bearing terminal `listRepoOps` page, a verified signed
commitment, and a verified two-root full CAR containing the expected record.
All 26 stateful assertions passed; the artifact contains no credentials,
passwords, DPoP proofs, request bodies, or record values. This is fresh
Swan-to-Swan recovery evidence, not proof that the unmodified pinned
TypeScript PDS implements `getRepo` or value-bearing `listRepoOps`.

The PLC service was then rebuilt with the final adapter, recreated against
the same named volume, and health-checked before a second permissioned write.
That post-restart stateful run also passed all 26 assertions; its sanitized
artifact is `/private/tmp/permissioned-after-plc-restart-20260731c.json`.

## Request-boundary rereview: 2026-07-31

An independent pass over the public repository read routes found three
request-derived dictionary force unwraps in `sync.getLatestCommit`,
`sync.getRepoStatus`, and `sync.getRepo`. The strict query parser currently
guarantees the `did` key, so this was not a reproducible authorization or
privacy bypass; it was a fail-closed robustness defect if that parser contract
ever changes or is bypassed. The routes now guard the key explicitly, parse a
typed `DID` once, and use that value for downstream dispatch and repository
selection. The existing `PublicRepositoryReadHTTPTests` malformed-selector and
JSON/read coverage passed 12/12 after a serialized clean-scratch build
(`SWIFTPM_MAX_CONCURRENT_OPERATIONS=1`, `--jobs 1`). No new P1 authorization,
public/private-isolation, CAR-integrity, credential, or recovery bypass was
reproduced.

## Stream-admission rereview: 2026-07-31

An additional independent pass focused on the Luna-era public/private blob
response paths. The byte budget alone did not bound the number of concurrent
descriptor-backed responses, and public or permissioned `getBlob` could open
and verify a blob before acquiring the shared transfer budget. A slow-reader
burst could therefore consume more descriptors and connection work than the
CAR spool budget intended.

The remediation is committed as `bb825ad2` (`security: bound public and
private blob streams`):

- `PublicRepositorySpoolAdmission` now enforces process-wide and per-account
  byte and lease ceilings, with overflow-safe accounting and idempotent
  release.
- Public and permissioned blob routes reserve before opening the blob, reject
  empty or over-256 MiB bodies, and retain the lease until the streaming body
  drains or fails.
- Hummingbird now applies an explicit connection ceiling and HTTP/1 idle
  timeout; the CLI passes the preopened directory's admission instance to all
  relevant routes.
- A regression holds the only lease and proves public `getBlob` fails closed
  before opening bytes, then succeeds and releases after the lease is freed.

Focused public-read, public-mutation, private-sync, and blob-binding tests
passed. The complete serialized macOS suite passed with a freshly built
`swan` executable and `SWAN_TEST_EXECUTABLE` explicitly pinned. The
clean-cache macOS acceptance wrapper also passed from a fresh dependency
build. Direct `swift test` remains unsafe as standalone evidence when a stale
`.build-task*` executable is present; use the explicit override or
`Scripts/run-clean-cache-acceptance.sh`.

No new authorization, credential, public/private-isolation, CAR-integrity, or
recovery bypass was reproduced. This closes a local availability boundary but
does not change the release boundary: native Linux, unmodified pinned
TypeScript semantic/recovery interoperability, reverse-authority OAuth and
lifecycle coverage, corrupted-operation/compaction-gap traffic, and the
official security launcher remain open.

## Permissioned projection and API rereview: 2026-07-31

The next adversarial pass targeted the remaining Luna-era read/write boundaries
and the low-level OAuth test seams. Permissioned JSON record reads now use a
keyset SQL page that selects metadata first, enforces the aggregate byte budget
before loading values, and rejects a changed value length before publication.
Permissioned writes perform a metadata-only authorization preflight; write-only
callers do not receive a commit, commitment, or record-value snapshot. The
durable SQLite wire revision seeds the process-local TID allocator, and a
monotonicity-only retry reuses the same request identifier after a concurrent
wire-revision race. No network I/O occurs in the transaction.

The public OAuth issuance and redemption entry points no longer expose the
active-subject opt-out or a caller-selected inactive-subject policy. Those
arguments remain internal test seams only; production wrappers require an
active-subject revision and always enforce active accounts. This removes a
low-level API footgun without changing the protocol surface.

Verification for commit `229d90b9` (`security: bound private reads and narrow
OAuth issuance`) passed: the focused permissioned read/write suite passed 13/13,
`SwanOAuthTests` passed 104/104, and `PublicRepositoryReadHTTPTests` passed
12/12. A fresh clean-cache macOS build and full XCTest acceptance passed with
exit code 0; the run reported the normal opt-in/reference-cache skips. The
explicit transfer gates then passed on the same source: public production
`getRepo` RSS, permissioned near-256 MiB CAR RSS, public CAR-spool RSS,
256 MiB staged CAR import, and private CAS streaming. The permissioned CAR
report verified 267,396,722 streamed bytes with a 19,922,944-byte peak RSS
increase and 65,536-byte maximum chunks; the public spool report verified
270,049,433 streamed bytes with a 17,301,504-byte RSS increase.

These results close the current local read/write, API-footgun, and bounded
transfer findings. They do not change the release boundary: native Linux,
unmodified pinned TypeScript semantic/recovery interoperability, reverse-
authority OAuth/browser and lifecycle coverage, corrupted-operation and
compaction-gap traffic, and the official security launcher remain open. The
clean-cache wrapper still explicitly reports that the live cross-host semantic
matrix was not run.

## Luna-era adversarial reconciliation and clean-cache rerun: 2026-07-31

An independent review of the Luna-era account-recovery surfaces compared the
reported candidates with the current source and focused tests rather than
accepting the historical receipts as proof.

- The suspected unbounded recovery-marker sink is closed locally. The control
  database enforces a 4,096-row marker ceiling, trims legacy overflow during
  migration, rejects a new digest at capacity, and limits request/background
  expiry purges to 256 rows. Existing-marker refresh remains allowed. The
  focused `AccountEmailOutboxSQLiteTests` capacity selection passed.
- The suspected SMTP lease/reclaim race is narrowed but not erased by policy.
  Crossing the durable send fence extends the lease to the five-minute
  bounded attempt window, while the recovery coordinator cancels a delivery
  after 240 seconds. This protects the supported Mailpit implementation and
  the tested cancellation path. A deliberately non-cancellable third-party
  `AccountEmailDelivery` could still outlive the five-minute fence; that is a
  residual implementation-contract risk, not evidence of a current account
  authorization bypass.
- Password-reset responses still have a known-work-shape difference: a matched
  active mailbox performs token/outbox writes after the account-free marker,
  while an unknown mailbox does not. The fixed empty response, keyed marker,
  rate limits, and 50 ms floor reduce the direct oracle, but no runtime
  distribution test under SQLite contention proves strict constant work. Keep
  this as an availability/privacy follow-up (ADV-50), not a completed
  constant-time claim.
- The review also found a clean-cache harness defect in the newly added
  collision-avoidance override: it rendered `172.34.0/24` and invalid service
  addresses instead of `172.34.0.0/24`/`172.34.0.x`. The generator now retains
  the first three octets and chooses a free loopback Caddy port without
  mutating the checked-in Compose file. `bash -n`, `git diff --check`, profile
  verification, effective/static/mutation lab verification, a fresh copied
  SwiftPM build, the full copied-tree test graph, and Compose health all pass.

The clean-cache run was executed on macOS through Docker's Linux containers;
it is not native-Linux evidence and it intentionally does not run the live
cross-host semantic matrix. The release boundary is unchanged: native Linux,
stock pinned-TypeScript value-bearing incremental/recovery behavior, reverse
authority OAuth/browser/lifecycle coverage, corrupted-operation and
compaction-gap traffic, and the official security launcher remain open.

## Oplog admission and test-binary follow-up: 2026-08-01

The follow-up review exercised the value-bearing oplog path with a direct
storage caller that places 4,097 operations in one wire transaction. The
previous aggregate guard rejected the page only after the second SQL query had
already materialized the BLOB-bearing rows. The scalar operation-count
preflight now rejects an oversized first transaction before that query; the
regression `testWireOplogRejectsOversizedAtomicBatchBeforeValueMaterialization`
passes alongside the existing aggregate-byte test. This closes a narrow local
availability gap without changing the wire limit.

The review also found that four child-process test helpers preferred stale
`.build-task*` executables over the current `.build/debug/swan`, producing
false `invalidManifest` and truncated-restore failures under an ordinary
`swift test`. The helpers now prefer the current build and retain the task
binary only as a fallback. The two affected CLI/export tests pass without an
environment override; `PublicRepositoryReadHTTPTests` passes 12/12, and a
serialized full macOS `swift test --jobs 1` run using the current executable
exited 0 with no failures.

No new authorization, credential, public/private-isolation, CAR-integrity, or
recovery bypass was reproduced. The release boundary is unchanged: native
Linux, unmodified pinned-TypeScript semantic/recovery interoperability,
reverse-authority OAuth/browser and lifecycle coverage,
corrupted-operation/compaction-gap traffic, and the official security launcher
remain open.

## Adversarial rereview: 2026-08-01

The next pass targeted the scope parser, route composition, and simple-space
authority state rather than accepting the preceding focused green suite as
coverage of those seams.

Three local defects were found and remediated:

- **ADV-80 (P1, authorization):** `SpaceAuthorizationPolicy` accepted an
  otherwise valid qualified scope with an unknown query member (for example,
  `action=read&unexpected=ignored`). The matcher checked the required tuple
  fields but not the complete key set, so a future scope extension could be
  interpreted inconsistently across authorization boundaries. Resource scopes
  now allow only `authority`, `skey`, `action`, and optional `collection`, while
  management scopes require exactly `authority`, `skey`, and `manage`. A
  regression proves the unknown-key grant cannot read a record.
- **ADV-81 (P2, availability/control composition):** `SwanHTTPServer` accepted
  a caller-provided `PublicRepositoryJSONReadAdmission`, but public repository
  routes silently used the global default during `buildRouter`; authenticated
  routes used the supplied instance. The server now stores one resolved
  admission object and passes it to public, permissioned-record, and oplog
  registration, so the configured process-wide response budget is actually
  enforced.
- **ADV-82 (P1, availability):** durable simple-space membership, client
  allow-lists, and managing-app decisions were loaded into unbounded Swift
  `Set`s, and `listMembers` sorted the entire membership set before applying a
  page limit. The domain now caps members at 10,000, client entries at 1,000,
  and managing-app decisions at 10,000; writes and schema migration reject or
  trim oversized state. `listMembers` validates scalar authority facts and
  cardinality, then uses a keyset SQL page without materializing the full
  membership set. The regression covers cursor paging and a persisted
  cap-plus-one state.

Serialized focused evidence after these changes: wildcard resource/management,
unknown-key denial, simple-space schema/tamper, and bounded keyset-page tests
passed; `git diff --check` remains clean. The full suite and native-Linux/live
interop gates are still pending, so this addendum is not an alpha sign-off.

The review then found **ADV-83 (P2, adapter consistency)** in the process-local
`SimpleSpaceAuthority`: unlike SQLite, it accepted control-character/oversized
client identifiers and could issue credentials for a non-DID user. The shared
`SimpleSpaceConfiguration` initializer now validates opaque app identifiers,
and the in-memory credential/decision operations validate user DIDs. The
existing SQLite adapter and the actor authority therefore reject the same
malformed policy inputs. The new cross-adapter negative test and the prior
scope/bounded-state focused tests pass. This is a local consistency fix; the
native-Linux, stock-reference, reverse-authority, corruption/recovery, and
security-launcher gates remain open.

The custom JSON-admission regression was also moved from direct route
registration to `SwanHTTPServer.buildRouter`, proving that a caller-supplied
admission is retained by the actual server composition. `PublicRepositoryReadHTTPTests`
passes 12/12 with the injected one-lease budget.

Finally, **ADV-84 (P2, public projection availability)** moved the collection
count and aggregate-name-byte checks from the SQLite-only preflight into
`PublicRepositoryReadDescription` itself. Alternate `PublicRepositoryReadDirectory`
implementations now fail before handing an oversized collection array to the
JSON encoder; the new regression is included in the 13-test public-read suite.

The adversarial pass also caught a test-harness authorization drift: the local
semantic interop runner still requested only the bare `atproto` scope for
permissioned record operations. That scope is intentionally sufficient for
account/public lifecycle calls, but it must not substitute for a space grant.
The runner now requests explicit authority/self/action/collection grants for
each permissioned operation, so the fixture exercises the same policy as a
real client (**ADV-85, P2, test validity**). `SwanInteropTests` is green at
82/82, including durable convergence, recovery, corruption, and isolation
scenarios.

Verification completed on the current macOS checkout:

- The serialized `swift test --scratch-path .build-scope-remediation --jobs 1`
  run exited 0: 904 tests, 8 intentional skips, 0 failures across all ten
  XCTest targets (plus the Swift Testing profile suite).
- `PublicRepositoryReadHTTPTests` passes 13/13, including the injected
  process-wide JSON admission and oversized projection checks.
- `bash Scripts/verify-profile.sh` and `bash Scripts/verify-interop-lab.sh`
  pass against the pinned profile/cache.
- Opt-in near-256 MiB RSS tests pass for both public repository export and
  permissioned CAR streaming; the permissioned run reported a 19,693,568-byte
  peak RSS increase for a 267,396,722-byte CAR and rejected the over-limit
  record before creating a spool.

At that checkpoint, the following findings remained deliberately open rather
than being hidden by the green local suite: the process-local
`SimpleSpaceActor` retained an unbounded dictionary of spaces and
managing-app decisions (a bounded durable SQLite path existed, but no total
in-memory space cap); native Linux execution;
live cross-host interop with the unmodified pinned TypeScript value-bearing
incremental/recovery paths; reverse-authority OAuth/browser/lifecycle flows;
corrupted-operation and compaction-gap traffic; stock TypeScript delegation
key pin/dynamic discovery; strict password-reset constant-work evidence; the
non-cooperative third-party email-delivery cancellation contract; and the
official Codex Security launcher. These are release-gate items, not claims
that the alpha is complete.

## Adversarial rereview: native Linux and process-lifecycle follow-up — 2026-08-01

The native Linux run was deliberately repeated in a disposable Ubuntu
26.04/Swift 6.2.3 ARM64 VM with one SwiftPM process and --jobs 1. This
separated a real test/runtime failure from the earlier apparent
PublicRepositoryReadHTTPTests hang, which was SwiftPM dependency
resolution/lock contention rather than a route deadlock.

Four portability/lifecycle defects were found and remediated:

- **ADV-86 (P2, test portability):** Swift 6.2's Glibc importer exposes
  RUSAGE_SELF as an enum while getrusage expects its underlying Int32; the
  256 MiB RSS helper now bridges that value only on Linux. Linux also
  rejected await in defer bodies, so asynchronous fixture cleanup uses
  XCTest teardown blocks.
- **ADV-87 (P2, test isolation):** Foundation URL equality on Linux compared
  filesystem metadata in the SQLite-root guard and falsely reported a
  database escape. The guard now compares canonical paths.
- **ADV-88 (P1, availability):** the concurrent account-provisioning
  regression reliably hit a Swift 6.2 Linux async-let deallocation crash
  while one child unwound. Explicit Task handles collect both outcomes
  without weakening the race itself; the targeted test passes on both
  platforms.
- **ADV-89 (P1, availability):** a TLS/HTTP pipeline failure could remove the
  NIO response handler without channelInactive, leaking its unresolved
  promise. Connect failures, request failures, and handlerRemoved now fail
  the promise idempotently before channel shutdown. The wrong-hostname
  regression that exposed the leak passes on macOS and Linux.

The process-local laboratory authority also had a residual bounded-state gap:
per-space members, clients, and decisions were capped, but the actor retained
an unbounded number of space/tombstone dictionaries. **ADV-90 (P2,
availability)** adds a 10,000-space authority cap and releases managing-app
decisions when a space is deleted. The cap regression passes on macOS and
Linux; the durable SQLite authority already has its own schema and per-space
limits.

Current cross-platform evidence:

- Native Linux full suite: 904 XCTest cases, 8 intentional skips, 0 failures,
  plus the four-test Swift Testing profile suite.
- Native Linux PublicRepositoryReadHTTPTests: 13/13 in 0.401 seconds.
- Native Linux opt-in bounded-transfer gates: public production getRepo,
  staged 256 MiB CAR import, public CAR-spool RSS
  (270,049,433 bytes streamed; 65,536-byte chunks), permissioned
  near-256 MiB CAR (267,396,722 bytes; 65,536-byte chunks), private CAR
  spool, and private CAS blob streaming all pass.
- Host macOS full suite after the lifecycle fixes: every XCTest target passed
  with zero failures; the Swift Testing profile suite passed all four tests.

These fixes close the Linux/build-harness and process-local bounded-state
findings. They do not turn the remaining release gates into proof: the
unmodified pinned TypeScript value-bearing incremental/recovery paths,
reverse-authority OAuth/browser/lifecycle coverage, corrupted-operation and
compaction-gap traffic, stock TypeScript delegation-key discovery, strict
password-reset constant-work measurement, non-cooperative third-party email
cancellation, and the official Codex Security launcher remain open. The
checked-in recovery overlay is qualification evidence only and must not be
described as stock-reference interoperability.

## Adversarial rereview: notification restart and stateful CLI guard — 2026-08-01

The crash-boundary acceptance was rerun after the stricter qualified-space
scope enforcement landed. The restart harness still constructed a localhost
OAuth client with only the broad `atproto` scope, so its seed write could not
obtain the authority/self/action grants required for a permissioned record.
That was a harness-validity defect rather than a server authorization failure.

**ADV-91 (P2, test validity):** the notification restart acceptance now derives
the authority DID from its space URI, encodes explicit read and collection-create
space scopes in the development client metadata, and passes those scopes to
both lab hosts alongside `atproto`. The disposable run then completed the real
OAuth/DPoP seed write, forced a process stop between commit and delivery, and
restarted the worker. It reported
`NOTIFICATION RESTART OUTBOX CONVERGENCE OK: successful_forwards=2
receiver_effects=1` with exit status 0. The private record value and credentials
remain confined to container tmpfs and are not copied into the artifact.

The same review found a documentation/harness mismatch: the README suggested
combining metadata-only `listRepoOps` with the stateful matrix even though the
stateful evaluator correctly requires values. The CLI now rejects that
combination before reading a body or starting network work; the README labels
metadata-only runs as compatibility smoke evidence and reserves the stateful
gate for value-bearing endpoints.

This closes the notification restart and CLI misuse findings. It does not close
stock TypeScript value-bearing/recovery support, reverse-authority automatic
key discovery, live corrupted-operation/compaction-gap traffic, or the formal
security-launcher gate.

Post-change local verification is current as of this addendum: with
`SWIFTPM_MAX_CONCURRENT_OPERATIONS=1` and `--jobs 1`, the exact
`--filter PublicRepositoryReadHTTPTests` invocation completed in 0.327 seconds
with all 13 tests passing, and the serialized full macOS suite completed with
906 XCTest cases, 8 intentional skips, and 0 failures. The Swift Testing
profile suite added four passing tests. The formal Codex Security launcher was
also attempted but could not start its bundled Python 3 helper; that remains an
environmental release gate rather than a silently omitted scan.

## Adversarial rereview: direct storage write admission — 2026-08-01

The next pass deliberately bypassed Hummingbird and called the public
in-memory and SQLite repository APIs with already-materialized mutation
arrays. The HTTP `applyWrites` handler had a 4,096-operation/1 MiB body bound,
but the lower layers did not enforce an equivalent limit. A trusted in-process
caller (or a future adapter that forgot the HTTP route) could therefore make a
large value-bearing transaction and outbox in one call.

**ADV-92 (P2, availability/adapter consistency):** repository mutation
admission now lives in `SpaceWriteLimits` and is enforced before revision
lookups, metadata maps, or SQLite transactions. The in-memory repository,
`SQLiteAccountDatabase.apply`, `DurableSpaceRepository.applyAtomically`,
`applyAuthorizedWrites`, and `currentWireRevisionForWrite` all reject more
than 4,096 operations, any value larger than 1 MiB, or an aggregate value body
over 1 MiB. The HTTP operation cap uses the same domain constant. The guard is
overflow-safe and deletes do not consume value bytes.

Focused macOS evidence passed:

- `SwanSpacesTests.testInMemoryRepositoryRejectsOversizedWriteBatchBeforeMutation`;
- `SwanSQLiteTests.testPermissionedStorageRejectsOversizedWriteBatchBeforeTransaction`;
- `SwanSQLiteTests.testWireOplogRejectsOversizedAtomicBatchBeforeValueMaterialization`.

The last test now seeds a batch at the domain ceiling and requests an
intentionally smaller value budget, proving the scalar preflight rejects it
before the BLOB query. No partial repository state is left by the direct
storage rejection.

This finding is closed locally. The review still does not promote the alpha to
release-ready: the stock pinned-TypeScript value-bearing incremental/recovery
path, reverse-authority OAuth/browser/lifecycle matrix, live corrupted/
compaction-gap traffic, stock delegation-key discovery, strict password-reset
constant-work evidence, non-cooperative third-party email cancellation, and
the unavailable official Codex Security launcher remain explicit gates.

## Adversarial rereview: Luna-era recovery acceptance — 2026-08-01

The next pass separated the committed Luna-era protocol/storage work from the
acceptance claims layered over it. The five Task 43 remediations remain sound
under source review: bounded SQL-backed public CAR traversal, process-wide
spool admission before file creation, reference-compatible descending record
pagination, direct strict DAG-CBOR decoding, and fail-closed PLC genesis
verification. The exact `PublicRepositoryReadHTTPTests` filter now completes
with 13/13 tests passing when SwiftPM is serialized with
`SWIFTPM_MAX_CONCURRENT_OPERATIONS=1` and `--jobs 1`; the earlier apparent
hang was SwiftPM lock/dependency work rather than a route deadlock.

The acceptance layer did contain three material defects:

- **ADV-93 (P1, missing capability):** `swan lab recover-permissioned` was
  advertised but returned an unconditional usage error. It now performs a
  credential-authenticated retention-gap probe, bounded two-root CAR recovery,
  durable publication, a corrupted retry, and a sanitized owner-only result
  artifact. It refuses unmanaged or inactive receiver accounts before remote
  authentication or account-database creation.
- **ADV-94 (P1, false acceptance):** the first corruption harness only proved
  that a downloaded file byte changed, and the initial CLI remediation counted
  any retry error as verifier rejection. A timeout, DNS error, or OAuth failure
  could therefore have produced a false pass. The gate now accepts only the
  deterministic local `CARBlockCIDMismatch` caused by the injected final-byte
  mutation and independently requires the durable head to equal the last valid
  installed head.
- **ADV-95 (P2, stale test binary):** `LabCLITests` ignored
  `SWAN_TEST_EXECUTABLE`, allowing a focused test to exercise an older default
  `.build/debug/swan`. The helper now honors the explicit executable and skips
  rather than silently substituting another binary when it is unavailable.

The remediation build also exposed two ordinary correctness defects before
they could be committed: the new command referenced Petrel's `TID` without a
direct target dependency, and importing Petrel made `Service` ambiguous with
ServiceLifecycle. The dependency is now explicit and the lifecycle protocol is
qualified. The command additionally rejects `--source-auth none`; an
unauthenticated source cannot satisfy the recovery-acceptance contract.

Focused macOS evidence on the current working copy:

- recovery artifact sanitization and failure projection: 3/3;
- HTTP CAR fault injection: 2/2;
- recovery CLI pre-network validation: 4/4;
- authenticated recovery orchestrator: 5/5;
- public repository read HTTP: 13/13.

This closes the local implementation defects but not the acceptance gate. A
live low-retention run must still prove an actual 409
`full_repo_recovery_required`, a valid durable full-CAR replacement, rejection
of the corrupted CAR, and preservation of the prior valid head. The resulting
artifact must be checked for mode 0600 and secret/private-value absence.
Reverse-authority OAuth/browser/lifecycle, password-reset timing and
non-cooperative email cancellation, final native Linux/current-profile
acceptance, clean-cache Compose, and formal security-scan completion remain
open.

## Adversarial closure: live permissioned recovery acceptance — 2026-08-01

Task 45 now closes the previously open local recovery-acceptance gate. A live
retention-2 Swan source returned the exact HTTP 409
`full_repo_recovery_required`; the receiver installed the verified two-root
CAR as a durable three-record head; a final-byte-corrupted retry failed only as
`CARBlockCIDMismatch`; and the final durable generation, revision, and
commitment remained equal to the last valid installed head. The semantic-only
artifact is mode 0600 and contains no DIDs, space URI, credentials, tokens,
DPoP material, record values, verifier material, paths, or raw LtHash state.

Three independent remediation rounds found and closed acceptance-harness
defects before approval:

- the first harness trusted shape-checked plaintext PLC JSON rather than the
  managed account's authenticated durable identity history;
- the first runner lifecycle had signal/timeout and creation-response windows
  that could outlive cleanup or leave a temporary container behind; and
- the first artifact projection did not bind exact scenario/profile values or
  strictly type its durable-head witnesses.

The final harness obtains only an algorithm-tagged public commit key from a
read-only CLI that verifies the canonical PLC operation/CID chain, rotation
signatures, expected DID, and terminal `atproto` method. It synchronously
creates a labelled runner, captures or safely recovers its exact full container
ID using a fresh cleanup nonce, removes only that validated ID, ignores
follow-on handled signals during restoration, and proves the exact original
Swan through both loopback and Caddy health checks. Dynamic tests exercise the
lost-create-response fallback and artifact mutations; ShellCheck and the
focused Swift artifact suite pass. Independent spec and code-quality verdicts
are both approved at head `ee31ffe97504`.

This is Swan-to-Swan evidence, not alpha completion. Stock pinned-TypeScript
value-bearing incremental/full-recovery behavior, reverse-authority
OAuth/browser/account lifecycle, strict password-reset constant-work and
non-cooperative delivery cancellation, native Linux, final clean-cache/current-
profile acceptance, and formal security review remain open.

## Adversarial rereview remediation closure — 2026-08-01

The rereview found that the retained Task 45 artifact was a first install
(`priorHeadPresent: false`, generation 1), so it could not support the claimed
stale-replica replacement. The Task 47 runner now performs two independent
phases: it installs a seed head, advances the source with write-only
`com.atproto.space.applyWrites`, then requires an existing receiver head before
the retention-gap recovery. The sanitized artifact requires generation N to
be replaced by N+1, changed revision and commitment, a deterministic
`CARBlockCIDMismatch` on the corrupted retry, and preservation of the new
valid head.

Fresh live evidence was rerun against the retained Compose project after
rebuilding the current Linux release image. The result was independently
validated with `Scripts/validate-permissioned-recovery-artifact.py` and had
mode 0600:

- `priorHeadGeneration: 1` → `replacementHeadGeneration: 2`;
- `replacementCASAdvanced: true` and `replacementRecordCount: 7`;
- `gapStatus: 409`, `gapErrorCode: full_repo_recovery_required`;
- `corruptErrorCode: CARBlockCIDMismatch` and `lastValidHeadPreserved: true`.

The first rebuild also exposed a Swift 6.1/Linux-only release failure in the
bounded portable-export staging writer; its explicit initializer and file-type
annotations are now checked by the Docker release build. The new mocked
transport test exercises the write-only POST and signed metadata-only
`listRepoOps` witness without a socket, and verifies that request values and
bearer material never enter the fixture recorder. The serialized focused gates
now pass: 6 recovery-artifact tests, 9 pre-migrated-storage tests, 13 public
repository read HTTP tests, and the shell acceptance/verifier suites.

The live artifact remains under the ignored `artifacts/` policy; the exact
reproduction command was:

```text
SWAN_PERMISSIONED_RECOVERY_PROJECT=swan-clean-cache-5df6895d450ef2a830ca506d \
SWAN_PERMISSIONED_RECOVERY_NO_BUILD=1 \
SWAN_INTEROP_SECRETS_DIR=<owner-only-lab-secret-directory> \
SWAN_PERMISSIONED_RECOVERY_OUTPUT=<owner-only-output>/permissioned-recovery.json \
./Scripts/run-permissioned-recovery-acceptance.sh
```

This closes the false-positive recovery finding, but does not close the alpha:
stock pinned-TypeScript value-bearing incremental/full recovery, reverse
authority OAuth/browser/account lifecycle, native-Linux host evidence,
current-profile clean-cache Compose, password-recovery timing and
non-cooperative delivery cancellation, and a formal security scan remain
required.

## Adversarial rereview closure: clean-cache and notification restart — 2026-08-01

The fresh macOS clean-cache gate was rerun from a new scratch directory after
updating the lifecycle test to obtain a new OAuth grant after deactivation.
The earlier 401 was the expected family revocation, not a missing-database
availability result. The rerun completed profile verification, static Compose
mutation checks, dependency resolution, a serialized fresh SwiftPM build, and
the complete test suite with no failures. In particular,
`PublicRepositoryReadHTTPTests` completed 13/13; the apparent hang remains
SwiftPM resolution/lock contention when multiple processes share a build
directory, not an HTTP route deadlock.

The restart acceptance then found and closed two Compose-isolation defects:
the runner now generates an unused per-run `172.x.0.0/24` subnet and rewrites
the trusted Caddy peer consistently, and it removes the host Caddy port
publication because the scenario uses only the internal TLS network. Static
verification still inspects the checked-in fixed topology; the generated
override is untracked, owned by the run, and removed by the bounded cleanup.
ShellCheck and syntax checks pass. Fresh live evidence passed:

- `Scripts/run-clean-cache-acceptance.sh --mode macos`: clean build/test gate
  green; and
- `Scripts/run-notification-restart-acceptance.sh`: two successful forwards,
  one dropped acknowledgement, one request digest, and one durable receiver
  effect after restart.

These local gates are closed. The alpha still requires a real pinned
TypeScript value-bearing incremental/full-recovery matrix, reverse-authority
OAuth/browser/account lifecycle, native-Linux host evidence, strict
password-reset timing and non-cooperative delivery cancellation, and a formal
security scan before release-ready status.

## Adversarial cross-host witness: pinned TypeScript member — 2026-08-01

The disposable Compose project was restored after a live reference-member run.
The pinned TypeScript PDS supplied the member account and delegation key; Swan
discovered that key through the allowlisted PLC resolver, issued the authority
credential, and completed create/read on the reference-hosted permissioned
repository. The sanitized mode-0600 artifact reports the same write/read CID,
four successful cross-host events, and no request bodies, record values,
tokens, passwords, DPoP proofs, or DIDs.

This closes the reference-member delegation/write/read witness for the
Swan-authority direction. It does not yet prove the separate incremental
oplog/full-CAR recovery matrix against the pinned TypeScript implementation,
reverse authority placement, or the native-Linux and formal-security gates.

## Formal security launcher status — 2026-08-01

The mandated Codex Security diff-scan launcher was invoked against the reviewed
working copy and did not start: its Python 3 helper failed before producing a
scan workspace or findings artifact, reporting that the Codex installation
must be reinstalled or updated (or `PYTHON` configured) and restarted. No
security result is inferred from that failure, and no substitute scan artifact
is fabricated. The formal security gate therefore remains open until the
launcher is available and a fresh scan covers this diff.

## Adversarial rereview: recovery qualification binding and test-run hygiene — 2026-08-01

The recovery-variant work added a second Compose file and a stateful dynamic
delegation mode. A verifier review found that the existing lab verifier did
not inspect those new inputs, so a future edit could have changed the recovery
image, archive, or patch while leaving the normal static gate green.

**ADV-96 (P2, acceptance provenance):** the recovery qualification topology
and overlay provenance were not part of the static interop verifier. The
verifier now requires the recovery Compose file, wrapper, Dockerfile, overlay
profile, patch, and integrity tests; binds the overlay commit/archive/patch
checksum to the active immutable profile; rejects network source fetches in
the recovery Dockerfile; and has a clean-cache mutation test for unsupported
reference variants. The source-overlay integrity test and verifier mutation
suite pass.

The exact serialized public-read filter was also rerun with
`SWIFTPM_MAX_CONCURRENT_OPERATIONS=1` and `--jobs 1`: the fresh build completed
and `PublicRepositoryReadHTTPTests` executed 13/13 tests in 0.206 seconds.
During cleanup, an older dynamic-delegation process was found still blocked in
an 18-minute `docker compose build swan` child after its earlier evidence had
already completed. Only that identified process tree and its disposable
Compose project were stopped/removed. This is harness/process hygiene evidence,
not a Swan HTTP deadlock; future runs should use the bounded no-build mode only
after verifying the project-scoped image and should keep the serialized SwiftPM
settings.

## Adversarial cross-host witness: reverse authority — 2026-08-01

The generalized dynamic harness now exercises both authority placements. The
first reverse run found two real compatibility defects rather than treating a
failed HTTP response as an interop pass: Swan requested only the base
`atproto` OAuth grant even though `getDelegationToken` requires a whole-space
qualified read grant, and Swan's PLC resolver did not apply the proposal's
ordinary `#atproto` fallback when a TypeScript credential declared
`kid: #atproto_space` without publishing a dedicated `atproto_space` method.

The harness now advertises exact space-read and collection-create scopes in its
localhost client metadata. The PLC resolver prefers `atproto_space`, falls
back to `atproto` only when the dedicated method is absent, and remains
fail-closed when a present dedicated method is malformed. The fallback is
covered by a focused resolver test (14/14 resolver tests passed).

Fresh disposable evidence after rebuilding the current Linux release image:

- TypeScript authority -> Swan member dynamic credential path: delegation,
  credential exchange, member write, and member read all returned HTTP 200;
- write and credential-read CIDs matched and the sanitized artifact reported
  `status: passed`, `credentialIssued: true`, and `converged: true`;
- the artifact was mode 0600 and contained no bearer material, DPoP proof,
  password, record value, or personal selector; and
- the original TypeScript-member/Swan-authority direction was rerun after the
  changes and also returned four HTTP 200 events with matching CIDs.

This closes the reverse dynamic credential/write/read witness, not the full
reverse-authority account lifecycle or fault matrix. Stock pinned-TypeScript
value-bearing incremental/full-CAR behavior, native Linux-host evidence,
strict password-reset constant-work/non-cooperative delivery cancellation,
and the unavailable formal Codex Security launcher remain open gates.

## Adversarial rereview: Luna storage and lifecycle boundaries — 2026-08-01

This pass reviewed the Luna-era storage remediations against their invariants
and then exercised the account lifecycle boundary that the focused public-read
suite did not cover. The attribution is a surface/time boundary only; the
repository does not preserve per-agent authorship for these changes.

The earlier storage candidates separate cleanly:

- Recovery now uses `openMode: .existingManaged`; it does not manufacture an
  account database for a missing account. `PreMigratedAccountDirectoryTests`
  proves this fail-closed behavior (9/9).
- New password-recovery work markers are capped at 4,096 rows and request and
  background expiry purges are bounded to 256 rows. The SQLite outbox/cap
  selection passes (14/14). A legacy migration can still delete a large
  pre-existing overflow in one transaction; that is a bounded migration-cost
  follow-up, not an unauthenticated sink for new requests.
- `SwanPortableExport` no longer retains every artifact body in one aggregate
  array; `StagedArtifactWriter` keeps files on disk and only retains bounded
  inventory/manifest metadata. The repository CAR path now uses the SQLite
  spool and the streaming two-root verifier, while CAS blob bodies are copied
  and hashed in 64 KiB chunks. Inventory cardinality, per-artifact bytes, and
  aggregate archive bytes are rejected before publication. The focused
  `SwanPortableExportTests` selection passes 13/13 after this remediation.
  Legacy SQLite blob rows remain a compatibility seam because SQLiteNIO still
  selects that historical payload as one row before chunking; managed opens
  migrate those rows on ordinary reads, but a hostile legacy-only RSS gate is
  not claimed here.
- The email timeout uses a structured task group. A deliberately
  non-cooperative `AccountEmailDelivery` can keep that group from returning
  after the timeout task wins. The durable five-minute send fence eventually
  expires, after which deletion can proceed while the old delivery is still in
  flight. Existing runtime tests use cooperative cancellation only, so this
  remains a lifecycle/availability and stale-mail privacy follow-up (P1).

**ADV-97 (P1, reactivation public-read availability)** was reproduced with a
temporary adversarial test and then removed from the tree. The test created a
valid preopened account, transitioned it to `deactivated`, transitioned it
back to `active`, and called
`SQLitePreMigratedAccountDirectory.describePublicRepository`. It failed with
`PublicRepositoryReadError.unavailable` at
`SQLitePreMigratedAccountDirectory.swift:1386`.

The cause is exact and local. `activePublicReadContext` requires the current
control row to compare equal to the bootstrap-time
`SQLiteVerifiedPublicRepositoryGeneration.controlAccount`. `transitionStatus`
increments `updated_at`, so deactivation/reactivation leaves the current row
active but unequal to the retained generation. The management and CLI paths
update only `control.sqlite`; `admitActivatedAccount` is for a database that is
not already admitted and `refreshPublicReadGenerationAfterMutation` runs only
after a public repository mutation. Permissioned space authorization can still
work, which makes this an easy split-brain lifecycle failure to miss.

The remediation is now implemented as a request-time, async generation refresh
for an active account whose retained generation is missing or stale. It
re-admits the existing database with the production identity verifier, verifies
the PLC preparation intent, rechecks the database path and exact active control
row before and after admission, and publishes the new generation only after
all checks pass. It remains existing-database-only and fails closed for
deactivated, deleted, missing, or tampered accounts.

Fresh serialized evidence for the surrounding claims is green:

- `PublicRepositoryReadHTTPTests`: 13/13;
- `PublicRepositoryReadDirectoryTests`: 16/16 with one explicit opt-in RSS
  skip, including the permanent reactivation regression;
- lifecycle, activation, preparation, OAuth revocation, simple-space, and
  public-admission selections: 43/43;
- `Scripts/verify-interop-lab.sh`, its mutation suite, and the reference
  overlay qualification: all pass; and
- no Swift, Docker, interop, or Caddy test process remains after cleanup.

ADV-97 is closed locally. The other open release gates remain the stock
pinned-TypeScript value-bearing incremental/full-CAR matrix,
reverse-authority OAuth/browser/account lifecycle, native Linux evidence,
strict password-reset timing, non-cooperative delivery cancellation, export
boundedness, and the formal security scan.

## Fresh reference and recovery rerun — 2026-08-01

The disposable lab was rerun against the current Swift image and the
unmodified pinned TypeScript image. The dynamic credential/write/read path
still returned HTTP 200 for delegation, credential exchange, create, and
read, with matching write/read CIDs. The stateful request then produced the
following sanitized failure artifact (0600):

- `com.atproto.space.listRepoOps`: HTTP 500 when values were requested;
- `com.atproto.space.getRepo`: HTTP 501; and
- the round trip consequently failed the incremental commitment and
  full-CAR assertions.

The failed run is retained under the owner-only lab output as
`current-reference-member-stateful.json.failed`. It contains only status,
endpoint, byte-count, digest, and redacted error metadata; the runner still
rejects any record value before publication. This makes a stock-reference
failure reviewable without retaining credentials, tokens, DPoP material,
request bodies, or selectors.
The result confirms that the checked-in recovery overlay cannot be described
as stock-reference interoperability.

The separate current-image permissioned recovery acceptance passed with a
real retention gap and a corrupted CAR response:

- the source returned HTTP 409 `full_repo_recovery_required`;
- a verified full-CAR replacement advanced the receiver from generation 1 to
  generation 2 with seven records;
- a deliberately corrupted CAR was rejected as `CARBlockCIDMismatch`; and
- the last valid head remained preserved while the replacement CAS advanced.

This closes the live compaction-gap/full-CAR replacement and corrupted-CAR
rejection witness. It does not close corrupted-operation traffic before
recovery, nor the stock TypeScript value-bearing/recovery endpoints. The
remaining release gates are the stock pinned-TypeScript matrix,
reverse-authority OAuth/browser/account lifecycle, strict password-reset
timing, non-cooperative delivery cancellation, export boundedness, and the
formal security scan.

## Fresh reverse-authority rerun — 2026-08-01

The disposable reverse placement was rerun against the current image with the
TypeScript host as authority and Swan as member. The automated OAuth/DPoP
member path obtained a delegation token, exchanged the cross-host space
credential, wrote on Swan, and read from the member repository:

- delegation token, credential exchange, create, and read all returned HTTP
  200;
- the write and read CIDs matched; and
- the sanitized artifact reported `credentialIssued: true`,
  `converged: true`, and `status: passed`.

This is fresh reverse-authority credential/write/read evidence. It still does
not prove the stock TypeScript value-bearing incremental/full-CAR surfaces or
the broader lifecycle/fault matrix.

The same current Compose project also reran the TypeScript-member direction
and the reverse direction directly through
`Scripts/run-reference-member-dynamic-delegation-acceptance.sh`, with
`SWAN_DYNAMIC_DELEGATION_NO_BUILD=1` and the project-scoped current image.
Both non-stateful artifacts passed. A stateful TypeScript-member run was then
attempted without the overlay and failed exactly at the stock reference
boundaries: `listRepoOps` returned HTTP 500 when values were requested and
`getRepo` returned HTTP 501. Credential issuance, create, and read still
returned HTTP 200 with matching CIDs, so the failure is isolated to the
incremental/full-recovery surface rather than authorization or record CRUD.

## Adversarial evidence revalidation: current workspace — 2026-08-01

The current checkout was reread after the Luna-era lifecycle and recovery
changes, and the focused boundary tests were rerun with one serialized SwiftPM
process:

- `PublicRepositoryReadHTTPTests`: 13/13;
- the permanent reactivation public-read regression: 1/1;
- OAuth family revocation after deactivation/reactivation: 1/1;
- account-email XRPC/outbox/runtime selections: 31/31;
- permissioned repository sync and private-blob isolation: 3/3.

No new authorization or public/private data-exposure defect was reproduced in
this pass. The attribution remains a surface/time boundary: the repository
does not preserve per-agent authorship, so these results do not assign or
exonerate a particular Luna agent.

## Adversarial rereview: legacy SQLite blob streaming — 2026-08-01

The remaining legacy-row concern was reproduced at the code boundary. The
private export stream previously selected `blob_payloads.payload` as a full
SQLiteNIO `Data` value and only then split it into 64 KiB callback chunks. A
large historical row could therefore bypass the otherwise bounded export
stream before the caller's aggregate limit was applied.

`streamBlobData` now performs a metadata-only reachability query for legacy
rows, derives the size with SQLite `length`, and reads the payload through
bounded `substr` slices inside one read transaction. Each slice is hashed and
delivered to the caller; the legacy `sha256:` CID is checked before the stream
is accepted as complete. Ordinary compatibility `blobData` reads still
materialize and migrate legacy rows, so the compatibility behavior is not
silently changed.

Evidence:

- `SwanSQLiteTests.testStreamLegacySQLiteBlobUsesBoundedSQLiteSlices`: 1/1;
  a 196,625-byte legacy row was returned with a maximum 64 KiB chunk and the
  database row remained legacy after the stream;
- the legacy migration/alias selection: 3/3;
- `SwanAccountExportTests`: 42/42; and
- the pre-v4 migration regression: 1/1.

This closes the managed legacy-row export allocation seam. The public HTTP
blob route remains CAS-only and fail-closed for legacy rows. Native Linux
execution was also attempted in the real Ubuntu Swift 6.2.3 VM, but the
current mounted virtiofs checkout failed during SwiftPM resource copying with
`NSCocoaErrorDomain Code=512` before the selected test executed. That is
environment/tooling evidence, not a Linux pass, so the native-Linux gate
remains open.

The platform evidence needs a provenance correction before release approval.
`/private/tmp/swan-clean-linux-20260801.log` identifies its host as `Darwin`
and ends with `swan-secrets-init` exit 1; it is a failed macOS Docker/Compose
attempt, not native-Linux evidence. `/private/tmp/swan-full-linux.log` likewise
reports an Apple macOS target platform. The earlier native-Linux result recorded
above is therefore historical evidence, not independently revalidated by a
retained log in this workspace. A fresh Ubuntu/Swift 6.2.3 host run must be
captured against the current profile and current checkout, including the opt-in
256 MiB transfer gates, before the Linux gate can be called current.

The stock pinned-TypeScript value-bearing `listRepoOps`/`getRepo` gap, broader
reverse-authority OAuth/browser/lifecycle matrix, corrupted-operation traffic,
strict password-reset work-shape proof, non-cooperative email cancellation,
aggregate export boundedness, and unavailable formal Codex Security launcher
remain open. This review is not an alpha-completion sign-off.

## Portable export boundedness remediation — 2026-08-01

The export path was then hardened against the remaining aggregate-artifact
finding. `prepareRepositoryCARSnapshot` supplies an owner-only SQLite spool;
publication writes the reader envelope prefix and spool suffix directly to a
descriptor-backed file. CAS blobs use the verified file body stream, and an
incremental SHA-256 is recorded without retaining the payload. The staged
archive verifier now parses permissioned CARs through
`SpaceCARCodec.verifyStreamingRecovery` with a disposable SQLite recovery
index, and streams blob verification through the same 64 KiB source. A
descriptor identity/length check rejects replacement or growth during
verification. A first implementation accidentally hashed the blob digest a
second time; the focused test exposed it, and the corrected implementation is
now green.

Evidence:

- `SWIFTPM_MAX_CONCURRENT_OPERATIONS=1 swift test --jobs 1 --scratch-path /tmp/swan-export-stream-20260801 --filter SwanPortableExportTests`: 13/13;
- the focused exporter test exercises two permissioned CARs and public/space
  blob namespace collisions through the new streaming verifier; and
- no export staging or recovery scratch process remains after the run.

This closes the current managed-CAS aggregate export seam. It does not close
the separate legacy SQLite-row compatibility limitation, native-Linux RSS
evidence, or the stock pinned-TypeScript and lifecycle gates listed above.

## Adversarial rereview: portable archive inventory bounds — 2026-08-01

The bounded-artifact remediation still left a filesystem-side admission gap.
SwanPortableExportFilesystem.entries first collected every name in a
directory and recursively descended every directory before the verifier
compared the result with the manifest. Payload and archive byte limits did not
bound this metadata work: a hostile restore tree could contain many empty
files, or a deep chain of empty directories, and force unbounded String/Set
growth or stack consumption without any CAR/blob bytes.

The verifier now derives the exact expected file and directory count from the
canonical manifest and passes that count into the inventory walk. Per-directory
readdir is capped by the remaining budget, the manifest is capped at 200,002
artifact entries (the current repository/blob inventory ceiling), and recursive
descent rejects depth greater than 256. Operator-backup verification uses the
same exact-count admission for both its portable subtree and outer tree.

The focused regression creates an entry-budget overflow and a 257-level
directory chain; both are rejected. The serialized export/restore/backup
selection passes 29 tests after the change. A final serialized full-suite
rerun also passed; the export target reported 42 tests with zero failures.
This closes the archive metadata boundedness finding locally. Native-Linux RSS
evidence, the legacy
SQLite-row compatibility seam, stock pinned-TypeScript value-bearing
incremental/full-CAR behavior, reverse-authority lifecycle/browser coverage,
strict password-reset work-shape proof, non-cooperative email cancellation,
and the formal security launcher remain open.

## Adversarial rereview: email-delivery cancellation contract — 2026-08-01

The recovery worker's timeout uses a structured task group. That is safe only
when the delivery implementation actually stops after cancellation: Swift
structured concurrency waits for every child before returning, so an
implementation that ignores cancellation could otherwise keep `deliverNext`
blocked while the five-minute durable send fence eventually became
reclaimable.

`AccountEmailDelivery` now requires an explicit, nonisolated cancellation
contract. The production `MailpitSMTPDelivery` declares `.bounded`, while an
`.unverified` implementation is rejected by `AccountEmailRecoveryService`
before it can claim or send any durable delivery. A deliberately
non-cooperative delivery regression passes and proves fail-closed construction
instead of exercising the hanging path. This closes the supported alpha
integration risk; an implementation that falsely declares `.bounded` violates
the protocol contract and remains outside the supported boundary.

The focused `AccountEmailOutboxRuntimeTests` selection passes 7/7. The
remaining release gates are native-Linux/current-profile evidence, stock
pinned-TypeScript value-bearing incremental/full-CAR behavior,
reverse-authority lifecycle/browser coverage, strict password-reset
work-shape evidence, the legacy SQLite blob-row compatibility seam, and the
formal security launcher.

## Adversarial rereview: portable-export SQLite read-only mode — 2026-08-01

The first clean-cache run found a reproducibility defect that the normal
cached build masked. The portable-export CLI opened the account database with
SQLite's mode=ro URI and PRAGMA query_only=ON. The exporter then attempted to
create its bounded connection-local CAR index table, and SQLite correctly
rejected that TEMP write as "attempt to write a readonly database".

The account source mode now relies on the mode=ro URI for durable-file
immutability while allowing only connection-local TEMP index tables. Durable
CREATE TABLE attempts still fail, and a regression explicitly proves the
TEMP create/drop path required by CAR export. The control database keeps its
query-only pragma because it does not need temporary write state.

Evidence:

- testPortableExportDatabaseModesRejectDurableWrites: 1/1;
- SwanAccountExportTests: 42/42;
- SWAN_INTEROP_SECRETS_DIR="" ./Scripts/run-clean-cache-acceptance.sh --mode macos --scratch-path /private/tmp/swan-clean-cache-20260801-readonly-fix: clean build and all targets passed, with the expected opt-in 256 MiB tests skipped; and
- the runner retained the explicit boundary LIVE CROSS-HOST SEMANTIC MATRIX NOT RUN; ALPHA INTEROP ACCEPTANCE REMAINS OPEN.

This closes the clean-cache portable-export launch defect locally. It does
not provide native-Linux evidence, stock pinned-TypeScript value-bearing
incremental/full-CAR interoperability, reverse-authority lifecycle/browser
coverage, strict password-reset work-shape evidence, legacy SQLite blob-row
RSS proof, or the formal security launcher.

## Adversarial rereview: opt-in transfer and RSS gates — 2026-08-01

After the clean-cache correction, the opt-in large-transfer gates were run
serially with `swift test --jobs 1` so that SwiftPM resolution and RSS samples
were not contaminated by concurrent test processes. All six macOS selections
passed:

- `SWAN_CAR_256M_STRESS=1 ... SwanSpacesTests.testPrivateCARSpool256MiBStressWhenExplicitlyEnabled`: 1/1;
- `SWAN_RUN_256MIB_PUBLIC_CAR_SPOOL_RSS=1 ... PublicRepositoryCARSpoolRSSRegressionTests.testOptInFreshProcess256MiBPublicCARSpoolDrainHasBoundedRSS`: 1/1, streamed 270,049,433 bytes, peak RSS delta 17,039,360 bytes;
- `SWAN_RUN_100K_PERMISSIONED_CAR_INDEX=1 ... PermissionedRepositoryCARStreamingTests.testOptInMaximumCardinalityRecoveryIndexBoundsRSSAndScratchDisk`: 1/1, logical 6,600,000 bytes, scratch 20,770,816 bytes, peak RSS delta 12,369,920 bytes;
- `SWAN_RUN_256MIB_PERMISSIONED_GET_REPO=1 ... PermissionedRepositoryCARStreamingTests.testOptInProductionSQLiteNear256MiBCARHasBoundedRSSAndRejectsOneMoreRecord`: 1/1, CAR 267,396,722 bytes, maximum chunk 65,536 bytes, integrity verified, over-limit request rejected without spool, peak RSS increase 21,708,800 bytes;
- `SWAN_RUN_256MIB_PUBLIC_GET_REPO=1 ... PublicRepositoryReadDirectoryTests.testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS`: 1/1 in 7.215 seconds; and
- `SWAN_RUN_256MIB_CAR_STAGING=1 ... PublicRepositoryImportStagingTests.testOptIn256MiBStagedCAR`: 1/1 in 12.432 seconds.

The blob stream harness also passed:
`SWAN_BLOB_STRESS=1 ... SwanSQLiteTests.testPrivateCASStreams256MiBInBoundedChunksWhenOptedIn`: 1/1 in 0.331 seconds. These results are macOS evidence only; they do not substitute for a native Linux run or for the open stock-reference and live cross-host semantic gates.

## Adversarial rereview: fresh native-Linux receipt — 2026-08-01

The earlier virtiofs resource-copy failure was not treated as a product
failure. The current Swan source was copied into the disposable ext4-backed
Ubuntu 26.04 ARM64 VM workspace `/tmp/swan-linux-work-20260801/Swan`, with
Swift 6.2.3 and one SwiftPM job. The warmed current-profile build then ran
the two selectors that had been blocked by the apparent test hang and the
legacy-row portability concern:

- `SwanSQLiteTests.testStreamLegacySQLiteBlobUsesBoundedSQLiteSlices`: 1/1,
  0.149 seconds;
- `PublicRepositoryReadHTTPTests`: 13/13, 0.384 seconds.

The target platform reported by XCTest was
`aarch64-unknown-linux-gnu`; the build completed in 342.43 seconds and the
tests completed without failures. This is current native-Linux execution
evidence for the focused selectors. The full-suite receipt and Linux opt-in
256 MiB/RSS selections are recorded in the follow-up below. The stock
pinned-TypeScript value-bearing
incremental/full-CAR limitation, reverse-authority browser/lifecycle matrix,
corrupted-operation and compaction-gap traffic, strict password-reset
work-shape proof, and unavailable formal security launcher remain open.

## Adversarial rereview: public-admission projection retention — 2026-08-01

The Luna-era public-read admission hardening had a subtle split boundary. Its
keyset preflight bounded the durable index to 100,000 entries, but admission
then called the older `RepositoryMSTValidation.validate` API, which retained
all reachable MST block bodies, leaves, and record-CID sets in Swift before
comparing the projection. A valid repository near the 512 MiB hostile-import
ceiling could therefore pass the preflight and still create a large
process-local allocation during startup or generation refresh.

The admission path now uses `validateProjection` with a connection-local
SQLite TEMP projection sink. MST and record block bodies are released after
each validation step; only the bounded validator topology metadata and the
durable index comparison remain. The storage-level projection verifier also
runs the same preflight, so it cannot bypass the public-read bound when called
outside bootstrap. TEMP state is dropped on success and every failure path,
and no durable repository rows are modified.

Evidence:

- `PublicRepositoryReadDirectoryTests`: 16 tests, 1 intentional opt-in skip,
  0 failures; the 100,001-row admission rejection still returns
  `resourceLimitExceeded` before projection traversal;
- `PublicRepositoryReadHTTPTests`: 13/13, 0 failures, warmed serialized
  invocation in 0.197 seconds; and
- the source compiles under the same pinned SwiftPM graph used by the clean
  acceptance path.

This closes the remaining public-admission whole-MST retention seam locally.
The separate non-admission compatibility validators and the explicitly
bounded public CAR writer remain unchanged. The focused current-source,
opt-in bounded-transfer, and full-suite Linux receipts are recorded below.
Stock pinned-TypeScript value-bearing
incremental/full-CAR behavior, reverse-authority
browser/lifecycle coverage, corrupted-operation and compaction-gap traffic,
strict password-reset work-shape proof, and the unavailable formal security
launcher remain release gates.

The new admission implementation was then rebuilt from the current source in
the same Ubuntu 26.04 ARM64 VM. Native Linux selectors passed as follows:

- `PublicRepositoryReadDirectoryTests`: 16 tests, 1 intentional opt-in skip,
  0 failures, 9.804 seconds;
- `PublicRepositoryReadHTTPTests`: 13/13, 0 failures, 0.384 seconds.

The XCTest platform remained `aarch64-unknown-linux-gnu`. The repeated
`cd` diagnostics from `limactl shell` refer only to the host working-directory
forwarding and did not affect the VM command; the source rsync and both test
invocations completed successfully.

The remaining native-Linux opt-in transfer gates were then run serially from
that same warmed SwiftPM scratch path. All passed on `aarch64-unknown-linux-gnu`:

- public CAR spool RSS: 1/1, 270,049,433 bytes streamed, RSS delta
  56,385,536 bytes;
- public production-directory getRepo: 1/1 in 10.811 seconds;
- staged 256 MiB CAR import: 1/1 in 6.584 seconds;
- permissioned near-256 MiB getRepo: 1/1, CAR 267,396,722 bytes, 65,536-byte
  maximum chunks, integrity and over-limit rejection verified, peak RSS
  increase 62,320,640 bytes;
- permissioned maximum-cardinality recovery index: 1/1, logical 6,600,000
  bytes and 20,770,816 bytes scratch, RSS delta 55,218,176 bytes;
- private CAR spool stress: 1/1; and
- private CAS blob streaming: 1/1 in 0.332 seconds.

These close the current native-Linux bounded-transfer receipt for the tested
selectors. They do not close the live stock-reference semantic/recovery and
lifecycle gates.

## Adversarial rereview: native-Linux full-suite receipt and stale CLI trap — 2026-08-01

The first bare native-Linux `swift test --jobs 1` invocation was intentionally
not accepted as a product failure. It executed 929 tests with eight skips and
eight failures because the CLI subprocess helpers found an old
`.build/debug/swan` binary: `swift test` does not build the executable product
when only test targets require it. The stale binary lacked the current
`--receiver-did`, `--space-oplog-retention`, and
`--permissioned-write-only-apply-writes` options. This is the Linux analogue
of the previously documented stale-CLI reproducibility trap, not a source
regression.

The correct run first built the current `swan` product in the same scratch
path, exported `SWAN_TEST_EXECUTABLE` to that exact binary, and then ran the
full graph serially. On the native Ubuntu 26.04 ARM64 VM with Swift 6.2.3:

- `swift build --product swan --jobs 1`: product built successfully in 2.97
  seconds after the warmed source build;
- `SWAN_TEST_EXECUTABLE=/tmp/swan-linux-test-20260801/aarch64-unknown-linux-gnu/debug/swan`
  `swift test --jobs 1`: 929 tests, 8 intentional skips, 0 failures, 81.51
  seconds; and
- XCTest reported target `aarch64-unknown-linux-gnu`; the Swift Testing public
  wire-profile suite also passed 4/4.

This closes the native-Linux full XCTest receipt. It does not close the stock
pinned-TypeScript value-bearing incremental/full-CAR limitation, reverse-
authority browser/lifecycle coverage, corrupted-operation and compaction-gap
traffic, strict password-reset work-shape proof, or the unavailable formal
security launcher.

## Adversarial rereview: qualified cross-host stateful recovery — 2026-08-01

The checksum-pinned recovery overlay was then exercised as a separate
disposable Compose project, without modifying the immutable reference cache.
The current Swan image was rebuilt from this checkout, the overlay image was
validated against the pinned archive and patch digest, and the dynamic PLC
delegation harness ran the TypeScript-member/Swan-authority stateful path.

The sanitized artifact was retained outside the repository at
`/Users/joshlacalamito/.swan-live-artifacts/current-reference-member-stateful-recovery.json`.
Its 26 assertions all passed:

- credential issuance, OAuth/DPoP write, read, and matching write/read CIDs;
- value-bearing `listRepoOps` with HTTP 200, a signed terminal revision, and
  verified commitment;
- two-root `getRepo` with HTTP 200, verified CAR integrity, and the expected
  record; and
- equality of the incremental-operation and full-CAR LtHash commitments.

The live result reported `status: passed`, `credentialIssued: true`,
`converged: true`, and `syncValuesIncluded: true`. The reference cache was
revalidated afterward and remained unchanged. This closes the qualified
overlay recovery witness. It does not upgrade the stock pinned TypeScript
image: that image still returns HTTP 500/501 for the value-bearing
`listRepoOps`/`getRepo` surfaces. Corrupted-operation traffic, compaction-gap
fault injection across hosts, reverse-authority lifecycle/browser coverage,
strict password-reset work-shape proof, and formal security scanning remain
open.

## Adversarial rereview: reverse-authority stateful recovery and signer binding — 2026-08-01

The first attempt to enable stateful reverse-authority coverage exposed a
test-validity defect: the harness supplied the TypeScript authority's
secp256k1 key while verifying the Swan member's P-256 repository commit. The
failure was `ContextSignatureMismatch`; it was not recorded as a product
failure. The runner now resolves the repository DID's canonical `did:key`
from the local PLC audit, and the CLI validates that multicodec before
selecting ES256 or ES256K. This binds verification to the repository signer
rather than to the authority placement or an operator-labelled curve.

The recovery-qualified Compose project was rebuilt from the corrected current
source. Both directions then passed the same 26-assertion stateful matrix:

- TypeScript member / Swan authority: credential issuance, OAuth/DPoP write
  and read, value-bearing `listRepoOps`, signed commitment verification,
  two-root `getRepo` CAR verification, and equal sync/full-CAR commitments;
- Swan member / TypeScript authority: the same checks with the repository
  signer resolved as Swan's P-256 PLC key; and
- both artifacts reported HTTP 200 for write/read/sync/full-CAR, matching
  terminal revisions and commitments, `credentialIssued: true`,
  `converged: true`, and `status: passed`.

The owner-only artifacts are outside the repository at
`/Users/joshlacalamito/.swan-live-artifacts/current-reference-member-stateful-recovery-v2.json`
and
`/Users/joshlacalamito/.swan-live-artifacts/current-reference-authority-stateful-recovery-v2.json`.
Each is mode 0600 and contains no password, bearer/refresh token, private key,
or record value. `interop/verify-reference.sh` passed afterward, proving the
immutable pinned cache was unchanged. This closes the reverse-authority
stateful recovery witness for the qualified overlay. It does not upgrade the
stock pinned TypeScript image, whose value-bearing `listRepoOps`/`getRepo`
surfaces remain HTTP 500/501, and it does not close the broader
reverse-authority browser/account lifecycle or cross-host corruption/fault
matrix.

## Adversarial rereview: Luna storage seams and final publication lease — 2026-08-01

The fresh Luna rereview found no P0 or P1 in the current tree. The earlier
missing-account-database and whole-export-payload findings are closed: recovery
opens only `.existingManaged` account databases, and portable export streams
CAR/blob artifacts while bounding inventory metadata. The rereview did identify
two residual P2-shaped boundedness seams and a lifecycle lease-scope bug in the
parent change; all three are addressed in this working copy.

The public import publication path now computes staged counts and its projection
digest through 256-row CID keyset pages. It walks the three canonical block
kinds independently so the `(session_id, cid)` primary key is used directly,
rejects unknown kinds explicitly, and replaces `RETURNING` row arrays with
scalar `changes()` counts. `PublicRepositoryImportQueryPlanTests` proves the
pagination plan has no temporary sort. Portable export now performs a scalar
blob-reference count before materializing the bounded inventory and rejects a
count/select mismatch.

The recovery CLI now routes its lifecycle callback through a dedicated
`PermissionedRemoteReplicaPublicationAuthorizingStore` capability and fails
closed for stores that cannot provide it. The SQLite implementation validates
and prepares the replacement before entering the callback, then holds
`withActiveAccountAuthorization` only across the final same-revision or
new-generation account transaction. Cleanup runs after the callback returns.
This keeps the control-plane `BEGIN IMMEDIATE` lease short while still making
deactivation serialize either before the authorization decision or after the
recovery mutation. The initial preflight remains an existence/lifecycle check;
the final lease is the authorization fence. The authorized new-generation
orchestrator route and authorized same-revision idempotency path are covered by
focused tests.

Evidence from the current macOS working copy:

- `PermissionedRemoteReplicaRecoverySQLiteTests`: 7/7, including the
  authorized same-revision path;
- `PermissionedRemoteReplicaRecoveryOrchestratorTests`: 5/5, including the
  authorization-capability route;
- `AccountAuthorizationLeaseTests`: 1/1;
- `PublicRepositoryImportQueryPlanTests`: 2/2;
- `PublicRepositoryImportStagingTests`: 15/15, one intentional opt-in skip;
- full serialized `SWIFTPM_MAX_CONCURRENT_OPERATIONS=1 swift test --jobs 1`:
  exit 0, with every XCTest target and the four-test Swift Testing public-wire
  profile suite passing (opt-in 256 MiB tests remained skipped); and
- the current-image stock reference-member stateful rerun reaches credential
  issuance and record write/read (HTTP 200), then reproduces the pinned host's
  value-bearing `listRepoOps` HTTP 500 and `getRepo` HTTP 501. The sanitized
  failed artifact is `/private/tmp/swan-adversarial-current-stock-20260801-rerun.json.failed`;
  `interop/verify-reference.sh` still reports the immutable cache unchanged.

The terminal Codex Security diff fallback also completed for the ten changed
files against `f80ba7f26043`. Preflight was `ready` with delegated workers
unavailable (parent-only review); discovery recorded in-scope receipts, found
no reportable candidate, and finalization succeeded. The generated report is
`/private/tmp/codex-security-scans/Swan/f80ba7f26043_adversarial_20260801/report.md`.
This is not formal launcher evidence.

The alpha remains open. The stock pinned-TypeScript value-bearing incremental
and full-CAR surfaces, broader corrupted/reordered/disconnected/compaction-gap
traffic, reverse-authority browser/account/OAuth lifecycle coverage, and
non-cooperative custom email-delivery cancellation still require explicit
evidence. The public import and export validators outside the changed paths
should not be treated as covered by this local diff scan.

## Adversarial rereview: native-Linux current-commit receipt and email-fence purge — 2026-08-01

The working copy based on parent commit `787aae50` was rebuilt from a
tracked-files-only copy in the
Ubuntu 26.04 ARM64 Lima VM. The first copy attempt accidentally streamed host
scratch build directories into Lima's 8 GiB `/tmp` tmpfs; it was stopped without
touching the repository, and the explicitly named temporary copies were removed.
The successful copy used `/var/tmp` and included only Swan and the local Petrel
package sources.

Current native-Linux evidence is now:

- `swift build --product swan --jobs 1`: passed with Swift 6.2.3;
- `swift test --jobs 1 --filter PublicRepositoryReadHTTPTests`: 13/13,
  0 failures;
- focused recovery/authorization/pagination/email suites on Linux: 7 recovery,
  5 orchestrator, 1 lease, 2 query-plan, and 15 email tests, all 0 failures;
- full `SWIFTPM_MAX_CONCURRENT_OPERATIONS=1 swift test --jobs 1`: 933 tests,
  8 intentional skips, 0 failures, plus the four-test Swift Testing
  public-wire profile suite; and
- the focused post-review email-outbox regression on macOS:
  `AccountEmailOutboxSQLiteTests` 15/15, 0 failures.

The Luna storage review was extended with a recovery-email lifecycle race. A
claim that has crossed the durable `send_started_at` fence can outlive the
proof's `expires_at`; expiry cleanup previously deleted that outbox row before
the bounded SMTP attempt ended, allowing permanent deletion to lose the fence.
Cleanup now preserves a row while `send_started_at` is set and
`lease_expires_at` is still live. `testExpiryPurgePreservesAnInFlightSendFence`
proves that cleanup retains the row and deletion remains blocked. This closes
the live Mailpit bounded-delivery seam; unverified custom delivery
implementations remain rejected by policy.

The active current interop project was restarted by exact container ID after a
Compose restart was refused because its generated file required a no-longer
exported secret-directory variable. Swan, the reference PDS, reference PLC,
Caddy, Mailpit, and Toxiproxy are healthy again. This does not change the
separate Lima VM descriptor-pressure incident.

## Adversarial rereview: restart-safe Toxiproxy topology — 2026-08-01

A direct restart exposed an operational seam in the lab itself: Toxiproxy's
proxy definitions are process memory, while `toxiproxy-setup` is a successful
one-shot dependency. Restarting only the long-running containers therefore
left `pds.test` returning Caddy 502 until the setup request was replayed.

The topology is now checked into the pinned Toxiproxy image rather than a host
bind or an assumed rerun of the setup container. `interop/Dockerfile.toxiproxy`
uses the pinned `2.12.0` digest and copies the exact single `reference-pds`
proxy from `interop/toxiproxy.json`; Compose starts it with the file-backed
configuration and keeps the setup service as an idempotent first-boot check.
This preserves the no-untrusted-host-bind invariant and makes direct restarts
reconstruct the proxy before Caddy accepts traffic.

Verification:

- the Toxiproxy image built successfully from the pinned base and its startup
  log reported `Populated proxies from file`;
- `./Scripts/verify-interop-lab.sh` passed effective and static invariants;
- `./Scripts/test-verify-interop-lab.sh` passed the mutation suite; and
- the restarted lab returned HTTP 200 for both `swan.test` and `pds.test`
  `com.atproto.server.describeServer` routes after the proxy was restored.

## Adversarial rereview: pinned TypeScript OAuth browser hop and public round trip — 2026-08-01

The reference-PDS OAuth provider does not return the client redirect directly
from its JSON consent API. It returns an issuer-local
`/oauth/authorize/redirect` URL; a browser GET with the same-origin navigation
headers and authorize-page referrer then receives one 303 to the registered
client URI. The Swift lab client now models that exact sequence. It retains a
bounded cookie jar, sends the provider's CSRF token and ephemeral bearer only
to the two same-origin JSON endpoints, validates the issuer/path/query/state
binding, and follows exactly one redirect hop with AsyncHTTPClient redirect
following disabled. External issuers, unexpected paths, fragments, modes, and
redirect targets fail closed.

The new regression test
`SwanInteropTests.testReferenceOAuthProviderUsesSameOriginJSONCSRFAndEphemeralBearer`
passes in the serialized macOS interop selection (91 tests, 0 failures) and
asserts the JSON bodies, CSRF/referrer headers, ephemeral bearer, navigation
headers, cookie, and 303 location.

A fresh account on the pinned TypeScript PDS then exercised the current Swan
release image through the Caddy/Toxiproxy network. The first probe correctly
rejected an `atproto`-only token at the PDS's collection authorization layer;
the corrected probe requested `atproto` plus
`repo:app.bsky.feed.post?action=create&action=update` and used a valid TID
record key. The sanitized artifact
`.interop-live/reference-oauth-public.SMYhmU/artifact.json` reports:

- OAuth authorization code, PKCE, DPoP, JSON sign-in, CSRF, consent, and 303
  redirect completion;
- reference `com.atproto.repo.putRecord`: HTTP 200;
- reference `com.atproto.repo.getRecord`: HTTP 200;
- matching canonical record CID and `converged: true`; and
- no account handle, password, bearer token, DPoP proof, or record value.

The tracked public fixture uses the valid TID `3jzfcwq7jrs2a`. This closes the
reference OAuth browser/provider and public write/read witness for the current
profile. It does not close the stock value-bearing `listRepoOps`/`getRepo`
upstream gap, cross-host corrupted/compaction fault matrix, reverse-authority
account/browser lifecycle, password-reset contention, or native-Linux live
profile evidence.

## Adversarial rereview: restart image identity and descriptor-safe overlay check — 2026-08-01

The restarted `swan-alpha-current-20260801` project initially retained a
recovery-qualified reference image under the default service tag. The image
identity was checked inside the container rather than inferred from its tag:
the running image contained the overlay `getRepo` implementation, while the
stock image contained the pinned branch's `MethodNotImplementedError` handler.
The stock image was restored under the project service tag and only the
`reference-pds` container was recreated, preserving its named data volume.
The recreated container is healthy, its source marker is the stock pinned
implementation, and the public `pds.test` describe-server route returns HTTP
200 through Caddy/Toxiproxy.

The source-only overlay qualification also exposed a local resource hazard:
its integrity check recursively hashed the pinned checkout's pnpm
`node_modules` hard-link farm. That could open enough files to reproduce the
host's descriptor-pressure failure. The check now hashes only the four files
touched by the checked-in patch, while the overlay copier already excludes
`node_modules`; `interop/reference-pds-overlay/test-reference-pds-overlay.sh`
passes without a recursive dependency-tree walk.

This closes the lab image-identity and overlay-test resource seams. It does
not turn the stock pinned value-bearing endpoints into an implementation, and
does not close the broader cross-host fault or lifecycle gates.

## Adversarial rereview: qualified stateful member matrix on the rebuilt Swan — 2026-08-02

The current Swan image was run against the explicitly qualified reference-PDS
overlay in member direction. The sanitized artifact
`/private/tmp/swan-qualified-stateful-member-20260802.json` reports a passed
credential exchange, permissioned write/read CID convergence, value-bearing
incremental sync, signed commit verification, two-root full-CAR recovery, and
matching sync/full-CAR commitments and revisions. Its 26 assertions all pass;
the artifact contains no password, bearer, DPoP, access-token, or permissioned
record value.

The qualified image was then removed from the current service tag and the
stock pinned image was restored. Both current HTTPS describe-server routes
remain HTTP 200 and both Swan and reference-PDS containers are healthy.

The run also showed that the current Compose project must select its existing
`swan-data-v2` encrypted volume explicitly. A checked-in external-volume
override now makes that selection auditable without copying or deleting either
volume; the older `swan-data` volume fails the key-envelope/secret lineage
check and is not used for current evidence.

This closes a qualified cross-host stateful member witness on the rebuilt
Swan and the persistence-selection seam. It remains qualified overlay
evidence, not stock TypeScript evidence; authority-direction recovery,
fault-injection, reverse lifecycle, and the stock value-bearing upstream gap
remain open.

The same qualified stateful matrix was then run with authority placement
reversed. `/private/tmp/swan-qualified-stateful-authority-20260802.json`
reports 26/26 assertions passed, including dynamic credential/key resolution,
value-bearing incremental sync, signed commit verification, full-CAR recovery,
and equal sync/full-CAR commitments and revisions. Its sanitized bytes contain
none of the checked credential or value markers. The reference service was
restored to the stock image afterward and verified by its source marker.

## Adversarial rereview: explicit reference full-CAR fallback — 2026-08-02

The first cross-host recovery attempt was intentionally retained as a failure:
the stock pinned TypeScript `listRepoOps` handler returned HTTP 200 for the old
cursor and never emits `full_repo_recovery_required`. The failure artifact
reported `RetentionGapMissing`; no receiver state was published. This is a
behavioral limitation of the pinned branch, not a reason to relabel a normal
200 response as a retention gap.

Swan now has an explicit `--allow-full-car-fallback` recovery flag. It remains
off by default and the strict command still requires HTTP 409 with the exact
`full_repo_recovery_required` error. When deliberately enabled for the
qualified reference overlay, a successful value-bearing `listRepoOps` response
may select the cryptographically verified full-CAR installer. The sanitized
artifact records `gapFallbackUsed: true`; the strict
`validate-permissioned-recovery-artifact.py` validator rejects that artifact as
retention-gap evidence.

The rebuilt Linux image then completed the cross-host fallback run against the
checksummed recovery overlay. The mode-0600 artifact
`/private/tmp/swan-qualified-cross-host-recovery-fallback-20260802.json` has
26/26 live assertions passed, `gapStatus: 200`,
`gapFallbackUsed: true`, a verified full-CAR install, deterministic
`CARBlockCIDMismatch` rejection of the corrupted retry, and preservation of the
last valid head. It contains no passwords, bearer/access tokens, DPoP material,
or permissioned record values. This closes cross-host full-CAR transfer and
corruption rejection for the qualified overlay only; it does not close the
stock TypeScript retention-gap signal or the native-Linux/fault/lifecycle
gates. The reference service was restored to the stock image and Swan was left
on the rebuilt current image afterward.

The focused artifact suite passes 7/7 and the shell validator/mutation suite
passes. During verification, a disposable isolated SwiftPM scratch graph
filled the host filesystem and caused `swiftc -print-target-info` to fail with
OS error 28. Only that exact scratch directory was removed, recovering about
2.4 GiB; no Docker volumes or Swan data were deleted.

## Adversarial rereview: successor profile pin and stock fault receipt — 2026-08-02

The active successor profile now explicitly records the pinned TypeScript
retention-gap behavior: its `listRepoOps` handler returns a successful page for
an old cursor and the pinned `getRepo` handler remains unavailable. The profile
SHA changed accordingly, so the Swift offline verifier and wire-generation
preflight were updated together; a first `SwanInteropTests` run failed on the
stale pin, and the corrected run passed 92/92. Pinned Swift/public-wire
regeneration and mutation suites, profile verification, and
`PublicRepositoryReadHTTPTests` 13/13 also pass.

The restarted stock-reference run reached credential issuance and permissioned
write/read with matching CIDs, then reproduced HTTP 500 for value-bearing
`listRepoOps` and HTTP 501 for `getRepo`. The sanitized mode-0600 failure
artifact is `/private/tmp/swan-stock-member-current-20260802.json.failed`; no
credentials, tokens, proofs, or record values were retained.

A disposable CA-trusted Swan runner executed the live profile endpoint matrix
through Caddy/Toxiproxy for normal, delayed, duplicated, reordered, offline,
disconnected, and corrupted modes. All seven matrix artifacts reported
`passed`, the two HTTPS describe-server routes remained HTTP 200, and the lab
services remained healthy. This closes a live transport/fault-topology receipt,
not the stock TypeScript value-bearing or compaction-gap semantic gate.

## Adversarial rereview: restart-safe suite and persisted fault artifacts — 2026-08-02

The restarted lab was kept on one active SwiftPM process. A final
`swift test --skip-build --jobs 1` exited 0 after covering every test product:
935 XCTest cases passed with 8 skips, and the four Swift Testing public-wire
cases passed. No failure was hidden by a shell wrapper; the exit status was
captured separately from the tail log.

The profile fault matrix was rerun through a disposable CA-trusted Swan
runner. A first host bind was not durable under Colima, so the rerun used an
exact named Docker volume, copied the seven sanitized JSON artifacts out after
completion, changed them to mode 0600, and removed the temporary volume. The
artifacts in `/private/tmp/swan-stock-fault-matrix-20260802/` all report
`status: passed` for normal, delayed, duplicated, reordered, offline,
disconnected, and corrupted traffic. This is stronger custody evidence for
the existing transport receipt, not a stateful semantic acceptance: no
value-bearing stock TypeScript sync, compaction-gap recovery, or reverse
lifecycle gate is being inferred from it. The Swan and reference HTTPS routes
remained HTTP 200 and the Compose services remained healthy after the run.

## Adversarial rereview: public blob metadata and commit-time isolation fence — 2026-08-02

The review compared Swan's public record mutation path with the pinned
TypeScript `verifyBlob` behavior. Swan previously checked only that a raw CID
was publicly reachable; a caller could therefore submit a structurally valid
typed blob object whose claimed `mimeType` or `size` differed from the stored
blob metadata. The HTTP path now performs a metadata-only lookup and rejects
both mismatches before signing. The lookup does not open or materialize the
blob body. `PublicRepositoryMutationHTTPTests` covers the valid case plus
wrong-size and wrong-MIME cases.

The same review found a public/private isolation race: permissioned promotion
can remove the last public namespace reference after an HTTP preflight but
before the public repository transaction commits. Prepared public mutations
now carry their raw blob CID requirements, and SQLite rechecks those CIDs while
the repository commit transaction is serialized against permissioned
promotion. A missing reference returns `BlobNotFound` and the public index is
unchanged. `PublicRepositoryMutationStoreTests` proves the commit-time fence
by removing the reference after preparation and asserting the typed storage
failure.

Evidence from the current macOS working copy:

- A fresh serialized SwiftPM graph (`--scratch-path
  /private/tmp/swan-adversarial-review-20260802-2 --jobs 1`) built successfully
  in 448.51 seconds;
- `PublicRepositoryMutationStoreTests`: 13/13, 0 failures;
- `PublicRepositoryMutationHTTPTests`: 6/6, 0 failures;
- `PublicRepositoryReadHTTPTests`: 13/13, 0 failures; and
- `PublicRepositoryEngineTests`: 9/9, 0 failures;
- recovery and interop verifier mutation suites: passed; and
- `git diff --check`: passed.

This closes the two local blob integrity/isolation findings. It does not
upgrade the stock pinned TypeScript value-bearing `listRepoOps`/`getRepo`
surfaces, and it does not close the broader native-Linux/current-profile,
fault/compaction, reverse-lifecycle, password-reset, or formal-security gates.

## Adversarial rereview: current full-suite regression and repair — 2026-08-02

The first full current-commit run caught one fixture regression introduced by
the strict typed-blob metadata fence: a storage test created a public blob
without MIME metadata and then asserted a typed `application/octet-stream`
record. The production path correctly rejected that mismatch. The fixture now
stores the declared MIME metadata explicitly.

Evidence after the repair:

- `PermissionedBlobRepositoryReachabilityTests`: 5/5, 0 failures;
- the complete serialized macOS `swift test --skip-build --jobs 1`: exit 0;
- every XCTest product passed, and all four Swift Testing public-wire cases
  passed; and
- the only shell failure encountered while capturing the first focused result
  was the zsh special variable name `status`, not SwiftPM or test execution.

## Adversarial rereview: current strict retention recovery and resolver boundary — 2026-08-02

The live strict recovery harness was first run with an old project-scoped
recovery image and correctly failed host artifact validation because that image
emitted a pre-successor artifact shape. The normal Compose Swan container was
restored healthy. The current project image was then retagged without changing
source or data, and the exact harness was rerun against the existing external
data volume.

The current run passed `Scripts/validate-permissioned-recovery-artifact.py` and
left the normal Swan container restored. Its mode-0600 sanitized artifact is
`/private/tmp/swan-live-recovery-current-20260802-rerun.json`; it records:

- HTTP 409 `full_repo_recovery_required` with no fallback;
- a generation-advancing replacement from one to two with revision/CAS and
  commitment agreement;
- seven recovered records in the replacement CAR;
- deterministic `CARBlockCIDMismatch` rejection; and
- preservation of the last valid head after corruption.

The artifact's declared fixture policy contains no DIDs, space URIs, paths,
request identities, verifier material, credentials, tokens, DPoP proofs,
record values, or raw LtHash state. Caddy, Swan, the pinned reference PDS/PLC,
Mailpit, and Toxiproxy were healthy after restoration. This closes the strict
Swan-host retention/full-CAR/corruption gate for the current profile; it does
not upgrade the stock TypeScript `listRepoOps`/`getRepo` gap or prove the
cross-host semantic matrix.

A fresh clean-cache macOS run was also attempted with one SwiftPM worker. It
resolved the pinned dependencies but remained for more than ten minutes in
the Xcode 27 beta `swift-crypto` manifest compiler with no progress. The
exact child compiler and scratch directory were cleaned up; the prior
serialized current-commit graph remains the authoritative green macOS test
receipt. This is a toolchain-resolution limitation, not a Swift test failure.

## Adversarial rereview: current reverse-authority dynamic credential witness — 2026-08-02

The running Compose project was restored after a fresh reverse-authority
acceptance in which the pinned TypeScript host acted as the space authority and
Swan hosted the member repository. No static credential-key pin was supplied:
Swan resolved the authority's current PLC `#atproto` key through the explicit
laboratory allowlist. The mode-0600 sanitized artifact is
`/private/tmp/swan-dynamic-reverse-current-20260802.json`.

The witness passed credential issuance, member-side permissioned blob upload,
record creation, credential-authenticated member read, blob read, and exact
write/read CID convergence. All six recorded endpoint events returned HTTP 200,
and the reverse authority/member roles are explicit in the artifact. This is
current dynamic credential/write/read evidence; it does not claim stock
value-bearing incremental/full-CAR support or the broader reverse lifecycle and
fault matrix.

## Adversarial rereview: current post-restart public round trip — 2026-08-02

After the recovery and reverse-authority harnesses restored the normal Compose
container, an isolated runner performed an OAuth-authenticated public
`com.atproto.repo.putRecord` on Swan and an unauthenticated public
`com.atproto.repo.getRecord` through the same Caddy route. Both endpoint events
returned HTTP 200, the record CIDs matched, and the sanitized artifact reports
`status: passed` and `converged: true` at
`.interop-live/public-current-20260802/artifact.json` (mode 0600). The
artifact contains only response digests, byte counts, statuses, and the
declared semantic-summary policy. This is current public-surface runtime
evidence alongside the strict permissioned recovery receipt; it does not close
the stock TypeScript recovery gap or the remaining cross-host fault/lifecycle
gates.

## Adversarial rereview: current post-restart typed public blob round trip — 2026-08-02

After the container restart, an isolated CA-trusted runner exercised the
modern typed public-blob path against the current Swan image. It uploaded the
fixture through OAuth, inserted the returned CID in a typed `blob` record,
read that record anonymously, and streamed the blob back through
`com.atproto.sync.getBlob`. Every endpoint returned HTTP 200, the write/read
record CIDs matched, and the downloaded bytes matched the upload. The
sanitized mode-0600 artifact is
`.interop-live/public-current-20260802/typed-blob-artifact.json`; it contains
only statuses, digests, byte counts, and the declared fixture policy.

This is current Swan public typed-blob evidence, including the metadata and
commit-time public/private reachability fences. It does not upgrade the stock
TypeScript value-bearing incremental/full-CAR limitation or prove the broader
cross-host fault and lifecycle matrix.

## Adversarial rereview: Xcode-toolchain clean-cache acceptance — 2026-08-02

The earlier clean-cache attempt used the shell's Swift 6.2.3 executable and
stalled in the Xcode 27 beta `swift-crypto` manifest compiler. The exact
acceptance was rerun with the installed Xcode Swift 6.4 toolchain first in
`PATH`, one SwiftPM worker, and a fresh scratch root
`/private/tmp/swan-clean-cache-current-xcode64-20260802-1`.

The run completed the isolated product build in 375.36 seconds, then built
and executed the full test graph. The script exited 0 with
`CLEAN-CACHE MACOS BUILD/TEST GATE OK`; every XCTest product passed with the
normal eight opt-in skips, and all four Swift Testing public-wire cases
passed. The only diagnostics were existing Swift 6.4 Sendable/deprecation and
local libsodium deployment-target warnings. The runner correctly reported
that it did not execute the live cross-host semantic matrix.

This closes the macOS clean-cache reproducibility gate when the Xcode 27
toolchain is selected explicitly. It does not substitute for native-Linux
host evidence, stock TypeScript value-bearing/recovery semantics, or the
remaining cross-host lifecycle/fault matrix.

The same isolated Xcode build then ran all six opt-in 256 MiB selectors
serially. All six passed: private CAR spool stress, permissioned near-256 MiB
CAR RSS/integrity/overflow rejection, public CAR spool RSS, staged public CAR
import, public production-directory `getRepo` RSS, and private CAS bounded
streaming. The permissioned CAR report streamed 267,396,722 bytes with
65,536-byte maximum chunks and a 22,233,088-byte peak RSS increase; the public
spool report streamed 270,049,433 bytes with a 15,433,728-byte RSS delta.

## Adversarial rereview: disposable Docker-Linux rebuild and capacity recovery — 2026-08-02

The clean-cache container workload copied only the pinned Swift/Compose inputs
to `/private/tmp/swan-clean-cache-linux-current-xcode64-20260802-2`, fetched the
reference cache at `3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`, and completed the
isolated Swift product build in 359.24 seconds. The no-cache Docker build then
completed all Swan, Caddy, PLC, and reference-PDS images, including a release
link of the `swan` executable. Its first fresh startup was correctly rejected
when the Colima overlay filesystem reached 100% (`98G` total, `0` available),
which surfaced as SQLite `database or disk is full` during bootstrap rather
than a misleading account failure.

Only reclaimable BuildKit cache was pruned (`9.941GB`); the active
`swan-alpha-current-20260801_swan-data-v2` volume and all normal lab resources
were preserved. With `7.9G` free in the Docker overlay, the already-built
disposable project was started without rebuilding. Every required service was
healthy or a successful one-shot: Swan, reference PDS, reference PLC, Caddy,
and Mailpit were `running 0 healthy`; Toxiproxy was `running 0`; and all init
services exited `0`. The Caddy-routed Swan `/health` endpoint returned `OK`, and
protected-resource metadata returned the expected `https://swan.test` resource
and authorization server.

This is a current Docker-on-Darwin container build/health receipt, not native
Linux-host evidence and not a successful clean-cache script exit. It also does
not upgrade the stock TypeScript value-bearing recovery gap or the remaining
stateful cross-host, lifecycle, password-reset, and formal-security gates.
