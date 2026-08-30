# Swan Security Scan Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development`. Execute independent lanes in parallel in separate `jj` workspaces; only the SQLite integration owner may land edits to `Sources/SwanSQLite/SwanSQLite.swift`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 29 validated findings from security scan `a9e1a68a-a5d5-410a-a44e-fcd3187dc23d` at revision `43e13da0`, with regression tests and a ref-diff security validation.

**Architecture:** Fix each issue at its shared trust, transaction, or resource-admission boundary. Seven subagent lanes run in parallel; work inside a lane is serial when files or interfaces overlap. One integration owner rebases lane commits and owns the final full verification.

**Tech Stack:** Swift 6, Hummingbird 2, SQLiteNIO, Petrel/PetrelCrypto, XCTest and Swift Testing, Svelte 5, TypeScript, Vitest, shell, Docker, npm lockfiles.

**Spec:** Sealed security report `/private/var/folders/f6/7_1t6xsd07j6601z9xpxxbdw0000gn/T/codex-security-scans-oZJTVw/Swan/43e13da06a7646fc38f2e4e2d4feb5fc5ce6cdc3_20260830T084300Z_qr1hrpl4/report.md` and canonical `findings.json` beside it.

## Global constraints

- Preserve Swan's security invariants: permissioned data never becomes public; read-only space credentials never become write capabilities; secrets enter only through owner-only files; authentication failures retain fixed client diagnostics.
- Treat scan findings as static evidence. Each implementation task starts with a failing behavioral regression test and does not close its finding until that test passes.
- Do not hand-edit `Sources/SwanPublicWire/Generated` or run public-wire generation.
- Reuse existing limits, admission gates, protected-file readers, transaction helpers, and retention patterns before adding code. No new third-party dependency is required.
- Use `jj` only for history mutation. Create one `jj workspace add` workspace per lane. Never use Git worktrees or mutating Git commands.
- Only the SQLite integration owner edits `Sources/SwanSQLite/SwanSQLite.swift`; other workers communicate required helper signatures and tests to that owner.
- Every task gets one scoped `jj` commit. Immediately after `jj describe -m "…"`, run `jj new` before reporting or starting another task.
- Update every caller in the same task. Do not leave deprecated overloads, environment aliases, compatibility shims, or temporary dual-acceptance paths.
- Changes that intentionally reject old insecure inputs—environment secrets, unbound service JWTs, plaintext credential transport—are clean cutovers. Emit fixed migration errors; never silently fall back.
- No production deploy, migration, restart, or external release is authorized by this plan. Those remain separate red-tier actions.

## Provisional decisions

These are reversible before merge and are recorded here because Swan has no local `docs/DECISIONS.md`.

1. **Service JWT body binding:** add optional Petrel claim `req` (`requestBodyDigest`) so generic ServiceJWT users remain source-compatible; Swan requires it for `notifyWrite` and `notifySpaceDeleted`. Old unbound tokens are rejected immediately after the coordinated Petrel/Swan cutover.
2. **Anonymous DPoP admission:** add a process-global `1,000 requests / 10 seconds` bucket in addition to the existing `600 / peer / 10 seconds` bucket. At the 300-second replay lifetime this caps anonymous contribution near 30,000 rows, below the 131,072-row replay table.
3. **Lexicon cache:** cap negative rows at 4,096 of the existing 8,192 total and evict negative rows older than one hour before capacity checks. Positive rows retain at least half the table.
4. **Firehose memory:** cap a page at four maximum frames and process-wide live page reservations at four pages. Existing row-count limits remain secondary bounds.
5. **Public repository history:** cap retained block bytes and rows at twice `PublicRepositoryLimits.standard` after an in-transaction reachability sweep. Terminal mutation receipts retain 24 hours and at most 100,000 rows, pruned in batches of 1,000.
6. **Notification ownership migration:** delete pre-fix notification registrations because their recorded service owner was not authenticated. Services re-register with service authentication; carrying attacker-selected ownership forward is unsafe. The production migration is destructive configuration cleanup and requires explicit point-of-risk approval, a backup, and an operator re-registration window before deploy.
7. **Signup admission:** reuse `SignupInviteRateAdmission`, extend it with a process-global `100 requests / 60 seconds` budget, instantiate it for production, and apply it to both invite and open-protected signup before local proof or network work.

## Finding coverage

| Canonical finding | Implementation task |
|---|---|
| 1 Environment-backed secrets | Task 1 |
| 2 Completed outbox payload retention | Task 7 |
| 3 Public repository history/receipt growth | Task 8 |
| 4 Legacy login limiter bypass | Task 3 |
| 5 Password recovery session survival | Task 2 |
| 6 `createRecord` overwrite | Task 5 |
| 7 Firehose page memory | Task 6 |
| 8 Deactivation session survival | Task 2 |
| 9 Uncancellable DNS | Task 10 |
| 10 Connected-app route unreachable | Task 4 |
| 11 Docker web-artifact shadowing | Task 16 |
| 12 Blob GC stale snapshot | Task 9 |
| 13 Stale password grant | Task 2 |
| 14 Proxy users share portal bucket | Task 3 |
| 15 Negative lexicon cache exhaustion | Task 12 |
| 16 Read credentials mutate notifications | Task 14 |
| 17 Anonymous DPoP replay exhaustion | Task 11 |
| 18 Unlocked maintenance npm graphs | Task 16 |
| 19 Replica high-water divergence | Task 15 |
| 20 Permissioned cumulative limits | Task 15 |
| 21 Notification config reopen race | Task 17 |
| 22 Full-CAR over-reservation | Task 15 |
| 23 Deletion JWT unbound | Task 14 |
| 24 Write JWT unbound | Task 14 |
| 25 Turnstile before local proof | Task 13 |
| 26 TOTP `Math.random` fallback | Task 18 |
| 27 Lab request-body reopen race | Task 17 |
| 28 Golden verifier lacks revision proof | Task 16 |
| 29 Plaintext lab credentials | Task 17 |

## Parallel execution lanes

| Lane | Owner | Serial task order | May run with |
|---|---|---|---|
| A | Configuration/interop subagent | 1 → 17 | B–G |
| B | Account-auth subagent | 2 → 3 → 4 → 13 | A, C–G |
| C | Public-HTTP subagent | 5 → 6 | A, B, D–G |
| D | SQLite integration subagent | 7 → 8 → 9 → 15 → storage half of 14 | A–C, E–G |
| E | Network/OAuth subagents | 10, 11, and 12 in parallel | A–D, F, G |
| F | Space-protocol subagent | Petrel half of 14 → Swan HTTP/OAuth half of 14 | A–E, G |
| G | Supply-chain/frontend subagents | 16 and 18 in parallel | A–F |

The integration owner creates the workspaces, pins every lane to `43e13da0`, records resulting commit IDs, and rebases them in the dependency order shown above. Lane D applies all `SwanSQLite.swift` changes itself; Lane F sends the required storage contract to Lane D before Task 14 starts.

---

### Task 1: Remove every secret environment fallback

**Findings:** 1.

**Files:**
- Modify: `Sources/SwanAccounts/AccountProvisioningSecrets.swift`
- Modify: `Sources/SwanAccounts/AccountOperatorService.swift`
- Modify: `Sources/swan/SwanCommand.swift`
- Test: `Tests/SwanAccountsTests/SwanAccountsTests.swift`
- Test: `Tests/SwanCLITests/AccountOperatorServiceTests.swift`
- Test: `Tests/SwanCLITests/ServeLocalSpaceInteropCLITests.swift`

**Interfaces:**
- Consume existing `requiredMountedAccountKeyConfiguration`, `requiredMounted32ByteSecret`, `readOAuthServerKeyFile`, and `readBoundedRegularFileNoFollow`.
- Produce file-only `--*-token-file` and `--*-password-file` lab options.

- [ ] **Write failing tests.** Prove `SWAN_ACCOUNT_KEK`, `SWAN_OPERATOR_SECRET`, and `SWAN_OAUTH_SERVER_KEY` alone cannot start their consumers; bearer/password lab modes require their corresponding file option; owner/mode/symlink/oversize failures remain fixed diagnostics.
- [ ] **Run:** `swift test --filter SwanAccountsTests`, `swift test --filter AccountOperatorServiceTests`, and `swift test --filter ServeLocalSpaceInteropCLITests`. **Expected:** new environment-only cases fail because current loaders accept them.
- [ ] **Delete environment APIs and dead helpers.** Remove `kekEnvironmentName`, both `accountKeyConfiguration` environment overloads, environment-only KEK decode/compare helpers, and `OperatorSecretResolver` environment overloads. Repoint all callers to `requiredMountedAccountKeyConfiguration`.
- [ ] **Cut over CLI configuration.** Require `--oauth-server-key-file`; remove `SWAN_OAUTH_SERVER_KEY` help text. Rename all lab token/password `--*-env` options to `--*-file`, read through one owner-only no-follow descriptor with a 4 KiB cap, and leave non-secret URL/handle/public-key environment configuration unchanged.
- [ ] **Run focused suites and build:** `swift test --filter SwanAccountsTests && swift test --filter SwanCLITests && swift build`.
- [ ] **Commit:** `jj describe -m "Swan: require owner-only files for every secret" && jj new`.

### Task 2: Revoke all sessions and stale password grants

**Findings:** 5, 8, 13.

**Files:**
- Modify: `Sources/SwanSQLite/AccountControlStore.swift`
- Modify: `Sources/SwanSQLite/AccountPortalSessionStore.swift`
- Modify: `Sources/SwanSQLite/AccountFactorStore.swift`
- Modify: `Sources/SwanAccounts/DurableAccountDirectory.swift`
- Modify: `Sources/SwanStorage/AccountIdentitySessionFactorContracts.swift`
- Test: `Tests/SwanSQLiteTests/PasswordRecoveryCompletionSQLiteTests.swift`
- Test: `Tests/SwanSQLiteTests/AccountPortalSessionStoreTests.swift`
- Test: `Tests/SwanAccountsTests/Task7MFATests.swift`
- Test: `Tests/SwanSQLiteTests/AccountAuthorizationLeaseTests.swift`

**Interfaces:**
```swift
func revokeManagementSessions(accountDID: String, now: Date) async throws
```
The password authorization grant stores `credential_revision`, copied from the account's monotonic `updated_at`, and consumption requires an exact current match.

- [ ] **Write failing tests.** After password recovery, reject pre-existing OAuth, legacy access/refresh, management-cookie, CSRF, and step-up authority. After deactivate/reactivate, reject every old management cookie. Issue a password grant, recover the password, then prove grant consumption creates no legacy family.
- [ ] **Run:** `swift test --filter PasswordRecoveryCompletionSQLiteTests`, `swift test --filter AccountPortalSessionStoreTests`, `swift test --filter Task7MFATests`, and `swift test --filter AccountAuthorizationLeaseTests`. **Expected:** old management/legacy sessions and the stale grant still work.
- [ ] **Add one account-wide revocation helper** inside the existing control-store transaction. Revoke OAuth families, legacy families/tokens, and all `management_sessions` for `account_did` with `revoked_at = COALESCE(revoked_at, ?)`. Call it from password recovery and every transition to an inactive account state; never un-revoke on activation.
- [ ] **Bind grants to credentials.** Add `credential_revision` to `account_authorization_grants`, backfill old rows to a non-matching fail-closed value, store `accounts.updated_at` at issuance, and add the revision equality predicate to the same `UPDATE … RETURNING` that consumes the grant.
- [ ] **Run the four focused suites and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanAccounts: invalidate every credential on recovery and deactivation" && jj new`.

### Task 3: Reuse durable admission for every password login

**Findings:** 4, 14.

**Files:**
- Modify: `Sources/SwanAccounts/AccountLoginAdmission.swift`
- Modify: `Sources/SwanHTTP/SwanLegacySessionXRPC.swift`
- Modify: `Sources/SwanHTTP/SwanAccountPortalHTTP.swift`
- Modify: `Sources/swan/SwanCommand.swift`
- Test: `Tests/SwanAccountsTests/AccountLoginHardeningTests.swift`
- Test: `Tests/SwanHTTPTests/SwanLegacySessionXRPCTests.swift`
- Test: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`

- [ ] **Write failing tests.** Whitespace/case aliases consume one account bucket; high-cardinality unknown identifiers cannot exceed peer/global Argon2 admission; trusted-proxy users get distinct buckets; an untrusted peer cannot spoof `X-Swan-Client-IP`; malformed trusted headers fail closed.
- [ ] **Run the three focused suites. Expected:** alias and proxy cases demonstrate the bypass/collapse.
- [ ] **Canonicalize once.** In `AccountLoginAdmissionService.admit`, trim first, canonicalize handle or DID, otherwise use the bounded unknown sentinel.
- [ ] **Delete `SwanInProcessLegacySessionRateLimiter`.** Resolve the peer through `SwanLoginClientIdentityPolicy`, then call the existing durable `DurableAccountDirectory.admitLogin` before Argon2 work.
- [ ] **Inject `SwanLoginClientIdentityPolicy` into `SwanAccountPortalHTTP`.** Resolve it at all login and mutation-context sites, not only the cited helper. Direct mode keeps current behavior when no proxy is configured.
- [ ] **Run focused suites and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanHTTP: unify login identity and durable admission" && jj new`.

### Task 4: Register the connected-app revocation route

**Findings:** 10.

**Files:**
- Modify: `Sources/SwanHTTP/SwanAccountPortalHTTP.swift`
- Test: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
- Test: `web/src/lib/api.test.ts`

- [ ] **Write a failing HTTP test** for authenticated, CSRF- and step-up-protected `DELETE /account/api/connected-apps/{id}` and assert only the selected OAuth family is revoked.
- [ ] **Run:** `swift test --filter AccountPortalSecurityHTTPTests`. **Expected:** 404 before the service branch runs.
- [ ] **Add `connected-apps` to the existing identifier-bearing DELETE prefix list.** Do not change the frontend path or service mutation code.
- [ ] **Run:** `swift test --filter AccountPortalSecurityHTTPTests && npm --prefix web test -- api.test.ts`.
- [ ] **Commit:** `jj describe -m "SwanHTTP: expose connected-app revocation" && jj new`.

### Task 5: Make public create atomic and create-only

**Findings:** 6.

**Files:**
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationCoordinator.swift`
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryMutationStoreTests.swift`
- Test: `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift`

**Interface:** add `SwanPublicRepositoryMutationCoordinator.create(...)`, implemented with `PublicRepositoryWrite.create`, plus `recordAlreadyExists` error mapping.

- [ ] **Write failing tests.** A create-scoped principal targets an occupied rkey and receives `400 InvalidRequest`; repository head, record CID, blocks, receipt, and firehose outbox remain unchanged.
- [ ] **Run both focused suites. Expected:** current `put` path commits an update before rejecting.
- [ ] **Implement `create`.** Use the Petrel engine's existing in-transaction `.create` absence check on every retry. Keep a preflight absence check only for a cheap early error. Map Petrel's `recordAlreadyExists` to Swan's stable client error.
- [ ] **Switch only `createRecord` to `.create`.** Leave `putRecord` as upsert and leave `applyWrites`' already-correct create mapping unchanged.
- [ ] **Run:** `swift test --filter PublicRepositoryMutationStoreTests && swift test --filter PublicRepositoryMutationHTTPTests && swift build`.
- [ ] **Commit:** `jj describe -m "SwanHTTP: enforce create-only repository mutations" && jj new`.

### Task 6: Bound firehose pages before materialization

**Findings:** 7.

**Files:**
- Modify: `Sources/SwanHTTP/PublicFirehoseStreaming.swift`
- Modify: `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift`
- Test: `Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift`
- Test: `Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift`

- [ ] **Write failing tests.** A lagging cursor is rejected before `events` is called; selected frame bytes never exceed four `FirehoseFrameLimits.maximumFrameBytes`; concurrent connections cannot reserve more than four pages; every disconnect/error releases its reservation.
- [ ] **Run the two focused suites. Expected:** current code fetches first and row count alone permits oversized pages.
- [ ] **Move lag checks before fetch.** Use `maxSequencedSeq()` to distinguish no data; preserve the post-fetch empty-page branch for deletion gaps.
- [ ] **Add byte-bounded selection.** `events(after:limit:maximumBytes:)` first reads `seq,length(frame_bytes)`, chooses the largest prefix under the byte budget while always allowing one valid frame, then materializes only that prefix.
- [ ] **Add process-wide page admission** in `PublicFirehoseStreaming.swift` using the existing lock/lease pattern: four page leases, each reserving four maximum frames. Hold the lease through delivery and release on cancellation or disconnect.
- [ ] **Update every `events(after:)` caller, run focused suites, then:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanFirehose: bound page bytes before loading frames" && jj new`.

### Task 7: Compact completed firehose outbox rows

**Findings:** 2.

**Files:**
- Modify: `Sources/SwanSQLite/SwanSQLite.swift`
- Modify: `Sources/SwanSQLite/PublicFirehoseOutboxStore.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseOutboxStoreTests.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseCommitEnqueueTests.swift`

- [ ] **Write failing tests.** Completion nulls payload/CAR bytes but exact replay still matches by digest; changed material conflicts; migration compacts pre-existing completed rows; a pre-completion crash retains exact replay bytes.
- [ ] **Run both focused suites. Expected:** completed bytes remain non-null indefinitely.
- [ ] **Add a crash-atomic shadow-table migration.** Make payload/CAR nullable, add 32-byte SHA-256 digest columns, enforce pending rows have bytes and completed rows do not, backfill in 1,000-row pages, and compact existing completed rows.
- [ ] **Write digests at enqueue and null bytes at completion.** Pending lease/sequencer queries keep full bytes; completed replay compares digests.
- [ ] **Run both focused suites and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanSQLite: compact completed firehose outbox payloads" && jj new`.

### Task 8: Bound and reclaim public repository history

**Findings:** 3.

**Files:**
- Modify: `Sources/SwanStorage/SwanStorage.swift`
- Modify: `Sources/SwanStorage/PublicRepositoryStore.swift`
- Modify: `Sources/SwanSQLite/PublicRepositoryStore.swift`
- Modify: `Sources/SwanSQLite/PublicRepositoryBoundedExport.swift`
- Modify: `Sources/SwanSQLite/SwanSQLite.swift`
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationCoordinator.swift`
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryRecordCeilingTests.swift`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryMutationStoreTests.swift`
- Create test: `Tests/SwanSQLiteTests/PublicRepositoryBlockGarbageCollectionTests.swift`
- Create test: `Tests/SwanSQLiteTests/PublicRepositoryReceiptRetentionTests.swift`

- [ ] **Write failing tests.** Repeated bounded writes stop at cumulative block count/bytes; quota rejection rolls back record index, state, receipt, and outbox; superseded blocks are reclaimed while every current-root block survives export; terminal receipts obey age/row bounds; reserved receipts are retained; restart/open performs bounded cleanup.
- [ ] **Run the four focused suites. Expected:** retained blocks and terminal receipts grow without bound.
- [ ] **Add `PublicRepositoryBlockQuota`** with defaults of twice `PublicRepositoryLimits.standard.maximumCARBytes` and twice `maximumCARBlocks`. Inside the mutation transaction, if inserts cross the quota, run the canonical export reachability walk, delete unreachable blocks in 1,000-row pages, remeasure, and reject atomically if still over.
- [ ] **Factor one reachability walk** from `PublicRepositoryBoundedExport.swift`; use it for export and GC so the definitions cannot drift. Run bounded GC on account-database open and when quota pressure triggers it. Reachability calculation and delete stay inside one write transaction.
- [ ] **Bound receipts without a new timer service.** Add/backfill `created_at`, prune terminal `committed`/`abandoned` receipts older than 24 hours or beyond 100,000 rows in 1,000-row batches during database open and reservation. Never prune `reserved` rows.
- [ ] **Map quota exhaustion to one stable XRPC error** and update all coordinator callers.
- [ ] **Run the four focused suites plus:** `swift test --filter PublicRepositoryReadHTTPTests && swift build`.
- [ ] **Commit:** `jj describe -m "SwanSQLite: bound public repository history and receipts" && jj new`.

### Task 9: Recheck public blob reachability inside deletion

**Findings:** 12.

**Files:**
- Modify: `Sources/SwanSQLite/SwanSQLite.swift`
- Test: `Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift`
- Create test if separation is clearer: `Tests/SwanSQLiteTests/PublicBlobGarbageCollectionTests.swift`

- [ ] **Write a failing race test.** Pause after sweep selection, commit a record that references the candidate CID, resume, and prove public edge/payload survive. Also prove a truly unreachable candidate is reclaimed.
- [ ] **Run the focused test. Expected:** stale in-memory reachability permits deletion.
- [ ] **Fix `removeBlobReference`.** For `.public`, call existing `publicRepositoryContainsBlobCIDWithoutGate` inside the same `BEGIN IMMEDIATE` transaction immediately before deleting the edge. On projection error, retain the edge.
- [ ] **Run focused tests and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanSQLite: recheck blob reachability before deletion" && jj new`.

### Task 10: Bound blocking DNS work and make deadlines honest

**Findings:** 9.

**Files:**
- Create: `Sources/SwanCore/SwanDeadlineRace.swift`
- Modify: `Sources/SwanAccounts/ATHandleVerification.swift`
- Modify: `Sources/SwanCore/OAuthScopes/SwanLexiconResolution.swift`
- Test: `Tests/SwanAccountsTests/ATHandleVerificationTests.swift`
- Test: `Tests/SwanOAuthTests/OAuthLexiconScopeResolutionTests.swift`

**Interface:** `swanRaceWithDeadline<T: Sendable>(seconds:onExpiry:operation:) async throws -> T`.

- [ ] **Write failing tests.** A never-returning operation does not hold `SwanLexiconDeadline` past its deadline; stalled resolver work is limited to eight active and 128 queued operations; cancelled waiters leave the queue; failure paths release slots.
- [ ] **Run focused suites. Expected:** task-group deadline waits for blocked children and the serial GCD queue grows unbounded.
- [ ] **Move the proven unstructured deadline relay** from `ATHandleVerification.swift` into `SwanDeadlineRace.swift`; delegate both handle and lexicon deadlines to it and delete the structured task-group race.
- [ ] **Add cancellation-aware counting admission** around blocking TXT/address calls: eight active workers and 128 queued waiters. Dispatch admitted calls on the global utility queue and release only when the OS call actually exits.
- [ ] **Run:** `swift test --filter ATHandleVerificationTests && swift test --filter OAuthLexiconScopeResolutionTests && swift build`.
- [ ] **Commit:** `jj describe -m "SwanCore: bound DNS workers and deadline races" && jj new`.

### Task 11: Add an aggregate anonymous OAuth budget

**Findings:** 17.

**Files:**
- Modify: `Sources/SwanAccounts/AccountLoginAdmission.swift`
- Test: `Tests/SwanAccountsTests/AccountLoginHardeningTests.swift`

- [ ] **Write failing tests.** Many individually-under-budget peers hit the aggregate 1,000/10-second ceiling; a global refusal does not consume that peer's own bucket; unidentified peers also charge the global bucket; the window reopens.
- [ ] **Run:** `swift test --filter AccountLoginHardeningTests`. **Expected:** distinct peers can exceed the replay table's safe aggregate rate.
- [ ] **Extend `OAuthPeerAdmissionPolicy`** with `globalAttempts = 1_000`. In `admit`, check global and peer buckets without mutation, then increment both only if both admit. Preserve global JTI replay semantics and existing purge-before-insert storage logic.
- [ ] **Run focused tests and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanOAuth: cap aggregate anonymous proof admission" && jj new`.

### Task 12: Evict negative lexicons and reserve positive capacity

**Findings:** 15.

**Files:**
- Modify: `Sources/SwanSQLite/OAuthLexiconDocumentStore.swift`
- Test: `Tests/SwanInteropTests/SwanLexiconResolverAdversarialTests.swift`
- Test: `Tests/SwanOAuthTests/OAuthLexiconScopeResolutionTests.swift`

- [ ] **Write failing tests.** Expired negatives are evicted before positive insertion; negative rows stop at 4,096; converting one NSID from negative to positive frees a negative slot; positives are never purged by negative cleanup.
- [ ] **Run focused suites. Expected:** failed NSIDs permanently consume the shared 8,192-row ceiling.
- [ ] **Inside `storeLexicon`'s transaction**, delete at most 512 negative rows older than one hour before capacity checks. Enforce the 4,096 negative-only ceiling before the existing total ceiling; updates to an existing NSID remain allowed.
- [ ] **Run focused suites and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanSQLite: bound negative lexicon cache entries" && jj new`.

### Task 13: Admit signup before proof and Turnstile work

**Findings:** 25.

**Files:**
- Modify: `Sources/SwanAccounts/Task4Onboarding.swift`
- Modify: `Sources/swan/SwanCommand.swift`
- Test: `Tests/SwanAccountsTests/Task4OnboardingTests.swift`

- [ ] **Write failing tests.** Wrong/missing local email proof causes zero Turnstile calls; open-protected attempts obey per-peer and global admission; valid proof plus valid Turnstile succeeds; invite behavior remains unchanged.
- [ ] **Run:** `swift test --filter Task4OnboardingTests`. **Expected:** Turnstile runs before the local proof and production has no rate-admission object.
- [ ] **Extend `SignupInviteRateAdmission`** with a 100/60-second process-global bucket, using check-then-commit so one refusal does not consume another bucket.
- [ ] **Instantiate it in `SwanCommand`** and pass it to production `SignupService` for invite and open-protected policies.
- [ ] **Order `SignupService.authorize`:** cheap structural checks → rate admission → local email-proof verification → Turnstile → durable reservation.
- [ ] **Run focused tests and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanAccounts: admit signup before outbound verification" && jj new`.

### Task 14: Authenticate notification owners and bind service JWT bodies

**Findings:** 16, 23, 24.

**Repositories:** Petrel first, then Swan.

**Petrel files:**
- Modify: `../Petrel/Sources/PetrelCrypto/ServiceJWT.swift`
- Modify matching Petrel tests for `ServiceJWT` claims and verification.

**Swan files:**
- Modify: `Package.swift` and `Package.resolved`
- Modify: `Sources/SwanOAuth/SpaceServiceAuthentication.swift`
- Modify: `Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift`
- Modify: `Sources/SwanSQLite/SwanSQLite.swift`
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`
- Test: `Tests/SwanOAuthTests/SwanOAuthTests.swift`
- Test: `Tests/SwanHTTPTests/SpaceNotificationHTTPTests.swift`
- Test: `Tests/SwanSQLiteTests/SpaceNotificationSQLiteTests.swift`
- Test: `Tests/SwanOAuthTests/TypeScriptSpaceNotificationContractTests.swift`

**Interfaces:**
```swift
// Petrel JWT claim key: "req"
public let requestBodyDigest: String?

func authenticate(
    token: String,
    expectedAudience: String?,
    expectedMethod: String,
    expectedRequestBodyDigest: String?
) async throws -> VerifiedSpaceServiceAuthentication
```
Canonical digests are domain-separated, length-prefixed SHA-256 tuples:
- deletion: `swan.space.notify-deleted.v1`, space URI;
- write: `swan.space.notify-write.v1`, space URI, repo DID, revision, raw commitment.

- [ ] **Petrel: write failing claim tests.** Verify `req` round-trips, participates in signatures, and any changed digest fails verification while generic callers may omit it.
- [ ] **Petrel: implement `requestBodyDigest`, run `swift test`, commit in the Petrel repo, push a feature bookmark, and record the immutable revision.** No package release is required.
- [ ] **Swan: write failing tests.** Every register/unregister requires a dedicated service-auth header; issuer must match body service when present; one service cannot replace/delete another's row; pre-fix registrations are cleared; changing space/repo/revision/commitment invalidates JWT; identical retransmission remains idempotent; one `(issuer,jti)` cannot target two spaces.
- [ ] **Bump Swan's Petrel pin** to the committed revision and update `Package.resolved` through SwiftPM, not by hand-editing generated code.
- [ ] **Require two factors for notification mutation.** Keep the read-only space credential in `Authorization`; require service JWT in `Atproto-Service-Auth` for every register/unregister. Derive `service_did` from the verified issuer, match an optional body service, and enforce owner equality inside the storage transaction.
- [ ] **Migrate ownership safely.** Delete existing `permissioned_space_notification_registrations` during the additive migration because old owner fields are unauthenticated.
- [ ] **Bind destructive/write requests.** Require Petrel's `req` digest in issuers and verifiers before high-water or deletion mutation. Add global `(issuer,eventID)` single-use storage for write/deletion service events, preserving identical-body idempotency.
- [ ] **Update every local issuer/caller and TypeScript contract fixture** in the same cutover; no acceptance of unbound tokens remains.
- [ ] **Run:** `swift test --filter SpaceNotificationHTTPTests && swift test --filter SpaceNotificationSQLiteTests && swift test --filter SwanOAuthTests && swift test --filter TypeScriptSpaceNotificationContractTests && swift build`.
- [ ] **Commit:** `jj describe -m "SwanSpaces: authenticate notification owners and bind service requests" && jj new`.

### Task 15: Keep permissioned state recoverable and monotonic

**Findings:** 19, 20, 22.

**Files:**
- Modify: `Sources/SwanSQLite/SwanSQLite.swift`
- Modify: `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaIncremental.swift`
- Modify: `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift`
- Modify: `Sources/SwanSpaces/SwanSpaces.swift` only if a private measurement type belongs with existing limits
- Test: `Tests/SwanSQLiteTests/PermissionedRemoteReplicaRecoverySQLiteTests.swift`
- Test: `Tests/SwanSQLiteTests/PermissionedRepositoryCARStreamingTests.swift`
- Test: `Tests/SwanInteropTests/PermissionedRemoteReplicaIncrementalVerifierTests.swift`

- [ ] **Write failing tests.** Incremental revision N rejects full recovery N−1 and conflicting N; repeated writes cannot make state unexportable; existing over-limit state accepts only count/byte-reducing updates/deletes; tiny CARs reserve measured bytes; cancellation/error releases the exact lease.
- [ ] **Run the three focused suites. Expected:** incremental state and recovery high-water diverge, cumulative writes cross export ceilings, and every CAR reserves the worst case.
- [ ] **Factor `advanceWriterHighWater`.** Call it inside existing transactions from live notification, incremental apply, and both full-recovery finalize paths. Lower revision is a no-op; same revision/different commitment is equivocation and rolls back.
- [ ] **Add exact cumulative usage preflight inside `apply`.** Read current count/value bytes and each touched record's old length once; apply create/update/delete deltas in request order. Reject projected count above `SpaceCARProductionLimits.maximumRecordCount` or bytes above `SpaceCARRecoveryLimits.absoluteMaximumLogicalRestoredBytes`. If legacy state starts over a ceiling, permit only a transaction that strictly reduces every exceeded dimension; this is the bounded recovery path.
- [ ] **Measure before reserving CAR memory.** Extend the existing admission aggregate with total value bytes and logical metadata, reserve that measured upper bound plus the existing recovery prefix, and hold/release the lease through stream completion, disconnect, cancellation, and errors.
- [ ] **Run the three focused suites and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanSQLite: preserve permissioned recovery ceilings and high-water" && jj new`.

### Task 16: Make release and maintenance inputs immutable

**Findings:** 11, 18, 28.

**Files:**
- Modify: `Dockerfile.dockerignore`
- Modify: `Scripts/build-browser-css.sh`
- Create: `Scripts/browser-css-tooling/package.json`
- Create: `Scripts/browser-css-tooling/package-lock.json`
- Modify: `Scripts/upstream-scope-goldens/verify-corpus-zero-diff.sh`
- Create: `Scripts/upstream-scope-goldens/package.json`
- Create: `Scripts/upstream-scope-goldens/package-lock.json`
- Modify: `Scripts/upstream-scope-goldens/README.md`
- Modify: `Scripts/verify-interop-lab.sh`
- Test: `Tests/SwanOAuthTests/UpstreamScopeCorpusIntegrityTests.swift`

**Pinned maintenance versions:** browser CSS uses `tailwindcss 4.3.3`, `@tailwindcss/cli 4.3.3`, `daisyui 5.7.19`; upstream scope tooling uses `zod 3.24.2`, `iso-datestring-validator 2.2.2`, `multiformats 13.4.2`.

- [ ] **Write failing integrity tests.** Docker context excludes `web/node_modules`, `.svelte-kit`, `build`, `test-results`, and `playwright-report`; scripts contain `npm ci --ignore-scripts` and no `npm install`; wrong/dirty upstream Git revision fails before npm/node executes.
- [ ] **Run:** `swift test --filter UpstreamScopeCorpusIntegrityTests` and `bash Scripts/verify-interop-lab.sh`. **Expected:** current broad copy and install paths violate assertions.
- [ ] **Add the five Docker exclusions** already present in `.gitignore`. Keep Dockerfile copy order unchanged because the denylist removes the shadow input.
- [ ] **Check in two minimal lockfile pairs** and replace ad-hoc installs with `npm ci --ignore-scripts --no-audit --no-fund` in clean temporary directories. Keep `npx --no-install`.
- [ ] **Require exact upstream provenance.** Before copying, require `git -C "$SWAN_UPSTREAM_ATPROTO" rev-parse HEAD` equals `bddc99fb24c34b4078b9bf65837283f37b49ab66`, require empty porcelain status including untracked files, then reject symlinks in copied package trees. Update the README from archive input to clean full checkout.
- [ ] **Run:** `bash Scripts/verify-interop-lab.sh`, the browser-CSS script with a byte-identical generated stylesheet assertion, and `swift test --filter UpstreamScopeCorpusIntegrityTests` against a clean pinned checkout.
- [ ] **Commit:** `jj describe -m "Swan: pin maintenance graphs and release inputs" && jj new`.

### Task 17: Pin local files and reject plaintext credential transport

**Findings:** 21, 27, 29.

**Files:**
- Modify: `Sources/swan/SwanCommand.swift`
- Modify: `Sources/SwanInterop/LiveInterop.swift`
- Test: `Tests/SwanCLITests/ServeLocalSpaceInteropCLITests.swift`
- Test: `Tests/SwanInteropTests/SwanInteropTests.swift`

- [ ] **Write failing tests.** Replacing notification config or request-body pathname after validation cannot change consumed bytes; symlink/FIFO/oversize inputs fail; credentialed non-loopback HTTP fails before headers are attached; `.none` HTTP and credentialed literal-loopback HTTP remain available.
- [ ] **Run both focused suites. Expected:** notification config/request body reopen paths and non-loopback credential HTTP remain accepted.
- [ ] **Read notification config once** through `readBoundedRegularFileNoFollow`, decode one immutable `Data`, and pass it to both the lab-PLC interlock and runtime loader.
- [ ] **Replace `LabLiveSupport.body` metadata-plus-`Data(contentsOf:)`** with one no-follow descriptor read capped at 2 MiB.
- [ ] **Make `InteropXRPCClient.addAuthorization` throwing.** Before adding bearer/DPoP/service headers, require HTTPS or literal `localhost`/`127.0.0.1`/`::1`; leave unauthenticated HTTP unchanged. Update all three authorization call sites.
- [ ] **Run focused suites and:** `swift build`.
- [ ] **Commit:** `jj describe -m "SwanInterop: pin local inputs and credential transport" && jj new`.

### Task 18: Fail closed without Web Crypto

**Findings:** 26.

**Files:**
- Modify: `web/src/lib/qrcode.ts`
- Modify: `web/src/lib/components/modals/TotpEnrollModal.svelte`
- Test: `web/src/lib/qrcode.test.ts`
- Test: `web/src/lib/components/modals_empirical_stress.test.ts`

- [ ] **Write failing tests.** Removing `crypto.getRandomValues` throws a fixed error and submits no secret; supported browsers generate the exact requested length only through Web Crypto; the modal shows the error instead of an infinite spinner.
- [ ] **Run:** `npm --prefix web test -- qrcode.test.ts modals_empirical_stress.test.ts`. **Expected:** current code calls `Math.random`.
- [ ] **Delete the fallback.** Throw a fixed unsupported-browser error when `crypto.getRandomValues` is unavailable. Render the existing alert and retry action when setup fails.
- [ ] **Run:** `npm --prefix web test -- qrcode.test.ts modals_empirical_stress.test.ts && npm --prefix web run check && npm --prefix web run build`.
- [ ] **Commit:** `jj describe -m "SwanWeb: require cryptographic randomness for TOTP" && jj new`.

### Task 19: Integrate, exercise, and close the scan

**Files:** all changed files; no new product behavior.

- [ ] **Rebase lane commits in task order** into one Swan integration head. Resolve only true textual overlaps; do not rewrite a task's security contract while resolving.
- [ ] **Run backend verification:** `swift build`, `swift test`, then `swift run swan verify`. Confirm every test filter executed at least one test.
- [ ] **Run frontend verification:** `npm --prefix web ci --ignore-scripts`, `npm --prefix web run check`, `npm --prefix web test`, `npm --prefix web run build`, and `npm --prefix web run test:browser` against the existing local fixture.
- [ ] **Run script/container verification:** `bash Scripts/verify-interop-lab.sh`, `bash Scripts/test-verify-interop-lab.sh`, browser-CSS deterministic regeneration, golden-corpus verification against the exact clean pinned checkout, and a Docker build-context sentinel test from a disposable directory.
- [ ] **Run runtime smoke checks:** exercise legacy login through trusted-proxy identity, password recovery/deactivate-reactivate invalidation, occupied `createRecord`, connected-app DELETE, firehose lag rejection, notification registration with two-factor authentication, signed write/deletion substitution rejection, and `swan verify` output. Capture fixed diagnostics and storage invariants, not secrets.
- [ ] **Run a ref-diff security scan** from `43e13da0` to the integrated head. Validate each original finding with its focused test and source evidence. A finding remains open if only a partial mitigation landed; Tasks 1–18 are required for closure.
- [ ] **Review scan coverage separately.** This plan closes the 29 reported findings; it does not convert the original partial repository scan into exhaustive line coverage. Schedule a new exhaustive scan as separate work if required.
- [ ] **Commit integration-only conflict fixes, if any:** `jj describe -m "Swan: integrate sealed-scan security remediations" && jj new`.

## Completion criteria

- All 29 findings map to passing focused regression tests and ref-diff validation evidence.
- Every migration is crash-atomic, bounded, and exercised against pre-fix rows.
- No secret environment fallback, unbound service token, insecure randomness fallback, or plaintext non-loopback credential path remains.
- Repository, replay, cache, resolver, streaming, and signup resources have cumulative process/storage bounds, not only per-request limits.
- Full Swift, web, script, container, runtime-smoke, and `swan verify` checks pass before any production action is proposed.
