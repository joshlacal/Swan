# Swan Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make swan.place a PDS the network can read continuously, then join it to the network.

**Architecture:** Three ordered workstreams. W1 makes public reads survive routine events instead of failing permanently. W2 closes the route gaps that actually matter, ranked by relay evidence rather than reference-PDS parity. W3 is the two-line relay activation, hard-gated on W1.

**Tech Stack:** Swift 6 strict concurrency, Hummingbird 2, SQLiteNIO, XCTest + HummingbirdTesting.

**Spec:** `docs/superpowers/specs/2026-08-12-swan-production-readiness-design.md`

## Global Constraints

- **Indentation is 4 spaces** in `Sources/SwanHTTP`, `Sources/SwanOAuth`, `Sources/SwanStorage`, `Sources/SwanSQLite`, `Sources/SwanCore`, `Sources/SwanSpaces` and their tests. The workspace CLAUDE.md's blanket "Swift: 2-space" rule is calibrated to Catbird/Petrel and does **not** apply here.
- **Never run `swiftformat` in this repo.** No `.swiftformat` exists; the defaults strip `: Sendable`, mangle numeric separators, and `hoistTry`/`hoistAwait` emit non-compiling code.
- **Never run bare `swift build` / `swift test`.** Use `xcrun --toolchain XcodeDefault swift build` and `xcrun --toolchain XcodeDefault swift test`. `swift build` is library-only — pass `--build-tests` before any `--skip-build` or you will run stale tests.
- **Verify your test filter matched something.** A `--filter` matching zero tests reports success. This has produced false greens in this repo.
- **Never widen a client-visible error body.** New diagnostics are server-side logs only. The 503 body stays `{"error":"temporarily_unavailable"}`.
- **Prefer allow-lists at trust boundaries.** Conditional capability registration plus a deny-list has produced two production security bugs here.
- **Nothing in W1 or W2 may change Phase 1's proxying, credential isolation, or peer-pinning.**
- Every task ends green before its commit.
- Commit style: imperative, scoped — `SwanSQLite: re-admit a stale public-read generation`.

## File Structure

**Modify**
- `Sources/SwanSQLite/PublicRepositoryReadStore.swift` — typed admission failure, `data_version` demotion.
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift` — re-admit on stale pin, evict on failed post-mutation refresh, logging.
- `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift` — logging at the six catch sites, `resolveHandle`, blob route relocation.
- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift` — blob route moves out.
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift` — route before authenticate.
- `Sources/SwanHTTP/SwanPublicUnavailableXRPC.swift` — identity namespace guard.
- `Sources/SwanHTTP/SwanHTTP.swift` — `did.json`, `describeServer`, profile-driven registration.
- `/etc/systemd/system/swan.service` (W3, server-side, not in-repo).

---

## W1 — The read path

### Task 1: Name the failing guard in logs

Do this **first**. Every later task in W1 is easier to verify when a failure says which guard fired, and this is the only thing that will diagnose a recurrence. Three hours of live 503s produced zero journal lines.

**Files:**
- Modify: `Sources/SwanSQLite/PublicRepositoryReadStore.swift`
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1456-1460`
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift` (six catch sites: `:298-300, 360-362, 424-426, 450-452, 476-478, 511-513`)
- Test: `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift`

**Interfaces:**
- Produces: `PublicRepositoryReadError.unavailable(reason: PublicReadUnavailableReason)` — an enum naming which guard failed. Tasks 2-4 pattern-match on it.

- [ ] **Step 1: Write the failing test**

```swift
func testAdmissionFailureNamesTheGuardThatFired() async throws {
    // An account whose journal stage is not .submitted must fail with a
    // reason identifying THAT guard, not a bare .unavailable.
    let outcome = await captureAdmissionFailure(stage: .submissionPending)
    XCTAssertEqual(outcome, .identityStageNotSubmitted)
}

func testDataVersionDriftIsDistinguishableFromIdentityFailure() async throws {
    // The two must not collapse to the same reason — telling them apart
    // is the entire point of this task.
    let drift = await captureAdmissionFailure(afterForeignCommit: true)
    XCTAssertEqual(drift, .generationPinStale)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryReadDiagnosticsTests`
Expected: FAIL — the reason type does not exist. Confirm the filter matched tests.

- [ ] **Step 3: Add the reason enum and thread it through**

Give `PublicRepositoryReadError.unavailable` an associated `PublicReadUnavailableReason` with one case per guard: `identityRowCount`, `identityStageNotSubmitted`, `genesisCIDMismatch`, `missingKeyMaterial`, `keyReferenceMismatch`, `historyVerifierUnavailable`, `terminalIdentityMismatch`, `commitAuthenticationFailed`, `projectionMismatch`, `generationPinStale`, `intentVerificationFailed`.

Replace each bare `throw PublicRepositoryReadError.unavailable` with the specific case. Do **not** change what the client sees.

- [ ] **Step 4: Log at the boundary**

At `SQLitePreMigratedAccountDirectory.swift:1456-1460` and each of the six handler catch sites, log one structured `warning` naming the DID and the reason. Client body unchanged.

- [ ] **Step 5: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
jj describe -m "SwanSQLite: name the guard that fails public-read admission"
jj new
```

---

### Task 2: Re-admit a stale generation instead of failing

The core fix. Confirmed correct empirically: the live outage cleared with no restart when a record was created and its post-commit refresh re-admitted the generation.

**Files:**
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1387-1409`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`

**Interfaces:**
- Consumes: Task 1's `.generationPinStale`.

- [ ] **Step 1: Write the failing test**

This is the regression test for the 2026-08-12 outage. It must reproduce the trigger exactly: a commit from a **second connection** to the account database that leaves repository state untouched.

```swift
func testForeignConnectionCommitDoesNotBreakPublicReads() async throws {
    let directory = try await makeDirectory(seeded: .twoPostAccount)
    let before = try await directory.publicRepositoryStatus(did: did)
    XCTAssertEqual(before?.revision, "…")

    // A second connection commits something irrelevant — a scratch table.
    // This is what PRAGMA data_version observes, and it never returns.
    try await commitFromSecondConnection(touchingRepositoryState: false)

    let after = try await directory.publicRepositoryStatus(did: did)
    XCTAssertEqual(after?.revision, before?.revision,
        "A foreign commit that touches no repository state must not " +
        "make the account permanently unreadable.")
}

func testGenuinelyUnadmittableAccountStill503sAndLogsWhy() async throws {
    // Re-admission must not become a way to serve a broken account.
}

func testReAdmissionHappensOnceNotInALoop() async throws {
    // A permanently-failing re-admit must not retry per read forever.
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryReadStaleGenerationTests`
Expected: FAIL — the first test throws `.unavailable`.

- [ ] **Step 3: Implement**

In `activePublicReadContext`, treat `.generationPinStale` from a generation-validated read as a signal to re-admit **once** and retry, returning 503 only if the re-admission itself fails. Re-admission must be bounded — one attempt per request, not a retry loop.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanSQLite: re-admit a stale public-read generation instead of failing"
jj new
```

---

### Task 3: Evict rather than fail when a post-mutation refresh errors

**Files:**
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1936-1941`
- Test: `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`

- [ ] **Step 1: Write the failing test**

```swift
func testFailedPostMutationRefreshDoesNotFailTheMutation() async throws {
    // The commit is durable before the refresh runs. A refresh error must
    // not fail a request whose write already succeeded.
}

func testFailedPostMutationRefreshEvictsRatherThanCachingStale() async throws {
    // With Task 2 in place, the next read re-admits.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryReadStaleGenerationTests`
Expected: FAIL on the two new cases.

- [ ] **Step 3: Implement** — evict `publicReadGenerations[did]` and swallow the refresh error, logging at `warning`.

- [ ] **Step 4: Run the full suite** — `xcrun --toolchain XcodeDefault swift test`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanSQLite: evict rather than fail when a post-mutation refresh errors"
jj new
```

---

### Task 4: Demote `data_version` to change detection

**Files:**
- Modify: `Sources/SwanSQLite/PublicRepositoryReadStore.swift:796-797`
- Test: existing stale-generation tests

- [ ] **Step 1: Write the failing test**

```swift
func testDataVersionDriftAloneTriggersReAdmissionNotRejection() async throws {
    // With Tasks 2-3 in place this is belt and braces, but it pins the
    // intent: data_version is a hint that something changed, not proof
    // that the generation is invalid.
}
```

- [ ] **Step 2: Run to verify it fails.** Run: `xcrun --toolchain XcodeDefault swift test --filter StaleGeneration`. Confirm the filter matched.

- [ ] **Step 3: Implement** — `data_version` movement maps to `.generationPinStale` (re-admit) rather than a hard failure. `fileIdentity` and `state` keep their meaning.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanSQLite: treat data_version movement as change detection"
jj new
```

---

### Task 5: W1 acceptance against the live deployment

**Not optional.** A clean suite is not "done" — this defect was invisible to the suite for its entire life.

- [ ] **Step 1:** Build and deploy to netcup.
- [ ] **Step 2:** Confirm public reads work for both accounts:

```bash
ssh netcup 'curl -sS "http://127.0.0.1:3020/xrpc/com.atproto.sync.getRepoStatus?did=did:plc:6u6rzv6fk3ga37kgs3tybgdk"'
ssh netcup 'curl -sS "http://127.0.0.1:3020/xrpc/com.atproto.sync.getRepoStatus?did=did:plc:7wr3tbi7gg5nyuocq64qietz"'
```

- [ ] **Step 3: Reproduce the original trigger in production.** Sign in from Catbird, make a post, and confirm public reads keep working across it — including for the *other* account, which is the one that has never been invalidated.
- [ ] **Step 4:** Confirm `journalctl -u swan.service` shows no `warning` reason lines. If admission is failing and silently re-admitting on every read, that is a different bug wearing this fix as a mask.
- [ ] **Step 5:** Record the evidence in the completion notes.

---

## W2 — Route surface

### Task 6: Route before authenticating

**Files:**
- Modify: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:302, 317-349`
- Test: `Tests/SwanHTTPTests/` (existing pipethrough test file)

- [ ] **Step 1: Write the failing test**

```swift
func testUnknownNSIDReturns404NotUnauthorized() async throws {
    // No Authorization header.
    let response = try await client.get("/xrpc/com.atproto.identity.resolveHandle")
    XCTAssertEqual(response.status, .notFound)
}

func testDeniedNamespaceReturns404WithoutTouchingCredentials() async throws {
    // blue.catbird.* is explicitly denied by the router.
}

func testAnonymousCallerStillCannotCauseAnOutboundConnection() async throws {
    // The invariant this reordering must preserve.
}
```

- [ ] **Step 2: Run to verify they fail.** Expected: 401 rather than 404.

- [ ] **Step 3: Implement** — move the `SwanXRPCProxyRouter(...).route(...)` block from `:336-349` to immediately after the NSID parse at `:317-320`, keeping `authorizedPipethroughSubject` at `:322-329` **after** it. `.denied`/`.unrouted` now 404 without touching credentials. Routing opens no sockets; the resolver at `:386` does, and it stays after auth.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: route before authenticating so missing routes 404"
jj new
```

---

### Task 7: Implement `com.atproto.identity.resolveHandle`

**Files:**
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:11-18, 247, 516-534`
- Modify: `Sources/SwanHTTP/SwanPublicUnavailableXRPC.swift:38-41`
- Test: `Tests/SwanHTTPTests/`

- [ ] **Step 1: Write the failing test**

```swift
func testResolveHandleAnswersUnauthenticated() async throws {
    let response = try await client.get(
        "/xrpc/com.atproto.identity.resolveHandle?handle=swan.place")
    XCTAssertEqual(response.status, .ok)
    XCTAssertEqual(try response.decode(ResolveHandleOutput.self).did,
                   "did:plc:6u6rzv6fk3ga37kgs3tybgdk")
}

func testResolveHandleRejectsUnknownHandleWithInvalidRequest() async throws { }
func testResolveHandleDoesNotRequireGenerationAdmission() async throws {
    // Must work even when public-read admission would fail — this is why
    // it ships independently of W1.
}
func testOtherIdentityMethodsReturn404NotUnauthorized() async throws { }
```

- [ ] **Step 2: Run to verify they fail.** Expected: 404 after Task 6.

- [ ] **Step 3: Implement** — a `router.get` handler registered from `registerPublicRepositoryReadEndpoints`, using `controlStore.account(canonicalHandle:)`. Add the NSID to `publicReadNSIDs` and its wrong-method guards. Add `/xrpc/com.atproto.identity.*` to `registerUnknownPublicEndpointGuards`.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: implement unauthenticated resolveHandle"
jj new
```

---

### Task 8: Move public blob reads off the write flag

**Files:**
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:536-611` (remove)
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:247` (add)
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:979-982` (delete the special case)
- Test: `Tests/SwanHTTPTests/`

- [ ] **Step 1: Write the failing test**

```swift
func testGetBlobIsServedWhenPublicMutationsAreDisabled() async throws {
    // Today disabling public writes silently disables avatar and image
    // serving for the entire network.
    let http = try makeRouter(publicRepositoryMutations: nil)
    let response = try await http.get("/xrpc/com.atproto.sync.getBlob?did=…&cid=…")
    XCTAssertNotEqual(response.status, .notFound)
}
```

- [ ] **Step 2: Run to verify it fails.** Expected: 404.

- [ ] **Step 3: Implement** — move the `blobPath` block into `registerPublicRepositoryReadEndpoints`, backed by the read directory so it registers whenever `publicRepositoryReadDirectory != nil`. Delete the `SwanHTTP.swift:979-982` special case.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: serve public blob reads from the read path"
jj new
```

---

### Task 9: Serve `did.json` and stop advertising invite codes

**Files:**
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:733-756, 807-814`
- Test: `Tests/SwanHTTPTests/`

- [ ] **Step 1: Write the failing test**

```swift
func testWellKnownDidJSONResolvesTheServiceDID() async throws {
    let response = try await client.get("/.well-known/did.json")
    XCTAssertEqual(response.status, .ok)
    let doc = try response.decode(DIDDocument.self)
    XCTAssertEqual(doc.id, "did:web:swan.place")
    XCTAssertTrue(doc.service.contains { $0.type == "AtprotoPersonalDataServer" })
}

func testDescribeServerDoesNotClaimInviteCodesAreRequired() async throws {
    XCTAssertFalse(try describeServer().inviteCodeRequired)
}
```

- [ ] **Step 2: Run to verify they fail.** Expected: 404, and `inviteCodeRequired: true`.

- [ ] **Step 3: Implement** — register `/.well-known/did.json` beside the OAuth well-knowns, with an `AtprotoPersonalDataServer` service entry for the public URL. Derive `inviteCodeRequired` from configuration rather than the hardcoded literal, defaulting to `false`.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: serve did.json and stop advertising unsupported invites"
jj new
```

---

### Task 10: Make `--profile` control the public route surface

**Files:**
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:966`
- Test: `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift` or a sibling

- [ ] **Step 1: Write the failing test**

```swift
func testRouteSurfaceFollowsTheLoadedProfile() async throws {
    // Registration currently iterates a hardcoded PublicDataTesting20260727
    // while the process loads --profile. The control is not the control.
}

func testStartupFailsLoudlyForAProfileWithNoRegistry() async throws {
    // Profiles/ ships public-data-testing-2026-08-06 with no Swift registry.
    // Silently registering the wrong surface is worse than refusing to boot.
}
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** — select the descriptor list from the loaded profile; throw a `ValidationError` at startup when a profile id has no matching registry.

- [ ] **Step 4: Run the full suite.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: drive public route registration from the loaded profile"
jj new
```

---

## W3 — Relay activation

### Task 11: Enable the firehose and join the network

**Gated.** Do not start until W1 Task 5 passed in production and reads survived a real foreign commit. **Requires Josh's explicit go-ahead** — `requestCrawl` is irreversible; there is no retraction, and the relay marks a host offline only after 15 failed dials.

Follow the runbook in `.../scratchpad/relay-readiness.md` §Deployment runbook, with one amendment: **the grey-cloud fallback is struck** — Caddy serves a Cloudflare Origin CA certificate that no public root store trusts, so grey-clouding would fail every TLS handshake, not just the relay's.

- [ ] **Step 1: Gating precondition.** `getRepo` returns `200 application/vnd.ipld.car` on `127.0.0.1:3020`. Do not proceed on 503.
- [ ] **Step 2:** Apply the two-line `swan.service` diff — `-e SWAN_PUBLIC_CRAWLERS=https://bsky.network` on the `docker run` line, `--enable-public-firehose` on the `serve` arguments. Retention defaults unchanged.
- [ ] **Step 3:** `daemon-reload` and restart; confirm active.
- [ ] **Step 4:** Confirm `firehose.sqlite` was created and the announcer logged.
- [ ] **Step 5: Smoke-test the WebSocket before the relay does.** `websocat wss://swan.place/xrpc/com.atproto.sync.subscribeRepos` — expect `101` and `#info`. Every component of this path is proven; the composition is not.
- [ ] **Step 6:** Confirm the relay subscribed, with **two** witnesses: `listHosts` on the relay side, and a `subscribe_repos.open` line with `cursor_mode=live` on Swan's. Never trust the announcer log alone — indigo returns 200-with-empty-body on several failure paths.
- [ ] **Step 7:** `swan firehose force-sync` — the queued backlog will not be delivered, because indigo dials a new host with no cursor and streams from current.
- [ ] **Step 8:** Post from Catbird and confirm it reaches `public.api.bsky.app`'s `getAuthorFeed`. **This is the success criterion for the entire document.**
- [ ] **Step 9:** Hold a `websocat` connection open for 20-30 minutes to cross both the 125s read timeout and the 900s idle timeout. Swan's 30s `autoPing` is expected to hold it.
