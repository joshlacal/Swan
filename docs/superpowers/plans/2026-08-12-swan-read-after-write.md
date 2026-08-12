# Swan Read-After-Write (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the authenticated account's own writes appear immediately in its own proxied `app.bsky` views, and its own deletions disappear immediately, without ever re-serializing content the AppView owns.

**Architecture:** A response decorator on Phase 1's pipethrough. A new storage reader returns the account's creates and deletions after a given repository revision; a builder turns those records into Petrel view types; per-route mungers splice them into the AppView response's JSON arrays by URI. Untouched entries pass through byte-identical.

**Tech Stack:** Swift 6 strict concurrency, Hummingbird 2, SQLiteNIO, Petrel (`app.bsky` view types), XCTest + HummingbirdTesting.

**Spec:** `docs/superpowers/specs/2026-08-12-swan-read-after-write-design.md` (amended 2026-08-12 — read the amendment note first; D1, D3's justification, and D4 all changed after research).

## Global Constraints

- **Indentation is 4 spaces** in `Sources/SwanHTTP`, `Sources/SwanOAuth`, `Sources/SwanStorage`, `Sources/SwanSQLite`, `Sources/SwanPublicRepository` and their tests. The workspace CLAUDE.md's blanket "Swift: 2-space" rule is calibrated to Catbird/Petrel and does **not** apply here.
- **Never run `swiftformat` in this repo.** There is no checked-in `.swiftformat`; the tool's defaults strip `: Sendable`, mangle numeric separators, and its `hoistTry`/`hoistAwait` rules emit non-compiling code. Match surrounding style by hand.
- **Never run bare `swift build` / `swift test`.** A custom toolchain is wedged. Use `xcrun --toolchain XcodeDefault swift build` and `xcrun --toolchain XcodeDefault swift test`. `swift build` is library-only — pass `--build-tests` before any `--skip-build`, or you will run stale tests.
- **RAW never re-serializes AppView-owned content.** Entries the munger does not insert or remove must reach the client byte-for-byte as the AppView sent them. This is the whole point of amended D1; a task that violates it is wrong even if its tests pass.
- **Fail open, and log.** Any RAW failure returns the unmodified AppView response and logs at `warning` with route and reason. RAW must never turn a working feed into a broken one, and must never degrade silently.
- **Only the authenticated account's own records are ever merged.** Merging into another actor's view is a privacy failure, not a display bug.
- **Do not widen Phase 1's client-facing header allow-list.** `atproto-repo-rev` is read internally and not forwarded.
- **Do not touch Phase 1's request path**, its routing, credential isolation, or peer-pinning.
- Every task ends green: `xcrun --toolchain XcodeDefault swift test` passes before the commit.
- Commit style: imperative, scoped — e.g. `SwanStorage: add local-write reader protocol`.

## File Structure

**Create**
- `Sources/SwanStorage/PublicRepositoryLocalWrites.swift` — Unit 1 types + `SwanLocalWriteReading` protocol. In `SwanStorage` so `SwanHTTP` depends on a protocol, never on `SQLiteAccountDatabase`, mirroring `PublicRepositoryReadDirectory`.
- `Sources/SwanSQLite/PublicRepositoryLocalWriteStore.swift` — Unit 1 implementation.
- `Sources/SwanHTTP/SwanRecordViewBuilder.swift` — Unit 2.
- `Sources/SwanHTTP/SwanReadAfterWriteJSON.swift` — array-splice primitives (Unit 3 substrate).
- `Sources/SwanHTTP/SwanReadAfterWriteMunging.swift` — the six per-route mungers + dispatch.
- `Tests/SwanSQLiteTests/PublicRepositoryLocalWriteStoreTests.swift`
- `Tests/SwanHTTPTests/SwanRecordViewBuilderTests.swift`
- `Tests/SwanHTTPTests/SwanReadAfterWriteJSONTests.swift`
- `Tests/SwanHTTPTests/SwanReadAfterWriteMungingTests.swift`

**Modify**
- `Sources/SwanPublicRepository/PublicRepositoryTID.swift` — promote revision encode/decode so both call sites share one base32 alphabet.
- `Sources/SwanSQLite/PublicRepositoryStore.swift` — `decodeProjection` `private` → `internal`; remove the now-duplicated private revision codec.
- `Sources/SwanSQLite/SwanSQLite.swift` — DDL comment recording RAW's retention dependency.
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift` — capture `atproto-repo-rev` internally; invoke the munge decorator.
- `Sources/swan/SwanCommand.swift` — construct and inject the reader.

---

### Task 1: Share the revision codec

The revision↔microseconds codec is `private static` on a SQLite extension (`PublicRepositoryStore.swift:785-810`). Unit 1 needs it too. Duplicating a base32 alphabet is how the two copies drift.

**Files:**
- Modify: `Sources/SwanPublicRepository/PublicRepositoryTID.swift`
- Modify: `Sources/SwanSQLite/PublicRepositoryStore.swift:785-810`
- Test: `Tests/SwanPublicRepositoryTests/PublicRepositoryTIDTests.swift`

**Interfaces:**
- Produces: `PublicRepositoryTID.encoding(rawValue: UInt64) -> String`, `PublicRepositoryTID.rawValue(of: String) -> UInt64?`. Later tasks use these to turn a wall-clock bound into a revision string and a revision back into a `Date`.

- [ ] **Step 1: Write the failing test**

```swift
func testRevisionCodecRoundTripsAndPreservesOrder() throws {
    let micros: UInt64 = 1_786_532_291_052_140
    let encoded = PublicRepositoryTID.encoding(rawValue: micros << 10)
    XCTAssertEqual(encoded.count, 13)
    XCTAssertEqual(PublicRepositoryTID.rawValue(of: encoded), micros << 10)

    // Lexicographic order must equal numeric order — the window query
    // relies on a plain string comparison.
    let earlier = PublicRepositoryTID.encoding(rawValue: (micros - 1_000_000) << 10)
    XCTAssertLessThan(earlier, encoded)
}

func testRevisionCodecMatchesLiveProductionValue() throws {
    // Pinned from the live swan.place repository head.
    XCTAssertEqual(
        PublicRepositoryTID.rawValue(of: "3msuxvdh2ng22").map { $0 >> 10 },
        1_786_532_291_052_140
    )
}

func testRevisionCodecRejectsMalformedInput() {
    XCTAssertNil(PublicRepositoryTID.rawValue(of: ""))
    XCTAssertNil(PublicRepositoryTID.rawValue(of: "not-base32!"))
    XCTAssertNil(PublicRepositoryTID.rawValue(of: "3msuxvdh2ng2"))   // 12 chars
    XCTAssertNil(PublicRepositoryTID.rawValue(of: "3msuxvdh2ng222")) // 14 chars
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryTIDTests`
Expected: FAIL — `encoding(rawValue:)` / `rawValue(of:)` do not exist.

- [ ] **Step 3: Move the codec**

Move the body of the two `private static` functions at `PublicRepositoryStore.swift:785-810` onto `PublicRepositoryTID` as `public static func encoding(rawValue: UInt64) -> String` and `public static func rawValue(of: String) -> UInt64?`. Keep the existing alphabet and width exactly — this is a move, not a rewrite. Then delete the private copies and update their call sites in `PublicRepositoryStore.swift` to call through `PublicRepositoryTID`.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS. Existing repository tests exercise the old call sites; a break here means the move was not faithful.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanPublicRepository: share the repository revision codec"
jj new
```

---

### Task 2: Unit 1 types and protocol

**Files:**
- Create: `Sources/SwanStorage/PublicRepositoryLocalWrites.swift`

**Interfaces:**
- Consumes: `PublicRepositoryPath`, `CID`, `PublicRepositoryReadError` (`Sources/SwanStorage/PublicRepositoryReadDirectory.swift:11-17`).
- Produces: `SwanLocalWriteRecord`, `SwanLocalWriteDeletion`, `SwanLocalWriteWindow`, `SwanLocalWriteReadLimits`, `SwanLocalWriteReading`. Tasks 3, 4 and 6-9 all depend on these exact names.

- [ ] **Step 1: Write the file**

Types are pure data; there is no behaviour to test-drive here, so the test comes with the implementation in Task 3. Match the 4-space style of `PublicRepositoryReadDirectory.swift`.

```swift
/// One public record the account wrote inside the merge window and that is
/// still present in the repository index.
public struct SwanLocalWriteRecord: Sendable, Equatable {
    public let path: PublicRepositoryPath
    public let cid: CID
    public let canonicalBytes: Data
    /// Repository revision of the commit that produced this record.
    public let revision: String
    /// Derived from `revision`, not from the record's own `createdAt`: the
    /// repository clock is the only server-authoritative one. Client-chosen
    /// rkeys and record bodies are not.
    public let writtenAt: Date

    public init(
        path: PublicRepositoryPath,
        cid: CID,
        canonicalBytes: Data,
        revision: String,
        writtenAt: Date
    ) {
        self.path = path
        self.cid = cid
        self.canonicalBytes = canonicalBytes
        self.revision = revision
        self.writtenAt = writtenAt
    }
}

/// One public record the account deleted inside the merge window.
public struct SwanLocalWriteDeletion: Sendable, Equatable {
    public let path: PublicRepositoryPath
    public let previousCID: CID
    public let revision: String
    public let deletedAt: Date

    public init(
        path: PublicRepositoryPath,
        previousCID: CID,
        revision: String,
        deletedAt: Date
    ) {
        self.path = path
        self.previousCID = previousCID
        self.revision = revision
        self.deletedAt = deletedAt
    }
}

/// The account's local writes for one merge window. `revision` is the
/// repository head observed while the window was read.
public struct SwanLocalWriteWindow: Sendable, Equatable {
    public let did: String
    public let revision: String
    public let records: [SwanLocalWriteRecord]      // newest revision first
    public let deletions: [SwanLocalWriteDeletion]  // newest revision first

    public init(
        did: String,
        revision: String,
        records: [SwanLocalWriteRecord],
        deletions: [SwanLocalWriteDeletion]
    ) {
        self.did = did
        self.revision = revision
        self.records = records
        self.deletions = deletions
    }

    public var isEmpty: Bool { records.isEmpty && deletions.isEmpty }
}

public enum SwanLocalWriteReadLimits {
    /// Bounds one window read regardless of how active the account is.
    public static let maximumWindowRecords = 50
    public static let maximumWindowBytes = 4 * 1_024 * 1_024
    /// Used only when the AppView did not send `atproto-repo-rev`.
    public static let fallbackWindow: Duration = .seconds(300)
}

/// Reads one authenticated account's own recent public writes. Deliberately
/// separate from `PublicRepositoryReadDirectory`: that protocol serves public
/// reads and pays for full generation admission, while this one serves only
/// the account's own view of its own repository.
public protocol SwanLocalWriteReading: Sendable {
    /// Local writes strictly newer than `sinceRevision`. Returns `nil` when
    /// the DID has no active repository.
    ///
    /// Prefer this form: the AppView's `atproto-repo-rev` is an exact
    /// indexing boundary, whereas a wall-clock window is a guess.
    func localWrites(
        did: String,
        sinceRevision: String,
        collections: Set<String>,
        limit: Int
    ) async throws -> SwanLocalWriteWindow?

    /// Fallback for when the AppView did not send `atproto-repo-rev`.
    func localWrites(
        did: String,
        window: Duration,
        collections: Set<String>,
        limit: Int
    ) async throws -> SwanLocalWriteWindow?
}
```

- [ ] **Step 2: Build**

Run: `xcrun --toolchain XcodeDefault swift build`
Expected: builds clean.

- [ ] **Step 3: Commit**

```bash
jj describe -m "SwanStorage: add local-write reader types and protocol"
jj new
```

---

### Task 3: Unit 1 implementation

The heart of the phase. Reads `public_repository_mutation_requests.committed_projection` — which retains creates, updates **and deletes** indefinitely — folds by path, and resolves bytes by direct CID lookup.

**Files:**
- Create: `Sources/SwanSQLite/PublicRepositoryLocalWriteStore.swift`
- Modify: `Sources/SwanSQLite/PublicRepositoryStore.swift:1190` (`decodeProjection` `private` → `internal`)
- Modify: `Sources/SwanSQLite/SwanSQLite.swift:448` (DDL comment)
- Test: `Tests/SwanSQLiteTests/PublicRepositoryLocalWriteStoreTests.swift`

**Interfaces:**
- Consumes: Task 1's `PublicRepositoryTID`, Task 2's types, `decodeProjection`, `blockBytesWithoutGate(_:)` (`PublicRepositoryStore.swift:1055`), `loadPublicRepositoryStateWithoutGate()` (`:846`).
- Produces: `extension SQLitePreMigratedAccountDirectory: SwanLocalWriteReading`.

- [ ] **Step 1: Write the failing tests**

Build each fixture through the real mutation path so the projections are genuine, then assert on the reader. Follow the existing setup helpers in `Tests/SwanSQLiteTests/` for creating an account database.

```swift
func testReturnsCreateInsideWindowAndNotOutside() async throws { /* two commits; window bounded between them */ }

func testCreateThenDeleteInsideWindowYieldsDeletionAndNoRecord() async throws { /* the fold, delete-wins */ }

func testCreateThenUpdateInsideWindowYieldsOneRecordAtLatestCID() async throws { /* the fold, latest-wins */ }

func testDeletionIsRecoverableAfterIndexRowIsGone() async throws {
    // Retention pin. The record index row is deleted, but committed_projection
    // still names the path. If this ever fails, RAW's removal half has
    // silently stopped working and nothing else will tell us.
}

func testCollectionFilterExcludesOtherCollections() async throws { }

func testRespectsRecordAndByteLimits() async throws { }

func testIndexMismatchDropsRecordAndDoesNotInventDeletion() async throws {
    // Defends against a repo import having replaced the index without
    // writing mutation rows (PublicRepositoryImportStaging.swift:898).
}

func testReturnsNilForUnknownDID() async throws { }
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter PublicRepositoryLocalWriteStoreTests`
Expected: FAIL — the type does not exist. Confirm the filter actually matched tests; a filter that matches zero tests reports success and has produced false greens in this repo before.

- [ ] **Step 3: Implement**

`extension SQLiteAccountDatabase` performing the read, plus `extension SQLitePreMigratedAccountDirectory: SwanLocalWriteReading` resolving `did → SQLiteAccountDatabase` the way `activePublicReadContext` does (`SQLitePreMigratedAccountDirectory.swift:1387-1409`). Everything inside one `withConnectionGate { readTransaction { … } }`:

1. `loadPublicRepositoryStateWithoutGate()` for the head revision and DID guard. Return `nil` if absent.
2. Range scan, newest first:

```sql
SELECT next_revision, committed_projection
FROM public_repository_mutation_requests
WHERE status = 'committed' AND next_revision > ?
ORDER BY next_revision DESC
LIMIT ?
```

3. `decodeProjection` each blob; filter to `collections`.
4. **Fold by path, newest revision wins.** A path already seen at a newer revision is skipped entirely. `delete` → a `SwanLocalWriteDeletion`; `create`/`update` → a candidate record.
5. For each surviving present path, confirm against `public_repository_record_index` and require `record_cid` to equal the folded CID. Mismatch → drop the record; **do not** synthesise a deletion.
6. `blockBytesWithoutGate(cid)` for bytes — direct CID lookup, no MST walk, no generation admission. Check `length(bytes)` first the way `publicRepositoryRecordBlockByteCountWithoutGate` does (`PublicRepositoryReadStore.swift:664-683`) and stop at `maximumWindowBytes`.
7. `writtenAt = Date(timeIntervalSince1970: Double(PublicRepositoryTID.rawValue(of: revision)! >> 10) / 1_000_000)`.

The `window:` overload encodes `now - window` into a revision lower bound via `PublicRepositoryTID.encoding(rawValue:)` and delegates to the `sinceRevision:` form.

- [ ] **Step 4: Add the DDL retention comment**

At `Sources/SwanSQLite/SwanSQLite.swift:448`, above the `public_repository_mutation_requests` DDL:

```swift
// Read-after-write depends on this table retaining committed delete
// operations: `committed_projection` is the only place a deleted record's
// path survives after its `public_repository_record_index` row is gone.
// Adding pruning here MUST retain at least the RAW merge window, or the
// removal half stops working with no error anywhere. Pinned by
// `testDeletionIsRecoverableAfterIndexRowIsGone`.
```

- [ ] **Step 5: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
jj describe -m "SwanSQLite: read the account's own recent writes and deletions"
jj new
```

---

### Task 4: Capture `atproto-repo-rev` inside the pipethrough

**Files:**
- Modify: `Sources/SwanHTTP/SwanXRPCPipethrough.swift:692-720`
- Test: `Tests/SwanHTTPTests/` (extend the existing pipethrough test file)

**Interfaces:**
- Produces: the upstream response's `atproto-repo-rev` value, available to the munge decorator. Task 9 consumes it.

- [ ] **Step 1: Write the failing tests**

```swift
func testCapturesRepoRevFromUpstreamResponse() async throws {
    // Stub sender returns atproto-repo-rev: 3msuxvdh2ng22.
    // Assert the captured value reaches the decorator.
}

func testDoesNotForwardRepoRevToTheClient() async throws {
    // The client-facing response must NOT carry atproto-repo-rev.
    // Phase 1's allow-list is a security posture; this test pins it.
}

func testMissingRepoRevIsRepresentedAsNil() async throws { }
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter Pipethrough`
Expected: FAIL.

- [ ] **Step 3: Implement**

Read the header where the upstream response is still intact, **before** `pipethroughResponse` narrows headers to `content-type`/`location`. Carry it alongside the buffered body. Do **not** add it to the forward list.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS — including the existing Phase 1 header-allow-list tests, which must be unchanged.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: capture the AppView's atproto-repo-rev without forwarding it"
jj new
```

---

### Task 5: JSON splice primitives

The substrate for amended D1. These functions are the reason untouched content survives byte-for-byte.

**Files:**
- Create: `Sources/SwanHTTP/SwanReadAfterWriteJSON.swift`
- Test: `Tests/SwanHTTPTests/SwanReadAfterWriteJSONTests.swift`

**Interfaces:**
- Produces: `SwanReadAfterWriteJSON.spliceArray(in:at:removingURIs:inserting:)` and `SwanReadAfterWriteJSON.uri(ofFeedEntry:)`. Tasks 6-8 consume these.

- [ ] **Step 1: Write the failing tests**

The critical one is the non-regression test — the property amended D1 exists to guarantee:

```swift
func testUntouchedEntriesSurviveByteForByte() throws {
    // A feed entry whose record carries fields Petrel does not model
    // (originalText / updatedAt from Bluesky's post editing).
    let original = /* fixture JSON containing that entry */
    let merged = try SwanReadAfterWriteJSON.spliceArray(
        in: original, at: ["feed"], removingURIs: [], inserting: []
    )
    XCTAssertEqual(merged, original,
        "A no-op splice must be the identity function on the response bytes.")
}

func testInsertedEntriesPrependAndUntouchedOnesAreUnchanged() throws { }
func testRemovalDropsOnlyMatchingURIs() throws { }
func testDedupeByURISkipsAnEntryTheAppViewAlreadyHas() throws { }
func testMissingArrayPathIsAnErrorNotASilentNoOp() throws { }
func testNonArrayAtPathIsAnError() throws { }
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanReadAfterWriteJSONTests`
Expected: FAIL.

- [ ] **Step 3: Implement**

Parse with `JSONSerialization` into `Any`, navigate to the array by key path, filter out entries whose URI is in `removingURIs`, prepend `inserting`, re-serialize. Entries are moved as opaque values — never decoded into typed models. Use `.sortedKeys` only if the existing response path already does; otherwise preserve default ordering and rely on the identity test to catch surprises.

**A no-op splice must be the identity.** If `JSONSerialization` round-tripping perturbs the bytes (key order, number formatting), that surfaces here as a failing identity test — resolve it by returning the original `Data` untouched when there is nothing to insert or remove, and document why.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: add read-after-write JSON splice primitives"
jj new
```

---

### Task 6: Unit 2 — `SwanRecordViewBuilder`

**Files:**
- Create: `Sources/SwanHTTP/SwanRecordViewBuilder.swift`
- Test: `Tests/SwanHTTPTests/SwanRecordViewBuilderTests.swift`

**Interfaces:**
- Consumes: Task 2's `SwanLocalWriteRecord`; Petrel's `AppBskyFeedDefs.PostView` (15-parameter memberwise init, no defaults, `AppBskyFeedDefs.swift:27-45`), `AppBskyFeedDefs.FeedViewPost` (`:641-657`), `AppBskyActorDefs.ProfileViewBasic`.
- Produces: `SwanRecordViewBuilder` with `postView(_:)`, `feedViewPost(_:)`, `likeSubjectURI(_:)`, `uri(for:)`.

- [ ] **Step 1: Write the failing tests**

```swift
func testPostViewCarriesZeroedCountsAndViewerState() throws {
    // A brand-new post genuinely has no likes. Zeroed, not omitted.
}

func testRecordBodyIsPassedThroughAsAValueContainer() throws {
    // PostView.record is ATProtocolValueContainer, which is exactly what
    // decodeRecordBlock returns — no re-encode, so unmodelled fields in the
    // local record survive too.
}

func testURIIsBuiltFromDIDAndPath() throws { }
func testUnsupportedCollectionThrows() throws { }
func testLikeSubjectURIIsExtractedFromALikeRecord() throws { }
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanRecordViewBuilderTests`
Expected: FAIL.

- [ ] **Step 3: Implement**

```swift
public enum SwanRecordViewBuilderError: Error, Sendable, Equatable {
    case undecodableRecord
    case unsupportedCollection
    case malformedURI
}

/// Builds Petrel view types from the authenticated account's own local
/// records. The author is fixed at construction: RAW only ever surfaces the
/// requester's own writes, so one `ProfileViewBasic` serves every record.
public struct SwanRecordViewBuilder: Sendable {
    public let did: DID
    public let author: AppBskyActorDefs.ProfileViewBasic

    public init(did: DID, author: AppBskyActorDefs.ProfileViewBasic)

    public func uri(for path: PublicRepositoryPath) throws -> ATProtocolURI
    /// Counts and viewer state are zeroed, not omitted.
    public func postView(_ record: SwanLocalWriteRecord) throws -> AppBskyFeedDefs.PostView
    public func feedViewPost(_ record: SwanLocalWriteRecord) throws -> AppBskyFeedDefs.FeedViewPost
    public func likeSubjectURI(_ record: SwanLocalWriteRecord) throws -> ATProtocolURI
}
```

Decode `canonicalBytes` with the same helper `getRecord` already uses (`RepositoryMSTValidation.decodeRecordBlock`, `Sources/SwanPublicRepository/RepositoryMSTValidation.swift:93-106`) so the record body reaches `PostView.record` as an `ATProtocolValueContainer` with no re-encode.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: build Petrel post views from local records"
jj new
```

---

### Task 7: Flat-list mungers — `getTimeline`, `getAuthorFeed`, `getActorLikes`

**Files:**
- Create: `Sources/SwanHTTP/SwanReadAfterWriteMunging.swift`
- Test: `Tests/SwanHTTPTests/SwanReadAfterWriteMungingTests.swift`

**Interfaces:**
- Consumes: Tasks 2, 5, 6.
- Produces: `SwanReadAfterWriteMunger.munge(nsid:body:window:builder:requestedActor:)`. Tasks 8 and 9 extend and call it.

- [ ] **Step 1: Write the failing tests**

Author the author-resolution rule here, since all three routes share it: lift the requester's `ProfileViewBasic` out of the AppView response when present, else fall back to DID + canonical handle with `avatar: nil`.

```swift
func testTimelinePrependsOwnPostMissingFromTheFeed() throws { }
func testTimelineDoesNotDuplicateAPostTheAppViewAlreadyHas() throws { }
func testTimelineRemovesADeletedPost() throws { }

func testAuthorFeedMergesOnlyWhenActorIsTheAccount() throws {
    // Negative case: requesting another actor's feed must return the
    // AppView response byte-identical. Privacy, not cosmetics.
}

func testActorLikesRemovalMatchesViewerLikeNotPostURI() throws {
    // A deleted like is visible as post.viewer.like, never as post.uri.
}

func testRepostRemovalMatchesReasonURIAndDegradesWhenAbsent() throws {
    // reason.uri is optional; absence must not drop an unrelated entry.
}

func testUnmodelledRecordFieldsSurviveTheMerge() throws {
    // End-to-end guarantee of amended D1, at the munger level.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanReadAfterWriteMungingTests`
Expected: FAIL.

- [ ] **Step 3: Implement the three flat-list routes**

Each: resolve the author, build inserts via Task 6, compute removal URIs per that route's match rule, call Task 5's splice at `["feed"]`. Dedupe by URI before inserting.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: merge local writes into timeline, author feed and likes"
jj new
```

---

### Task 8: `getProfile`, `getProfiles`, and `getPostThread`

Thread merging lands last, after the flat-list pattern is proven.

**Files:**
- Modify: `Sources/SwanHTTP/SwanReadAfterWriteMunging.swift`
- Test: `Tests/SwanHTTPTests/SwanReadAfterWriteMungingTests.swift`

- [ ] **Step 1: Write the failing tests**

```swift
func testProfileAdjustsPostsCountForLocalCreatesAndDeletes() throws { }
func testProfileDoesNotMergeForAnotherActor() throws { }
func testProfilesAdjustsOnlyTheAccountsOwnEntry() throws { }
func testPostThreadInsertsOwnReplyMissingFromTheThread() throws { }
func testPostThreadRemovesOwnDeletedReply() throws { }
func testPostThreadLeavesOtherActorsRepliesByteIdentical() throws { }
func testPostThreadHandlesNotFoundAndBlockedThreadUnions() throws { }
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter SwanReadAfterWriteMungingTests`
Expected: FAIL on the new cases only.

- [ ] **Step 3: Implement**

Profiles adjust counts in place — no array splice. `getPostThread` splices at `["thread", "replies"]`; when `thread` is a `notFoundPost` or `blockedPost` union member there is no replies array, so return unmodified rather than treating a missing path as an error.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: merge local writes into profile and thread views"
jj new
```

---

### Task 9: Wire RAW into the pipethrough

**Files:**
- Modify: `Sources/SwanHTTP/SwanXRPCPipethrough.swift`
- Modify: `Sources/swan/SwanCommand.swift`
- Test: `Tests/SwanHTTPTests/` (pipethrough integration)

- [ ] **Step 1: Write the failing tests**

```swift
func testMungesOnlyTheSixRoutesAndOnlyWhenAuthenticated() async throws { }

func testNon2xxUpstreamResponseIsNeverMunged() async throws { }

func testBuilderThrowFailsOpenByteIdentical() async throws {
    // The property that keeps a RAW bug from becoming an outage.
}

func testMissingRepoRevFallsBackToWallClockAndLogsWarning() async throws {
    // The fallback must never become the silent normal.
}

func testRAWDisabledLeavesPhase1BehaviourUnchanged() async throws { }
```

- [ ] **Step 2: Run to verify they fail**

Run: `xcrun --toolchain XcodeDefault swift test --filter Pipethrough`
Expected: FAIL.

- [ ] **Step 3: Implement**

Invoke the munge decorator after a 2xx pipethrough response, for the six NSIDs, when authenticated and a reader is configured. Wrap the whole decorator in a `do/catch` that returns the original `Data` on any error and logs at `warning` with route and reason. Construct the reader in `SwanCommand.Serve` and inject it; follow the **unconditional** registration pattern used for preferences (`SwanCommand.swift:2622-2631`), not the conditional-capability pattern — conditional registration plus a deny-list is what produced two production security bugs in this codebase.

- [ ] **Step 4: Run the full suite**

Run: `xcrun --toolchain XcodeDefault swift test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj describe -m "SwanHTTP: serve read-after-write on the six proxied routes"
jj new
```

---

### Task 10: Live verification

A clean build is not "done" — the project's verification rules require observing the change in the running app.

**Prerequisite:** the public-read 503 incident must be resolved first if it turns out to share the account-database read path. RAW's Unit 1 deliberately bypasses generation admission, so it may well be unaffected — confirm rather than assume.

- [ ] **Step 1: Deploy** to the swan.place instance.
- [ ] **Step 2:** Post from Catbird on the swan.place account. Confirm the post appears in the author's own timeline **immediately**, before the AppView could have indexed it.
- [ ] **Step 3:** Delete it. Confirm it disappears immediately.
- [ ] **Step 4:** Check `journalctl -u swan.service` for RAW `warning` lines. A green suite plus a silent warning stream means RAW is failing open on every request and doing nothing — the exact outcome D5's logging exists to expose. Zero warnings is the pass condition.
- [ ] **Step 5:** Capture a screenshot and the relevant log lines as evidence, and record them in the completion notes.
