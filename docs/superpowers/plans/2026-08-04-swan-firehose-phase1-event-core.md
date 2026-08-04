# Swan Firehose Phase 1: Durable Event Core — Reviewed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Review status:** Revised after source-level review of Swan, Petrel, and the current reference PDS event formatter.

**Goal:** Every public repository commit, and every explicitly enqueued lifecycle batch, durably lands in a global `firehose.sqlite` log with a monotonic `seq` and fully encoded firehose frame bytes — crash-safe, idempotent, and causally ordered per DID.

**Architecture:**

- Account-local `public_event_outbox` rows are inserted in the same SQLite transaction as the public repository commit. They contain final event kind, typed JSON material, and exact CAR bytes.
- A control-plane lifecycle outbox stores ordered identity/account/sync batches and assigns a monotonically increasing lifecycle generation per DID.
- A single sequencer actor merges the two sources per DID. Account event generation `g` is ordered after lifecycle batch `g` and before lifecycle batch `g + 1`.
- The sequencer allocates consecutive sequence ranges from `firehose_meta`, encodes complete header-plus-body DAG-CBOR frames, and atomically appends them to `firehose.sqlite`.
- `firehose.sqlite` is the durable authority. Phase 2 live delivery may use in-process notifications only as wakeups; it must always tail this log.

**Tech stack:** Swift 6 strict concurrency, SQLiteNIO, Petrel `DAGCBOR` / `OrderedCBORMap` / `ATProtoLink`, XCTest.

**Governing design:** `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md`, after Task 0 reconciles it with this reviewed plan.

## Review changes applied

This revision changes the submitted plan in the following material ways:

1. Makes `since` and `prevDataCID` optional, encodes absent `since` as CBOR null, and omits absent `prevData` and operation `prev`, matching current event semantics.
2. Uses Petrel’s actual immutable `OrderedCBORMap(entries:)` / `.adding(key:value:)` API. Petrel has no generic `decodeValueWithLength`; tests receive a dedicated strict two-object CBOR parser.
3. Adds the 10,000-byte `#sync.blocks` limit and validates operations, CAR sizes, and the complete 5,000,000-byte frame.
4. Keeps the `PublicRepositoryMutationStore` protocol method signature unchanged. Firehose material is derived internally; Phase 1 writes lifecycle generation `0`.
5. Makes source CAR bytes non-null and enforces strict account-outbox head-of-line order. A failed older commit can never be overtaken by a newer commit.
6. Makes source-key replay exact: the same key with different kind, generation, payload, CAR, DID, batch, or encoded frame is corruption, not idempotency.
7. Splits lifecycle batches from lifecycle items, namespaces batch IDs by DID, carries CAR bytes for lifecycle `#sync`, rejects empty or conflicting replays, and validates material before enqueue.
8. Replaces the one-sided “lifecycle first” rule with a two-sided per-DID causal merge: account generation `g` precedes lifecycle generation `g + 1`, while lifecycle generation `g` precedes account generation `g`.
9. Strengthens global sequence allocation against overflow, partial batch replay, mixed existing/new rows, and restore-induced sequence regression.
10. Corrects service composition: the runtime is assembled in `Sources/swan/SwanCommand.swift`, not `Sources/SwanHTTP/SwanHTTP.swift`; the Phase 1 worker is explicitly feature-gated and closed on every shutdown path.
11. Corrects all fixed test dates. `2026-08-04T12:00:00.000Z` is Unix time `1_785_844_800`, not `1_754_308_800`.
12. Adds failure-injection, rollback, multi-DID fairness, generation-boundary, lifecycle crash-replay, and source-conflict tests.

## Global constraints

- Swift 6 strict concurrency; actors; 2-space indentation; XCTest, not Swift Testing.
- VCS: `jj` only; never mutate history with Git. Commit using path-restricted commands such as:

  ```bash
  jj commit <paths> -m "firehose: …"
  ```

- Work from:

  ```text
  /Users/joshlacalamito/Developer/Catbird+Petrel/.worktrees/swan-public-federation
  ```

- All SQLite access uses `connection.query(sql, bindings)`.
- Public mutation methods acquire `withConnectionGate` and use `transaction`. Helpers explicitly named `...InTransaction` assume that gate and transaction are already held and must not reacquire either.
- Never open one database transaction while another database transaction is open.
- Never perform network I/O inside a transaction.
- Build CAR bytes and other pure in-memory material before entering a transaction whenever the required values are already available. Only the durable outbox insertion must be in the repository transaction.
- Frame encoding uses Petrel’s actual API:
  - `DAGCBOR.encodeValue(_:)`
  - `OrderedCBORMap(entries:)` or `.adding(key:value:)`
  - `CID.parse(_:)`
  - `ATProtoLink(cid:)`
- `OrderedCBORMap` is immutable and has no `append` method. Petrel’s DAG-CBOR encoder performs canonical map-key ordering itself; do not rely on insertion order.
- Petrel currently has no public generic “decode the first CBOR object and return consumed length” API. Do not invent `DAGCBOR.decodeValue` or `decodeValueWithLength`; use the test-only parser required by Task 2.
- The uploaded Swan archive does not contain its required sibling `../Petrel` checkout. This review verified the current accessible Petrel source; before Task 2, inspect the actual workspace sibling and let that checked-out source win on API spelling. The frame semantics and tests in this plan remain the contract.
- Hard event invariants:
  - `1 <= seq <= 9_007_199_254_740_991`
  - `firehose_meta.next_seq` may additionally equal `9_007_199_254_740_992` as an exhausted sentinel
  - complete encoded frame `<= 5_000_000` bytes
  - `#commit.blocks <= 2_000_000` bytes
  - `#sync.blocks <= 10_000` bytes
  - `#commit.ops.count <= 200`
  - `#commit.blobs` is always `[]`
  - `#commit` operation `cid` is always present as a link or null
  - operation `prev` is omitted when absent, never encoded as null
  - `#commit.prevData` is omitted when absent
  - `#commit.since` is encoded as a string or null
- Swan-produced operation semantics are stricter than the permissive wire shape:
  - create: `cid != nil`, `prev == nil`
  - update: `cid != nil`, `prev != nil`
  - delete: `cid == nil`, `prev != nil`
- Public and permissioned storage remain isolated. No permissioned write path may import `SwanPublicFirehose`, insert into `public_event_outbox`, or append to `firehose.sqlite`.
- Build: `swift build`.
- Focused test: `swift test --filter <TargetOrTest>`.
- Account DB migration ledger: version `13` is free in the reviewed snapshot (`permissionedRemoteReplicaLogicalLimitMigrationVersion = 12`). Recheck after rebasing and renumber if necessary.

---

### Task 0: Reconcile the governing design before code changes

**Files:**

- Verify or create: `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md`
- Modify the design if it still contains the pre-review architecture.

The uploaded implementation plan references this spec, but the reviewed archive does not contain it. The older design text also contains superseded decisions: low-level lifecycle hooks, deferred CAR resolution by CID list, direct in-memory event broadcast as a correctness path, and a minimum-row retention floor.

- [ ] **Step 1: Make the design document exist in the workspace**

If the file is absent, create it from the approved P0 design and record that this reviewed implementation plan is authoritative for Phase 1 details.

- [ ] **Step 2: Apply the required architecture corrections**

The design must say all of the following before implementation begins:

- lifecycle events are enqueued by confirmed higher-level operations, not raw PLC-history installation;
- lifecycle events are ordered batches with per-DID generations;
- source outboxes persist exact CAR bytes;
- account outboxes are strict FIFO by insertion ID;
- global log frames are complete header-plus-body bytes;
- in-process broadcasts are wakeups only;
- retention has a hard maximum age and no minimum row count that defeats it;
- deletion can prune older retained rows for that DID in Phase 3;
- cursor behavior and relay acceptance are later phases;
- Phase 1 does not yet integrate real lifecycle operations, so ordinary public commits are stamped generation `0` until the Phase 4 lifecycle saga is wired.

- [ ] **Step 3: Verify no superseded claims remain**

Run:

```bash
rg -n \
  'installPublicPLCOperation|CID list|minimum 10,000|Broadcast the event|transitionStatus.*emits' \
  docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md
```

Expected: no stale architecture claim. Legitimate historical discussion must be explicitly marked superseded.

- [ ] **Step 4: Commit**

```bash
jj commit docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md \
  -m "docs: reconcile Swan public firehose design"
```

---

### Task 1: Add `SwanPublicFirehose` event models and source keys

**Files:**

- Modify: `Package.swift`
- Create: `Sources/SwanPublicFirehose/PublicFirehoseEvent.swift`
- Create: `Sources/SwanPublicFirehose/PublicFirehoseSourceKey.swift`
- Test: `Tests/SwanPublicFirehoseTests/PublicFirehoseEventTests.swift`

**Produces:**

```swift
public enum PublicFirehoseEventKind: String, Codable, Sendable {
  case commit, sync, identity, account
}

public enum PublicFirehoseRepoAction: String, Codable, Sendable {
  case create, update, delete
}

public struct PublicFirehoseRepoOp: Codable, Sendable, Equatable {
  public let action: PublicFirehoseRepoAction
  public let path: String
  public let cid: String?
  public let prev: String?
}

public struct PublicFirehoseCommitMaterial: Codable, Sendable, Equatable {
  public let did: String
  public let rev: String
  public let since: String?
  public let commitCID: String
  public let prevDataCID: String?
  public let ops: [PublicFirehoseRepoOp]
  public let time: String
}

public struct PublicFirehoseSyncMaterial: Codable, Sendable, Equatable {
  public let did: String
  public let rev: String
  public let commitCID: String
  public let time: String
}

public struct PublicFirehoseIdentityMaterial: Codable, Sendable, Equatable {
  public let did: String
  public let handle: String?
  public let time: String
}

public enum PublicFirehoseAccountStatus: String, Codable, Sendable {
  case deactivated
  case suspended
  case takendown
  case desynchronized
  case throttled
  case deleted
}

public struct PublicFirehoseAccountMaterial: Codable, Sendable, Equatable {
  public let did: String
  public let active: Bool
  public let status: PublicFirehoseAccountStatus?
  public let time: String
}
```

`PublicFirehoseSourceKey` exposes:

```swift
commit(did:commitCID:)
syncOversize(did:commitCID:)
syncManual(did:requestUUID:)
syncActivation(did:operationID:)
syncReactivation(did:operationID:)
account(did:operationID:)
identity(did:plcOperationCID:)
lifecycleBatch(did:operationID:)
```

Exact formats:

```text
<did>|commit|<cid>
<did>|sync|oversize|<cid>
<did>|sync|manual|<lowercase UUID>
<did>|sync|activation|<operation ID>
<did>|sync|reactivation|<operation ID>
<did>|account|<operation ID>
<did>|identity|<PLC operation CID>
<did>|lifecycle|<operation ID>
```

`PublicFirehoseTime` exposes:

```swift
public enum PublicFirehoseTimeError: Error, Equatable {
  case outOfRange
}

public enum PublicFirehoseTime {
  public static func encode(_ date: Date) -> String
  public static func microseconds(_ date: Date) throws -> Int64
}
```

`encode` uses UTC ISO-8601 with fractional seconds. `microseconds` rejects non-finite, negative, or overflowing values with `.outOfRange` rather than trapping on conversion.

- [ ] **Step 1: Add package entries**

Add the library product:

```swift
.library(name: "SwanPublicFirehose", targets: ["SwanPublicFirehose"]),
```

Add targets:

```swift
.target(
  name: "SwanPublicFirehose",
  dependencies: [
    "SwanPublicRepository",
    .product(name: "Petrel", package: "Petrel"),
  ]
),
.testTarget(
  name: "SwanPublicFirehoseTests",
  dependencies: [
    "SwanPublicFirehose",
    "SwanPublicRepository",
    .product(name: "Petrel", package: "Petrel"),
  ]
),
```

Do not add `Crypto` unless a test actually imports it.

- [ ] **Step 2: Write failing tests**

Cover:

- every source-key format, including DID-namespaced lifecycle batch IDs;
- JSON round-trip with non-null `since` and `prevDataCID`;
- JSON round-trip with both optional fields nil;
- typed repository actions;
- account status round-trip;
- exact date encoding:

  ```swift
  let date = Date(timeIntervalSince1970: 1_785_844_800)
  XCTAssertEqual(
    PublicFirehoseTime.encode(date),
    "2026-08-04T12:00:00.000Z"
  )
  ```

- microsecond conversion and invalid-date rejection.

- [ ] **Step 3: Confirm red**

```bash
swift test --filter PublicFirehoseEventTests
```

Expected: module or type compilation failure.

- [ ] **Step 4: Implement the models**

All public structs have explicit public initializers. Keep material storage JSON-only; CIDs remain strings until frame encoding so SQLite rows do not depend on Petrel binary layout.

For account material, do not encode internal `deleting`, `unknown`, or `active` as status strings. Active events use `active: true, status: nil`.

- [ ] **Step 5: Confirm green**

```bash
swift test --filter PublicFirehoseEventTests
```

- [ ] **Step 6: Commit**

```bash
jj commit Package.swift Sources/SwanPublicFirehose Tests/SwanPublicFirehoseTests \
  -m "firehose: add event models and source keys"
```

---

### Task 2: Add the complete DAG-CBOR frame encoder and strict test decoder

**Files:**

- Create: `Sources/SwanPublicFirehose/FirehoseFrameLimits.swift`
- Create: `Sources/SwanPublicFirehose/FirehoseFrameEncoder.swift`
- Create: `Tests/SwanPublicFirehoseTests/FirehoseFrameTestDecoder.swift`
- Test: `Tests/SwanPublicFirehoseTests/FirehoseFrameEncoderTests.swift`

**Produces:**

```swift
public enum FirehoseFrameLimits {
  public static let maximumFrameBytes = 5_000_000
  public static let maximumCommitBlocksBytes = 2_000_000
  public static let maximumSyncBlocksBytes = 10_000
  public static let maximumOps = 200
  public static let maximumSequence: Int64 = 9_007_199_254_740_991

  public static func validateSequence(_ seq: Int64) throws
}

public enum FirehoseFrameEncoderError: Error, Equatable {
  case sequenceOutOfRange
  case tooManyOperations(Int)
  case blocksTooLarge(actual: Int, maximum: Int)
  case frameTooLarge(Int)
  case invalidCID(String)
  case invalidOperation(index: Int, reason: String)
  case invalidAccountStatus
}

public enum FirehoseFrameEncoder {
  public static func commitFrame(
    seq: Int64,
    material: PublicFirehoseCommitMaterial,
    diffCAR: Data
  ) throws -> Data

  public static func syncFrame(
    seq: Int64,
    material: PublicFirehoseSyncMaterial,
    commitCAR: Data
  ) throws -> Data

  public static func identityFrame(
    seq: Int64,
    material: PublicFirehoseIdentityMaterial
  ) throws -> Data

  public static func accountFrame(
    seq: Int64,
    material: PublicFirehoseAccountMaterial
  ) throws -> Data

  public static func infoFrame(name: String, message: String?) throws -> Data
  public static func errorFrame(error: String, message: String?) throws -> Data
}
```

Each method returns the complete concatenated frame:

```text
canonical DAG-CBOR header object || canonical DAG-CBOR body object
```

- [ ] **Step 1: Add the test-only two-object decoder first**

Petrel does not currently expose the decode helpers used in the submitted sketch. Add `FirehoseFrameTestDecoder.swift`, modeled on the private `CommitCBORParser` in `Sources/SwanPublicRepository/PublicRepositoryCommit.swift`.

The helper must:

- parse one canonical CBOR value and return its consumed byte count;
- parse the second value from the exact remaining bytes;
- reject trailing bytes;
- support maps, arrays, strings, byte strings, signed/unsigned integers, booleans, null, and tag-42 CID links;
- validate shortest integer encodings and canonical map-key order;
- expose a small test-only value enum rather than `[String: Any]` casts;
- preserve the distinction between null, omitted fields, and tag-42 CIDs.

Do not add a production decoder in Phase 1 and do not import transitive `SwiftCBOR` directly.

- [ ] **Step 2: Write failing encoder tests**

Cover at least:

1. Ordinary create commit:
   - header `op = 1`, `t = #commit`;
   - `seq`, `repo`, `rev`, `since`, `commit`, `prevData`, `blocks`, `ops`;
   - `rebase = false`, `tooBig = false`, `blobs = []`;
   - create operation has link `cid` and omitted `prev`.
2. Initial/genesis-shaped commit:
   - `since` is CBOR null;
   - `prevData` is absent.
3. Update and delete operation link/null semantics.
4. `#sync` uses only the required `seq`, `did`, `blocks`, `rev`, and `time` body fields; its supplied CAR is separately proven commit-rooted by `PublicFirehoseDiffCARTests`.
5. Identity with and without handle.
6. Active account requires nil status; inactive account requires non-nil status.
7. `#info` header type and body.
8. Error frame header `{op: -1}` with no `t`.
9. sequence `0` and `2^53` rejection.
10. 201-op rejection.
11. commit CAR over 2,000,000 rejection.
12. sync CAR over 10,000 rejection.
13. complete-frame over 5,000,000 rejection.
14. invalid CID rejection.
15. malformed action/CID/previous-CID combinations rejection.
16. deterministic byte equality across repeated encodes.

- [ ] **Step 3: Confirm red**

```bash
swift test --filter FirehoseFrameEncoderTests
```

- [ ] **Step 4: Implement using Petrel’s actual immutable map API**

Construct maps with `OrderedCBORMap(entries:)`, for example:

```swift
let header = OrderedCBORMap(entries: [
  (key: "op", value: 1),
  (key: "t", value: "#commit"),
])
```

Petrel canonicalizes keys when encoding; canonical wire order for this header is therefore `t` then `op` because DAG-CBOR sorts by encoded key length and then bytewise. The source entry order is not a wire contract.

For commit operations:

```swift
let cidValue: Any
if let cid = op.cid {
  cidValue = try link(cid)
} else {
  cidValue = NSNull()
}

var entries: [(key: String, value: Any)] = [
  ("cid", cidValue),
  ("path", op.path),
  ("action", op.action.rawValue),
]
if let prev = op.prev {
  entries.append(("prev", try link(prev)))
}
```

Build the commit body with:

- `since` always present as string or null;
- `prevData` only when non-nil;
- `cid` always present in every op as link or null;
- `prev` omitted when nil;
- empty `[Any]()` for `blobs`.

Use:

```swift
private static func link(_ string: String) throws -> ATProtoLink {
  do {
    return ATProtoLink(cid: try CID.parse(string))
  } catch {
    throw FirehoseFrameEncoderError.invalidCID(string)
  }
}
```

Validate limits before encoding where possible, then validate the final concatenated byte count.

- [ ] **Step 5: Confirm green**

```bash
swift test --filter FirehoseFrameEncoderTests
```

- [ ] **Step 6: Commit**

```bash
jj commit Sources/SwanPublicFirehose Tests/SwanPublicFirehoseTests \
  -m "firehose: add canonical frame encoder and strict test decoder"
```

---
### Task 3: Add the strict-FIFO account-local public event outbox

**Files:**

- Modify: `Package.swift`
- Modify: `Sources/SwanSQLite/SwanSQLite.swift`
- Create: `Sources/SwanSQLite/PublicFirehoseOutboxStore.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseOutboxStoreTests.swift`

**Package changes:**

- Add `"SwanPublicFirehose"` to the `SwanSQLite` target dependencies.
- Add `"SwanPublicFirehose"` to `SwanSQLiteTests` dependencies.

**Produces on `SQLiteAccountDatabase`:**

```swift
public struct PublicFirehoseOutboxRow: Sendable, Equatable {
  public let id: Int64
  public let sourceKey: String
  public let kind: PublicFirehoseEventKind
  public let lifecycleGeneration: Int64
  public let payload: Data
  public let carBytes: Data
  public let createdAt: Int64
  public let availableAt: Int64
  public let attempts: Int
}

public struct PublicFirehoseOutboxLease: Sendable, Equatable {
  public let row: PublicFirehoseOutboxRow
  public let token: UUID
  public let expiresAt: Date
}
```

Methods:

```swift
func enqueuePublicFirehoseEventInTransaction(
  sourceKey: String,
  kind: PublicFirehoseEventKind,
  lifecycleGeneration: Int64,
  payload: Data,
  carBytes: Data,
  createdAt: Int64
) async throws -> Bool

public func enqueuePublicFirehoseEvent(
  sourceKey: String,
  kind: PublicFirehoseEventKind,
  lifecycleGeneration: Int64,
  payload: Data,
  carBytes: Data,
  now: Date
) async throws -> Bool

public func oldestPendingPublicFirehoseOutbox()
  async throws -> PublicFirehoseOutboxRow?

public func leaseNextPublicFirehoseOutbox(
  now: Date = Date(),
  leaseDuration: TimeInterval
) async throws -> PublicFirehoseOutboxLease?

@discardableResult
public func completePublicFirehoseOutboxLease(
  id: Int64,
  token: UUID
) async throws -> Bool

@discardableResult
public func failPublicFirehoseOutboxLease(
  id: Int64,
  token: UUID,
  retryAt: Date
) async throws -> Int?

public func pendingPublicFirehoseOutbox(
  limit: Int = 100
) async throws -> [PublicFirehoseOutboxRow]
```

Add a storage error case for exact-key conflicts, for example:

```swift
case conflictingPublicFirehoseSourceKey(String)
```

- [ ] **Step 1: Add account migration version 13**

In `SQLiteAccountDatabase`:

```swift
private static let publicFirehoseOutboxMigrationVersion = 13
```

Create:

```sql
CREATE TABLE IF NOT EXISTS public_event_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync')),
    lifecycle_generation INTEGER NOT NULL DEFAULT 0
        CHECK(lifecycle_generation >= 0),
    payload BLOB NOT NULL CHECK(length(payload) > 0),
    car_bytes BLOB NOT NULL CHECK(length(car_bytes) > 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    available_at INTEGER NOT NULL CHECK(available_at >= 0),
    lease_token TEXT,
    lease_expires_at INTEGER,
    CHECK(
        (lease_token IS NULL AND lease_expires_at IS NULL)
        OR (
            lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND lease_expires_at >= 0
        )
    )
);
```

A source row always contains CAR bytes:

- commit row: exact diff CAR;
- sync row: exact commit-only CAR.

Do not use a nullable `diff_car` column.

Insert migration ledger version 13 using the existing account migration pattern. Call it from the account migration transaction after the current version-12 migration.

- [ ] **Step 2: Write failing store tests**

Cover:

1. enqueue → lease → complete;
2. exact source-key replay returns `false` and leaves one row;
3. same source key with changed kind, generation, payload, or CAR throws conflict;
4. active lease is invisible until expiry;
5. stale token cannot complete or fail;
6. failure increments attempts and reschedules;
7. strict head-of-line behavior:
   - enqueue `k1`, then `k2`;
   - lease and fail `k1` to a future `retryAt`;
   - a lease before that deadline returns nil even though `k2` is otherwise ready;
   - after the deadline, `k1` leases first and `k2` only after `k1` completes;
8. pending rows are returned in ascending `id` order;
9. `.identity` and `.account` are rejected by the account outbox before SQL;
10. invalid lease durations, timestamp overflow, invalid limits, or corrupt rows fail closed.

Use corrected fixed dates beginning at:

```swift
Date(timeIntervalSince1970: 1_785_844_800)
```

- [ ] **Step 3: Confirm red**

```bash
swift test --filter PublicFirehoseOutboxStoreTests
```

- [ ] **Step 4: Implement exact replay and strict FIFO**

The standalone enqueue wraps:

```swift
try await withConnectionGate {
  try await transaction { ... }
}
```

The in-transaction helper does not acquire the gate or begin a transaction.

On source-key reuse:

1. read the existing row;
2. compare kind, lifecycle generation, payload, and CAR byte-for-byte;
3. return `false` only if all values match;
4. otherwise throw `conflictingPublicFirehoseSourceKey`.

The lease query must examine only the smallest outstanding `id`. It must not order by `available_at`, because that would allow a later repository revision to overtake a failed earlier revision.

Use this logical flow in one transaction:

```text
head = SELECT ... FROM public_event_outbox ORDER BY id LIMIT 1
if no head: return nil
if head.available_at > now: return nil
if head has an unexpired lease: return nil
UPDATE that exact id with a new token and expiry, guarded by availability/expiry
RETURNING row
```

A blocked account head is local to that DID; Task 7 will continue checking other DIDs.

`oldestPendingPublicFirehoseOutbox` is a non-leasing peek used only by the sequencer’s causal merge. It returns the smallest `id` regardless of availability or lease state.

The helper functions `requiredText`, `requiredInteger`, and `requiredBlob` in `SwanSQLite.swift` are private and cannot be called from a new file. Either:

- add file-private decoding helpers in `PublicFirehoseOutboxStore.swift`, or
- deliberately refactor only the shared safe row helpers to internal access and run the full SQLite suite.

Do not simply reference the current private helpers from another file.

- [ ] **Step 5: Confirm focused and full SQLite tests**

```bash
swift test --filter PublicFirehoseOutboxStoreTests
swift test --filter SwanSQLiteTests
```

- [ ] **Step 6: Commit**

```bash
jj commit Package.swift Sources/SwanSQLite Tests/SwanSQLiteTests \
  -m "firehose: add strict FIFO public event outbox"
```

---

### Task 4: Derive and enqueue final commit-or-sync material atomically with public writes

**Files:**

- Create: `Sources/SwanPublicFirehose/PublicFirehoseDiffCAR.swift`
- Test: `Tests/SwanPublicFirehoseTests/PublicFirehoseDiffCARTests.swift`
- Modify: `Sources/SwanSQLite/PublicRepositoryStore.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseCommitEnqueueTests.swift`
- Modify existing public repository mutation failure-injection tests as required by the extra mutating SQL statement.

**Critical signature rule:**

Do **not** add parameters to:

```swift
func applyPublicRepositoryMutation(
  reservation: PublicRepositoryMutationReservation,
  prepared: PreparedPublicRepositoryMutation
) async throws -> CommittedPublicRepositoryMutation
```

That exact method is a `PublicRepositoryMutationStore` protocol requirement. Defaulted extra parameters do not satisfy the protocol witness. Phase 1 stamps normal public commits with lifecycle generation `0`; Phase 4 will add a durable lifecycle-generation handoff without changing this protocol surface.

**Produces:**

```swift
public enum PublicFirehoseDiffCAR {
  public static func build(
    commitCID: CID,
    commitBytes: Data,
    newBlocks: PublicRepositoryBlockMap
  ) async throws -> Data

  public static func commitOnly(
    commitCID: CID,
    commitBytes: Data
  ) async throws -> Data
}
```

The diff CAR is deterministic:

1. root is the commit CID;
2. commit block is emitted first;
3. all remaining block CIDs are sorted ascending by `cid.string`;
4. no duplicate commit block;
5. every emitted block’s bytes validate against its CID.

- [ ] **Step 1: Write failing diff-CAR tests**

Cover:

- repeated builds are byte-identical;
- CAR root is the commit CID;
- commit block is the first block;
- remaining blocks are sorted by CID string, not `Set` iteration order;
- a missing block produces a typed error;
- `commitOnly` contains exactly the commit block;
- synthetic blocks use valid `CID.fromDAGCBOR` values.

Use a private array-backed `PublicRepositoryCARBlockStream` with an integer cursor. Do not use `removeFirst()` in the actor, which makes iteration quadratic.

- [ ] **Step 2: Confirm red, implement, and confirm green**

```bash
swift test --filter PublicFirehoseDiffCARTests
```

Implementation uses `PublicRepositoryCAR.write(rootCID:blocks:to:)` and an in-memory actor sink. No filesystem or database access is allowed.

- [ ] **Step 3: Add failing mutation integration tests**

Reuse an existing real public mutation fixture: install genesis, reserve a revision, prepare through `PublicRepositoryEngine`, and call the protocol method.

After a successful ordinary write, assert:

- one account outbox row;
- final kind `.commit`;
- source key `did|commit|<new commit CID>`;
- lifecycle generation `0`;
- decoded material matches DID, new revision, previous revision, commit CID, previous data CID, and operations;
- CAR is nonempty and deterministic;
- repeated request replay keeps exactly one source row.

Add these additional tests:

1. **Action mapping:** create/update/delete map by explicit `switch`; no `.rawValue` exists on `PublicRepositoryMutationAction`.
2. **Rollback on outbox conflict:** preinsert a conflicting row using the prepared commit source key, call apply, assert the repository head, projection, mutation request status, and outbox all remain at pre-call state.
3. **Injected SQL failure:** every newly introduced mutation point rolls back repository blocks, projection, head, request status, and outbox together.
4. **Final-frame fallback:** material whose final maximum-sequence commit frame exceeds a commit limit is persisted as `.sync` with a `syncOversize` key and commit-only CAR.
5. **No runtime decision drift:** the stored event kind is final and replaying the same prepared mutation cannot change it.

- [ ] **Step 4: Build pure event material before entering the repository transaction**

At the beginning of `applyPublicRepositoryMutation`, before `withConnectionGate`:

- capture `eventTime = Date()` once;
- compute `eventTimeString` and checked microseconds once;
- map `prepared.recordResults` to typed firehose operations using an explicit action switch;
- build the deterministic diff CAR from `prepared.newBlocks`;
- build the commit-only CAR from `prepared.signedCommit`.

These operations use immutable prepared data and in-memory actors only. They must not open SQLite or perform network I/O.

- [ ] **Step 5: Decide the durable final kind inside the existing transaction**

After current state has been loaded and validated, build commit material using:

```text
did             = accountDID
rev             = prepared.state.revision
since           = prepared.sinceRevision
commitCID       = prepared.state.commitCID.string
prevDataCID     = current.dataCID.string
ops             = precomputed typed ops
time            = captured event time
```

Preflight the exact complete commit frame at the largest legal sequence:

```swift
try FirehoseFrameEncoder.commitFrame(
  seq: FirehoseFrameLimits.maximumSequence,
  material: material,
  diffCAR: diffCAR
)
```

Using the maximum sequence ensures the preflight is not smaller than a later real frame due to integer encoding width.

Decision:

- success → persist `.commit`, commit material, diff CAR, `commit` source key;
- `tooManyOperations`, commit `blocksTooLarge`, or `frameTooLarge` → persist `.sync`, sync material, commit-only CAR, `syncOversize` source key;
- invalid CID, invalid operation, invalid account state, or an invalid sync preflight → throw as an internal invariant violation and roll back the repository transaction.

Preflight the generated sync frame at maximum sequence before insertion as well.

The sequencer must never later reinterpret a persisted commit row as sync. The source transaction owns this decision.

- [ ] **Step 6: Insert at the existing committed-request point**

After the mutation request is marked committed and before returning `CommittedPublicRepositoryMutation`, call:

```swift
let inserted = try await enqueuePublicFirehoseEventInTransaction(...)
guard inserted else {
  throw PublicRepositoryMutationStoreError.corruptRepository
}
```

An exact duplicate cannot legitimately occur on this path because committed-request replay returned earlier. Then immediately call:

```swift
try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
```

The new INSERT is part of the public mutation’s fault-injection sequence. Update expected mutation counts and all hostile rollback matrices rather than bypassing the instrumentation.

The existing early committed-request replay return remains before this point; it is the primary duplicate-prevention mechanism. The unique source key is a second line of defense.

- [ ] **Step 7: Confirm focused, SQLite, and repository suites**

```bash
swift test --filter PublicFirehoseCommitEnqueueTests
swift test --filter PublicRepositoryMutationStoreTests
swift test --filter SwanSQLiteTests
```

- [ ] **Step 8: Commit**

```bash
jj commit Sources/SwanPublicFirehose Sources/SwanSQLite Tests \
  -m "firehose: enqueue final public events with repository commits"
```

---
### Task 5: Add durable lifecycle batches and per-DID generations

**Files:**

- Modify: `Sources/SwanSQLite/SwanSQLite.swift` (`SQLiteLayout.controlMigrations`)
- Create: `Sources/SwanSQLite/LifecycleEventOutboxStore.swift`
- Test: `Tests/SwanSQLiteTests/LifecycleEventOutboxStoreTests.swift`

**Scope:** This task implements the durable batch model and ordering metadata. It does **not** hook raw status or PLC-history methods. Confirmed lifecycle operation integrations remain Phase 4.

**Produces:**

```swift
public struct LifecycleEventItem: Sendable, Equatable {
  public let sourceKey: String
  public let kind: PublicFirehoseEventKind
  public let payload: Data
  public let carBytes: Data?
}

public struct LifecycleEventBatch: Sendable, Equatable {
  public let batchID: String
  public let did: String
  public let generation: Int64
  public let createdAt: Int64
  public let items: [LifecycleEventItem]
}
```

Methods on `SQLiteControlDatabase`:

```swift
public func enqueueLifecycleEventBatch(
  did: String,
  operationID: String,
  items: [LifecycleEventItem],
  now: Date
) async throws -> LifecycleEventBatch

public func currentLifecycleGeneration(did: String) async throws -> Int64

public func nextPendingLifecycleBatch(
  did: String?
) async throws -> LifecycleEventBatch?

public func pendingLifecycleDIDs() async throws -> [String]

@discardableResult
public func completeLifecycleBatch(batchID: String) async throws -> Bool
```

Batch IDs are not raw operation IDs. They are:

```swift
PublicFirehoseSourceKey.lifecycleBatch(did: did, operationID: operationID)
```

This prevents two accounts from colliding on the same external operation identifier.

- [ ] **Step 1: Add normalized control-plane tables**

Append idempotent DDL to `SQLiteLayout.controlMigrations`:

```sql
CREATE TABLE IF NOT EXISTS account_lifecycle_generation (
    did TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK(generation >= 0)
);

CREATE TABLE IF NOT EXISTS lifecycle_event_batches (
    batch_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    UNIQUE(did, generation)
);

CREATE TABLE IF NOT EXISTS lifecycle_event_items (
    batch_id TEXT NOT NULL
        REFERENCES lifecycle_event_batches(batch_id) ON DELETE CASCADE,
    batch_ordinal INTEGER NOT NULL CHECK(batch_ordinal >= 0),
    source_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK(kind IN ('sync', 'identity', 'account')),
    payload BLOB NOT NULL CHECK(length(payload) > 0),
    car_bytes BLOB,
    PRIMARY KEY(batch_id, batch_ordinal),
    CHECK(
        (kind = 'sync' AND car_bytes IS NOT NULL AND length(car_bytes) > 0)
        OR (kind IN ('identity', 'account') AND car_bytes IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS lifecycle_event_batches_pending
ON lifecycle_event_batches(did, generation, created_at, batch_id);
```

A lifecycle batch contains 1–16 items. Commit events never originate in the control database.

- [ ] **Step 2: Write failing tests**

Cover:

1. first batch for a DID receives generation 1;
2. a second new operation receives generation 2;
3. another DID starts at generation 1;
4. exact operation replay returns the stored batch and does not increment generation;
5. same operation ID with changed DID, item count, ordinal, source key, kind, payload, or CAR throws conflict;
6. batch ID is DID-namespaced;
7. empty and over-limit batches are rejected;
8. commit-kind lifecycle item is rejected;
9. sync without CAR is rejected;
10. identity/account with CAR is rejected;
11. malformed payload or a payload whose frame cannot preflight at maximum sequence is rejected before storage;
12. pending batch order is generation order for one DID;
13. `pendingLifecycleDIDs` is unique and sorted;
14. completion deletes items by cascade but preserves the generation counter;
15. completion replay returns false.

Use real encoded material, valid CIDs, and corrected fixed dates.

- [ ] **Step 3: Confirm red**

```bash
swift test --filter LifecycleEventOutboxStoreTests
```

- [ ] **Step 4: Implement idempotent batch enqueue**

The public method uses one gate and one `BEGIN IMMEDIATE` transaction.

Algorithm:

1. validate item count and kind/CAR shape;
2. decode each payload by kind;
3. preflight its frame at `FirehoseFrameLimits.maximumSequence` using its CAR where required;
4. compute the DID-namespaced batch ID;
5. if batch ID exists, load the complete stored batch and require exact equality; return it unchanged;
6. otherwise increment generation atomically:

   ```sql
   INSERT INTO account_lifecycle_generation(did, generation)
   VALUES (?, 1)
   ON CONFLICT(did) DO UPDATE SET generation = generation + 1
   RETURNING generation;
   ```

7. insert the batch row;
8. insert every item with ordinals `0 ..< count`;
9. return the durable representation.

Map unique-key violations on `source_key` or `(did, generation)` to a typed conflict/corruption error rather than presenting them as successful replay.

No lease columns are required in Phase 1 because there is one sequencer and the global append is idempotent by exact source key. Crash recovery is append-then-complete: a batch left in this table is safely replayed. This assumption must remain in the store’s documentation.

- [ ] **Step 5: Confirm green and run control-store regressions**

```bash
swift test --filter LifecycleEventOutboxStoreTests
swift test --filter SwanSQLiteTests
```

- [ ] **Step 6: Commit**

```bash
jj commit Sources/SwanSQLite Tests/SwanSQLiteTests \
  -m "firehose: add lifecycle batches and per-DID generations"
```

---

### Task 6: Add the global `firehose.sqlite` log and checked sequence allocator

**Files:**

- Modify: `Sources/SwanSQLite/SwanSQLite.swift` (`SQLiteLayout` path helper)
- Create: `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift`
- Test: `Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift`

**Produces:**

```swift
public actor SQLiteFirehoseDatabase

public struct FirehoseAppendItem: Sendable {
  public let sourceKey: String
  public let batchID: String?
  public let did: String
  public let kind: PublicFirehoseEventKind
  public let encodeFrame: @Sendable (Int64) throws -> Data
}

public struct FirehoseStoredEvent: Sendable, Equatable {
  public let seq: Int64
  public let sourceKey: String
  public let batchID: String?
  public let batchOrdinal: Int?
  public let did: String
  public let kind: PublicFirehoseEventKind
  public let sequencedAt: Int64
  public let frameBytes: Data
}
```

Methods:

```swift
public init(dataDirectory: URL) async throws

public func appendBatch(
  _ items: [FirehoseAppendItem],
  now: Date
) async throws -> [Int64]

public func maxSequencedSeq() async throws -> Int64

public func events(
  after seq: Int64,
  limit: Int
) async throws -> [FirehoseStoredEvent]

public func reseedSequence(toAtLeast nextSeq: Int64) async throws

public func close() async throws
```

Add:

```swift
public static func firehoseDatabase(in dataDirectory: URL) -> URL {
  dataDirectory.appending(path: "firehose.sqlite")
}
```

- [ ] **Step 1: Add hardened schema**

Open and harden the file by copying the managed `SQLiteControlDatabase` path discipline:

- `SQLiteProtectedPaths.openRoot`
- `openDatabaseFile(... name: "firehose.sqlite" ...)`
- `SQLiteConnection.open`
- `SQLiteLayout.controlConnectionPragmas`
- migration busy retry where applicable
- `SQLiteProtectedPaths.hardenSQLiteFiles`
- retained descriptors closed on success, explicit close, and failure paths.

Schema:

```sql
CREATE TABLE IF NOT EXISTS firehose_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    next_seq INTEGER NOT NULL
        CHECK(next_seq >= 1 AND next_seq <= 9007199254740992),
    retained_from_seq INTEGER
        CHECK(
            retained_from_seq IS NULL
            OR (
                retained_from_seq >= 1
                AND retained_from_seq <= 9007199254740991
            )
        )
);

INSERT INTO firehose_meta(singleton, next_seq, retained_from_seq)
SELECT 1, 1, NULL
WHERE NOT EXISTS (SELECT 1 FROM firehose_meta WHERE singleton = 1);

CREATE TABLE IF NOT EXISTS firehose_events (
    seq INTEGER PRIMARY KEY
        CHECK(seq >= 1 AND seq <= 9007199254740991),
    source_key TEXT NOT NULL UNIQUE,
    batch_id TEXT,
    batch_ordinal INTEGER,
    did TEXT NOT NULL CHECK(length(did) > 0),
    kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync', 'identity', 'account')),
    sequenced_at INTEGER NOT NULL CHECK(sequenced_at >= 0),
    frame_bytes BLOB NOT NULL
        CHECK(length(frame_bytes) > 0 AND length(frame_bytes) <= 5000000),
    CHECK(
        (batch_id IS NULL AND batch_ordinal IS NULL)
        OR (batch_id IS NOT NULL AND batch_ordinal IS NOT NULL AND batch_ordinal >= 0)
    ),
    UNIQUE(batch_id, batch_ordinal)
);

CREATE INDEX IF NOT EXISTS firehose_events_did_seq
ON firehose_events(did, seq);

CREATE INDEX IF NOT EXISTS firehose_events_batch
ON firehose_events(batch_id, batch_ordinal)
WHERE batch_id IS NOT NULL;
```

`next_seq` is the next unused number. `9_007_199_254_740_992` is allowed only as the exhausted sentinel; no event may receive it.

- [ ] **Step 2: Write failing tests**

Cover:

1. three-item batch allocates `[1, 2, 3]` and stores complete frames;
2. reopening continues at `4`;
3. exact source replay returns original sequences without new rows;
4. same source key with changed DID, kind, batch ID, or frame bytes throws conflict;
5. a non-nil batch must be all new or all existing; mixed existing/new is corruption;
6. an all-existing batch must preserve the same item order, stored batch ordinals, and consecutive sequence range; reordering the request is conflict;
7. all items in a non-nil batch must share the same batch ID;
8. a nil batch ID is allowed only for one item;
9. duplicate source keys inside one request are rejected before SQL;
10. sequence arithmetic never uses unchecked SQL addition;
11. allocating across `maximumSequence` fails and inserts nothing;
12. `next_seq = maximumSequence + 1` is a stable exhausted state;
13. encoding failure rolls back sequence metadata and rows;
14. frame larger than 5,000,000 fails before or at the table constraint and rolls back;
15. `events(after:limit:)` is ascending and strictly greater than `after`;
16. `after = 0` is valid; negative or over-maximum cursors and non-positive/excessive limits are rejected;
17. `reseedSequence` raises only, never lowers, and accepts the exhausted sentinel;
18. close/reopen and descriptor cleanup.

- [ ] **Step 3: Confirm red**

```bash
swift test --filter SQLiteFirehoseDatabaseTests
```

- [ ] **Step 4: Implement checked atomic allocation**

`appendBatch` validates request shape before entering the transaction.

Inside one `BEGIN IMMEDIATE` transaction:

1. look up all existing `source_key` rows;
2. if any exist:
   - require either all items exist or, for a single nil-batch item, that one exists;
   - for a non-nil batch, require stored `batch_ordinal` values to equal request indices `0 ..< count` and stored sequences to be consecutive in that same order;
   - re-encode every requested item at its stored sequence;
   - require exact equality of source key, batch ID, batch ordinal, DID, kind, and frame bytes;
   - return stored sequence numbers in request order;
3. if none exist:
   - `SELECT next_seq FROM firehose_meta WHERE singleton = 1`;
   - calculate `last = start + count - 1` using checked Swift arithmetic;
   - require `start <= maximumSequence` and `last <= maximumSequence`;
   - set `newNext = last + 1`, which may be the exhausted sentinel;
   - encode all frames before mutating metadata if possible; at minimum, keep all encoding and inserts inside the same transaction so failure rolls back;
   - `UPDATE firehose_meta SET next_seq = ? WHERE singleton = 1 AND next_seq = ?` and require one row;
   - insert all events in item order with consecutive sequences, storing array index as `batch_ordinal` for non-nil batches and null for single account events;
   - commit and return sequences.

Do not use:

```sql
UPDATE firehose_meta SET next_seq = next_seq + ?
```

without first performing checked host-language arithmetic. SQLite signed overflow and the AT Protocol safe-integer boundary are separate hazards.

- [ ] **Step 5: Implement exact replay validation**

Idempotency means “the same durable fact was retried,” not “the key happened to exist.” Re-encoding at the stored sequence protects against:

- source-key collisions;
- changed material under the same source key;
- a code regression that would change replay bytes;
- a lifecycle batch partially or incorrectly reconstructed after a crash.

A mixed existing/new non-nil batch cannot result from a successful atomic append and must fail closed.

- [ ] **Step 6: Confirm focused and full SQLite suites**

```bash
swift test --filter SQLiteFirehoseDatabaseTests
swift test --filter SwanSQLiteTests
```

- [ ] **Step 7: Commit**

```bash
jj commit Sources/SwanSQLite Tests/SwanSQLiteTests \
  -m "firehose: add checked global event log"
```

---
### Task 7: Add the causally ordered sequencer worker

**Files:**

- Create: `Sources/SwanSQLite/PublicFirehoseSequencer.swift`
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseSequencerTests.swift`

**Produces:**

```swift
public struct PublicFirehoseAccountDatabase: Sendable {
  public let did: String
  public let database: SQLiteAccountDatabase
}

public protocol PublicFirehoseAccountDatabaseSource: Sendable {
  func publicFirehoseAccountDatabases()
    async throws -> [PublicFirehoseAccountDatabase]
}

public protocol PublicFirehoseWakeupSink: Sendable {
  func firehoseDidAppend(maxSeq: Int64) async
}

public struct PublicFirehoseSequencerConfiguration: Sendable, Equatable {
  public let leaseDuration: TimeInterval
  public let idlePollInterval: TimeInterval
  public let initialFailureBackoff: TimeInterval
  public let maximumFailureBackoff: TimeInterval

  public static let standard: Self

  public init(
    leaseDuration: TimeInterval = 30,
    idlePollInterval: TimeInterval = 0.25,
    initialFailureBackoff: TimeInterval = 1,
    maximumFailureBackoff: TimeInterval = 60
  ) throws
}

public enum PublicFirehoseSequencerResult: Sendable, Equatable {
  case idle
  case sequencedLifecycleBatch(batchID: String, seqs: [Int64])
  case sequencedAccountEvent(sourceKey: String, seq: Int64)
  case leaseLost(sourceKey: String, seq: Int64)
}

public actor PublicFirehoseSequencer {
  public init(
    accountSource: any PublicFirehoseAccountDatabaseSource,
    control: SQLiteControlDatabase,
    firehose: SQLiteFirehoseDatabase,
    wakeup: (any PublicFirehoseWakeupSink)? = nil,
    configuration: PublicFirehoseSequencerConfiguration = .standard
  )

  public func sequenceNext(
    now: Date = Date()
  ) async throws -> PublicFirehoseSequencerResult

  public func drainAll(
    now: Date = Date()
  ) async throws -> Int

  public func runUntilCancelled() async
}
```

The configuration mirrors `PermissionedSpaceOutboxDeliveryConfiguration`; do not store an arbitrary retry closure in a `Sendable` public configuration. Validate finite positive values, one-day maximum, and initial-backoff `<=` maximum-backoff.

- [ ] **Step 1: Add a dynamic account database source**

Make `SQLitePreMigratedAccountDirectory` conform to `PublicFirehoseAccountDatabaseSource` with:

```swift
public func publicFirehoseAccountDatabases()
  async throws -> [PublicFirehoseAccountDatabase]
```

Requirements:

- return a fresh snapshot on every call so accounts activated after server startup can be discovered;
- sort by DID for deterministic scheduling;
- return all currently managed/preopened account databases, not only accounts whose current control status is active;
- do not open, create, or migrate a database from this method;
- do not reuse `notificationRecoveryDatabases()`, because its active-only filter could strand public commits written before deactivation;
- reject calls after directory close;
- permanent deletion must continue removing/closing the account database through the directory’s existing lifecycle path.

Tests use a small fixed source implementation rather than the production directory where convenient.

- [ ] **Step 2: Write failing causal-order and crash tests**

Use real encoded frames and real SQLite stores. Cover:

1. ordinary generation-0 commit flows to global seq 1 and drains its source row;
2. wakeup receives the new max sequence after source completion;
3. exact account crash replay:
   - lease source row;
   - append globally;
   - trigger a test-only simulated process crash before source completion;
   - advance `now` past lease expiry;
   - retry;
   - global row count remains one and the original sequence is returned;
4. exact lifecycle crash replay:
   - append a multi-item batch;
   - crash before control-batch completion;
   - retry;
   - all original sequences are reused and the batch is then completed;
5. same-generation ordering:
   - lifecycle generation 1 contains identity then account;
   - account source row carries generation 1;
   - global order is identity, account, account-source event;
6. two-sided boundary ordering:
   - account event generation 0;
   - lifecycle batch generation 1;
   - account event generation 1;
   - lifecycle batch generation 2;
   - account event generation 2;
   - global order is exactly account-0, lifecycle-1 items, account-1, lifecycle-2 items, account-2;
7. multiple pending lifecycle generations merge correctly with account heads between them;
8. a failed or leased account head blocks later account rows and the next lifecycle generation for that DID, but does not block another DID;
9. round-robin scheduling prevents one hot DID from permanently starving another;
10. account row final kind is honored; the sequencer never dynamically changes commit to sync;
11. lifecycle sync uses its stored CAR bytes;
12. source-key/global-frame conflict fails closed and does not delete the source;
13. stale source lease completion produces `.leaseLost` while the global append remains durable;
14. `drainAll` counts successful source steps, where one lifecycle batch is one step even if it appends multiple events.

Add an internal test hook, not a public production API, for the exact crash boundary:

```text
after global append commits
before source outbox/batch completion
```

A throwing hook must leave the source untouched. Do not simulate this by successfully completing and then manually recreating a row; that does not test the real boundary.

- [ ] **Step 3: Confirm red**

```bash
swift test --filter PublicFirehoseSequencerTests
```

- [ ] **Step 4: Implement the per-DID causal merge**

The ordering model is:

```text
lifecycle batch g  <  account events stamped g  <  lifecycle batch g + 1
```

For each DID, peek:

- the smallest account outbox `id`, with generation `a`;
- the smallest pending lifecycle batch generation `l`.

Choose the next causal source:

```text
only account exists       -> account
only lifecycle exists     -> lifecycle
both and a < l            -> account
both and l <= a           -> lifecycle
neither                    -> none
```

This is intentionally not “all lifecycle batches first.” Draining lifecycle generation 2 before an older account event stamped generation 1 would invert externally visible causality.

Scheduling algorithm for one `sequenceNext` call:

1. obtain a dynamic account snapshot;
2. obtain `pendingLifecycleDIDs()`;
3. take the sorted union of DIDs and rotate it from the actor’s round-robin cursor;
4. for each DID:
   - peek both source heads;
   - choose the causal source by the rule above;
   - if account is chosen, attempt to lease only its strict FIFO head;
   - if that head is delayed or has an unexpired lease, continue to another DID; do not process a later event or the next lifecycle batch for this DID;
   - if lifecycle is chosen, append the complete ordered batch;
5. after one successful source step, advance the round-robin cursor and return;
6. if no DID has a causally ready source, return `.idle`.

- [ ] **Step 5: Encode persisted final material without reinterpretation**

Account source:

- decode payload according to stored kind;
- commit requires its stored diff CAR;
- sync requires its stored commit-only CAR;
- construct one `FirehoseAppendItem` with `batchID: nil`;
- append globally;
- invoke the test crash hook, if any;
- complete the token-checked source lease;
- notify the wakeup sink only after source completion;
- return `.sequencedAccountEvent` or `.leaseLost`.

Lifecycle source:

- preserve stored item ordinal;
- decode identity/account/sync material;
- sync requires stored CAR;
- construct items sharing the durable batch ID;
- append as one global transaction;
- invoke the test crash hook;
- complete the control batch;
- notify with `seqs.last`;
- return `.sequencedLifecycleBatch`.

A persisted `.commit` that no longer encodes within limits is source corruption. Do not silently turn it into `.sync` in this worker; Task 4 owned the durable decision.

- [ ] **Step 6: Preserve append-then-complete crash safety**

Document this invariant on the actor:

```text
source lease/batch remains durable
        ↓
global append commits
        ↓
source completion commits
```

A crash after global append but before source completion leaves the source present. On retry, `appendBatch` finds the exact source key, re-encodes and validates the stored frame, returns the original sequence, and source completion then removes the source. There is no duplicate sequence and no lost event.

Transient pre-append failures reschedule account leases using the persisted attempts count and bounded exponential backoff. Exact source conflicts, malformed durable material, and global-log corruption fail closed and must not delete the source.

- [ ] **Step 7: Implement the service loop**

Mirror the bounded cancellation loop in `PermissionedSpaceOutboxDeliveryWorker`:

- call `sequenceNext`;
- sleep for `idlePollInterval` on idle;
- sleep on transient errors;
- exit promptly when the task is cancelled;
- never retain arbitrary error strings in durable storage.

- [ ] **Step 8: Confirm focused and full tests**

```bash
swift test --filter PublicFirehoseSequencerTests
swift test --filter SwanSQLiteTests
```

- [ ] **Step 9: Commit**

```bash
jj commit Sources/SwanSQLite Tests/SwanSQLiteTests \
  -m "firehose: add causally ordered global sequencer"
```

---

### Task 8: Wire the sequencer service and add the isolation/exit gates

**Files:**

- Create: `Sources/SwanHTTP/SwanPublicFirehoseSequencerService.swift`
- Modify: `Sources/swan/SwanCommand.swift`
- Modify: `Package.swift` only if tests need direct `SwanPublicFirehose` imports
- Test: `Tests/SwanSQLiteTests/PublicFirehoseIsolationTests.swift`
- Test: `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift`

`SQLitePreMigratedAccountDirectory` source conformance was added in Task 7; do not add a second static database inventory here.

**Produces:**

```swift
public struct SwanPublicFirehoseSequencerService: Service {
  public init(sequencer: PublicFirehoseSequencer)
  public func run() async throws
}
```

Implementation:

```swift
public func run() async throws {
  await sequencer.runUntilCancelled()
}
```

Match the actual `SwanNotificationRecoveryService` lifecycle style. Do not call a nonexistent `cancelWhenGracefulShutdown` helper.

- [ ] **Step 1: Add the hard permissioned-isolation test**

Copy a real permissioned-space write fixture and perform a successful permissioned write. Then assert:

- `pendingPublicFirehoseOutbox()` is empty;
- no lifecycle batch was created;
- running a sequencer over the account produces zero steps;
- `firehose.events(after: 0, limit: 10)` is empty.

Also add a source-level dependency tripwire if the repository already uses architecture/dependency tests: permissioned domain and write files must not import `SwanPublicFirehose`.

This test is expected to pass before service wiring; it is a permanent regression gate rather than red/green TDD.

- [ ] **Step 2: Add an explicit Phase 1 server flag**

In the `serve` command in `Sources/swan/SwanCommand.swift`, next to the notification-delivery flag, add:

```swift
@Flag(
  name: .customLong("enable-public-firehose"),
  help: "Enable durable public firehose sequencing into firehose.sqlite"
)
var enablePublicFirehose = false
```

Keep the default false during Phase 1 because:

- there is not yet a WebSocket consumer surface;
- retention/pruning is Phase 3;
- an always-on append-only global log would otherwise grow without a production serve path.

The account-local outbox insertion is not feature-gated. With the worker disabled, rows accumulate durably and drain when the flag is enabled. Record this intermediate behavior in the CLI help or nearby comment. Reconsider the default at the Phase 2/3 activation gate.

- [ ] **Step 3: Write a failing direct service test**

Prefer a direct service test over inspecting opaque `ServiceGroup` contents:

1. construct account/control/firehose fixture databases;
2. construct a dynamic fixed account source and sequencer;
3. start `SwanPublicFirehoseSequencerService.run()` in a task;
4. commit a real public repository mutation through the existing mutation store;
5. poll `firehose.maxSequencedSeq()` with a strict five-second test deadline;
6. cancel the service task;
7. assert clean exit;
8. decode stored frame and confirm DID, revision, source key, and sequence.

Add `SwanPublicFirehose` as a direct `SwanHTTPTests` dependency only if the test imports its types. Do not rely on transitive module visibility.

- [ ] **Step 4: Wire in `SwanCommand.swift`, not `SwanHTTP.swift`**

The executable composition root currently opens `control.sqlite`, builds the account directory, constructs optional workers, assembles `[any Service]`, and calls `SwanHTTPServiceLifecycle.makeServiceGroup` in `Sources/swan/SwanCommand.swift`.

When `--enable-public-firehose` is set:

1. open `SQLiteFirehoseDatabase(dataDirectory:)`;
2. create `PublicFirehoseSequencer` with:
   - `accountSource: directory`;
   - the existing control database;
   - the new firehose database;
   - `wakeup: nil` in Phase 1;
3. wrap it in `SwanPublicFirehoseSequencerService`;
4. append the service beside notification recovery and email recovery services;
5. log that durable public firehose sequencing is enabled, without logging paths, rows, payloads, or account identifiers.

The service and initializer must be public because the executable target imports them from `SwanHTTP`.

- [ ] **Step 5: Close the global database on every exit path**

Track the optional `SQLiteFirehoseDatabase` alongside other preopened resources.

- after `serviceGroup.run()` returns, close it before or alongside directory/control closure;
- in the outer `catch`, `try? await` close it;
- avoid double close by following the established preopened-resource pattern;
- add a test or hostile path showing startup failure after global DB open does not leak descriptors.

- [ ] **Step 6: Run the Phase 1 exit gate**

```bash
swift build
swift test --filter PublicFirehoseIsolationTests
swift test --filter PublicFirehoseServiceWiringTests
swift test --filter PublicFirehose
swift test
```

Phase 1 is complete only when all of the following are true:

- a real public mutation transaction atomically creates one exact source event;
- the running sequencer service appends one complete, decodable frame to `firehose.sqlite`;
- crash after global append reuses the same sequence;
- lifecycle batch crash replay reuses the same consecutive sequence range;
- per-DID generation-boundary tests prove both sides of the causal merge;
- a delayed DID cannot block another DID;
- source conflicts fail closed;
- permissioned writes produce no public source or global rows;
- all existing test suites remain green.

- [ ] **Step 7: Commit**

```bash
jj commit Package.swift Sources/SwanHTTP Sources/swan Sources/SwanSQLite Tests \
  -m "firehose: wire durable sequencer service"
```

---

## Phase 1 completion record

Before declaring this phase sealed, append a brief implementation record to the governing design or a dedicated completion note containing:

- final migration version;
- final source-key formats;
- final per-DID generation ordering rule;
- exact global sequence allocator semantics;
- focused and full test commands with results;
- any renamed files or APIs;
- whether `--enable-public-firehose` remains default-off;
- explicit statement that WebSocket streaming, retention, lifecycle integrations, crawl announcement, and Indigo proof remain unimplemented.

## Deferred work and residual risks

These are deliberately outside Phase 1 and must not be presented as completed:

1. **Real lifecycle integrations.** Phase 1 stores and sequences lifecycle batches, but ordinary public writes are stamped generation `0`. Phase 4 must implement a confirmed, idempotent lifecycle saga that assigns generations to affected account writes without opening cross-database transactions.
2. **Initial activation ordering.** The activation flow must ensure identity/account generation `g` precedes the genesis or activation repository event stamped `g`. Do not hook low-level PLC-history installation.
3. **Rotation barrier.** A commit signed by a newly confirmed key must not pass its corresponding identity generation.
4. **Deletion.** Emit the public deleted account event when public availability ends, not after final physical erasure. Phase 3 may prune older retained rows for that DID after appending the deletion event.
5. **WebSocket/tailer.** Phase 2 must read `firehose.sqlite` as authority and use wakeups only to shorten polling latency.
6. **Cursor and retention semantics.** Phase 3 owns cursor `0`, future/outdated cursor behavior, hard-age/byte retention, and slow-consumer closure.
7. **`requestCrawl` and live relay proof.** Later phases own crawler retry state, Indigo pinning, subscription readiness, and inductive verification.
8. **Restore sequence recovery.** Phase 1 exposes `reseedSequence`; the operator restore workflow must later supply a safe high-water mark and prove that sequence values are never reused after restoring an older database.
9. **Feature-disabled accumulation.** While the Phase 1 flag is off, account outboxes grow. This is acceptable only as an intermediate development state and must be resolved before production activation.

## Final self-review checklist

- [ ] The governing design exists and no longer contains superseded source hooks, CID-list replay, direct-broadcast correctness, or unbounded minimum-row retention.
- [ ] No sketch calls nonexistent Petrel APIs such as mutable `OrderedCBORMap.append` or `DAGCBOR.decodeValueWithLength`.
- [ ] `since`, `prevData`, and operation `prev` have the correct null/optional wire distinctions.
- [ ] The 10,000-byte sync CAR limit is enforced.
- [ ] The public mutation protocol signature is unchanged.
- [ ] Final commit-versus-sync choice is persisted in the repository transaction.
- [ ] The new outbox INSERT participates in the existing mutating-SQL failure-injection ledger.
- [ ] Account outbox order is strict by smallest ID; later commits never overtake a delayed head.
- [ ] Exact source-key reuse compares all durable content.
- [ ] Lifecycle batches are DID-namespaced, nonempty, bounded, exact-replay validated, and carry sync CAR bytes.
- [ ] Global batch append is all-existing or all-new; partial replay fails closed.
- [ ] Sequence arithmetic is checked in Swift and permits only the exhausted sentinel above the event maximum.
- [ ] Per-DID causal merge proves `lifecycle g < account g < lifecycle g+1`.
- [ ] One blocked DID cannot stall another.
- [ ] Crash tests occur at the real append-before-complete boundary.
- [ ] Service composition changes are in `Sources/swan/SwanCommand.swift`.
- [ ] The global database is closed on successful shutdown and every startup/runtime failure path.
- [ ] Permissioned isolation remains a hard gate.
- [ ] All fixed 2026 dates use Unix time `1_785_844_800` or a value derived from it.
- [ ] `swift build` and the complete `swift test` suite pass.
