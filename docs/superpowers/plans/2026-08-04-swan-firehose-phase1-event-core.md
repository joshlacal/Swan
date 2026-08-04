# Swan Firehose Phase 1: Durable Event Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every public repository commit, and every enqueued lifecycle batch, durably lands in a global `firehose.sqlite` log with a monotonic `seq` and fully encoded firehose frame bytes — crash-safe, idempotent, and ordered per-DID.

**Architecture:** Account-local `public_event_outbox` rows are written inside the same SQLite transaction as the public repo commit (exact event material including diff-CAR bytes). A control-plane `lifecycle_event_outbox` holds ordered lifecycle batches with a per-DID generation counter. A single sequencer actor drains both, respects generation barriers, encodes complete DAG-CBOR frames, and appends batches atomically to `firehose.sqlite` with seqs allocated from `firehose_meta`.

**Tech Stack:** Swift 6 strict concurrency, SQLiteNIO, Petrel `DAGCBOR`/`OrderedCBORMap`, XCTest.

**Spec:** `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md` (read it first).

## Global Constraints

- Swift 6 strict concurrency; actors; 2-space indentation; XCTest (not Swift Testing).
- VCS: jj only, never git mutation. Commit with path-restricted `jj commit <paths> -m "firehose: …"`. Work happens in the jj workspace at `/Users/joshlacalamito/Developer/Catbird+Petrel/.worktrees/swan-public-federation` — run all commands from there.
- All DB access via `connection.query(sql, bindings)`; every mutation wrapped `try await withConnectionGate { try await transaction { … } }`. Never open a second database's transaction inside another's. Never perform network I/O inside a transaction.
- Frame encoding must use Petrel's `DAGCBOR.encodeValue` / `OrderedCBORMap` / tag-42 CID links, mirroring the exact usage in `Sources/SwanPublicRepository/PublicRepositoryCommit.swift:303-326` (`encodeUnsigned`/`encodeSigned`). If a signature there differs from this plan's sketch, the precedent file wins.
- Hard invariants: `1 <= seq < 9_007_199_254_740_992` (2^53); `#commit.blobs` is always `[]`; total encoded frame ≤ 5,000,000 bytes; `blocks` CAR ≤ 2,000,000 bytes; ≤ 200 ops.
- Sizes/limits and event body shapes come from the spec — do not improvise fields.
- Build: `swift build` (~fast on this machine). Test: `swift test --filter <TargetOrTest>`.
- Account DB migration version ledger: next free version is **13** (`permissionedRemoteReplicaLogicalLimitMigrationVersion = 12` is current highest). If rebasing onto newer main claims 13, renumber.

---

### Task 1: `SwanPublicFirehose` module — event model + source keys

**Files:**
- Modify: `Package.swift` (add product, target, test target)
- Create: `Sources/SwanPublicFirehose/PublicFirehoseEvent.swift`
- Create: `Sources/SwanPublicFirehose/PublicFirehoseSourceKey.swift`
- Test: `Tests/SwanPublicFirehoseTests/PublicFirehoseEventTests.swift`

**Interfaces:**
- Consumes: `CID` from Petrel; nothing else.
- Produces (later tasks depend on these exact names):
  - `enum PublicFirehoseEventKind: String, Codable, Sendable { case commit, sync, identity, account }`
  - `struct PublicFirehoseRepoOp: Codable, Sendable, Equatable { let action: String; let path: String; let cid: String?; let prev: String? }` (action ∈ create/update/delete; path `collection/rkey`; CIDs as strings in stored material)
  - `struct PublicFirehoseCommitMaterial: Codable, Sendable, Equatable { let did: String; let rev: String; let since: String; let commitCID: String; let prevDataCID: String; let ops: [PublicFirehoseRepoOp]; let time: String }`
  - `struct PublicFirehoseSyncMaterial: Codable, Sendable, Equatable { let did: String; let rev: String; let commitCID: String; let time: String }`
  - `struct PublicFirehoseIdentityMaterial: Codable, Sendable, Equatable { let did: String; let handle: String?; let time: String }`
  - `struct PublicFirehoseAccountMaterial: Codable, Sendable, Equatable { let did: String; let active: Bool; let status: String?; let time: String }`
  - `enum PublicFirehoseSourceKey` with static funcs: `commit(did:commitCID:) -> String`, `syncOversize(did:commitCID:)`, `syncManual(did:requestUUID:)`, `syncActivation(did:operationID:)`, `syncReactivation(did:operationID:)`, `account(did:operationID:)`, `identity(did:plcOperationCID:)` — formats exactly `"\(did)|commit|\(cid)"`, `"\(did)|sync|oversize|\(cid)"`, `"\(did)|sync|manual|\(uuid)"`, `"\(did)|sync|activation|\(op)"`, `"\(did)|sync|reactivation|\(op)"`, `"\(did)|account|\(op)"`, `"\(did)|identity|\(cid)"`.
  - `enum PublicFirehoseTime { static func encode(_ date: Date) -> String }` — ISO8601 with fractional seconds, UTC (`ISO8601DateFormatter` with `[.withInternetDateTime, .withFractionalSeconds]`).

- [ ] **Step 1: Add Package.swift entries**

In `products:` (alongside the other 12 libraries):
```swift
        .library(name: "SwanPublicFirehose", targets: ["SwanPublicFirehose"]),
```
In `targets:`:
```swift
        .target(
            name: "SwanPublicFirehose",
            dependencies: [
                "SwanCore", "SwanPublicRepository",
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
        .testTarget(
            name: "SwanPublicFirehoseTests",
            dependencies: [
                "SwanPublicFirehose", "SwanPublicRepository",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Petrel", package: "Petrel"),
            ]
        ),
```

- [ ] **Step 2: Write the failing tests**

`Tests/SwanPublicFirehoseTests/PublicFirehoseEventTests.swift`:
```swift
import Foundation
@testable import SwanPublicFirehose
import XCTest

final class PublicFirehoseEventTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testSourceKeyFormats() {
        XCTAssertEqual(
            PublicFirehoseSourceKey.commit(did: did, commitCID: "bafyreiabc"),
            "did:plc:abcdefghijklmnopqrstuvwx|commit|bafyreiabc"
        )
        XCTAssertEqual(
            PublicFirehoseSourceKey.syncOversize(did: did, commitCID: "bafyreiabc"),
            "did:plc:abcdefghijklmnopqrstuvwx|sync|oversize|bafyreiabc"
        )
        XCTAssertEqual(
            PublicFirehoseSourceKey.syncManual(
                did: did,
                requestUUID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
            ),
            "did:plc:abcdefghijklmnopqrstuvwx|sync|manual|00000000-0000-0000-0000-000000000001"
        )
        XCTAssertEqual(
            PublicFirehoseSourceKey.identity(did: did, plcOperationCID: "bafyreiop"),
            "did:plc:abcdefghijklmnopqrstuvwx|identity|bafyreiop"
        )
    }

    func testCommitMaterialJSONRoundTrip() throws {
        let material = PublicFirehoseCommitMaterial(
            did: did,
            rev: "3jzfcijpj2z2b",
            since: "3jzfcijpj2z2a",
            commitCID: "bafyreiabc",
            prevDataCID: "bafyreidef",
            ops: [PublicFirehoseRepoOp(
                action: "create",
                path: "app.bsky.feed.post/3jzfcijpj2z2b",
                cid: "bafyreirec",
                prev: nil
            )],
            time: "2026-08-04T12:00:00.000Z"
        )
        let data = try JSONEncoder().encode(material)
        let decoded = try JSONDecoder().decode(PublicFirehoseCommitMaterial.self, from: data)
        XCTAssertEqual(decoded, material)
    }

    func testTimeEncodingIsUTCWithFractionalSeconds() {
        let date = Date(timeIntervalSince1970: 1_754_308_800)
        XCTAssertEqual(PublicFirehoseTime.encode(date), "2026-08-04T12:00:00.000Z")
    }
}
```

- [ ] **Step 3: Run tests, verify they fail to compile (module doesn't exist)**

Run: `swift test --filter PublicFirehoseEventTests`
Expected: build failure — `no such module 'SwanPublicFirehose'` / missing types.

- [ ] **Step 4: Implement the types**

`Sources/SwanPublicFirehose/PublicFirehoseEvent.swift` — the structs/enums exactly as in Interfaces, all `public`, memberwise `public init`. `Sources/SwanPublicFirehose/PublicFirehoseSourceKey.swift`:
```swift
import Foundation

public enum PublicFirehoseSourceKey {
    public static func commit(did: String, commitCID: String) -> String {
        "\(did)|commit|\(commitCID)"
    }

    public static func syncOversize(did: String, commitCID: String) -> String {
        "\(did)|sync|oversize|\(commitCID)"
    }

    public static func syncManual(did: String, requestUUID: UUID) -> String {
        "\(did)|sync|manual|\(requestUUID.uuidString.lowercased())"
    }

    public static func syncActivation(did: String, operationID: String) -> String {
        "\(did)|sync|activation|\(operationID)"
    }

    public static func syncReactivation(did: String, operationID: String) -> String {
        "\(did)|sync|reactivation|\(operationID)"
    }

    public static func account(did: String, operationID: String) -> String {
        "\(did)|account|\(operationID)"
    }

    public static func identity(did: String, plcOperationCID: String) -> String {
        "\(did)|identity|\(plcOperationCID)"
    }
}

public enum PublicFirehoseTime {
    public static func encode(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `swift test --filter PublicFirehoseEventTests`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
jj commit Package.swift Sources/SwanPublicFirehose Tests/SwanPublicFirehoseTests -m "firehose: add SwanPublicFirehose event model and source keys"
```

---

### Task 2: DAG-CBOR frame encoder

**Files:**
- Create: `Sources/SwanPublicFirehose/FirehoseFrameEncoder.swift`
- Create: `Sources/SwanPublicFirehose/FirehoseFrameLimits.swift`
- Test: `Tests/SwanPublicFirehoseTests/FirehoseFrameEncoderTests.swift`

**Interfaces:**
- Consumes: Task 1 material types; Petrel `DAGCBOR`, `OrderedCBORMap`, `ATProtoLink`, `CID` (mirror usage in `PublicRepositoryCommit.swift:303-326` — that file is the authority on the encode API).
- Produces:
  - `enum FirehoseFrameLimits { static let maximumFrameBytes = 5_000_000; static let maximumBlocksBytes = 2_000_000; static let maximumOps = 200; static let maximumSequence: Int64 = 9_007_199_254_740_991; static func validateSequence(_ seq: Int64) throws }`
  - `enum FirehoseFrameEncoderError: Error, Equatable { case sequenceOutOfRange, frameTooLarge(Int), invalidCID(String) }`
  - `enum FirehoseFrameEncoder` with:
    - `static func commitFrame(seq: Int64, material: PublicFirehoseCommitMaterial, diffCAR: Data) throws -> Data`
    - `static func syncFrame(seq: Int64, material: PublicFirehoseSyncMaterial, commitCAR: Data) throws -> Data`
    - `static func identityFrame(seq: Int64, material: PublicFirehoseIdentityMaterial) throws -> Data`
    - `static func accountFrame(seq: Int64, material: PublicFirehoseAccountMaterial) throws -> Data`
    - `static func infoFrame(name: String, message: String?) throws -> Data`
    - `static func errorFrame(error: String, message: String?) throws -> Data`
  - Each returns header+body concatenated. Header map key order: `op`, `t` (alphabetical — DAG-CBOR canonical ordering is enforced by `OrderedCBORMap`/encoder; mirror the commit-encoder precedent). Body fields per spec: commit body keys `seq, rebase, tooBig, repo, commit, rev, since, blocks, ops, blobs, prevData, time` with `rebase: false`, `tooBig: false`, `blobs: []`, `commit`/`prevData` as tag-42 links, `blocks` as CBOR byte string; op entries `{action, path, cid (link or null), prev (link or null)}`.

- [ ] **Step 1: Write the failing tests**

```swift
import Foundation
import Petrel
@testable import SwanPublicFirehose
import XCTest

final class FirehoseFrameEncoderTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    // Valid CIDv1 dag-cbor sha2-256 strings: generate once in a helper from real bytes.
    private func makeCID(_ seed: String) throws -> CID {
        CID.fromDAGCBOR(Data(seed.utf8))
    }

    func testCommitFrameDecodesWithExpectedFields() throws {
        let commitCID = try makeCID("commit")
        let prevData = try makeCID("prevdata")
        let recordCID = try makeCID("record")
        let material = PublicFirehoseCommitMaterial(
            did: did, rev: "3jzfcijpj2z2b", since: "3jzfcijpj2z2a",
            commitCID: commitCID.string, prevDataCID: prevData.string,
            ops: [PublicFirehoseRepoOp(
                action: "create", path: "app.bsky.feed.post/3jzfcijpj2z2b",
                cid: recordCID.string, prev: nil
            )],
            time: "2026-08-04T12:00:00.000Z"
        )
        let car = Data([0x0a, 0x0b, 0x0c])
        let frame = try FirehoseFrameEncoder.commitFrame(seq: 42, material: material, diffCAR: car)

        // Decode the two concatenated DAG-CBOR objects.
        let (header, headerLength) = try DAGCBOR.decodeValueWithLength(frame)
        let body = try DAGCBOR.decodeValue(frame.dropFirst(headerLength))
        let headerMap = try XCTUnwrap(header as? [String: Any])
        XCTAssertEqual(headerMap["op"] as? Int, 1)
        XCTAssertEqual(headerMap["t"] as? String, "#commit")
        let bodyMap = try XCTUnwrap(body as? [String: Any])
        XCTAssertEqual(bodyMap["seq"] as? Int, 42)
        XCTAssertEqual(bodyMap["repo"] as? String, did)
        XCTAssertEqual(bodyMap["rev"] as? String, "3jzfcijpj2z2b")
        XCTAssertEqual(bodyMap["since"] as? String, "3jzfcijpj2z2a")
        XCTAssertEqual(bodyMap["rebase"] as? Bool, false)
        XCTAssertEqual(bodyMap["tooBig"] as? Bool, false)
        XCTAssertEqual((bodyMap["blobs"] as? [Any])?.count, 0)
        XCTAssertEqual(bodyMap["blocks"] as? Data, car)
        let ops = try XCTUnwrap(bodyMap["ops"] as? [[String: Any]])
        XCTAssertEqual(ops.count, 1)
        XCTAssertEqual(ops[0]["action"] as? String, "create")
        XCTAssertEqual(ops[0]["path"] as? String, "app.bsky.feed.post/3jzfcijpj2z2b")
    }

    func testSequenceBoundsRejected() {
        let material = PublicFirehoseAccountMaterial(
            did: did, active: false, status: "deactivated",
            time: "2026-08-04T12:00:00.000Z"
        )
        XCTAssertThrowsError(
            try FirehoseFrameEncoder.accountFrame(seq: 0, material: material)
        )
        XCTAssertThrowsError(
            try FirehoseFrameEncoder.accountFrame(
                seq: 9_007_199_254_740_992, material: material
            )
        )
    }

    func testFrameTooLargeRejected() throws {
        let material = PublicFirehoseSyncMaterial(
            did: did, rev: "3jzfcijpj2z2b",
            commitCID: try makeCID("commit").string,
            time: "2026-08-04T12:00:00.000Z"
        )
        let oversized = Data(count: 5_000_001)
        XCTAssertThrowsError(
            try FirehoseFrameEncoder.syncFrame(seq: 1, material: material, commitCAR: oversized)
        ) { error in
            guard case FirehoseFrameEncoderError.frameTooLarge = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    func testErrorFrame() throws {
        let frame = try FirehoseFrameEncoder.errorFrame(error: "ConsumerTooSlow", message: nil)
        let (header, headerLength) = try DAGCBOR.decodeValueWithLength(frame)
        let headerMap = try XCTUnwrap(header as? [String: Any])
        XCTAssertEqual(headerMap["op"] as? Int, -1)
        XCTAssertNil(headerMap["t"])
        let body = try DAGCBOR.decodeValue(frame.dropFirst(headerLength))
        XCTAssertEqual((body as? [String: Any])?["error"] as? String, "ConsumerTooSlow")
    }
}
```
NOTE for implementer: Petrel's decode entry points are in `Petrel/Sources/Petrel/Core/Types/CID.swift:586`. If `decodeValueWithLength` does not exist under that name, use whatever decode API `CommitCBORParser` (`PublicRepositoryCommit.swift:389+`) uses to split concatenated objects — or add a small test-only splitter that decodes the first object and returns consumed byte count. Adjust the test to the real API; the assertions are the contract, not the helper names.

- [ ] **Step 2: Run tests, verify fail**

Run: `swift test --filter FirehoseFrameEncoderTests`
Expected: compile failure (encoder types missing).

- [ ] **Step 3: Implement**

`FirehoseFrameLimits.swift`:
```swift
public enum FirehoseFrameLimits {
    public static let maximumFrameBytes = 5_000_000
    public static let maximumBlocksBytes = 2_000_000
    public static let maximumOps = 200
    public static let maximumSequence: Int64 = 9_007_199_254_740_991

    public static func validateSequence(_ seq: Int64) throws {
        guard seq >= 1, seq <= maximumSequence else {
            throw FirehoseFrameEncoderError.sequenceOutOfRange
        }
    }
}
```
`FirehoseFrameEncoder.swift` sketch (mirror `PublicRepositoryCommit.encodeSigned` for the exact `OrderedCBORMap`/`DAGCBOR.encodeValue` idioms; keys inserted in canonical order):
```swift
import Foundation
import Petrel

public enum FirehoseFrameEncoderError: Error, Equatable {
    case sequenceOutOfRange
    case frameTooLarge(Int)
    case invalidCID(String)
}

public enum FirehoseFrameEncoder {
    public static func commitFrame(
        seq: Int64,
        material: PublicFirehoseCommitMaterial,
        diffCAR: Data
    ) throws -> Data {
        try FirehoseFrameLimits.validateSequence(seq)
        let commitLink = try link(material.commitCID)
        let prevDataLink = try link(material.prevDataCID)
        var ops: [Any] = []
        for op in material.ops {
            let map = OrderedCBORMap()
            map.append(key: "cid", value: op.cid.map { try link($0) } as Any? ?? NSNull())
            map.append(key: "path", value: op.path)
            map.append(key: "prev", value: op.prev.map { try link($0) } as Any? ?? NSNull())
            map.append(key: "action", value: op.action)
            ops.append(map)
        }
        let body = OrderedCBORMap()
        body.append(key: "ops", value: ops)
        body.append(key: "rev", value: material.rev)
        body.append(key: "seq", value: seq)
        body.append(key: "repo", value: material.did)
        body.append(key: "time", value: material.time)
        body.append(key: "blobs", value: [Any]())
        body.append(key: "since", value: material.since)
        body.append(key: "blocks", value: diffCAR)
        body.append(key: "commit", value: commitLink)
        body.append(key: "rebase", value: false)
        body.append(key: "tooBig", value: false)
        body.append(key: "prevData", value: prevDataLink)
        return try frame(type: "#commit", body: body)
    }
    // syncFrame / identityFrame / accountFrame analogous, fields per spec.

    public static func infoFrame(name: String, message: String?) throws -> Data { … }
    public static func errorFrame(error: String, message: String?) throws -> Data {
        // header {"op": -1} (no "t"), body {"error": …, "message"?: …}
        …
    }

    private static func frame(type: String, body: OrderedCBORMap) throws -> Data {
        let header = OrderedCBORMap()
        header.append(key: "t", value: type)
        header.append(key: "op", value: 1)
        let encoded = try DAGCBOR.encodeValue(header) + DAGCBOR.encodeValue(body)
        guard encoded.count <= FirehoseFrameLimits.maximumFrameBytes else {
            throw FirehoseFrameEncoderError.frameTooLarge(encoded.count)
        }
        return encoded
    }

    private static func link(_ cidString: String) throws -> ATProtoLink {
        guard let cid = try? CID.parse(cidString) else {
            throw FirehoseFrameEncoderError.invalidCID(cidString)
        }
        return ATProtoLink(cid: cid)
    }
}
```
IMPORTANT: `OrderedCBORMap`'s canonical-ordering behavior belongs to Petrel — if it sorts on encode, insertion order above is irrelevant; if it preserves insertion order, insert in DAG-CBOR canonical key order (length-first, then bytewise: e.g. `ops, rev, seq, repo, time, blobs, since, blocks, commit, rebase, tooBig, prevData`). Check `OrderedCBORMap.swift:4` and the commit-encoder precedent, then match. Same for `CID.parse` vs the real parse API name and `ATProtoLink`'s init.

- [ ] **Step 4: Run tests, verify pass**

Run: `swift test --filter FirehoseFrameEncoderTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj commit Sources/SwanPublicFirehose Tests/SwanPublicFirehoseTests -m "firehose: add DAG-CBOR frame encoder with limits"
```

---

### Task 3: Account-local `public_event_outbox` table + store methods

**Files:**
- Modify: `Sources/SwanSQLite/SwanSQLite.swift` (migration version constant + migration function + call in `migrateWithoutGate()`)
- Create: `Sources/SwanSQLite/PublicFirehoseOutboxStore.swift`
- Modify: `Package.swift` (add `"SwanPublicFirehose"` to `SwanSQLite` target dependencies and to `SwanSQLiteTests`)
- Test: `Tests/SwanSQLiteTests/PublicFirehoseOutboxStoreTests.swift`

**Interfaces:**
- Consumes: Task 1 types; `SQLiteAccountDatabase` internals (`connection`, `withConnectionGate`, `transaction`).
- Produces (on `extension SQLiteAccountDatabase`):
  - `struct PublicFirehoseOutboxRow: Sendable, Equatable { let id: Int64; let sourceKey: String; let kind: PublicFirehoseEventKind; let lifecycleGeneration: Int64; let payload: Data; let diffCAR: Data?; let createdAt: Int64; let attempts: Int }`
  - `struct PublicFirehoseOutboxLease: Sendable, Equatable { let row: PublicFirehoseOutboxRow; let token: UUID; let expiresAt: Date }`
  - `func enqueuePublicFirehoseEventInTransaction(sourceKey:kind:lifecycleGeneration:payload:diffCAR:createdAt:) async throws` — **no gate/transaction of its own**; caller must already hold one (Task 4 calls it from inside `applyPublicRepositoryMutation`'s transaction).
  - `func enqueuePublicFirehoseEvent(sourceKey:kind:lifecycleGeneration:payload:diffCAR:now:) async throws -> Bool` — standalone (gate+txn), returns false if `sourceKey` already present (idempotent saga enqueue).
  - `func leaseNextPublicFirehoseOutbox(now: Date = Date(), leaseDuration: TimeInterval) async throws -> PublicFirehoseOutboxLease?`
  - `@discardableResult func completePublicFirehoseOutboxLease(id: Int64, token: UUID) async throws -> Bool` — deletes the row, token-checked.
  - `@discardableResult func failPublicFirehoseOutboxLease(id: Int64, token: UUID, retryAt: Date) async throws -> Int?`
  - `func pendingPublicFirehoseOutbox(limit: Int = 100) async throws -> [PublicFirehoseOutboxRow]`

- [ ] **Step 1: Add schema migration**

In `SQLiteAccountDatabase` (`SwanSQLite.swift`), next to the other version constants:
```swift
    private static let publicFirehoseOutboxMigrationVersion = 13
```
New function, modeled verbatim on `migratePermissionedOutboxLeasesIfNeeded` (`SwanSQLite.swift:2480`):
```swift
    private func migratePublicFirehoseOutboxIfNeeded() async throws {
        let version = Self.publicFirehoseOutboxMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS public_event_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_key TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync')),
                lifecycle_generation INTEGER NOT NULL DEFAULT 0
                    CHECK(lifecycle_generation >= 0),
                payload BLOB NOT NULL,
                diff_car BLOB,
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                created_at INTEGER NOT NULL CHECK(created_at >= 0),
                available_at INTEGER NOT NULL CHECK(available_at >= 0),
                lease_token TEXT,
                lease_expires_at INTEGER,
                CHECK(
                    (lease_token IS NULL AND lease_expires_at IS NULL)
                    OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                        AND lease_expires_at >= 0)
                )
            )
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS public_event_outbox_available
            ON public_event_outbox(available_at, created_at, id)
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }
```
Call it in `migrateWithoutGate()` inside the first `transaction { … }`, immediately after `try await migratePermissionedRemoteReplicaLogicalLimitIfNeeded()`.

`id INTEGER PRIMARY KEY AUTOINCREMENT` (not UUID like the permissioned outbox): drain order must be insertion order per account — `ORDER BY available_at, id` gives it directly.

- [ ] **Step 2: Write the failing tests**

`Tests/SwanSQLiteTests/PublicFirehoseOutboxStoreTests.swift` (copy the private `temporaryDirectory()` helper pattern from `PublicRepositoryMutationStoreTests.swift:1168` — 0o700 permissions are mandatory):
```swift
import Foundation
import SwanPublicFirehose
@testable import SwanSQLite
import XCTest

final class PublicFirehoseOutboxStoreTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testEnqueueLeaseCompleteLifecycle() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        defer { Task { try? await database.close() } }

        let inserted = try await database.enqueuePublicFirehoseEvent(
            sourceKey: PublicFirehoseSourceKey.commit(did: did, commitCID: "bafyreiabc"),
            kind: .commit,
            lifecycleGeneration: 0,
            payload: Data("{}".utf8),
            diffCAR: Data([0x01]),
            now: Date(timeIntervalSince1970: 1_754_308_800)
        )
        XCTAssertTrue(inserted)

        // Same source key again: idempotent, no duplicate.
        let duplicate = try await database.enqueuePublicFirehoseEvent(
            sourceKey: PublicFirehoseSourceKey.commit(did: did, commitCID: "bafyreiabc"),
            kind: .commit,
            lifecycleGeneration: 0,
            payload: Data("{}".utf8),
            diffCAR: Data([0x01]),
            now: Date(timeIntervalSince1970: 1_754_308_801)
        )
        XCTAssertFalse(duplicate)

        let lease = try await database.leaseNextPublicFirehoseOutbox(
            now: Date(timeIntervalSince1970: 1_754_308_802),
            leaseDuration: 30
        )
        let unwrapped = try XCTUnwrap(lease)
        XCTAssertEqual(unwrapped.row.kind, .commit)
        XCTAssertEqual(unwrapped.row.diffCAR, Data([0x01]))

        // Leased row is invisible to a second lease until expiry.
        let second = try await database.leaseNextPublicFirehoseOutbox(
            now: Date(timeIntervalSince1970: 1_754_308_803),
            leaseDuration: 30
        )
        XCTAssertNil(second)

        // Stale token cannot complete.
        let stale = try await database.completePublicFirehoseOutboxLease(
            id: unwrapped.row.id, token: UUID()
        )
        XCTAssertFalse(stale)

        let done = try await database.completePublicFirehoseOutboxLease(
            id: unwrapped.row.id, token: unwrapped.token
        )
        XCTAssertTrue(done)
        let remaining = try await database.pendingPublicFirehoseOutbox()
        XCTAssertTrue(remaining.isEmpty)
    }

    func testFailReschedulesWithAttemptIncrement() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        defer { Task { try? await database.close() } }

        _ = try await database.enqueuePublicFirehoseEvent(
            sourceKey: "k1", kind: .sync, lifecycleGeneration: 0,
            payload: Data("{}".utf8), diffCAR: nil,
            now: Date(timeIntervalSince1970: 1_754_308_800)
        )
        let lease = try XCTUnwrap(try await database.leaseNextPublicFirehoseOutbox(
            now: Date(timeIntervalSince1970: 1_754_308_801), leaseDuration: 30
        ))
        let attempts = try await database.failPublicFirehoseOutboxLease(
            id: lease.row.id, token: lease.token,
            retryAt: Date(timeIntervalSince1970: 1_754_308_900)
        )
        XCTAssertEqual(attempts, 1)
        // Not yet available before retryAt.
        let early = try await database.leaseNextPublicFirehoseOutbox(
            now: Date(timeIntervalSince1970: 1_754_308_850), leaseDuration: 30
        )
        XCTAssertNil(early)
        let later = try await database.leaseNextPublicFirehoseOutbox(
            now: Date(timeIntervalSince1970: 1_754_308_901), leaseDuration: 30
        )
        XCTAssertNotNil(later)
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicFirehoseOutboxStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: root.path
        )
        return root
    }
}
```

- [ ] **Step 3: Run tests, verify fail**

Run: `swift test --filter PublicFirehoseOutboxStoreTests`
Expected: compile failure (methods missing).

- [ ] **Step 4: Implement `PublicFirehoseOutboxStore.swift`**

`extension SQLiteAccountDatabase` cloning the permissioned outbox bodies (lease SQL from `SwanSQLite.swift:8213`, complete `:8263`, fail `:8298`), adapted: table `public_event_outbox`, `ORDER BY available_at, id LIMIT 1`, integer id bindings, and decode via the existing `requiredText`/`requiredInteger`/`requiredBlob` helpers. The in-transaction enqueue:
```swift
    func enqueuePublicFirehoseEventInTransaction(
        sourceKey: String,
        kind: PublicFirehoseEventKind,
        lifecycleGeneration: Int64,
        payload: Data,
        diffCAR: Data?,
        createdAt: Int64
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO public_event_outbox(
                source_key, kind, lifecycle_generation, payload, diff_car,
                attempts, created_at, available_at, lease_token, lease_expires_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
            """,
            [
                .text(sourceKey), .text(kind.rawValue), .integer(Int(lifecycleGeneration)),
                payload.sqliteData!, diffCAR.map { $0.sqliteData! } ?? .null,
                .integer(Int(createdAt)), .integer(Int(createdAt)),
            ]
        )
    }
```
The standalone variant wraps `withConnectionGate { transaction { … } }`, first `SELECT 1 … WHERE source_key = ?` and returns `false` if present.

- [ ] **Step 5: Run tests, verify pass; run the full SwanSQLite suite for regressions**

Run: `swift test --filter PublicFirehoseOutboxStoreTests` → PASS.
Run: `swift test --filter SwanSQLiteTests` → no new failures (migration must not break existing DBs).

- [ ] **Step 6: Commit**

```bash
jj commit Package.swift Sources/SwanSQLite Tests/SwanSQLiteTests -m "firehose: add account-local public event outbox"
```

---

### Task 4: Enqueue commit events inside `applyPublicRepositoryMutation`

**Files:**
- Modify: `Sources/SwanSQLite/PublicRepositoryStore.swift` (insertion point F, after the request is marked committed, before `return CommittedPublicRepositoryMutation(…)` — around line 460)
- Create: `Sources/SwanPublicFirehose/PublicFirehoseDiffCAR.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseCommitEnqueueTests.swift`, additions to `Tests/SwanPublicFirehoseTests/PublicFirehoseDiffCARTests.swift`

**Interfaces:**
- Consumes: in-scope transaction values — `prepared.state` (`did/revision/commitCID/dataCID`), `prepared.baseCommitCID`, `prepared.sinceRevision`, `prepared.signedCommit.{commitCID, signedCommitBytes}`, `prepared.recordResults`, `prepared.newBlocks`, `current.dataCID` (previous data root), `reservation`; Task 1 material types; Task 3 `enqueuePublicFirehoseEventInTransaction`.
- Produces:
  - `enum PublicFirehoseDiffCAR { static func build(commitCID: CID, commitBytes: Data, newBlocks: PublicRepositoryBlockMap) async throws -> Data }` — CAR with commit CID as root; block order: commit block first, remaining CIDs sorted ascending by `cid.string` (deterministic). Built with `PublicRepositoryCAR.write(rootCID:blocks:to:)` using a private array-backed `PublicRepositoryCARBlockStream` (copy the shape of `ArrayCARBlockStream` in `Tests/SwanPublicRepositoryTests/PublicRepositoryCARTests.swift:818`) and a private in-memory `PublicRepositoryCARByteSink`.
  - `enum PublicFirehoseCommitDecision: Equatable { case commit; case sync }` + `static func decide(opCount: Int, diffCARByteCount: Int) -> PublicFirehoseCommitDecision` (sync iff `opCount > FirehoseFrameLimits.maximumOps || diffCARByteCount > FirehoseFrameLimits.maximumBlocksBytes`).
  - `applyPublicRepositoryMutation` gains an outbox row per committed mutation. New optional parameter `lifecycleGeneration: Int64 = 0` (threaded for real in Phase 4) and `eventTime: Date = Date()` — compute BOTH **before** the SQL statements, never inside a tight loop.

- [ ] **Step 1: Write the failing diff-CAR unit tests**

`Tests/SwanPublicFirehoseTests/PublicFirehoseDiffCARTests.swift`:
```swift
import Foundation
import Petrel
import SwanPublicRepository
@testable import SwanPublicFirehose
import XCTest

final class PublicFirehoseDiffCARTests: XCTestCase {
    func testBuildProducesCommitRootedDeterministicCAR() async throws {
        let commitBytes = Data("commit-block".utf8)
        let commitCID = CID.fromDAGCBOR(commitBytes)
        let blockA = Data("block-a".utf8)
        let blockB = Data("block-b".utf8)
        let blocks = try PublicRepositoryBlockMap(blocks: [
            PublicRepositoryBlock(cid: CID.fromDAGCBOR(blockA), bytes: blockA),
            PublicRepositoryBlock(cid: CID.fromDAGCBOR(blockB), bytes: blockB),
            PublicRepositoryBlock(cid: commitCID, bytes: commitBytes),
        ])
        let first = try await PublicFirehoseDiffCAR.build(
            commitCID: commitCID, commitBytes: commitBytes, newBlocks: blocks
        )
        let second = try await PublicFirehoseDiffCAR.build(
            commitCID: commitCID, commitBytes: commitBytes, newBlocks: blocks
        )
        XCTAssertEqual(first, second, "diff CAR must be byte-deterministic")
        XCTAssertFalse(first.isEmpty)
        // Root + first block must be the commit: assert the commit CID bytes
        // appear before either record block's CID bytes in the CAR.
        let commitRange = first.range(of: commitBytes)
        let aRange = first.range(of: blockA)
        XCTAssertNotNil(commitRange)
        XCTAssertNotNil(aRange)
        XCTAssertLessThan(commitRange!.lowerBound, aRange!.lowerBound)
    }

    func testDecision() {
        XCTAssertEqual(PublicFirehoseDiffCAR.decide(opCount: 1, diffCARByteCount: 100), .commit)
        XCTAssertEqual(PublicFirehoseDiffCAR.decide(opCount: 201, diffCARByteCount: 100), .sync)
        XCTAssertEqual(
            PublicFirehoseDiffCAR.decide(opCount: 1, diffCARByteCount: 2_000_001), .sync
        )
    }
}
```
CAVEAT: `PublicRepositoryCID.validate` pins CIDv1/dag-cbor/sha256 — `CID.fromDAGCBOR(Data(...))` produces exactly that, so these synthetic blocks pass validation.

- [ ] **Step 2: Run, verify fail; implement `PublicFirehoseDiffCAR`**

Run: `swift test --filter PublicFirehoseDiffCARTests` → compile failure.
Implement in `Sources/SwanPublicFirehose/PublicFirehoseDiffCAR.swift`:
```swift
import Foundation
import Petrel
import SwanPublicRepository

public enum PublicFirehoseDiffCAR {
    public static func build(
        commitCID: CID,
        commitBytes: Data,
        newBlocks: PublicRepositoryBlockMap
    ) async throws -> Data {
        var ordered: [PublicRepositoryBlock] = [
            PublicRepositoryBlock(cid: commitCID, bytes: commitBytes)
        ]
        let remaining = newBlocks.cids
            .filter { $0 != commitCID }
            .sorted { $0.string < $1.string }
        for cid in remaining {
            guard let bytes = newBlocks.block(for: cid) else {
                throw PublicFirehoseDiffCARError.missingBlock(cid.string)
            }
            ordered.append(PublicRepositoryBlock(cid: cid, bytes: bytes))
        }
        let sink = MemoryCARSink()
        _ = try await PublicRepositoryCAR.write(
            rootCID: commitCID,
            blocks: ArrayBlockStream(blocks: ordered),
            to: sink
        )
        return await sink.data
    }

    public static func decide(
        opCount: Int, diffCARByteCount: Int
    ) -> PublicFirehoseCommitDecision {
        if opCount > FirehoseFrameLimits.maximumOps { return .sync }
        if diffCARByteCount > FirehoseFrameLimits.maximumBlocksBytes { return .sync }
        return .commit
    }
}

public enum PublicFirehoseCommitDecision: Equatable { case commit, sync }
public enum PublicFirehoseDiffCARError: Error { case missingBlock(String) }

private actor MemoryCARSink: PublicRepositoryCARByteSink {
    private(set) var buffer = Data()
    var data: Data { buffer }
    func write(_ bytes: Data) async throws { buffer.append(bytes) }
}

private actor ArrayBlockStream: PublicRepositoryCARBlockStream {
    private var blocks: [PublicRepositoryBlock]
    init(blocks: [PublicRepositoryBlock]) { self.blocks = blocks }
    func nextBlock() async throws -> PublicRepositoryBlock? {
        blocks.isEmpty ? nil : blocks.removeFirst()
    }
}
```
Run: `swift test --filter PublicFirehoseDiffCARTests` → PASS.

- [ ] **Step 3: Write the failing integration test**

`Tests/SwanSQLiteTests/PublicFirehoseCommitEnqueueTests.swift` — reuse the setup shape of `PublicRepositoryMutationStoreTests` (genesis install via `PublicRepositoryGenesisCodec.create`, `reservePublicRepositoryRevision`, engine-prepared mutation, then `applyPublicRepositoryMutation`; copy an existing passing mutation test's fixture wholesale — `Fixture`/`commitFirst(on:)` in `Tests/SwanSQLiteTests/SwanSQLiteTests.swift` if reusable). Assertions after a successful commit:
```swift
        let rows = try await database.pendingPublicFirehoseOutbox()
        XCTAssertEqual(rows.count, 1)
        let row = rows[0]
        XCTAssertEqual(row.kind, .commit)
        XCTAssertEqual(
            row.sourceKey,
            PublicFirehoseSourceKey.commit(did: did, commitCID: committed.state.commitCID.string)
        )
        let material = try JSONDecoder().decode(
            PublicFirehoseCommitMaterial.self, from: row.payload
        )
        XCTAssertEqual(material.did, did)
        XCTAssertEqual(material.rev, committed.state.revision)
        XCTAssertEqual(material.commitCID, committed.state.commitCID.string)
        XCTAssertEqual(material.ops.count, 1)
        XCTAssertEqual(material.ops[0].action, "create")
        let car = try XCTUnwrap(row.diffCAR)
        XCTAssertFalse(car.isEmpty)
```
Add a second test: replay the same reservation/prepared pair (idempotent path A) and assert `pendingPublicFirehoseOutbox()` still has exactly 1 row.

- [ ] **Step 4: Run, verify fail; hook the mutation transaction**

Run: `swift test --filter PublicFirehoseCommitEnqueueTests` → failure (0 rows).

In `applyPublicRepositoryMutation`, at point F (after the `marked.count == 1` guard, before `return CommittedPublicRepositoryMutation(…)`), with `import SwanPublicFirehose` added to the file:
```swift
                let diffCAR = try await PublicFirehoseDiffCAR.build(
                    commitCID: prepared.signedCommit.commitCID,
                    commitBytes: prepared.signedCommit.signedCommitBytes,
                    newBlocks: prepared.newBlocks
                )
                let ops = prepared.recordResults.map { result in
                    PublicFirehoseRepoOp(
                        action: result.action.rawValue,
                        path: "\(result.path.collection)/\(result.path.recordKey)",
                        cid: result.recordCID?.string,
                        prev: result.previousRecordCID?.string
                    )
                }
                let time = PublicFirehoseTime.encode(eventTime)
                let decision = PublicFirehoseDiffCAR.decide(
                    opCount: ops.count, diffCARByteCount: diffCAR.count
                )
                let createdAt = Int64(eventTime.timeIntervalSince1970 * 1_000_000)
                switch decision {
                case .commit:
                    let material = PublicFirehoseCommitMaterial(
                        did: accountDID,
                        rev: prepared.state.revision,
                        since: prepared.sinceRevision,
                        commitCID: prepared.state.commitCID.string,
                        prevDataCID: current.dataCID.string,
                        ops: ops,
                        time: time
                    )
                    try await enqueuePublicFirehoseEventInTransaction(
                        sourceKey: PublicFirehoseSourceKey.commit(
                            did: accountDID,
                            commitCID: prepared.state.commitCID.string
                        ),
                        kind: .commit,
                        lifecycleGeneration: lifecycleGeneration,
                        payload: try JSONEncoder().encode(material),
                        diffCAR: diffCAR,
                        createdAt: createdAt
                    )
                case .sync:
                    let commitOnlyCAR = try await PublicFirehoseDiffCAR.build(
                        commitCID: prepared.signedCommit.commitCID,
                        commitBytes: prepared.signedCommit.signedCommitBytes,
                        newBlocks: try PublicRepositoryBlockMap(blocks: [])
                    )
                    let material = PublicFirehoseSyncMaterial(
                        did: accountDID,
                        rev: prepared.state.revision,
                        commitCID: prepared.state.commitCID.string,
                        time: time
                    )
                    try await enqueuePublicFirehoseEventInTransaction(
                        sourceKey: PublicFirehoseSourceKey.syncOversize(
                            did: accountDID,
                            commitCID: prepared.state.commitCID.string
                        ),
                        kind: .sync,
                        lifecycleGeneration: lifecycleGeneration,
                        payload: try JSONEncoder().encode(material),
                        diffCAR: commitOnlyCAR,
                        createdAt: createdAt
                    )
                }
```
Check the real property names on `PublicRepositoryMutationRecordResult` (`.action` raw value, `PublicRepositoryPath.collection/.recordKey`) at `PublicRepositoryEngine.swift:25-40` — adjust to the actual accessors if `rawValue` isn't `"create"/"update"/"delete"` (if the enum's raw values differ, map explicitly).

Signature change: append `lifecycleGeneration: Int64 = 0, eventTime: Date = Date()` to `applyPublicRepositoryMutation` — defaulted, so existing call sites (grep for `applyPublicRepositoryMutation(`; includes `SQLitePreMigratedAccountDirectory.swift:1850` wrapper) compile unchanged.

The idempotent-replay early return (point A) precedes point F, so replays cannot double-enqueue; the UNIQUE `source_key` is a backstop, not the mechanism.

- [ ] **Step 5: Run tests, verify pass; full suite**

Run: `swift test --filter PublicFirehoseCommitEnqueueTests` → PASS.
Run: `swift test --filter SwanSQLiteTests` → no regressions (existing mutation tests must still pass with the defaulted parameters).

- [ ] **Step 6: Commit**

```bash
jj commit Sources/SwanSQLite Sources/SwanPublicFirehose Tests -m "firehose: enqueue commit events inside public mutation transaction"
```

---

### Task 5: Control-plane lifecycle outbox + generation counter

**Files:**
- Modify: `Sources/SwanSQLite/SwanSQLite.swift` (`SQLiteLayout.controlMigrations` — append DDL)
- Create: `Sources/SwanSQLite/LifecycleEventOutboxStore.swift`
- Test: `Tests/SwanSQLiteTests/LifecycleEventOutboxStoreTests.swift`

**Interfaces:**
- Consumes: `SQLiteControlDatabase` internals (`connection`, `withConnectionGate`, `transaction` — `OAuthControlStore.swift:1425-1461`); Task 1 types.
- Produces (on `extension SQLiteControlDatabase`):
  - `struct LifecycleEventItem: Sendable, Equatable { let sourceKey: String; let kind: PublicFirehoseEventKind; let payload: Data }` (kind ∈ .identity/.account/.sync only — commit never originates here)
  - `struct LifecycleEventBatch: Sendable, Equatable { let batchID: String; let did: String; let generation: Int64; let items: [LifecycleEventItem] }`
  - `func enqueueLifecycleEventBatch(did: String, operationID: String, items: [LifecycleEventItem], now: Date) async throws -> LifecycleEventBatch` — `batchID = operationID`; **idempotent**: if a batch with this `batchID` exists, return the stored batch unchanged (no generation bump); otherwise increment the per-DID generation and insert all items with ordinals 0..n-1 in one transaction.
  - `func currentLifecycleGeneration(did: String) async throws -> Int64` (0 if absent)
  - `func nextPendingLifecycleBatch(did: String?) async throws -> LifecycleEventBatch?` — oldest pending batch (optionally filtered by DID), ordered by generation.
  - `func completeLifecycleBatch(batchID: String) async throws -> Bool` — deletes the batch's rows.
  - Simplicity note: no lease columns here — Phase 1 has exactly one sequencer; batch completion is idempotent via the global log's UNIQUE source keys. Record this in a doc comment.

- [ ] **Step 1: Add DDL to `SQLiteLayout.controlMigrations`** (idempotent `CREATE TABLE IF NOT EXISTS`, matching how control tables are declared):

```sql
CREATE TABLE IF NOT EXISTS lifecycle_event_outbox (
    batch_id TEXT NOT NULL,
    batch_ordinal INTEGER NOT NULL CHECK(batch_ordinal >= 0),
    did TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    source_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK(kind IN ('sync', 'identity', 'account')),
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    PRIMARY KEY (batch_id, batch_ordinal)
);
CREATE INDEX IF NOT EXISTS lifecycle_event_outbox_pending
ON lifecycle_event_outbox(did, generation, batch_id, batch_ordinal);
CREATE TABLE IF NOT EXISTS account_lifecycle_generation (
    did TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK(generation >= 0)
);
```

- [ ] **Step 2: Write the failing tests**

`Tests/SwanSQLiteTests/LifecycleEventOutboxStoreTests.swift` (control DB opens with `SQLiteControlDatabase(dataDirectory: root)`; reuse the 0o700 temp-dir helper):
```swift
    func testEnqueueIsIdempotentAndIncrementsGeneration() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }

        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let items = [
            LifecycleEventItem(
                sourceKey: PublicFirehoseSourceKey.identity(did: did, plcOperationCID: "bafyop"),
                kind: .identity, payload: Data("{}".utf8)
            ),
            LifecycleEventItem(
                sourceKey: PublicFirehoseSourceKey.account(did: did, operationID: "op-1"),
                kind: .account, payload: Data("{}".utf8)
            ),
        ]
        let batch = try await control.enqueueLifecycleEventBatch(
            did: did, operationID: "op-1", items: items,
            now: Date(timeIntervalSince1970: 1_754_308_800)
        )
        XCTAssertEqual(batch.generation, 1)
        XCTAssertEqual(batch.items.count, 2)

        let replay = try await control.enqueueLifecycleEventBatch(
            did: did, operationID: "op-1", items: items,
            now: Date(timeIntervalSince1970: 1_754_308_900)
        )
        XCTAssertEqual(replay, batch, "idempotent replay returns the stored batch")
        let generation = try await control.currentLifecycleGeneration(did: did)
        XCTAssertEqual(generation, 1)

        let pending = try await control.nextPendingLifecycleBatch(did: did)
        XCTAssertEqual(pending, batch)
        XCTAssertTrue(try await control.completeLifecycleBatch(batchID: "op-1"))
        let drained = try await control.nextPendingLifecycleBatch(did: did)
        XCTAssertNil(drained)
        // Generation survives batch completion.
        let after = try await control.currentLifecycleGeneration(did: did)
        XCTAssertEqual(after, 1)
    }
```
(Confirm the control DB close method name — `SQLiteAccountDatabase` has `close()`; check `SQLiteControlDatabase` for its equivalent and match.)

- [ ] **Step 3: Run, verify fail; implement; run, verify pass**

Run: `swift test --filter LifecycleEventOutboxStoreTests` → compile failure → implement `LifecycleEventOutboxStore.swift` (single `withConnectionGate { transaction { … } }` per public method; generation upsert `INSERT INTO account_lifecycle_generation(did, generation) VALUES (?, 1) ON CONFLICT(did) DO UPDATE SET generation = generation + 1 RETURNING generation`) → PASS.

- [ ] **Step 4: Commit**

```bash
jj commit Sources/SwanSQLite Tests/SwanSQLiteTests -m "firehose: add control-plane lifecycle event outbox with generations"
```

---

### Task 6: `firehose.sqlite` global log store

**Files:**
- Create: `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift`
- Test: `Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift`

**Interfaces:**
- Consumes: `SQLiteConnection`, `SQLiteProtectedPaths.openRoot`/`openDatabaseFile` (the `control.sqlite` open pattern at `OAuthControlStore.swift:220-245`); `FirehoseFrameLimits.validateSequence`.
- Produces:
  - `public actor SQLiteFirehoseDatabase` with `public init(dataDirectory: URL) async throws` opening `<root>/firehose.sqlite` (one per PDS, sibling of `control.sqlite`), applying pragmas (copy `SQLiteLayout.controlConnectionPragmas`) and schema.
  - `struct FirehoseAppendItem: Sendable { let sourceKey: String; let batchID: String?; let did: String; let kind: PublicFirehoseEventKind; let encodeFrame: @Sendable (Int64) throws -> Data }` — the closure is pure CPU (frame encoding), safe inside the transaction.
  - `struct FirehoseStoredEvent: Sendable, Equatable { let seq: Int64; let sourceKey: String; let did: String; let kind: String; let sequencedAt: Int64; let frameBytes: Data }`
  - `func appendBatch(_ items: [FirehoseAppendItem], now: Date) async throws -> [Int64]` — one transaction: for each item whose `source_key` already exists, return its existing seq (idempotent replay); for the rest, allocate `n` consecutive seqs via `UPDATE firehose_meta SET next_seq = next_seq + n RETURNING next_seq`, validate every seq with `FirehoseFrameLimits.validateSequence`, call `encodeFrame(seq)`, insert. Returns seqs in item order.
  - `func maxSequencedSeq() async throws -> Int64` (0 when empty)
  - `func events(after seq: Int64, limit: Int) async throws -> [FirehoseStoredEvent]`
  - `func reseedSequence(toAtLeast seq: Int64) async throws` — raises `next_seq` only (never lowers), for post-restore recovery.
  - `func close() async throws`

Schema (spec verbatim + meta seeded at first open):
```sql
CREATE TABLE IF NOT EXISTS firehose_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    next_seq INTEGER NOT NULL CHECK(next_seq >= 1),
    retained_from_seq INTEGER
);
INSERT INTO firehose_meta(singleton, next_seq, retained_from_seq)
    SELECT 1, 1, NULL WHERE NOT EXISTS (SELECT 1 FROM firehose_meta);
CREATE TABLE IF NOT EXISTS firehose_events (
    seq INTEGER PRIMARY KEY CHECK(seq >= 1),
    source_key TEXT NOT NULL UNIQUE,
    batch_id TEXT,
    did TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync', 'identity', 'account')),
    sequenced_at INTEGER NOT NULL CHECK(sequenced_at >= 0),
    frame_bytes BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS firehose_events_did ON firehose_events(did, seq);
```

- [ ] **Step 1: Write the failing tests**

```swift
    func testAppendAllocatesConsecutiveSeqsAndIsIdempotent() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
        defer { Task { try? await firehose.close() } }

        let items = (0..<3).map { index in
            FirehoseAppendItem(
                sourceKey: "key-\(index)", batchID: "batch-1",
                did: "did:plc:abcdefghijklmnopqrstuvwx", kind: .account,
                encodeFrame: { seq in Data("frame-\(index)-seq-\(seq)".utf8) }
            )
        }
        let seqs = try await firehose.appendBatch(
            items, now: Date(timeIntervalSince1970: 1_754_308_800)
        )
        XCTAssertEqual(seqs, [1, 2, 3])

        // Replay: same source keys return the same seqs, no new rows.
        let replayed = try await firehose.appendBatch(
            items, now: Date(timeIntervalSince1970: 1_754_308_900)
        )
        XCTAssertEqual(replayed, [1, 2, 3])
        let max = try await firehose.maxSequencedSeq()
        XCTAssertEqual(max, 3)

        let page = try await firehose.events(after: 1, limit: 10)
        XCTAssertEqual(page.map(\.seq), [2, 3])
        XCTAssertEqual(page[0].frameBytes, Data("frame-1-seq-2".utf8))
    }

    func testSequenceSurvivesReopen() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
            _ = try await firehose.appendBatch([FirehoseAppendItem(
                sourceKey: "a", batchID: nil, did: "did:plc:abcdefghijklmnopqrstuvwx",
                kind: .sync, encodeFrame: { _ in Data([0x01]) }
            )], now: Date(timeIntervalSince1970: 1_754_308_800))
            try await firehose.close()
        }
        let reopened = try await SQLiteFirehoseDatabase(dataDirectory: root)
        defer { Task { try? await reopened.close() } }
        let seqs = try await reopened.appendBatch([FirehoseAppendItem(
            sourceKey: "b", batchID: nil, did: "did:plc:abcdefghijklmnopqrstuvwx",
            kind: .sync, encodeFrame: { _ in Data([0x02]) }
        )], now: Date(timeIntervalSince1970: 1_754_308_900))
        XCTAssertEqual(seqs, [2])
    }

    func testReseedOnlyRaises() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
        defer { Task { try? await firehose.close() } }
        try await firehose.reseedSequence(toAtLeast: 1_000)
        try await firehose.reseedSequence(toAtLeast: 5)  // no-op
        let seqs = try await firehose.appendBatch([FirehoseAppendItem(
            sourceKey: "a", batchID: nil, did: "did:plc:abcdefghijklmnopqrstuvwx",
            kind: .sync, encodeFrame: { _ in Data([0x01]) }
        )], now: Date(timeIntervalSince1970: 1_754_308_800))
        XCTAssertEqual(seqs, [1_000])
    }
```

- [ ] **Step 2: Run, verify fail; implement; run, verify pass**

Run: `swift test --filter SQLiteFirehoseDatabaseTests` → compile failure → implement (actor with `connection`, gate pattern copied from `SQLiteControlDatabase`; `BEGIN IMMEDIATE` transactions; open via `SQLiteProtectedPaths.openRoot` + `openDatabaseFile(parentDescriptor:name:"firehose.sqlite":resolvedPath:)` + `hardenSQLiteFiles`) → PASS.

- [ ] **Step 3: Commit**

```bash
jj commit Sources/SwanSQLite Tests/SwanSQLiteTests -m "firehose: add global firehose.sqlite log with seq allocator"
```

---

### Task 7: Sequencer worker with generation barriers

**Files:**
- Create: `Sources/SwanSQLite/PublicFirehoseSequencer.swift`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseSequencerTests.swift`

**Interfaces:**
- Consumes: Tasks 3–6 APIs exactly as named; `PermissionedSpaceOutboxDeliveryWorker` (`PermissionedOutboxDelivery.swift:114`) as the structural template.
- Produces:
  - `public protocol PublicFirehoseWakeupSink: Sendable { func firehoseDidAppend(maxSeq: Int64) async }` (Phase 2 hooks the tailer here; Phase 1 tests use a recorder)
  - `public struct PublicFirehoseSequencerConfiguration: Sendable { public var leaseDuration: TimeInterval = 30; public var idlePollInterval: TimeInterval = 0.25; public var retryDelay: (Int) -> TimeInterval = PublicFirehoseSequencerConfiguration.defaultRetryDelay; public static let standard = … }`
  - `public actor PublicFirehoseSequencer` with:
    - `public init(accountDatabases: [(did: String, database: SQLiteAccountDatabase)], control: SQLiteControlDatabase, firehose: SQLiteFirehoseDatabase, wakeup: (any PublicFirehoseWakeupSink)?, configuration: PublicFirehoseSequencerConfiguration = .standard)`
    - `public func sequenceNext(now: Date = Date()) async throws -> PublicFirehoseSequencerResult` — one drain step
    - `public func drainAll(now: Date = Date()) async throws -> Int` — loop `sequenceNext` until `.idle`, returns count (tests use this)
    - `public func runUntilCancelled() async` — clone of the permissioned worker's loop
  - `public enum PublicFirehoseSequencerResult: Sendable, Equatable { case idle; case sequencedLifecycleBatch(batchID: String, seqs: [Int64]); case sequencedAccountEvent(sourceKey: String, seq: Int64); case blockedOnBarrier(did: String, requiredGeneration: Int64) }`

**Drain algorithm (`sequenceNext`):**
1. `control.nextPendingLifecycleBatch(did: nil)` — if present, decode each item's payload (`PublicFirehoseIdentityMaterial` / `PublicFirehoseAccountMaterial` / `PublicFirehoseSyncMaterial` by kind), build `FirehoseAppendItem`s whose `encodeFrame` closures call the matching `FirehoseFrameEncoder` function, `firehose.appendBatch`, then `control.completeLifecycleBatch(batchID:)`, notify wakeup, return `.sequencedLifecycleBatch`. Lifecycle batches always drain before account rows — this plus the generation check below is the barrier.
2. Otherwise iterate `accountDatabases` round-robin: `leaseNextPublicFirehoseOutbox`. For a leased row:
   - Barrier check: if `row.lifecycleGeneration > 0`, load pending lifecycle batches for that DID; if any pending batch has `generation <= row.lifecycleGeneration`, `failPublicFirehoseOutboxLease(retryAt: now + retry)` and return `.blockedOnBarrier` (step 1 will drain the batch on the next call).
   - Decode payload by kind; `encodeFrame` calls `FirehoseFrameEncoder.commitFrame(seq:material:diffCAR: row.diffCAR!)` (or `syncFrame`). If the encoder throws `frameTooLarge` for a commit, re-encode as a `#sync` frame from a `PublicFirehoseSyncMaterial` derived from the commit material (same `sourceKey` — the kind stored in `firehose_events` becomes `sync`; add a doc comment citing the spec's fallback rule).
   - `firehose.appendBatch([item])` → `completePublicFirehoseOutboxLease(id:token:)` → notify wakeup → `.sequencedAccountEvent`.
3. Nothing anywhere → `.idle`.

Crash-safety argument (put in the type's doc comment): append-then-complete means a crash between the two leaves the outbox row leased-but-present; on lease expiry it is re-leased, `appendBatch` finds the `source_key` and returns the existing seq without inserting, then completion deletes the row. No duplicates, no losses.

- [ ] **Step 1: Write the failing tests**

`Tests/SwanSQLiteTests/PublicFirehoseSequencerTests.swift` — three tests:

```swift
    func testCommitEventFlowsToGlobalLog() async throws {
        // Fixture: account DB with genesis + one committed mutation (reuse Task 4's
        // fixture — the mutation itself wrote the outbox row), control DB, firehose DB.
        let sequencer = PublicFirehoseSequencer(
            accountDatabases: [(did: did, database: database)],
            control: control, firehose: firehose, wakeup: recorder
        )
        let sequenced = try await sequencer.drainAll(
            now: Date(timeIntervalSince1970: 1_754_308_800)
        )
        XCTAssertEqual(sequenced, 1)
        let events = try await firehose.events(after: 0, limit: 10)
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].seq, 1)
        XCTAssertEqual(events[0].kind, "commit")
        // Frame decodes and carries the right seq/repo/rev (use the same
        // DAG-CBOR decode helper as FirehoseFrameEncoderTests).
        …
        // Outbox drained.
        let remaining = try await database.pendingPublicFirehoseOutbox()
        XCTAssertTrue(remaining.isEmpty)
        // Wakeup fired with maxSeq 1.
        let wakeups = await recorder.received
        XCTAssertEqual(wakeups, [1])
    }

    func testCrashBetweenAppendAndCompleteDoesNotDuplicate() async throws {
        // Simulate: sequence once, then manually re-insert the outbox situation by
        // appending the same source key again via a second sequencer pass after
        // resetting the lease (UPDATE public_event_outbox SET lease_token = NULL,
        // lease_expires_at = NULL via database.connection.query — the
        // @testable import gives access). appendBatch must return the original
        // seq and firehose row count must stay 1.
    }

    func testLifecycleBarrierOrdersBatchBeforeCommit() async throws {
        // 1. Enqueue lifecycle batch (identity + account items) with operationID
        //    "op-1" → generation 1.
        // 2. Enqueue an account-outbox row directly via
        //    database.enqueuePublicFirehoseEvent(sourceKey: "…|sync|manual|…",
        //    kind: .sync, lifecycleGeneration: 1, …).
        // 3. drainAll. Assert global order: seqs 1,2 are the lifecycle items
        //    (kinds identity, account), seq 3 is the sync event.
    }
```
Write all three fully (the comments above describe intent; the test bodies must be real code following the Task 4/5/6 fixtures).

- [ ] **Step 2: Run, verify fail; implement `PublicFirehoseSequencer`; run, verify pass**

Run: `swift test --filter PublicFirehoseSequencerTests` → compile failure → implement per the drain algorithm → PASS.

- [ ] **Step 3: Full suite**

Run: `swift test`
Expected: everything green.

- [ ] **Step 4: Commit**

```bash
jj commit Sources/SwanSQLite Tests/SwanSQLiteTests -m "firehose: add global sequencer with lifecycle generation barriers"
```

---

### Task 8: Service wiring + permissioned-isolation gate

**Files:**
- Create: `Sources/SwanHTTP/SwanPublicFirehoseSequencerService.swift`
- Modify: `Sources/SwanHTTP/SwanHTTP.swift` (construct + register the service where `SwanNotificationRecoveryService` is wired; grep `makeServiceGroup` / `SwanNotificationRecoveryService` for the exact spot)
- Modify: `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift` (add `func publicFirehoseDatabases() -> [(did: String, database: SQLiteAccountDatabase)]` next to `notificationRecoveryDatabases()`)
- Test: `Tests/SwanSQLiteTests/PublicFirehoseIsolationTests.swift`, `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift`

**Interfaces:**
- Consumes: Task 7 `PublicFirehoseSequencer`; `SwanNotificationRecoveryService` (`SwanNotificationRecoveryService.swift:47-64`) as the service template; `SwanHTTPServiceLifecycle.makeServiceGroup(services:)`.
- Produces:
  - `struct SwanPublicFirehoseSequencerService: Service` (swift-service-lifecycle) whose `run()` calls `sequencer.runUntilCancelled()` and respects graceful shutdown, mirroring the notification recovery service.
  - `SQLiteFirehoseDatabase` opened during app composition from the same `dataDirectory` as `control.sqlite`, passed to the service. Feature-gate: only wire the service when a new option `publicFirehoseEnabled` (plumb through the same configuration type the notification recovery service uses; find it by reading `SwanHTTP.swift`'s composition of that service) is true — default **true** in tests, and choose the default for the server binary by matching how other new subsystems were introduced (grep `SwanCommand.swift` for feature flags; if none exists, default true and note it).

- [ ] **Step 1: Write the failing isolation test (the hard gate from the spec)**

`Tests/SwanSQLiteTests/PublicFirehoseIsolationTests.swift`: perform a permissioned space write using an existing permissioned-write test fixture (copy the setup from a passing test in the permissioned suite — grep `appendOplogAndOutbox` in `Tests/SwanSQLiteTests` for one), then assert:
```swift
        let publicRows = try await database.pendingPublicFirehoseOutbox()
        XCTAssertTrue(
            publicRows.isEmpty,
            "permissioned write must never produce a public firehose outbox row"
        )
```
Also assert `firehose.events(after: 0, limit: 10)` is empty after running a sequencer over the account DB.

- [ ] **Step 2: Run — this should already PASS (nothing hooks permissioned writes). It is a regression tripwire, not TDD red.**

Run: `swift test --filter PublicFirehoseIsolationTests`
Expected: PASS immediately. Keep it — the spec calls this a hard gate.

- [ ] **Step 3: Write the failing wiring test, implement the service, verify**

`Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift`: build the app composition the way existing `SwanHTTPTests` construct it (grep for a test that asserts `SwanNotificationRecoveryService` wiring or service-group contents and mirror it — if no precedent asserts service registration, instead test `SwanPublicFirehoseSequencerService` directly: construct with a sequencer over a fixture DB set, start it in a task, enqueue an event, poll `firehose.maxSequencedSeq()` until 1 or timeout 5s, cancel, assert clean exit).

Implement the service:
```swift
import ServiceLifecycle
import SwanSQLite

struct SwanPublicFirehoseSequencerService: Service {
    let sequencer: PublicFirehoseSequencer

    func run() async throws {
        await cancelWhenGracefulShutdown {
            await sequencer.runUntilCancelled()
        }
    }
}
```
(Match the exact graceful-shutdown idiom used by `SwanNotificationRecoveryService.run()` — copy it verbatim.) Wire into `SwanHTTP.swift` composition next to the notification recovery service, constructing `SQLiteFirehoseDatabase(dataDirectory:)` alongside the control DB open.

Run: `swift test --filter PublicFirehoseServiceWiringTests` → PASS.

- [ ] **Step 4: Full suite + build**

Run: `swift build && swift test`
Expected: green. This is the Phase 1 exit gate: a record written through the running server's mutation path now lands in `firehose.sqlite` with a decodable `#commit` frame.

- [ ] **Step 5: Commit**

```bash
jj commit Sources/SwanHTTP Sources/SwanSQLite Tests -m "firehose: wire sequencer service and permissioned isolation gate"
```

---

## Self-review notes (already applied)

- Spec coverage: Phase 1 spec items — account outbox w/ exact material ✔ (T3+T4), oversize→sync durable decision ✔ (T4), lifecycle batch model + generation counter ✔ (T5), barriers ✔ (T7), allocator + `firehose_meta` + full frame bytes + reseed ✔ (T6), batch-atomic append + idempotent source keys ✔ (T6/T7), crash/idempotency tests ✔ (T6/T7), isolation gate ✔ (T8). Deliberately deferred per spec phasing: tailer (Phase 2), WebSocket/cursor/retention (Phase 3), lifecycle *integrations* + announcer + CLI (Phase 4), relay lab (Phase 5). `lifecycleGeneration` is threaded as a defaulted parameter until Phase 4 wires real generations through `withActiveAccountAuthorization` callers.
- Known API-uncertainty points are marked inline (Petrel decode helper names, `OrderedCBORMap` ordering behavior, control-DB `close()`): in each case the named precedent file is the authority and the tests' assertions are the contract.
- Type consistency: `PublicFirehoseEventKind` string raw values (`commit`/`sync`/`identity`/`account`) match every CHECK constraint; `FirehoseAppendItem.encodeFrame: (Int64) throws -> Data` matches sequencer usage; source-key helpers match all call sites.
