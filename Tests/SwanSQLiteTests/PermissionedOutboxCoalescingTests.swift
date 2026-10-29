import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// SWAN-SYNC-2: the notifyWrite outbox keeps one row per `(space, author)`
/// carrying the latest state and stops retrying 24 hours after the newest
/// state, restarting that window when newer state arrives (October 1
/// section 3).
final class PermissionedOutboxCoalescingTests: XCTestCase {
    func testCommitsCoalesceToLatestRowPerSpaceAndAuthorWithoutStealingLiveLease() async throws {
        let fixture = try OutboxFixture()
        let database = try await fixture.open()
        do {
            for revision: UInt64 in 1 ... 3 {
                try await fixture.write(revision, to: fixture.space, on: database)
            }
            try await fixture.write(1, to: fixture.otherSpace, on: database)
            let pending = try await database.pendingOutbox()
            XCTAssertEqual(pending.count, 2, "500 backlogged commits must not become 500 deliveries")
            XCTAssertEqual(pending.first { $0.space == fixture.space }?.revision, 3)
            XCTAssertEqual(pending.first { $0.space == fixture.otherSpace }?.revision, 1)

            // A row under a live lease is never removed by a newer commit.
            var leased: PersistedOutboxLease?
            while let lease = try await database.leaseNextOutbox(leaseDuration: 60) {
                if lease.event.space == fixture.space { leased = lease; break }
            }
            let inFlight = try XCTUnwrap(leased)
            try await fixture.write(4, to: fixture.space, on: database)
            let withNewer = try await database.pendingOutbox()
            XCTAssertEqual(
                withNewer.filter { $0.space == fixture.space }.map(\.revision).sorted(), [3, 4]
            )
            let completed = try await database.completeOutboxLease(eventID: inFlight.event.id, token: inFlight.token)
            XCTAssertTrue(completed)
            let remaining = try await database.pendingOutbox()
            XCTAssertEqual(remaining.filter { $0.space == fixture.space }.map(\.revision), [4])
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testRetryStopsAfterWindowAndNewerStateRestartsIt() async throws {
        let fixture = try OutboxFixture()
        let database = try await fixture.open()
        do {
            try await fixture.write(1, to: fixture.space, on: database)
            let initial = try await database.pendingOutbox()
            let original = try XCTUnwrap(initial.first)
            // Model an authority that has been failing for almost a day.
            let day = SQLiteAccountDatabase.permissionedOutboxRetryWindow
            try await fixture.age(original.id, by: day - 60, attempts: 40, on: database)
            let stillOwed = try await database.leaseNextOutbox(leaseDuration: 30)
            let lease = try XCTUnwrap(stillOwed, "state younger than the window is still retried")
            _ = try await database.failOutboxLease(
                eventID: lease.event.id, token: lease.token, retryAt: Date()
            )

            // Newer state replaces the row: a fresh deadline and attempt count.
            try await fixture.write(2, to: fixture.space, on: database)
            let replaced = try await database.pendingOutbox()
            XCTAssertEqual(replaced.map(\.revision), [2])
            XCTAssertEqual(replaced.first?.attempts, 0)
            let laterLease = try await database.leaseNextOutbox(
                now: Date().addingTimeInterval(120), leaseDuration: 30
            )
            let renewed = try XCTUnwrap(laterLease, "a newer revision restarts the retry window")
            XCTAssertEqual(renewed.event.revision, 2)
            _ = try await database.failOutboxLease(
                eventID: renewed.event.id, token: renewed.token, retryAt: Date()
            )

            // Without newer state, the row is dropped once the window passes.
            try await fixture.age(renewed.event.id, by: day + 1, attempts: 41, on: database)
            let expired = try await database.leaseNextOutbox(leaseDuration: 30)
            XCTAssertNil(expired)
            let drained = try await database.pendingOutbox()
            XCTAssertTrue(drained.isEmpty, "an unreachable authority must not retry forever")
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testMigrationCompactsBacklogToNewestUnleasedRowAndKeepsLeasedRows() async throws {
        let fixture = try OutboxFixture()
        let database = try await fixture.open()
        do {
            try await fixture.write(1, to: fixture.space, on: database)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
        let legacy = try await fixture.open()
        do {
            // Reconstruct a pre-v25 backlog: several unleased rows for one
            // pair, plus an older leased row and another pair's row.
            _ = try await legacy.connection.query("DELETE FROM permissioned_space_outbox")
            _ = try await legacy.connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.permissionedOutboxCoalescingMigrationVersion)]
            )
            _ = try await legacy.connection.query("DROP INDEX IF EXISTS permissioned_space_outbox_pair")
            let now = Int(Date().timeIntervalSince1970 * 1_000_000)
            let backlog: [(Int, Bool, SpaceURI)] = [
                (1, true, fixture.space), (2, false, fixture.space), (3, false, fixture.space),
                (4, false, fixture.space), (1, false, fixture.otherSpace),
            ]
            for (revision, leased, space) in backlog {
                let id = UUID()
                let payload: SQLiteData = Data(id.uuidString.lowercased().utf8).sqliteData!
                let leaseToken: SQLiteData = leased ? .text(UUID().uuidString) : .null
                let leaseExpiry: SQLiteData = leased ? .integer(now + 60_000_000) : .null
                _ = try await legacy.connection.query(
                    """
                    INSERT INTO permissioned_space_outbox(
                        id, space_uri, author_did, revision, payload, attempts,
                        created_at, available_at, lease_token, lease_expires_at
                    ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                    """,
                    [
                        .text(id.uuidString), .text(space.rawValue), .text(fixture.author),
                        .integer(revision), payload,
                        .integer(now + revision), .integer(now + revision),
                        leaseToken, leaseExpiry,
                    ]
                )
            }
            try await legacy.close()
        } catch {
            try? await legacy.close()
            throw error
        }
        let migrated = try await fixture.open()
        do {
            let rows = try await migrated.connection.query(
                "SELECT space_uri, revision, lease_token FROM permissioned_space_outbox ORDER BY space_uri, revision"
            )
            let summary: [String] = rows.map { row in
                let name = row.column("space_uri")?.string == fixture.space.rawValue ? "space" : "other"
                let revision = row.column("revision")?.integer ?? -1
                let state = row.column("lease_token")?.string == nil ? "free" : "leased"
                return "\(name):\(revision):\(state)"
            }
            XCTAssertEqual(summary.sorted(), ["other:1:free", "space:1:leased", "space:4:free"])
            let index = try await migrated.connection.query(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'permissioned_space_outbox_pair'"
            )
            XCTAssertEqual(index.count, 1)
            try await migrated.close()
        } catch {
            try? await migrated.close()
            throw error
        }
    }
}

private struct OutboxFixture {
    let root = FileManager.default.temporaryDirectory.appending(path: "SwanOutboxCoalescing-\(UUID().uuidString)")
    let author = "did:plc:writerabcdefghijklmn"
    let space: SpaceURI
    let otherSpace: SpaceURI

    init() throws {
        space = try SpaceURI(authority: "did:plc:authorityabcdefghijk", spaceType: "com.example.forum", skey: "one")
        otherSpace = try SpaceURI(authority: "did:plc:authorityabcdefghijk", spaceType: "com.example.forum", skey: "two")
    }

    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: author)
    }

    func write(_ revision: UInt64, to space: SpaceURI, on database: SQLiteAccountDatabase) async throws {
        let value = Data([0xA1, 0x61, 0x61, UInt8(revision)])
        let uri = try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: "r\(revision)")
        let suffixes = Array("234567abcdefghij")
        let tid = try TID(tidString: "222222222222" + String(suffixes[Int(revision)]))
        _ = try await database.apply(
            space: space, author: author, expectedRevision: revision - 1, requestID: UUID(),
            wireRevision: tid,
            writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
        )
    }

    /// Moves one row's newest-state time into the past, as if delivery had
    /// been failing since then.
    func age(_ id: UUID, by interval: TimeInterval, attempts: Int, on database: SQLiteAccountDatabase) async throws {
        let created = Int(Date().addingTimeInterval(-interval).timeIntervalSince1970 * 1_000_000)
        _ = try await database.connection.query(
            "UPDATE permissioned_space_outbox SET created_at = ?, attempts = ? WHERE id = ?",
            [.integer(created), .integer(attempts), .text(id.uuidString)]
        )
    }
}
