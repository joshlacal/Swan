import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// SWAN-SYNC-4: syncer registrations, owed deletion recipients and fanout
/// de-duplication are keyed by service identity, with the endpoint kept as
/// data, so services that share an endpoint each keep their registration and
/// each receive notifySpaceDeleted (October 22 section 6).
final class SpaceNotificationServiceKeyTests: XCTestCase {
    func testServicesSharingAnEndpointEachKeepRegistrationAndReceiveDeletion() async throws {
        let fixture = try ServiceKeyFixture()
        let database = try await fixture.open()
        do {
            try await fixture.createSpace(on: database)
            let now = Date()
            // Two fragments of one DID, and a second DID, behind one endpoint.
            for service in [fixture.serviceA, fixture.serviceB, fixture.otherService] {
                try await fixture.register(service, at: fixture.sharedEndpoint, on: database, now: now)
            }
            let rows = try await database.connection.query(
                "SELECT service_key, endpoint FROM permissioned_space_notification_registrations WHERE space_uri = ? ORDER BY service_key",
                [.text(fixture.space.rawValue)]
            )
            XCTAssertEqual(
                rows.compactMap { $0.column("service_key")?.string },
                [fixture.serviceA, fixture.serviceB, fixture.otherService].sorted()
            )
            XCTAssertTrue(rows.allSatisfy { $0.column("endpoint")?.string == fixture.sharedEndpoint })

            _ = try await database.deleteSimpleSpace(space: fixture.space, authorization: fixture.ownerAuthorization)
            let fanout = try await database.pendingNotificationFanout()
            XCTAssertEqual(fanout.count, 3, "every registered service is owed the deletion")
            var delivered: [String] = []
            for event in fanout {
                XCTAssertEqual(event.kind, .deleted)
                XCTAssertEqual(event.endpoint, fixture.sharedEndpoint)
                let registration = try await database.currentSpaceDeletionDeliveryRegistration(for: event)
                delivered.append(try XCTUnwrap(registration?.serviceIdentity))
            }
            XCTAssertEqual(delivered.sorted(), [fixture.serviceA, fixture.serviceB, fixture.otherService].sorted())
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testReRegisteringServiceReplacesItsEndpointAndForeignOwnerCannotTakeIt() async throws {
        let fixture = try ServiceKeyFixture()
        let database = try await fixture.open()
        do {
            try await fixture.createSpace(on: database)
            let now = Date()
            try await fixture.register(fixture.serviceA, at: fixture.sharedEndpoint, on: database, now: now)
            try await fixture.register(fixture.serviceA, at: fixture.movedEndpoint, on: database, now: now)
            let rows = try await database.connection.query(
                "SELECT endpoint FROM permissioned_space_notification_registrations WHERE space_uri = ? AND service_key = ?",
                [.text(fixture.space.rawValue), .text(fixture.serviceA)]
            )
            XCTAssertEqual(rows.compactMap { $0.column("endpoint")?.string }, [fixture.movedEndpoint])
            do {
                try await database.registerSpaceNotification(
                    .init(space: fixture.space, endpoint: fixture.sharedEndpoint, repository: nil,
                          expiresAt: now.addingTimeInterval(600), ownerServiceDID: "did:web:other.example",
                          deliveryServiceDID: fixture.serviceA),
                    authorization: fixture.credential, now: now
                )
                XCTFail("another owner must not replace a registered service")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testSharedEndpointWriteForwardIsQueuedOnceForTheServiceTheTransportResolves() async throws {
        let fixture = try ServiceKeyFixture()
        let database = try await fixture.open()
        do {
            try await fixture.createSpace(on: database)
            let now = Date()
            try await fixture.register(fixture.serviceB, at: fixture.sharedEndpoint, on: database, now: now)
            try await fixture.register(fixture.serviceA, at: fixture.sharedEndpoint, on: database, now: now)
            try await database.receiveSpaceWriteNotification(try fixture.writeNotification())
            let fanout = try await database.pendingNotificationFanout()
            XCTAssertEqual(fanout.count, 1, "one forward per endpoint; never two identical posts to one audience")
            let resolved = try await database.spaceNotificationRegistrationService(
                space: fixture.space, endpoint: fixture.sharedEndpoint, repository: fixture.writer
            )
            XCTAssertEqual(resolved, fixture.serviceA)
            let queued = try await database.connection.query(
                "SELECT service_key FROM permissioned_space_notification_fanout WHERE kind = 'write'"
            )
            XCTAssertEqual(queued.first?.column("service_key")?.string, resolved)
            let active = try await database.isSpaceNotificationRegistrationActive(
                space: fixture.space, endpoint: fixture.sharedEndpoint, repository: fixture.writer
            )
            XCTAssertTrue(active)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testMigrationRekeysEndpointTablesAndKeepsQueuedDeletionDeliverable() async throws {
        let fixture = try ServiceKeyFixture()
        let database = try await fixture.open()
        do {
            try await fixture.createSpace(on: database)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
        let legacy = try await fixture.open()
        let expires = Int(Date().addingTimeInterval(3_600).timeIntervalSince1970 * 1_000_000)
        do {
            // Rebuild the pre-v27 endpoint-keyed shapes with one service-named
            // registration, one endpoint-only registration and one queued
            // deletion for the service-named recipient.
            for statement in [
                "DROP TABLE permissioned_space_notification_registrations",
                """
                CREATE TABLE permissioned_space_notification_registrations (
                    space_uri TEXT NOT NULL, endpoint TEXT NOT NULL, repo_did TEXT,
                    expires_at INTEGER NOT NULL CHECK(expires_at >= 0), updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
                    owner_service_did TEXT NOT NULL, delivery_service_did TEXT,
                    PRIMARY KEY(space_uri, endpoint), CHECK(length(endpoint) > 0))
                """,
                "DROP TABLE permissioned_space_notification_fanout",
                """
                CREATE TABLE permissioned_space_notification_fanout (
                    id TEXT PRIMARY KEY, source_issuer TEXT NOT NULL, source_event_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('write', 'deleted')), space_uri TEXT NOT NULL,
                    repo_did TEXT, wire_revision TEXT, commitment BLOB, endpoint TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    created_at INTEGER NOT NULL CHECK(created_at >= 0), available_at INTEGER NOT NULL CHECK(available_at >= 0),
                    lease_token TEXT, lease_expires_at INTEGER, space_rev TEXT, prev_space_rev TEXT,
                    UNIQUE(source_issuer, source_event_id, kind, endpoint))
                """,
                "DROP TABLE conversation_space_deletion_recipients",
                """
                CREATE TABLE conversation_space_deletion_recipients (
                    space_uri TEXT NOT NULL REFERENCES conversation_space_authorities(space_uri) ON DELETE CASCADE,
                    deletion_event_id TEXT NOT NULL, endpoint TEXT NOT NULL, owner_service_did TEXT NOT NULL,
                    delivery_service_did TEXT, registration_expires_at INTEGER NOT NULL CHECK(registration_expires_at >= 0),
                    PRIMARY KEY(space_uri, endpoint), CHECK(length(endpoint) > 0))
                """,
            ] {
                _ = try await legacy.connection.query(statement)
            }
            _ = try await legacy.connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.spaceNotificationServiceKeyMigrationVersion)]
            )
            for (endpoint, delivery) in [(fixture.sharedEndpoint, fixture.serviceA as String?), (fixture.movedEndpoint, nil)] {
                _ = try await legacy.connection.query(
                    """
                    INSERT INTO permissioned_space_notification_registrations
                        (space_uri, endpoint, repo_did, expires_at, updated_at, owner_service_did, delivery_service_did)
                    VALUES (?, ?, NULL, ?, 1, ?, ?)
                    """,
                    [
                        .text(fixture.space.rawValue), .text(endpoint), .integer(expires),
                        .text("did:web:sync.example"), delivery.map(SQLiteData.text) ?? .null,
                    ]
                )
            }
            _ = try await legacy.connection.query(
                """
                INSERT INTO permissioned_space_notification_fanout(
                    id, source_issuer, source_event_id, kind, space_uri, endpoint, attempts, created_at, available_at)
                VALUES (?, ?, 'legacy-deletion', 'deleted', ?, ?, 0, 1, 1)
                """,
                [
                    .text(UUID().uuidString), .text(fixture.owner),
                    .text(fixture.space.rawValue), .text(fixture.sharedEndpoint),
                ]
            )
            try await legacy.close()
        } catch {
            try? await legacy.close()
            throw error
        }
        let migrated = try await fixture.open()
        do {
            let registrations = try await migrated.connection.query(
                "SELECT service_key, endpoint FROM permissioned_space_notification_registrations ORDER BY service_key"
            )
            XCTAssertEqual(
                registrations.compactMap { $0.column("service_key")?.string },
                [fixture.serviceA, "endpoint:" + fixture.movedEndpoint]
            )
            for table in ["conversation_space_deletion_recipients", "permissioned_space_notification_fanout"] {
                let hasKey = try await migrated.notificationTableHasColumn(table, "service_key")
                XCTAssertTrue(hasKey, table)
            }
            let index = try await migrated.connection.query(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'permissioned_space_notification_fanout_available'"
            )
            XCTAssertEqual(index.count, 1, "the rebuilt fanout keeps its lease index")
            // The pre-v27 row carries the legacy empty key and still resolves
            // through its endpoint.
            let queued = try await migrated.pendingNotificationFanout()
            let legacyEvent = try XCTUnwrap(queued.first)
            let registration = try await migrated.currentSpaceDeletionDeliveryRegistration(for: legacyEvent)
            XCTAssertEqual(registration?.serviceIdentity, fixture.serviceA)
            try await migrated.close()
        } catch {
            try? await migrated.close()
            throw error
        }
    }
}

private struct ServiceKeyFixture {
    let root = FileManager.default.temporaryDirectory.appending(path: "SwanServiceKey-\(UUID().uuidString)")
    let owner = "did:plc:alice"
    let writer = "did:plc:bob"
    let reader = "did:plc:reader"
    let serviceA = "did:web:sync.example#a"
    let serviceB = "did:web:sync.example#b"
    let otherService = "did:web:other.example#atproto_sync"
    let sharedEndpoint = "https://sync.example/xrpc"
    let movedEndpoint = "https://moved.sync.example/xrpc"
    let space: SpaceURI

    init() throws {
        space = try SpaceURI(authority: owner, spaceType: "app.bsky.bookmarks", skey: "service-key")
    }

    var ownerAuthorization: AuthorizationContext { .accountOAuthForTesting(subject: owner, scopes: ["atproto"]) }
    var credential: AuthorizationContext {
        .spaceCredential(.init(subject: reader, space: space, permissions: [.read], expiresAt: Date(timeIntervalSinceNow: 3_600)))
    }

    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: owner)
    }

    func createSpace(on database: SQLiteAccountDatabase) async throws {
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await authority.create(
            space: space, owner: owner,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: ownerAuthorization
        )
        _ = try await authority.addMember(space: space, member: writer, authorization: ownerAuthorization)
    }

    func register(_ service: String, at endpoint: String, on database: SQLiteAccountDatabase, now: Date) async throws {
        let owner = String(service.split(separator: "#").first ?? Substring(service))
        try await database.registerSpaceNotification(
            .init(space: space, endpoint: endpoint, repository: nil, expiresAt: now.addingTimeInterval(3_600),
                  ownerServiceDID: owner, deliveryServiceDID: service),
            authorization: credential, now: now
        )
    }

    func writeNotification() throws -> AuthorizedSpaceWriteNotification {
        let revision = try TID(tidString: "2222222222223").toString()
        let commitment = Data(repeating: 7, count: 32)
        return AuthorizedSpaceWriteNotification(
            eventID: "service-key-write", space: space, repository: writer, wireRevision: revision,
            commitment: commitment, issuer: writer, audience: owner,
            requestBodyDigest: SpaceNotificationRequestDigest.write(
                space: space, repository: writer, wireRevision: revision, commitment: commitment
            )
        )
    }
}
