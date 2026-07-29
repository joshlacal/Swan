import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

final class SpaceNotificationHTTPTests: XCTestCase, @unchecked Sendable {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let writer = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testCredentialOnlyWriterDiscoveryRegistrationAndServiceNotifications() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let app = try fixture.server().buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests"))
            let credentialHeaders = try fixture.bearerHeaders()
            let encodedSpace = notificationPercentEncode(fixture.space.rawValue)
            let expectedWriter = writer
            let registerBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/xrpc/com.atproto.space.notifyWrite\"}")
            let commitment = Data(repeating: 0xAB, count: 32).base64EncodedString()
            let writeBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"repo\":\"\(writer)\",\"rev\":\"2222222222222\",\"hash\":{\"$bytes\":\"\(commitment)\"}}")
            let serviceHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer writer-token"
                return fields
            }()
            let authorityFanoutHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer authority-fanout-token"
                return fields
            }()
            let unknownRecipientHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer authority-unknown-recipient-token"
                return fields
            }()

            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    let value = try notificationJSONObject(response.body)
                    XCTAssertEqual(Set(value.keys), ["expiresAt"])
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: serviceHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
                // The pinned TypeScript receiver requires `iss == repo` for
                // notifyWrite. Do not accept an authority-signed surrogate:
                // it would be incompatible with that receiver and would let
                // Swan claim an unsupported cross-host delivery mode.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: authorityFanoutHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Likewise, an unbound recipient audience cannot turn an
                // authority signature into a member-writer notification.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: unknownRecipientHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Deletion remains an authority-signed control-plane message.
                // An unbound configured recipient is intentionally a no-op.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifySpaceDeleted",
                    method: .post,
                    headers: unknownRecipientHeaders,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)",
                    method: .get,
                    headers: credentialHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try notificationJSONObject(response.body)
                    let repos = try XCTUnwrap(value["repos"] as? [[String: Any]])
                    XCTAssertEqual(repos.count, 1)
                    XCTAssertEqual(repos.first?["did"] as? String, expectedWriter)
                    XCTAssertEqual(repos.first?["rev"] as? String, "2222222222222")
                    let rendered = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertFalse(rendered.contains("record"))
                    XCTAssertFalse(rendered.contains("credential"))
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)",
                    method: .post
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try notificationErrorCode(response.body), "permissioned_endpoint_unavailable")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/x\"}")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try notificationErrorCode(response.body), "InvalidRequest")
                }
            }
            let registered = await fixture.directory.registrations()
            let notifications = await fixture.directory.notifications()
            XCTAssertEqual(registered.count, 1)
            XCTAssertEqual(notifications.count, 1)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testNotificationRecoveryServiceDrainsCommittedWriterAndAuthorityQueues() async throws {
        let fixture = try NotificationRecoveryFixture()
        let database = try await fixture.open()
        defer {
            Task { try? await database.close() }
            fixture.cleanup()
        }
        try await fixture.prepareCommittedQueues(on: database)

        let transport = NotificationRecoveryTransport()
        let service = SwanNotificationRecoveryService(
            databases: [database],
            makeOutboxTransport: { _ in transport },
            makeFanoutTransport: { _ in transport },
            configuration: try notificationRecoveryConfiguration()
        )
        let running = Task { try? await service.run() }
        defer { running.cancel() }

        for _ in 0 ..< 100 {
            let counts = await transport.counts()
            if counts.outbox == 1 { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let counts = await transport.counts()
        XCTAssertEqual(counts.outbox, 1)
        XCTAssertEqual(counts.fanout, 0)
        let remainingOutbox = try await database.pendingOutbox()
        let remainingFanout = try await database.pendingNotificationFanout()
        XCTAssertTrue(remainingOutbox.isEmpty)
        XCTAssertTrue(remainingFanout.isEmpty)
        running.cancel()
        _ = await running.value
    }

    func testCommittedWriteSurvivesStopAndRecoversIdempotentlyFromPreopenedDirectory() async throws {
        let fixture = try PreopenedRecoveryFixture()
        defer { fixture.cleanup() }
        try await fixture.createCommittedWrite()

        // The first process opens the exact startup directory used by HTTP
        // writes, observes the committed event, then stops before delivery.
        let first = try await fixture.openRuntime()
        let firstDatabases = try await first.directory.notificationRecoveryDatabases()
        let firstPending = try await XCTUnwrap(firstDatabases.first).pendingOutbox()
        XCTAssertEqual(firstPending.count, 1)
        try await first.close()

        // The restarted process reopens the same durable inventory. The
        // transport records one logical receiver effect, then simulates a
        // lost acknowledgement so the stable event ID is delivered twice.
        let restarted = try await fixture.openRuntime()
        let transport = IdempotentCrashRecoveryTransport()
        let service = try await SwanNotificationRecoveryService.fromPreopenedDirectory(
            restarted.directory,
            makeOutboxTransport: { _ in transport },
            makeFanoutTransport: { _ in transport },
            configuration: try notificationRecoveryConfiguration()
        )
        let running = Task { try? await service.run() }
        defer { running.cancel() }

        for _ in 0 ..< 200 {
            let state = await transport.state()
            if state.attempts >= 2 { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let state = await transport.state()
        XCTAssertEqual(state.attempts, 2)
        XCTAssertEqual(state.uniqueEffects, 1)
        let restartedDatabases = try await restarted.directory.notificationRecoveryDatabases()
        let remaining = try await XCTUnwrap(restartedDatabases.first).pendingOutbox()
        XCTAssertTrue(remaining.isEmpty)
        running.cancel()
        _ = await running.value
        try await restarted.close()
    }
}

private struct NotificationHTTPFixture {
    let root: URL
    let space: SpaceURI
    let authority: String
    let writer: String
    let key: P256.Signing.PrivateKey
    let control: SQLiteControlDatabase
    let runtime: SwanOAuthRuntime
    let directory: NotificationHTTPDirectory

    static func make(authority: String, writer: String) async throws -> NotificationHTTPFixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceNotificationHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
            return NotificationHTTPFixture(
                root: root,
                space: space,
                authority: authority,
                writer: writer,
                key: P256.Signing.PrivateKey(),
                control: control,
                runtime: try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xA1, count: 32)),
                directory: NotificationHTTPDirectory(authority: authority, writer: writer)
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func server() throws -> SwanHTTPServer {
        let credentialKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: authority, generation: 1, publicKey: key.publicKey),
        ])
        return SwanHTTPServer(
            profile: try ProtocolProfile.load(from: notificationPackageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")),
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: URL(string: "https://swan.example")!),
            oauthRuntime: runtime,
            authenticatedGetSpaceDirectory: directory,
            accountControlStore: control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: NotificationNoSigningKeyResolver(),
                delegationPublicKeys: UnavailableSpaceDelegationPublicKeyResolver(),
                credentialPublicKeys: credentialKeys
            ),
            spaceNotificationConfiguration: .init(
                serviceAuthentication: NotificationServiceVerifier(authority: authority, writer: writer)
            )
        )
    }

    func bearerHeaders() throws -> HTTPFields {
        let credential = try PermissionedDataJWT.createSpaceCredential(issuer: authority, space: space, key: key)
        var headers: HTTPFields = [.contentType: "application/json"]
        headers[.authorization] = "Bearer \(credential)"
        return headers
    }

    func close() async throws {
        try await control.close()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private struct NotificationRecoveryFixture {
    let root: URL
    let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    let writer = "did:plc:bcdefghijklmnopqrstuvwxy"
    let reader = "did:plc:cdefghijklmnopqrstuvwxyz"
    let space: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanNotificationRecoveryServiceTests-\(UUID().uuidString)")
        space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "recovery")
    }

    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
    }

    func prepareCommittedQueues(on database: SQLiteAccountDatabase) async throws {
        let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await lifecycle.create(
            space: space,
            owner: authority,
            configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
            authorization: .accountOAuth(subject: authority, scopes: ["atproto"])
        )
        _ = try await lifecycle.addMember(
            space: space,
            member: writer,
            authorization: .accountOAuth(subject: authority, scopes: ["atproto"])
        )
        let now = Date()
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: "https://receiver.example/xrpc/com.atproto.space.notifyWrite",
                repository: writer,
                expiresAt: now.addingTimeInterval(3_600)
            ),
            authorization: .spaceCredential(.init(
                subject: reader,
                space: space,
                permissions: [.read],
                expiresAt: now.addingTimeInterval(3_600)
            )),
            now: now
        )
        _ = try await database.appendOplogAndOutbox(
            space: space,
            revision: 1,
            operation: Data([0xA1, 0x61, 0x61, 0x01]),
            commitment: Data(repeating: 0xA4, count: 32)
        )
        try await database.receiveSpaceWriteNotification(
            .init(
                eventID: "writer-recovery-event",
                space: space,
                repository: writer,
                wireRevision: "2222222222223",
                commitment: Data(repeating: 0xA5, count: 32),
                issuer: writer,
                audience: authority
            ),
            now: now
        )
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private actor NotificationRecoveryTransport:
    PermissionedSpaceOutboxTransport,
    PermissionedSpaceNotificationFanoutTransport
{
    private var outboxCount = 0
    private var fanoutCount = 0

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        XCTAssertFalse(notification.payload.isEmpty)
        outboxCount += 1
    }

    func deliver(_ notification: PersistedSpaceNotificationFanout) async throws {
        XCTAssertEqual(notification.kind, .write)
        XCTAssertNil(String(describing: notification).range(of: "private record value"))
        fanoutCount += 1
    }

    func counts() -> (outbox: Int, fanout: Int) {
        (outboxCount, fanoutCount)
    }
}

private actor IdempotentCrashRecoveryTransport:
    PermissionedSpaceOutboxTransport,
    PermissionedSpaceNotificationFanoutTransport
{
    private var attempts = 0
    private var applied = Set<UUID>()

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        attempts += 1
        applied.insert(notification.id)
        if attempts == 1 {
            throw SwanError.unavailable("simulated lost delivery acknowledgement")
        }
    }

    func deliver(_: PersistedSpaceNotificationFanout) async throws {}

    func state() -> (attempts: Int, uniqueEffects: Int) {
        (attempts, applied.count)
    }
}

private struct PreopenedRecoveryFixture {
    let root: URL
    let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    let space: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPreopenedRecoveryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "preopened-recovery"
        )
    }

    func createCommittedWrite() async throws {
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try .init(
                did: authority,
                canonicalHandle: "recovery.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let database = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: authority
            )
            let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
            _ = try await lifecycle.create(
                space: space,
                owner: authority,
                configuration: try .init(policy: .public, appAccess: .open),
                authorization: .accountOAuth(subject: authority, scopes: ["atproto"])
            )
            _ = try await database.appendOplogAndOutbox(
                space: space,
                revision: 1,
                operation: Data([0xA1, 0x61, 0x61, 0x01]),
                commitment: Data(repeating: 0xB4, count: 32)
            )
            try await database.close()
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func openRuntime() async throws -> PreopenedRecoveryRuntime {
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            return .init(
                control: control,
                directory: try await .bootstrap(
                    dataDirectory: root,
                    controlStore: control,
                    publicIdentityVerifier: nil
                )
            )
        } catch {
            try? await control.close()
            throw error
        }
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private struct PreopenedRecoveryRuntime {
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory

    func close() async throws {
        try await directory.close()
        try await control.close()
    }
}

private func notificationRecoveryConfiguration() throws -> PermissionedSpaceOutboxDeliveryConfiguration {
    try .init(
        leaseDuration: 1,
        idlePollInterval: 0.01,
        initialFailureBackoff: 0.01,
        maximumFailureBackoff: 0.01
    )
}

private actor NotificationHTTPDirectory: AuthorizedSimpleSpaceDirectory, AuthorizedSpaceNotificationDirectory {
    private let authority: String
    private let writer: String
    private var registrationsValue: [AuthorizedSpaceNotificationRegistration] = []
    private var notificationsValue: [AuthorizedSpaceWriteNotification] = []

    init(authority: String, writer: String) {
        self.authority = authority
        self.writer = writer
    }

    func space(_ space: SpaceURI, authorization _: AuthorizationContext) async throws -> AuthenticatedSimpleSpaceDescription? {
        guard space.authority == authority else { return nil }
        return .init(space: space, configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open))
    }

    func close() async throws {}

    func listSpaceWriters(
        space: SpaceURI,
        limit _: Int,
        cursor _: String?,
        authorization _: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter] {
        guard space.authority == authority else { throw AuthorizedSimpleSpaceLifecycleError.notFound }
        return notificationsValue.map {
            .init(space: space, repository: $0.repository, wireRevision: $0.wireRevision, commitment: $0.commitment)
        }
    }

    func registerSpaceNotification(
        _ registration: AuthorizedSpaceNotificationRegistration,
        authorization _: AuthorizationContext
    ) async throws {
        registrationsValue.removeAll { $0.endpoint == registration.endpoint }
        registrationsValue.append(registration)
    }

    func receiveSpaceWriteNotification(_ notification: AuthorizedSpaceWriteNotification) async throws {
        guard notification.space.authority == authority, notification.repository == writer else {
            throw SwanError.unauthorized("notification is invalid")
        }
        if !notificationsValue.contains(where: { $0.eventID == notification.eventID }) {
            notificationsValue.append(notification)
        }
    }

    func receiveSpaceDeletionNotification(
        space _: SpaceURI,
        issuer _: String,
        audience _: String,
        eventID _: String
    ) async throws {}

    func registrations() -> [AuthorizedSpaceNotificationRegistration] { registrationsValue }
    func notifications() -> [AuthorizedSpaceWriteNotification] { notificationsValue }
}

private struct NotificationNoSigningKeyResolver: SpaceCredentialSigningKeyResolver {
    func signingKey(for _: String) async throws -> SpaceCredentialAuthoritySigningKey? { nil }
}

private struct NotificationServiceVerifier: SpaceServiceAuthenticationVerifier {
    let authority: String
    let writer: String

    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        now _: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        guard expectedAudience == nil else {
            throw SwanError.unauthorized("service authentication is invalid")
        }
        switch (compact, expectedMethod) {
        case ("writer-token", "com.atproto.space.notifyWrite"):
            return .init(
                issuer: writer,
                audience: authority,
                method: expectedMethod,
                eventID: "service-event-1",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-fanout-token", "com.atproto.space.notifyWrite"):
            return .init(
                issuer: authority,
                audience: "did:plc:recipientabcdefghijklmnop",
                method: expectedMethod,
                eventID: "service-event-2",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-unknown-recipient-token", "com.atproto.space.notifyWrite"):
            return .init(
                issuer: authority,
                audience: "did:plc:unknownabcdefghijklmnopqr",
                method: expectedMethod,
                eventID: "service-event-3",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-unknown-recipient-token", "com.atproto.space.notifySpaceDeleted"):
            return .init(
                issuer: authority,
                audience: "did:plc:unknownabcdefghijklmnopqr",
                method: expectedMethod,
                eventID: "service-event-4",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        default:
            throw SwanError.unauthorized("service authentication is invalid")
        }
    }
}

private func notificationPackageRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}

private func notificationPercentEncode(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
}

private func notificationJSONObject(_ body: ByteBuffer) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(body.readableBytesView)) as! [String: Any]
}

private func notificationErrorCode(_ body: ByteBuffer) throws -> String {
    try XCTUnwrap(notificationJSONObject(body)["error"] as? String)
}
