import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import PetrelCrypto
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

    /// A writer's own notifyRepoUpdate to the space authority retries a 502
    /// `UpstreamFailure` and signs every attempt with a fresh jti. With the
    /// outbox row id as the jti, a receiver with a single-use jti store could
    /// consume it on the failed attempt and reject the retry.
    func testWriterOutboxRetriesUpstreamFailureWithAFreshJTI() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanWriterOutboxJTI-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: writer)
        do {
            let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "outbox-jti")
            let uri = try SpaceRecordURI(space: space, author: writer, collection: "app.bsky.feed.post", rkey: "jti")
            let value = Data([0xA1, 0x61, 0x61, 0x01])
            _ = try await database.apply(
                space: space, author: writer, expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            let pending = try await database.pendingOutbox()
            let row = try XCTUnwrap(pending.first)
            XCTAssertEqual(pending.count, 1)

            let signer = SigningNotificationServiceIssuer()
            let posts = RecordingPostTransport(
                responseStatuses: [502, 200],
                responseBodies: [
                    Data(#"{"error":"UpstreamFailure"}"#.utf8),
                    Data(),
                ]
            )
            let endpoint = "https://authority.example"
            let audience = "\(authority)#atproto_pds"
            let transport = HTTPPermissionedSpaceOutboxTransport(
                destinations: try StaticSwanSpaceNotificationDestinations(authorityDestinations: [
                    authority: try SwanSpaceNotificationDestination(
                        endpoint: try XCTUnwrap(URL(string: endpoint)), audience: audience
                    ),
                ]),
                announcements: SQLiteSpaceWriteAnnouncementSource(database: database),
                serviceAuthentication: signer,
                poster: OAuthBoundedJSONPoster(
                    policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                    resolver: FixedHostnameResolver(answer: try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))),
                    transport: posts
                )
            )
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: database, transport: transport,
                configuration: try .init(initialFailureBackoff: 1, maximumFailureBackoff: 1)
            )
            let now = Date()
            let failed = try await worker.deliverNext(now: now)
            XCTAssertEqual(failed, .failed(eventID: row.id, attempts: 1))
            let delivered = try await worker.deliverNext(now: now.addingTimeInterval(2))
            XCTAssertEqual(delivered, .delivered(eventID: row.id))

            let captured = await posts.posts()
            XCTAssertEqual(captured.count, 2)
            let verifier = DurableSpaceServiceAuthenticationVerifier(
                publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                    PinnedSpaceServicePublicKey(issuer: writer, generation: 1, publicKey: signer.key.publicKey),
                ])
            )
            var attemptJTIs: [String] = []
            for post in captured {
                XCTAssertEqual(post.url.absoluteString, "\(endpoint)/xrpc/com.atproto.space.notifyRepoUpdate")
                XCTAssertEqual(post.body, captured[0].body, "both attempts announce the same revision")
                let authorization = try XCTUnwrap(post.headers["authorization"])
                let verified = try await verifier.authenticate(
                    String(authorization.dropFirst("Bearer ".count)),
                    expectedAudience: audience,
                    expectedMethod: "com.atproto.space.notifyRepoUpdate",
                    now: Date()
                )
                XCTAssertEqual(verified.issuer, writer)
                attemptJTIs.append(verified.eventID)
            }
            XCTAssertEqual(Set(attemptJTIs).count, captured.count, "a retry must not reuse the failed attempt's jti")
            XCTAssertFalse(attemptJTIs.contains { $0.lowercased() == row.id.uuidString.lowercased() })
            let remaining = try await database.pendingOutbox()
            XCTAssertTrue(remaining.isEmpty)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testNotificationRecoveryServiceDrainsCommittedWriterAndSyncQueues() async throws {
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
            makeSyncTransport: { _ in transport },
            configuration: try notificationRecoveryConfiguration()
        )
        let running = Task { try? await service.run() }
        defer { running.cancel() }

        for _ in 0 ..< 100 {
            let counts = await transport.counts()
            if counts.outbox == 1 && counts.sync == 1 { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let counts = await transport.counts()
        XCTAssertEqual(counts.outbox, 1)
        XCTAssertEqual(counts.sync, 1)
        let remainingOutbox = try await database.pendingOutbox()
        let remainingSync = try await database.pendingSpaceSyncNotifications()
        XCTAssertTrue(remainingOutbox.isEmpty)
        XCTAssertTrue(remainingSync.isEmpty)
        running.cancel()
        _ = await running.value
    }

    func testNotificationRecoveryServiceExitsAfterServiceGroupGracefulShutdown() async throws {
        let fixture = try NotificationRecoveryFixture()
        defer { fixture.cleanup() }
        let database = try await fixture.open()
        do {
            try await fixture.prepareCommittedQueues(on: database)
            let transport = NotificationRecoveryTransport()
            let service = SwanNotificationRecoveryService(
                databases: [database],
                makeOutboxTransport: { _ in transport },
                makeSyncTransport: { _ in transport },
                configuration: try notificationRecoveryConfiguration()
            )
            let serviceGroup = SwanHTTPServiceLifecycle.makeServiceGroup(
                services: [service],
                logger: Logger(label: "SpaceNotificationHTTPTests.graceful-shutdown")
            )
            let finished = expectation(description: "Notification service exits on graceful shutdown")
            let running = Task {
                defer { finished.fulfill() }
                try await serviceGroup.run()
            }
            for _ in 0 ..< 100 {
                let counts = await transport.counts()
                if counts.outbox == 1 && counts.sync == 1 { break }
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
            let counts = await transport.counts()
            XCTAssertEqual(counts.outbox, 1)
            XCTAssertEqual(counts.sync, 1)

            await serviceGroup.triggerGracefulShutdown()
            await fulfillment(of: [finished], timeout: 2)
            // Cancellation is cleanup after the assertion. It must not be what
            // allows the service group to complete the expectation above.
            running.cancel()
            try await running.value
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
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
            makeSyncTransport: { _ in transport },
            configuration: try notificationRecoveryConfiguration()
        )
        let running = Task { try? await service.run() }
        defer { running.cancel() }

        for _ in 0 ..< 200 {
            let state = await transport.state()
            let restartedDatabases = try await restarted.directory.notificationRecoveryDatabases()
            let remaining = (try? await XCTUnwrap(restartedDatabases.first).pendingOutbox()) ?? []
            if state.attempts >= 2 && remaining.isEmpty { break }
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

    func testRegistrationConfirmerAcceptsExtendedAny2xxResponseAndRewritesBasePath() async throws {
        let challenge = "challenge-1"
        let response = try JSONSerialization.data(withJSONObject: [
            "challenge": challenge,
            "$type": "future-extension",
        ])
        let posts = RecordingPostTransport(
            responseStatuses: [201],
            responseBodies: [response]
        )
        let confirmer = HTTPSwanSpaceRegistrationConfirmer(
            policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
            transport: posts,
            resolver: FixedHostnameResolver(
                answer: try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
            )
        )
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "confirmation"
        )

        try await confirmer.confirmRegistration(
            space: space,
            endpoint: try XCTUnwrap(
                URL(string: "https://syncer.example:443/base?ignored=1")
            ),
            token: "opaque-token",
            challenge: challenge
        )

        let captured = await posts.posts()
        let post = try XCTUnwrap(captured.first)
        XCTAssertEqual(
            post.url.absoluteString,
            "https://syncer.example:443/xrpc/com.atproto.space.confirmRegistration"
        )
        XCTAssertNil(post.headers["authorization"])
        let body = try XCTUnwrap(
            JSONSerialization.jsonObject(with: post.body) as? [String: Any]
        )
        XCTAssertEqual(
            Set(body.keys),
            ["space", "token", "challenge"]
        )
        XCTAssertEqual(body["space"] as? String, space.rawValue)
        XCTAssertEqual(body["token"] as? String, "opaque-token")
        XCTAssertEqual(body["challenge"] as? String, challenge)
    }

    func testSyncDeliveryTreatsHTTP425AsRetryable() async throws {
        let posts = RecordingPostTransport(responseStatuses: [425])
        let transport = HTTPPermissionedSpaceSyncNotificationTransport(
            poster: OAuthBoundedJSONPoster(
                policy: try OAuthRemoteFetchPolicy(
                    maximumBodyBytes: 4_096,
                    timeout: 2
                ),
                resolver: FixedHostnameResolver(
                    answer: try XCTUnwrap(
                        OAuthIPAddress(literal: "93.184.216.34")
                    )
                ),
                transport: posts
            )
        )
        let space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "too-early"
        )
        let disposition = await transport.deliver(.init(
            id: UUID(),
            kind: .spaceDeleted,
            space: space,
            endpoint: "https://syncer.example",
            token: "token",
            retryExpiresAt: Date().addingTimeInterval(60),
            attempts: 0
        ))
        XCTAssertEqual(disposition, .retryableFailure)
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

    func server(
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil,
        decodeObserver: (@Sendable () async -> Void)? = nil,
        recipientBindings: SwanSpaceNotificationRecipientBindings = .empty,
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil,
        serviceAuthentication: (any SpaceServiceAuthenticationVerifier)? = nil,
        spacesOpenInterop: SwanSpacesOpenInteropConfiguration? = nil
    ) throws -> SwanHTTPServer {
        let serviceAuthentication = serviceAuthentication
            ?? NotificationServiceVerifier(authority: authority, writer: writer)
        let credentialKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: authority, generation: 1, publicKey: key.publicKey),
        ])
        return SwanHTTPServer(
            profile: try ProtocolProfile.load(from: notificationPackageRoot().appending(path: "Profiles/permissioned-data-0016-2026-11-12.json")),
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: URL(string: "https://swan.example")!),
            oauthRuntime: runtime,
            authenticatedGetSpaceDirectory: directory,
            accountControlStore: control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: NotificationNoSigningKeyResolver(),
                delegationPublicKeys: UnavailableSpaceDelegationPublicKeyResolver(),
                credentialPublicKeys: credentialKeys
            ),
            spaceNotificationConfiguration: decodeObserver.map {
                SwanSpaceNotificationHTTPConfiguration(
                    serviceAuthentication: serviceAuthentication,
                    recipientBindings: recipientBindings,
                    serviceEndpointResolver: serviceEndpointResolver,
                    notificationJSONDecodeObserver: $0
                )
            } ?? .init(
                serviceAuthentication: serviceAuthentication,
                recipientBindings: recipientBindings,
                serviceEndpointResolver: serviceEndpointResolver
            ),
            spacesOpenInterop: spacesOpenInterop,
            jsonWriteAdmission: jsonWriteAdmission
        )
    }

    func credentialHeaders(serviceAuth: String? = "register-service-token") throws -> HTTPFields {
        let credential = try PermissionedDataJWT.createSpaceCredential(
            issuer: authority, space: space, key: key,
            confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
        )
        // listRepos, registerNotify, and unregisterNotify are space-host
        // operations: the signed audience is the authority's bare DID, and
        // one signature serves all three.
        var headers = try SpaceCredentialSignatureTestSupport.headers(
            token: credential, audience: authority
        )
        headers[.contentType] = "application/json"
        if let serviceAuth {
            headers[.init("Atproto-Service-Auth")!] = "Bearer \(serviceAuth)"
        }
        return headers
    }

    func credentialOnlyHeaders() throws -> HTTPFields {
        try credentialHeaders(serviceAuth: nil)
    }

    func registerHeaders(for serviceDID: String? = nil) throws -> HTTPFields {
        var headers = try credentialHeaders()
        let did = serviceDID ?? writer
        headers[HTTPField.Name("atproto-service-auth")!] = "Bearer service-token:\(did)"
        return headers
    }

    func foreignAudienceRegisterHeaders(for serviceDID: String? = nil) throws -> HTTPFields {
        var headers = try credentialHeaders()
        let did = serviceDID ?? writer
        headers[HTTPField.Name("atproto-service-auth")!] = "Bearer foreign-audience-token:\(did)"
        return headers
    }

    /// The reference presentation: `Atproto-Space` plus an HTTP message
    /// signature by the credential's `cnf.kid` key over the authorization and
    /// audience fields.
    func spaceSchemeCredentialHeaders(for serviceDID: String? = nil) throws -> HTTPFields {
        try registerHeaders(for: serviceDID)
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
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
        )
        _ = try await lifecycle.putMembers(
            space: space,
            members: [.init(did: writer, read: true, write: true)],
            authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
        )
        let now = Date()
        try await database.putSpaceSyncRegistration(
            .init(
                space: space,
                endpoint: "https://receiver.example/xrpc/com.atproto.space.notifySpaceUpdate",
                token: "recovery-token",
                expiresAt: now.addingTimeInterval(3_600)
            )
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
                audience: authority,
                requestBodyDigest: SpaceNotificationRequestDigest.write(
                    space: space,
                    repository: writer,
                    wireRevision: "2222222222223",
                    commitment: Data(repeating: 0xA5, count: 32)
                )
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
    PermissionedSpaceSyncNotificationTransport
{
    private var outboxCount = 0
    private var syncCount = 0

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        XCTAssertFalse(notification.payload.isEmpty)
        outboxCount += 1
    }

    func deliver(
        _ notification: PersistedSpaceSyncNotification
    ) async -> PermissionedSpaceSyncNotificationDisposition {
        XCTAssertEqual(notification.kind, .repoWrite)
        XCTAssertNil(String(describing: notification).range(of: "private record value"))
        syncCount += 1
        return .delivered
    }

    func counts() -> (outbox: Int, sync: Int) {
        (outboxCount, syncCount)
    }
}

private actor IdempotentCrashRecoveryTransport:
    PermissionedSpaceOutboxTransport,
    PermissionedSpaceSyncNotificationTransport
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

    func deliver(
        _: PersistedSpaceSyncNotification
    ) async -> PermissionedSpaceSyncNotificationDisposition {
        .delivered
    }

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
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open),
                authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
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

private struct TestSpaceUpstreamFailure: AuthorizedSpaceUpstreamFailure {}

private actor NotificationHTTPDirectory:
    AuthorizedSimpleSpaceDirectory,
    AuthorizedSpaceNotificationDirectory
{
    private let authority: String
    private let writer: String
    private var notificationsValue: [AuthorizedSpaceWriteNotification] = []
    private var failNextRepoUpdate = false

    init(authority: String, writer: String) {
        self.authority = authority
        self.writer = writer
    }

    func space(
        _ space: SpaceURI,
        authorization _: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? {
        guard space.authority == authority else { return nil }
        return .init(
            space: space,
            configuration: try SimpleSpaceConfiguration(
                readPolicy: .memberList,
                writePolicy: .memberList,
                appAccess: .open
            )
        )
    }

    func close() async throws {}

    func listSpaceWriters(
        space: SpaceURI,
        limit _: Int,
        cursor: String?,
        authorization _: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter] {
        guard space.authority == authority else {
            throw AuthorizedSimpleSpaceLifecycleError.notFound
        }
        return notificationsValue
            .filter { cursor == nil || $0.wireRevision > cursor! }
            .sorted { $0.wireRevision < $1.wireRevision }
            .map {
                .init(
                    space: space,
                    repository: $0.repository,
                    wireRevision: $0.wireRevision,
                    commitment: $0.commitment,
                    spaceRevision: $0.wireRevision
                )
            }
    }

    func failNextRepoUpdateUpstream() {
        failNextRepoUpdate = true
    }

    func receiveSpaceWriteNotification(
        _ notification: AuthorizedSpaceWriteNotification
    ) async throws {
        guard notification.space.authority == authority,
              notification.repository == writer else {
            throw SwanError.unauthorized("notification is invalid")
        }
        if failNextRepoUpdate {
            failNextRepoUpdate = false
            throw TestSpaceUpstreamFailure()
        }
        if !notificationsValue.contains(where: { $0.eventID == notification.eventID }) {
            notificationsValue.append(notification)
        }
    }

    func notifications() -> [AuthorizedSpaceWriteNotification] {
        notificationsValue
    }
}

/// The deletion arguments the route hands to the durable receiver. The route
/// is the only place a space can still be substituted, so record it exactly.
struct RecordedSpaceDeletion: Sendable, Equatable {
    let space: SpaceURI
    let issuer: String
    let audience: String
    let eventID: String
    let requestBodyDigest: String
    var issuedAt: Date? = nil
}

private struct NotificationNoSigningKeyResolver: SpaceCredentialSigningKeyResolver {
    func signingKey(for _: String) async throws -> SpaceCredentialAuthoritySigningKey? { nil }
}

/// Canned DID documents for the register-time service resolution tests —
/// resolution logic runs for real, only the network fetch is substituted.
private struct StubNotificationDIDDocumentFetcher: SwanDIDDocumentFetching {
    let documents: [String: Data]

    func documentJSON(forDID did: String) async throws -> Data {
        guard let data = documents[did] else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return data
    }
}

/// Answers every hostname with one fixed public address, so the poster's
/// pre- and post-request DNS policy both approve the same peer.
private struct FixedHostnameResolver: OAuthHostnameResolving {
    let answer: OAuthIPAddress
    func resolve(host _: String) async throws -> [OAuthIPAddress] { [answer] }
}

private actor RecordingPostTransport: OAuthRemotePostTransport {
    struct RecordedPost: Sendable {
        let url: URL
        let headers: [String: String]
        let body: Data
    }

    private var recorded: [RecordedPost] = []
    private var failuresRemaining: Int
    private var responseStatuses: [Int]
    private var responseBodies: [Data]

    init(
        failuresRemaining: Int = 0,
        responseStatuses: [Int] = [],
        responseBodies: [Data] = []
    ) {
        self.failuresRemaining = failuresRemaining
        self.responseStatuses = responseStatuses
        self.responseBodies = responseBodies
    }

    func post(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        headers: [String: String],
        body: Data,
        timeout _: TimeInterval,
        maximumResponseBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        recorded.append(.init(url: url, headers: headers, body: body))
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw SwanError.unavailable("notification delivery failed")
        }
        let status = responseStatuses.isEmpty ? 200 : responseStatuses.removeFirst()
        let responseBody = responseBodies.isEmpty ? Data() : responseBodies.removeFirst()
        return .init(
            status: status,
            headers: ["content-length": ["\(responseBody.count)"]],
            body: responseBody,
            responseURL: url,
            connectedPeerAddress: approvedPeers.first
        )
    }

    func posts() -> [RecordedPost] { recorded }
}

private struct SigningNotificationServiceIssuer: SpaceServiceAuthenticationIssuer {
    let key = P256.Signing.PrivateKey()

    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        requestBodyDigest: String?,
        now: Date
    ) async throws -> String {
        try SpaceServiceJWT.create(
            issuer: issuer, audience: audience, method: method, eventID: eventID,
            requestBodyDigest: requestBodyDigest, key: key, now: now
        )
    }
}

private actor RecordingServiceIssuer: SpaceServiceAuthenticationIssuer {
    struct Issued: Sendable {
        let issuer: String
        let audience: String
        let method: String
        let requestBodyDigest: String?
    }

    private var recorded: [Issued] = []

    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID _: String,
        requestBodyDigest: String? = nil,
        now _: Date = Date()
    ) async throws -> String {
        recorded.append(.init(
            issuer: issuer, audience: audience, method: method,
            requestBodyDigest: requestBodyDigest
        ))
        return "recorded-service-token"
    }

    func issued() -> [Issued] { recorded }
}

private struct NotificationServiceVerifier: SpaceServiceAuthenticationVerifier {
    struct TokenMeta {
        let issuer: String
        let audience: String
        let eventID: String
        let requestBodyDigest: String?
        var issuedAt: Date? = nil
    }

    /// The `iat` the bound deletion token carries, so the route test can see
    /// it reach the durable receiver (SW-A).
    static let boundDeletionIssuedAt = Date(timeIntervalSince1970: 1_800_000_000)

    /// The pinned reference PDS registers a raw endpoint as the recipient
    /// service identity, so the binding key is not a DID.
    static let boundRecipientIdentity =
        "https://receiver.example/xrpc/com.atproto.space.notifySpaceDeleted"

    let authority: String
    let writer: String

    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        expectedRequestBodyDigest: String?,
        now _: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        let meta: TokenMeta
        if compact.hasPrefix("service-token:") {
            let issuer = String(compact.dropFirst("service-token:".count))
            meta = TokenMeta(
                issuer: issuer,
                audience: authority,
                eventID: "service-event-\(UUID().uuidString)",
                requestBodyDigest: expectedRequestBodyDigest
            )
        } else if compact.hasPrefix("foreign-audience-token:") {
            let issuer = String(compact.dropFirst("foreign-audience-token:".count))
            meta = TokenMeta(
                issuer: issuer,
                audience: "did:plc:foreignauthority99999",
                eventID: "service-event-foreign",
                requestBodyDigest: nil
            )
        } else {
            switch (compact, expectedMethod) {
            case ("register-service-token", "com.atproto.space.registerNotify"):
                meta = TokenMeta(
                    issuer: "did:web:events.bulleted.example",
                    audience: authority,
                    eventID: "service-event-reg",
                    requestBodyDigest: nil
                )
            case ("unregister-service-token", "com.atproto.space.unregisterNotify"):
                meta = TokenMeta(
                    issuer: "did:web:events.bulleted.example",
                    audience: authority,
                    eventID: "service-event-unreg",
                    requestBodyDigest: nil
                )
            case ("wrong-audience-token", "com.atproto.space.registerNotify"),
                 ("wrong-audience-token", "com.atproto.space.unregisterNotify"):
                meta = TokenMeta(
                    issuer: "did:web:events.bulleted.example",
                    audience: "did:plc:other-authority",
                    eventID: "service-event-wrong-aud",
                    requestBodyDigest: nil
                )
            case ("writer-token", "com.atproto.space.registerNotify"),
                 ("writer-token", "com.atproto.space.unregisterNotify"):
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-registration",
                    requestBodyDigest: nil
                )
            case ("writer-token", "com.atproto.space.notifyRepoUpdate"):
                let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
                let writeDigest = SpaceNotificationRequestDigest.write(
                    space: space,
                    repository: writer,
                    wireRevision: "3l72c4e2y2222",
                    commitment: Data(repeating: 0x01, count: 32)
                )
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-1",
                    requestBodyDigest: writeDigest
                )
            case ("mismatched-digest-token", "com.atproto.space.notifyRepoUpdate"):
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-bad",
                    requestBodyDigest: "mismatched-digest"
                )
            case ("bad-digest-token", "com.atproto.space.notifySpaceDeleted"):
                meta = TokenMeta(
                    issuer: authority,
                    audience: NotificationServiceVerifier.boundRecipientIdentity,
                    eventID: "service-event-bad-digest",
                    requestBodyDigest: "sha256:mismatched-digest"
                )
            case ("bad-digest-token", "com.atproto.space.notifyRepoUpdate"):
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-bad-digest",
                    requestBodyDigest: "sha256:mismatched-digest"
                )
            case ("authority-fanout-token", "com.atproto.space.notifyRepoUpdate"):
                meta = TokenMeta(
                    issuer: authority,
                    audience: "did:plc:recipientabcdefghijklmnop",
                    eventID: "service-event-2",
                    requestBodyDigest: expectedRequestBodyDigest
                )
            case ("authority-unknown-recipient-token", "com.atproto.space.notifyRepoUpdate"):
                meta = TokenMeta(
                    issuer: authority,
                    audience: "did:plc:unknownabcdefghijklmnopqr",
                    eventID: "service-event-3",
                    requestBodyDigest: expectedRequestBodyDigest
                )
            case ("authority-unknown-recipient-token", "com.atproto.space.notifySpaceDeleted"):
                let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
                meta = TokenMeta(
                    issuer: authority,
                    audience: "did:plc:unknownabcdefghijklmnopqr",
                    eventID: "service-event-4",
                    requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space)
                )
            case ("authority-bound-recipient-token", "com.atproto.space.notifySpaceDeleted"):
                let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
                let sibling = try? SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http-sibling")
                let digest: String
                if let sibling, expectedRequestBodyDigest == SpaceNotificationRequestDigest.deletion(space: sibling) {
                    digest = SpaceNotificationRequestDigest.deletion(space: sibling)
                } else {
                    digest = SpaceNotificationRequestDigest.deletion(space: space)
                }
                meta = TokenMeta(
                    issuer: authority,
                    audience: NotificationServiceVerifier.boundRecipientIdentity,
                    eventID: "service-event-5",
                    requestBodyDigest: digest,
                    issuedAt: NotificationServiceVerifier.boundDeletionIssuedAt
                )
            default:
                throw SwanError.unauthorized("service authentication is invalid")
            }
        }

        if let expectedAudience {
            guard meta.audience == expectedAudience else {
                throw SwanError.unauthorized("service authentication audience mismatch")
            }
        }
        if let expectedRequestBodyDigest {
            guard let tokenDigest = meta.requestBodyDigest, tokenDigest == expectedRequestBodyDigest else {
                throw SwanError.unauthorized("service authentication digest mismatch")
            }
        }
        return VerifiedSpaceServiceAuthentication(
            issuer: meta.issuer,
            audience: meta.audience,
            method: expectedMethod,
            eventID: meta.eventID,
            requestBodyDigest: meta.requestBodyDigest,
            expiresAt: Date(timeIntervalSinceNow: 60),
            issuedAt: meta.issuedAt
        )
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


// MARK: - `--enable-spaces-open-interop` (SWAN-04 / SWAN-05)

extension SpaceNotificationHTTPTests {
    private struct SignedServiceKeys {
        let writer = P256.Signing.PrivateKey()
        let authority = P256.Signing.PrivateKey()

        func verifier(authority authorityDID: String, writer writerDID: String) throws
            -> DurableSpaceServiceAuthenticationVerifier
        {
            DurableSpaceServiceAuthenticationVerifier(
                publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                    try .init(issuer: writerDID, generation: 1, publicKey: writer.publicKey),
                    try .init(issuer: authorityDID, generation: 1, publicKey: authority.publicKey),
                ])
            )
        }
    }

    private func serviceHeaders(_ token: String) -> HTTPFields {
        var fields: HTTPFields = [.contentType: "application/json"]
        fields[.authorization] = "Bearer \(token)"
        return fields
    }

    /// Hand-signs an ES256 service JWT so the test can choose a lifetime the
    /// production minter refuses to produce.
    private func handSignedServiceJWT(
        issuer: String,
        audience: String,
        method: String,
        jti: String,
        iat: Int64,
        exp: Int64,
        key: P256.Signing.PrivateKey
    ) throws -> String {
        let header = try JSONSerialization.data(
            withJSONObject: ["alg": "ES256", "typ": "JWT"],
            options: [.sortedKeys]
        )
        let payload = try JSONSerialization.data(
            withJSONObject: [
                "iss": issuer, "aud": audience, "lxm": method, "jti": jti,
                "iat": NSNumber(value: iat), "exp": NSNumber(value: exp),
            ],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let input = "\(header.base64URLEncodedString()).\(payload.base64URLEncodedString())"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: key)
        return "\(input).\(signature.base64URLEncodedString())"
    }

    /// SWAN-04: an upstream writer's notifyRepoUpdate carries no `req`. Hardened
    /// Swan refuses it; the interop flag admits it once, for either audience
    /// form, within 60 s, and still refuses a `req` that does not match.
    func testOpenInteropAdmitsUnboundUpstreamNotifyRepoUpdateOnceAndKeepsBoundChecks() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let keys = SignedServiceKeys()
            let verifier = try keys.verifier(authority: authority, writer: writer)
            let hardened = try fixture.server(serviceAuthentication: verifier)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.hardened"))
            let interop = try fixture.server(
                serviceAuthentication: verifier,
                spacesOpenInterop: .standard
            ).buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.interop"))
            let method = "com.atproto.space.notifyRepoUpdate"
            let rev = "3l72c4e2y2222"
            let hash = Data(repeating: 0x02, count: 32)
            let body = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"repo\":\"\(writer)\",\"repoRev\":\"\(rev)\",\"data\":{\"$bytes\":\"\(hash.base64EncodedString())\"}}")
            let digest = SpaceNotificationRequestDigest.write(
                space: fixture.space, repository: writer, wireRevision: rev, commitment: hash
            )
            @Sendable func unbound(_ jti: String, audience: String? = nil, issuer: String? = nil, key: P256.Signing.PrivateKey? = nil) throws -> String {
                try SpaceServiceJWT.create(
                    issuer: issuer ?? writer, audience: audience ?? authority, method: method,
                    eventID: jti, key: key ?? keys.writer
                )
            }
            let upstream = try unbound("upstream-1")

            try await hardened.test(.router) { client in
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(upstream), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            try await interop.test(.router) { client in
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(upstream), body: body) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Single-use jti: the identical token is refused on replay.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(upstream), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // The current `#atproto_pds` audience form is accepted too.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-2", audience: "\(self.authority)#atproto_pds")), body: body) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // The retired service fragment must not regain authority.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-retired", audience: "\(self.authority)#atproto_space_host")), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // Any other audience, or an issuer other than the repo, is not.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-3", audience: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz")), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-4", issuer: self.authority, key: keys.authority)), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // A lifetime over 60 s is refused for unbound tokens.
                let now = Int64(Date().timeIntervalSince1970)
                let long = try self.handSignedServiceJWT(
                    issuer: self.writer, audience: self.authority, method: method,
                    jti: "upstream-long", iat: now, exp: now + 90, key: keys.writer
                )
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(long), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // A token that carries `req` must still match the body.
                let wrongReq = try SpaceServiceJWT.create(
                    issuer: self.writer, audience: self.authority, method: method,
                    eventID: "bound-wrong", requestBodyDigest: String(repeating: "A", count: 43),
                    key: keys.writer
                )
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(wrongReq), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                let bound = try SpaceServiceJWT.create(
                    issuer: self.writer, audience: self.authority, method: method,
                    eventID: "bound-right", requestBodyDigest: digest, key: keys.writer
                )
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(bound), body: body) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }
            let recorded = await fixture.directory.notifications()
            XCTAssertEqual(Set(recorded.map(\.eventID)), ["upstream-1", "upstream-2", "bound-right"])
            XCTAssertTrue(recorded.allSatisfy { $0.audience == self.authority && $0.requestBodyDigest == digest })
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

}

// MARK: - notifyCredentialsRevoked (atproto#5567)

extension SpaceNotificationHTTPTests {
    private func revocationBody(_ space: SpaceURI, _ credentials: [String]) -> ByteBuffer {
        let ids = credentials.map { "\"\($0)\"" }.joined(separator: ",")
        return ByteBuffer(string: "{\"space\":\"\(space.rawValue)\",\"credentials\":[\(ids)]}")
    }

    private func hostWriterAccount(_ fixture: NotificationHTTPFixture) async throws {
        _ = try await fixture.control.createAccount(try AccountControlRegistration(
            did: writer,
            canonicalHandle: "revocation-writer.example.com",
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: AccountControlKeyReference(purpose: .rotation, generation: 1),
            publicGenesisCommitCID: nil,
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        ))
    }

    /// The authority revokes one credential at a repo host: the host persists
    /// it idempotently and refuses that credential with CredentialRevoked,
    /// while another credential for the same space keeps working.
    func testRevokedCredentialIsRefusedWithCredentialRevoked() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            try await hostWriterAccount(fixture)
            let keys = SignedServiceKeys()
            let app = try fixture.server(serviceAuthentication: try keys.verifier(authority: authority, writer: writer))
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.revocation"))
            let revoked = try PermissionedDataJWT.createSpaceCredential(
                issuer: authority, space: fixture.space, key: fixture.key,
                confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
            )
            let kept = try PermissionedDataJWT.createSpaceCredential(
                issuer: authority, space: fixture.space, key: fixture.key,
                confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
            )
            let revokedJTI = try PermissionedDataJWT.inspectSpaceCredential(revoked).claims.jti
            let listURI = "/xrpc/com.atproto.space.listWriters?space=\(fixture.space.rawValue.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)"
            let revokedHeaders = try SpaceCredentialSignatureTestSupport.headers(token: revoked, audience: authority)
            let keptHeaders = try SpaceCredentialSignatureTestSupport.headers(token: kept, audience: authority)
            let method = ComAtprotoSpaceNotifyCredentialsRevoked.typeIdentifier
            let body = revocationBody(fixture.space, [revokedJTI])
            let digest = SpaceNotificationRequestDigest.credentialRevocation(
                space: fixture.space, credentials: [revokedJTI]
            )
            @Sendable func revocation(_ jti: String) throws -> HTTPFields {
                serviceHeaders(try SpaceServiceJWT.create(
                    issuer: authority, audience: writer, method: method, eventID: jti,
                    requestBodyDigest: digest, key: keys.authority
                ))
            }
            try await app.test(.router) { client in
                try await client.execute(uri: listURI, method: .get, headers: revokedHeaders) { response in
                    XCTAssertEqual(response.status, .ok, "positive control: not yet revoked")
                }
                for eventID in ["revoke-1", "revoke-2"] {
                    try await client.execute(
                        uri: "/xrpc/\(method)", method: .post,
                        headers: try revocation(eventID), body: body
                    ) { response in
                        XCTAssertEqual(response.status, .ok, eventID)
                    }
                }
                try await client.execute(uri: listURI, method: .get, headers: revokedHeaders) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "CredentialRevoked")
                }
                // A revoked credential is refused even when its audience is
                // also wrong: revocation is checked first, as in the reference.
                let wrongAudience = try SpaceCredentialSignatureTestSupport.headers(token: revoked, audience: writer)
                try await client.execute(uri: listURI, method: .get, headers: wrongAudience) { response in
                    XCTAssertEqual(try notificationErrorCode(response.body), "CredentialRevoked")
                }
                try await client.execute(uri: listURI, method: .get, headers: keptHeaders) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let keptWrongAudience = try SpaceCredentialSignatureTestSupport.headers(token: kept, audience: writer)
                try await client.execute(uri: listURI, method: .get, headers: keptWrongAudience) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "BadSpaceAudience")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Service auth must come from the space authority, name a repo account
    /// hosted here as its audience, carry this method's lxm, and (without
    /// open interop) bind the body with `req`. The body must hold 1...100
    /// nonempty JWT IDs.
    func testRevocationRequiresAuthorityIssuerHostedAudienceAndAValidBody() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            try await hostWriterAccount(fixture)
            let keys = SignedServiceKeys()
            let app = try fixture.server(serviceAuthentication: try keys.verifier(authority: authority, writer: writer))
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.revocationAuth"))
            let method = ComAtprotoSpaceNotifyCredentialsRevoked.typeIdentifier
            let body = revocationBody(fixture.space, ["jti-1"])
            let digest = SpaceNotificationRequestDigest.credentialRevocation(space: fixture.space, credentials: ["jti-1"])
            @Sendable func token(
                issuer: String? = nil, audience: String? = nil, lxm: String? = nil,
                req: String?? = nil, key: P256.Signing.PrivateKey? = nil, jti: String
            ) throws -> HTTPFields {
                // nil: bind the real digest; .some(nil): unbound; .some(x): x.
                let bound: String? = req ?? digest
                return serviceHeaders(try SpaceServiceJWT.create(
                    issuer: issuer ?? authority, audience: audience ?? writer,
                    method: lxm ?? method, eventID: jti,
                    requestBodyDigest: bound, key: key ?? keys.authority
                ))
            }
            try await app.test(.router) { client in
                let denied: [(String, HTTPFields)] = [
                    ("writer as issuer", try token(issuer: writer, key: keys.writer, jti: "a")),
                    ("authority (not hosted) as audience", try token(audience: authority, jti: "b")),
                    ("service identifier audience", try token(audience: "\(writer)#atproto_pds", jti: "c")),
                    ("wrong lxm", try token(lxm: "com.atproto.space.notifyRepoUpdate", jti: "d")),
                    ("unbound without open interop", try token(req: .some(.none), jti: "e")),
                    ("mismatched req", try token(req: .some(String(repeating: "A", count: 43)), jti: "f")),
                ]
                for (name, headers) in denied {
                    try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: headers, body: body) { response in
                        XCTAssertEqual(response.status, .unauthorized, name)
                    }
                }
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: try token(jti: "ok"), body: body) { response in
                    XCTAssertEqual(response.status, .ok, "positive control")
                }
                for (index, (name, invalid)) in [
                    ("empty list", revocationBody(fixture.space, [])),
                    ("101 IDs", revocationBody(fixture.space, (0 ... 100).map { "j\($0)" })),
                    ("empty ID", revocationBody(fixture.space, [""])),
                    ("extra key", ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"credentials\":[\"jti-1\"],\"extra\":1}")),
                    ("missing credentials", ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")),
                ].enumerated() {
                    try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: try token(jti: "body-\(index)"), body: invalid) { response in
                        XCTAssertEqual(response.status, .badRequest, name)
                    }
                }
                try await client.execute(uri: "/xrpc/\(method)", method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Under --enable-spaces-open-interop an upstream authority's unbound
    /// service JWT is admitted once, as for the other notification routes.
    func testOpenInteropAdmitsUnboundRevocationOnce() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            try await hostWriterAccount(fixture)
            let keys = SignedServiceKeys()
            let app = try fixture.server(
                serviceAuthentication: try keys.verifier(authority: authority, writer: writer),
                spacesOpenInterop: .standard
            ).buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.revocationInterop"))
            let method = ComAtprotoSpaceNotifyCredentialsRevoked.typeIdentifier
            let unbound = serviceHeaders(try SpaceServiceJWT.create(
                issuer: authority, audience: writer, method: method,
                eventID: "upstream-revocation", key: keys.authority
            ))
            try await app.test(.router) { client in
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: unbound, body: revocationBody(fixture.space, ["jti-1"])) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: unbound, body: revocationBody(fixture.space, ["jti-1"])) { response in
                    XCTAssertEqual(response.status, .unauthorized, "an unbound token is single-use")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }
}
