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
                fields[.authorization] = "Bearer service-token"
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
        guard compact == "service-token",
              expectedAudience == authority,
              expectedMethod == "com.atproto.space.notifyWrite" else {
            throw SwanError.unauthorized("service authentication is invalid")
        }
        return .init(
            issuer: writer,
            audience: authority,
            method: expectedMethod,
            eventID: "service-event-1",
            expiresAt: Date(timeIntervalSinceNow: 60)
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
