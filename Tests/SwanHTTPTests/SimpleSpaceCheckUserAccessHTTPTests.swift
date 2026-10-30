import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import PetrelCrypto
import SwanCore
import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanSpaces
import XCTest

final class SimpleSpaceCheckUserAccessHTTPTests: XCTestCase, @unchecked Sendable {
    fileprivate static let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    fileprivate static let user = "did:plc:bcdefghijklmnopqrstuvwxy"
    fileprivate static let audience = "did:web:managing.swan.example#service"

    func testServiceAuthenticatedGenericPDSDeniesWithoutStorage() async throws {
        let fixture = try await CheckUserAccessFixture.make()
        defer { fixture.cleanup() }
        let token = try fixture.token()
        let app = try fixture.server().buildApplication(logger: Logger(label: "SimpleSpaceCheckUserAccessHTTPTests.valid"))
        let uri = checkUserAccessURI(space: fixture.space, user: Self.user, clientID: "https://client.example/meta")
        try await app.test(.router) { client in
            try await client.execute(uri: uri, method: .get, headers: bearer(token)) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[.contentType], "application/json")
                XCTAssertEqual(response.headers[.cacheControl], "no-store")
                let object = try checkUserAccessObject(response.body)
                XCTAssertEqual(Set(object.keys), ["authorized"])
                XCTAssertEqual(object["authorized"] as? Bool, false)
            }
        }
        // The fixture supplies no account directory, authority state, policy,
        // record, or blob store. A valid request can therefore only invoke its
        // fixed service verifier and cannot read or mutate authority state.
        let callCount = await fixture.verifier.callCount()
        let expectation = await fixture.verifier.lastExpectation()
        XCTAssertEqual(callCount, 1)
        XCTAssertEqual(expectation?.audience, Self.audience)
        XCTAssertEqual(expectation?.method, "com.atproto.managedspace.checkUserAccess")
        try await fixture.close()
    }

    func testInvalidCredentialsAndQueriesAreOpaqueDenials() async throws {
        let fixture = try await CheckUserAccessFixture.make()
        defer { fixture.cleanup() }
        let app = try fixture.server().buildApplication(logger: Logger(label: "SimpleSpaceCheckUserAccessHTTPTests.denied"))
        let validURI = checkUserAccessURI(space: fixture.space, user: Self.user)
        let valid = try fixture.token()
        let wrongMethod = try fixture.token(method: "com.atproto.space.notifyWrite")
        let wrongAudience = try fixture.token(audience: "did:web:other.example#service")
        let expired = try fixture.token(now: Date(timeIntervalSinceNow: -120), lifetime: 1)
        let malformedSignature = String(valid.dropLast()) + "x"
        let encodedSpace = checkUserAccessEncode(fixture.space.rawValue)
        let invalidQueries = [
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace,
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace + "&user=" + Self.user,
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace + "&user=" + Self.user + "&access=invalid",
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace + "&user=" + Self.user + "&access=write&clientId=foo",
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace + "&user=" + Self.user + "&access=read&user=" + Self.user,
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace + "&user=" + Self.user + "&access=read&unknown=x",
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=at%3A%2F%2Fbad&user=" + Self.user + "&access=read",
            "/xrpc/com.atproto.managedspace.checkUserAccess?space=" + encodedSpace + "&user=not-a-did&access=read",
        ]
        try await app.test(.router) { client in
            for headers in [HTTPFields(), bearer(""), bearer("not a jwt"), bearer(wrongMethod), bearer(wrongAudience), bearer(expired), bearer(malformedSignature)] {
                try await client.execute(uri: validURI, method: .get, headers: headers) { response in
                    self.assertOpaqueDenied(response)
                }
            }
            var duplicateAuthorization = bearer(valid)
            duplicateAuthorization.append(HTTPField(name: .authorization, value: "Bearer \(valid)"))
            try await client.execute(uri: validURI, method: .get, headers: duplicateAuthorization) { response in
                self.assertOpaqueDenied(response)
            }
            for uri in invalidQueries {
                try await client.execute(uri: uri, method: .get, headers: bearer(valid)) { response in
                    self.assertOpaqueDenied(response)
                }
            }
            try await client.execute(uri: validURI, method: .post, headers: bearer(valid)) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertEqual(response.headers[.cacheControl], "no-store")
                XCTAssertEqual(try checkUserAccessError(response.body), "permissioned_endpoint_unavailable")
            }
        }
        try await fixture.close()
    }

    func testAbsentCapabilityStaysMethodCorrectClosedAndUnavailableVerifierIsTemporary() async throws {
        let fixture = try await CheckUserAccessFixture.make()
        defer { fixture.cleanup() }
        let profile = try checkUserAccessProfile()
        let noCapability = SwanHTTPServer(profile: profile, oauthRuntime: fixture.runtime)
        let unavailable = SwanHTTPServer(
            profile: profile,
            oauthRuntime: fixture.runtime,
            simpleSpaceCheckUserAccessConfiguration: try .init(
                serviceAuthentication: CheckUserAccessUnavailableVerifier(),
                managingServiceAudience: Self.audience
            )
        )
        let uri = checkUserAccessURI(space: fixture.space, user: Self.user)
        let token = try fixture.token()
        try await noCapability.buildApplication(logger: Logger(label: "SimpleSpaceCheckUserAccessHTTPTests.closed")).test(.router) { client in
            try await client.execute(uri: uri, method: .get) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(response.headers[.cacheControl], "no-store")
                XCTAssertEqual(try checkUserAccessError(response.body), "permissioned_data_pending")
            }
        }
        try await unavailable.buildApplication(logger: Logger(label: "SimpleSpaceCheckUserAccessHTTPTests.unavailable")).test(.router) { client in
            try await client.execute(uri: uri, method: .get, headers: bearer(token)) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(response.headers[.cacheControl], "no-store")
                XCTAssertEqual(try checkUserAccessError(response.body), "temporarily_unavailable")
            }
        }
        XCTAssertThrowsError(try SwanSimpleSpaceCheckUserAccessHTTPConfiguration(
            serviceAuthentication: fixture.verifier,
            managingServiceAudience: ""
        ))
        try await fixture.close()
    }

    private func assertOpaqueDenied(_ response: TestResponse) {
        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(response.headers[.contentType], "application/json")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(try? checkUserAccessError(response.body), "Unauthorized")
    }
}

private actor CheckUserAccessVerifier: SpaceServiceAuthenticationVerifier {
    private let verifier: DurableSpaceServiceAuthenticationVerifier
    private var expectations: [(audience: String?, method: String)] = []

    init(key: P256.Signing.PublicKey) throws {
        verifier = DurableSpaceServiceAuthenticationVerifier(
            publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                try .init(issuer: SimpleSpaceCheckUserAccessHTTPTests.authority, generation: 1, publicKey: key),
            ])
        )
    }

    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        expectedRequestBodyDigest: String?,
        now: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        expectations.append((expectedAudience, expectedMethod))
        return try await verifier.authenticate(
            compact,
            expectedAudience: expectedAudience,
            expectedMethod: expectedMethod,
            expectedRequestBodyDigest: expectedRequestBodyDigest,
            now: now
        )
    }

    func callCount() -> Int { expectations.count }
    func lastExpectation() -> (audience: String?, method: String)? { expectations.last }
}

private struct CheckUserAccessUnavailableVerifier: SpaceServiceAuthenticationVerifier {
    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        expectedRequestBodyDigest: String?,
        now: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        throw SwanError.unavailable("test verifier unavailable")
    }
}

private struct CheckUserAccessFixture {
    let root: URL
    let control: SQLiteControlDatabase
    let runtime: SwanOAuthRuntime
    let key: P256.Signing.PrivateKey
    let verifier: CheckUserAccessVerifier
    let space: SpaceURI

    static func make() async throws -> Self {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanCheckUserAccess-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let key = P256.Signing.PrivateKey()
            return try .init(
                root: root,
                control: control,
                runtime: SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xAA, count: 32)),
                key: key,
                verifier: CheckUserAccessVerifier(key: key.publicKey),
                space: SpaceURI(authority: SimpleSpaceCheckUserAccessHTTPTests.authority, spaceType: "app.bsky.bookmarks", skey: "access")
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func server() throws -> SwanHTTPServer {
        try .init(
            profile: checkUserAccessProfile(),
            oauthRuntime: runtime,
            simpleSpaceCheckUserAccessConfiguration: .init(
                serviceAuthentication: verifier,
                managingServiceAudience: SimpleSpaceCheckUserAccessHTTPTests.audience
            )
        )
    }

    func token(
        method: String = "com.atproto.managedspace.checkUserAccess",
        audience: String = SimpleSpaceCheckUserAccessHTTPTests.audience,
        now: Date = Date(),
        lifetime: TimeInterval = SpaceServiceJWT.lifetime
    ) throws -> String {
        try SpaceServiceJWT.create(
            issuer: SimpleSpaceCheckUserAccessHTTPTests.authority,
            audience: audience,
            method: method,
            eventID: "check-user-access-event",
            key: key,
            now: now,
            lifetime: lifetime
        )
    }

    func close() async throws { try await control.close() }
    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

private func checkUserAccessProfile() throws -> ProtocolProfile {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    return try ProtocolProfile.load(from: root.appending(path: "Profiles/permissioned-data-0016-2026-10-29.json"))
}

private func checkUserAccessURI(space: SpaceURI, user: String, access: String = "read", clientID: String? = nil) -> String {
    var result = "/xrpc/com.atproto.managedspace.checkUserAccess?space=\(checkUserAccessEncode(space.rawValue))&user=\(checkUserAccessEncode(user))&access=\(checkUserAccessEncode(access))"
    if let clientID { result += "&clientId=\(checkUserAccessEncode(clientID))" }
    return result
}

private func checkUserAccessEncode(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
}

private func bearer(_ token: String) -> HTTPFields {
    var headers = HTTPFields()
    headers[.authorization] = "Bearer \(token)"
    return headers
}

private func checkUserAccessObject(_ buffer: ByteBuffer) throws -> [String: Any] {
    try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer.readableBytesView)) as? [String: Any])
}

private func checkUserAccessError(_ buffer: ByteBuffer) throws -> String {
    try XCTUnwrap(checkUserAccessObject(buffer)["error"] as? String)
}
