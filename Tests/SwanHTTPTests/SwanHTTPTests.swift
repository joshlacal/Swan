import Foundation
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSpacesWire
import SwanSQLite
import SwanStorage
import UnixSignals
import XCTest

final class SwanHTTPTests: XCTestCase {
    func testProfileAndGeneratedWireHaveTheSamePermissionedCoverage() throws {
        let profile = try loadPinnedProfile()
        let generated = PermissionedData0016.methods

        XCTAssertEqual(profile.id, PermissionedData0016.profileID)
        XCTAssertEqual(profile.endpoints.count, 25)
        XCTAssertEqual(profile.endpoints, generated.map(\.nsid))
        XCTAssertEqual(Set(profile.endpoints).count, profile.endpoints.count)
    }

    func testEveryPinnedPermissionedEndpointIsMethodCorrectAndFailClosed() async throws {
        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }

        do {
            let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
            try await app.test(.router) { client in
                for descriptor in PermissionedData0016.methods {
                    let path = "/xrpc/\(descriptor.nsid)"
                    let method = httpMethod(for: descriptor)
                    try await client.execute(uri: path, method: method) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable, "\(method.rawValue) \(path)")
                    }

                    let wrongMethod: HTTPRequest.Method = method == .get ? .post : .get
                    try await client.execute(uri: path, method: wrongMethod) { response in
                        XCTAssertEqual(response.status, .notFound, "\(wrongMethod.rawValue) \(path)")
                    }
                }
            }
            try await controlDatabase.close()
        } catch {
            try? await controlDatabase.close()
            throw error
        }
    }

    func testUnknownPermissionedMethodsAreNotPublicFallbacks() async throws {
        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }

        do {
            let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
            try await app.test(.router) { client in
                let methods: [HTTPRequest.Method] = [
                    .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
                ]
                for path in [
                    "/xrpc/com.atproto.space.unpinnedMethod",
                    "/xrpc/com.atproto.simplespace.unpinnedMethod",
                ] {
                    for method in methods {
                        try await client.execute(uri: path, method: method) { response in
                            XCTAssertEqual(response.status, .notFound, "\(method.rawValue) \(path)")
                        }
                    }
                }
            }
            try await controlDatabase.close()
        } catch {
            try? await controlDatabase.close()
            throw error
        }
    }

    func testHealthDescribeServerAndOAuthRemainIsolated() async throws {
        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }

        do {
            let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
            try await app.test(.router) { client in
                for path in [
                    "/.well-known/oauth-protected-resource",
                    "/.well-known/oauth-authorization-server",
                    "/oauth/authorize",
                ] {
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable)
                    }
                }
                for path in ["/oauth/par", "/oauth/token", "/oauth/revoke"] {
                    try await client.execute(uri: path, method: .post) { response in
                        XCTAssertEqual(response.status, .notFound)
                    }
                }
                for path in ["/health", "/xrpc/com.atproto.server.describeServer", "/v1/accounts"] {
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, path == "/v1/accounts" ? .notFound : .ok)
                    }
                }
            }
            try await controlDatabase.close()
        } catch {
            try? await controlDatabase.close()
            throw error
        }
    }

    func testOAuthMetadataIsReviewableButUnavailableByDefault() async throws {
        let resource = try XCTUnwrap(URL(string: "https://pds.swan.example"))
        let issuer = try XCTUnwrap(URL(string: "https://auth.swan.example"))
        let publication = try OAuthMetadataPublication(resource: resource, issuer: issuer)
        let rendered = try OAuthMetadataRenderer.render(publication.authorizationServer)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: rendered) as? [String: Any])
        XCTAssertEqual(object["issuer"] as? String, issuer.absoluteString)
        XCTAssertEqual(object["authorization_endpoint"] as? String, "https://auth.swan.example/oauth/authorize")
        XCTAssertEqual(object["pushed_authorization_request_endpoint"] as? String, "https://auth.swan.example/oauth/par")
        XCTAssertThrowsError(try OAuthMetadataPublication(resource: resource, issuer: XCTUnwrap(URL(string: "http://auth.swan.example"))))

        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
            try await app.test(.router) { client in
                for path in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"] {
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable)
                    }
                }
            }
            try await controlDatabase.close()
        } catch {
            try? await controlDatabase.close()
            throw error
        }
    }

    func testManagementConfigurationAndPeerPolicyFailClosed() throws {
        XCTAssertThrowsError(try SwanManagementHTTPConfiguration(bindAddressLiteral: "localhost", port: 3001))
        XCTAssertThrowsError(try SwanManagementHTTPConfiguration(bindAddressLiteral: "0.0.0.0", port: 3001))
        XCTAssertThrowsError(try SwanManagementHTTPConfiguration(bindAddressLiteral: "::", port: 3001))
        XCTAssertThrowsError(try SwanManagementHTTPConfiguration(bindAddressLiteral: "127.0.0.1", port: 0))
        XCTAssertNoThrow(try SwanManagementHTTPConfiguration(bindAddressLiteral: "127.0.0.1", port: 3001))
        XCTAssertFalse(SwanManagementPeerPolicy.permits(nil))
        XCTAssertFalse(try SwanManagementPeerPolicy.permits(SocketAddress(ipAddress: "127.0.0.2", port: 1)))
        XCTAssertTrue(try SwanManagementPeerPolicy.permits(SocketAddress(ipAddress: "127.0.0.1", port: 1)))
        XCTAssertTrue(try SwanManagementPeerPolicy.permits(SocketAddress(ipAddress: "::1", port: 1)))
        XCTAssertEqual(SwanHTTPServiceLifecycle.gracefulShutdownSignals, [.sigterm, .sigint])
    }

    func testManagementListenerRequiresBearerAndOnlyReturnsSanitizedViews() async throws {
        let fixture = try await makeManagementServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "SwanManagementHTTPTests"))
            try await app.test(.live) { client in
                try await client.execute(uri: "/v1/accounts?did=\(Self.aliceDID)", method: .get) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
                try await client.execute(
                    uri: "/v1/accounts?did=\(Self.aliceDID)",
                    method: .get,
                    headers: Self.bearerHeaders("wrong-secret")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                var malformedHeaders = HTTPFields()
                malformedHeaders[.authorization] = "Basic operator-secret"
                try await client.execute(
                    uri: "/v1/accounts?did=\(Self.aliceDID)",
                    method: .get,
                    headers: malformedHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(
                    uri: "/v1/accounts?did=\(Self.aliceDID)",
                    method: .get,
                    headers: Self.duplicateBearerHeaders()
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(
                    uri: "/v1/accounts?did=\(Self.aliceDID)",
                    method: .get,
                    headers: Self.bearerHeaders(String(repeating: "a", count: SwanManagementHTTPServer.maximumJSONBytes + 1))
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(
                    uri: "/v1/accounts?did=\(Self.aliceDID)",
                    method: .get,
                    headers: Self.bearerHeaders("operator-secret")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any])
                    XCTAssertTrue(Set(object.keys).isSubset(of: ["canonicalHandle", "createdAt", "did", "export", "status", "tombstone", "updatedAt"]))
                    XCTAssertEqual(object["did"] as? String, Self.aliceDID)
                    XCTAssertEqual(object["canonicalHandle"] as? String, "alice.example.com")
                    XCTAssertEqual(object["status"] as? String, "active")
                    let text = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertFalse(text.contains("argon2"))
                    XCTAssertFalse(text.contains("signingKey"))
                    XCTAssertFalse(text.contains("operator-secret"))
                }
                try await client.execute(
                    uri: "/v1/accounts?did=\(Self.aliceDID)&handle=alice.example.com",
                    method: .get,
                    headers: Self.bearerHeaders("operator-secret")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                try await client.execute(uri: "/v1/accounts", method: .post) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(
                    uri: "/v1/accounts",
                    method: .post,
                    headers: Self.bearerHeaders("operator-secret")
                ) { response in
                    XCTAssertEqual(response.status, .methodNotAllowed)
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testManagementListenerValidatesBodiesAndPreservesLifecyclePolicy() async throws {
        let fixture = try await makeManagementServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let authorization = Self.bearerHeaders("operator-secret")
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "SwanManagementHTTPTests"))
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/v1/accounts/deactivate",
                    method: .post,
                    headers: authorization,
                    body: ByteBuffer(string: #"{"did":"did:plc:abcdefghijklmnopqrstuvwx"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                try await client.execute(
                    uri: "/v1/accounts/deactivate",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: ByteBuffer(string: #"{"did":"did:plc:abcdefghijklmnopqrstuvwx","unexpected":true}"#)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                try await client.execute(
                    uri: "/v1/accounts/deactivate",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: ByteBuffer(string: #"{"did":"did:plc:abcdefghijklmnopqrstuvwx"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(try Self.status(from: response.body), "deactivated")
                }
                try await client.execute(
                    uri: "/v1/accounts/reactivate",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: ByteBuffer(string: #"{"did":"did:plc:abcdefghijklmnopqrstuvwx"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(try Self.status(from: response.body), "active")
                }
                try await client.execute(
                    uri: "/v1/accounts/delete",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: ByteBuffer(string: #"{"did":"did:plc:abcdefghijklmnopqrstuvwx","tombstoneReason":"operator-request","exportReference":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(try Self.status(from: response.body), "deleted")
                }
                try await client.execute(
                    uri: "/v1/accounts/reactivate",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: ByteBuffer(string: #"{"did":"did:plc:abcdefghijklmnopqrstuvwx"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                let oversized = ByteBuffer(string: #"{"did":""# + String(repeating: "a", count: SwanManagementHTTPServer.maximumJSONBytes) + #""}"#)
                try await client.execute(
                    uri: "/v1/accounts/delete",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: oversized
                ) { response in
                    XCTAssertEqual(response.status, .contentTooLarge)
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testManagementPLCProvisioningRoutesAreCapabilityGatedAndNeverPublic() async throws {
        let management = try await makeManagementServer()
        defer { try? FileManager.default.removeItem(at: management.root) }
        do {
            let app = management.server.buildApplication(
                logger: Logger(label: "SwanManagementPLCDisabledTests")
            )
            try await app.test(.live) { client in
                for path in ["/v1/accounts/plc/prepare", "/v1/accounts/plc/activate"] {
                    try await client.execute(
                        uri: path,
                        method: .post,
                        headers: Self.jsonBearerHeaders("operator-secret"),
                        body: ByteBuffer(string: "{}")
                    ) { response in
                        XCTAssertEqual(response.status, .notFound)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    }
                }
            }
            try await management.control.close()
        } catch {
            try? await management.control.close()
            throw error
        }

        let profile = try loadPinnedProfile()
        let (server, control, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let publicApp = server.buildApplication(logger: Logger(label: "SwanPublicRouterPLCIsolation"))
            try await publicApp.test(.router) { client in
                for path in ["/v1/accounts/plc/prepare", "/v1/accounts/plc/activate"] {
                    try await client.execute(
                        uri: path,
                        method: .post,
                        body: ByteBuffer(string: "{}")
                    ) { response in
                        XCTAssertEqual(response.status, .notFound)
                    }
                }
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testManagementPLCProvisioningAuthorizesBeforeDecodeAndValidatesModes() async throws {
        let provisioning = TestManagementPLCProvisioning()
        let fixture = try await makeManagementServer(plcProvisioning: provisioning)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanManagementPLCValidationTests")
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/v1/accounts/plc/activate",
                    method: .post,
                    body: ByteBuffer(string: #"{"password":"secret-body-sentinel"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertFalse(
                        String(decoding: response.body.readableBytesView, as: UTF8.self)
                            .contains("secret-body-sentinel")
                    )
                }

                let invalidBodies = [
                    #"{ "requestId":"r1","handle":"alice.test","pdsOrigin":"https://pds.example/path","repositoryRevision":"3lqby3xuo4k2a","plcOrigin":"http://127.0.0.1:2582","plcLaboratory":true }"#,
                    #"{ "requestId":"r1","handle":"alice.test","pdsOrigin":"https://pds.example","repositoryRevision":"3lqby3xuo4k2a","plcReferenceCompatibility":"did-plc-server-0.0.1" }"#,
                ]
                for body in invalidBodies {
                    try await client.execute(
                        uri: "/v1/accounts/plc/prepare",
                        method: .post,
                        headers: Self.jsonBearerHeaders("operator-secret"),
                        body: ByteBuffer(string: body)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest)
                    }
                }

                let invalidActivations = [
                    #"{ "requestId":"r1","password":"password","plcOrigin":"http://127.0.0.1:2582","plcLaboratory":true }"#,
                    #"{ "requestId":"r1","password":"password","handleLaboratoryOrigin":"http://127.0.0.1:2583" }"#,
                    #"{ "requestId":"r1","password":"password","plcReferenceCompatibility":"did-plc-server-0.0.1" }"#,
                    #"{ "requestId":"r1","password":"bad\u0000password" }"#,
                ]
                for body in invalidActivations {
                    try await client.execute(
                        uri: "/v1/accounts/plc/activate",
                        method: .post,
                        headers: Self.jsonBearerHeaders("operator-secret"),
                        body: ByteBuffer(string: body)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest)
                    }
                }
            }
            let prepareCount = await provisioning.prepareCount
            let activateCount = await provisioning.activateCount
            XCTAssertEqual(prepareCount, 0)
            XCTAssertEqual(activateCount, 0)
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testManagementPLCPrepareActivateAreSanitizedIdempotentAndMapAvailability() async throws {
        let provisioning = TestManagementPLCProvisioning()
        let fixture = try await makeManagementServer(plcProvisioning: provisioning)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let password = "raw-password-MUST-NOT-RENDER-7CE4"
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanManagementPLCSuccessTests")
            )
            try await app.test(.live) { client in
                let prepareBody = ByteBuffer(string:
                    #"{ "requestId":"management-r1","handle":"alice.test","pdsOrigin":"https://pds.example","repositoryRevision":"3lqby3xuo4k2a","plcOrigin":"http://127.0.0.1:2582","plcLaboratory":true,"plcReferenceCompatibility":"did-plc-server-0.0.1" }"#)
                for _ in 0 ..< 2 {
                    try await client.execute(
                        uri: "/v1/accounts/plc/prepare",
                        method: .post,
                        headers: Self.jsonBearerHeaders("operator-secret"),
                        body: prepareBody
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                        let object = try XCTUnwrap(
                            JSONSerialization.jsonObject(with: Data(buffer: response.body))
                                as? [String: Any]
                        )
                        XCTAssertEqual(Set(object.keys), [
                            "requestId", "did", "canonicalHandle", "pdsOrigin",
                            "repositoryRevision", "plcOperationCID",
                            "publicGenesisCommitCID",
                        ])
                        XCTAssertEqual(object["requestId"] as? String, "management-r1")
                    }
                }

                let activateBody = ByteBuffer(string:
                    #"{ "requestId":"management-r1","password":"\#(password)","plcOrigin":"http://127.0.0.1:2582","plcLaboratory":true,"handleLaboratoryOrigin":"http://127.0.0.1:2583" }"#)
                for _ in 0 ..< 2 {
                    try await client.execute(
                        uri: "/v1/accounts/plc/activate",
                        method: .post,
                        headers: Self.jsonBearerHeaders("operator-secret"),
                        body: activateBody
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        let text = String(
                            decoding: response.body.readableBytesView,
                            as: UTF8.self
                        )
                        XCTAssertFalse(text.contains(password))
                        XCTAssertFalse(text.contains("operator-secret"))
                        let object = try XCTUnwrap(
                            JSONSerialization.jsonObject(with: Data(buffer: response.body))
                                as? [String: Any]
                        )
                        XCTAssertEqual(Set(object.keys), [
                            "did", "canonicalHandle", "status",
                            "publicGenesisCommitCID", "publicGenesisRevision",
                            "recovered",
                        ])
                        XCTAssertEqual(object["status"] as? String, "active")
                    }
                }

                await provisioning.setFailure(.unavailable)
                try await client.execute(
                    uri: "/v1/accounts/plc/activate",
                    method: .post,
                    headers: Self.jsonBearerHeaders("operator-secret"),
                    body: activateBody
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    let text = String(
                        decoding: response.body.readableBytesView,
                        as: UTF8.self
                    )
                    XCTAssertFalse(text.contains(password))
                }
            }
            let prepareCount = await provisioning.prepareCount
            let activateCount = await provisioning.activateCount
            XCTAssertEqual(prepareCount, 2)
            XCTAssertEqual(activateCount, 3)
            let storedAccount = try await fixture.control.account(
                did: "did:plc:zyxwvutsrqponmlkjihgfedc"
            )
            XCTAssertNil(storedAccount)
            try await fixture.control.close()

            try Self.assertNoRegularFile(
                under: fixture.root,
                contains: Data(password.utf8)
            )
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    private func loadPinnedProfile() throws -> ProtocolProfile {
        try ProtocolProfile.load(from: packageRoot()
            .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json"))
    }

    private func makeServer(profile: ProtocolProfile) async throws -> (SwanHTTPServer, SQLiteControlDatabase, URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanHTTPTests-\(UUID().uuidString)")
        let controlDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let runtime = try SwanOAuthRuntime(
            controlStore: controlDatabase,
            serverKey: Data(repeating: 0x71, count: 32)
        )
        return (SwanHTTPServer(profile: profile, oauthRuntime: runtime), controlDatabase, root)
    }

    private func makeManagementServer(
        plcProvisioning: (any SwanManagementPLCProvisioning)? = nil
    ) async throws -> (server: SwanManagementHTTPServer, control: SQLiteControlDatabase, root: URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanManagementHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(
                AccountControlRegistration(
                    did: Self.aliceDID,
                    canonicalHandle: "alice.example.com",
                    passwordVerifier: Self.testVerifier,
                    signingKey: AccountControlKeyReference(purpose: .signing, generation: 1),
                    rotationKey: AccountControlKeyReference(purpose: .rotation, generation: 1),
                    createdAt: Date(timeIntervalSince1970: 1_750_000_000)
                )
            )
            let file = root.appending(path: "operator-secret")
            try Data("operator-secret\n".utf8).write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            let verifier = try OperatorSecretResolver.loadVerifier(secretFile: file)
            let configuration = try SwanManagementHTTPConfiguration(bindAddressLiteral: "127.0.0.1", port: 3001)
            return (SwanManagementHTTPServer(
                configuration: configuration,
                controlStore: control,
                operatorSecretVerifier: verifier,
                plcProvisioning: plcProvisioning
            ), control, root)
        } catch {
            try? await control.close()
            throw error
        }
    }

    private static func bearerHeaders(_ token: String) -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "Bearer \(token)"
        return headers
    }

    private static func duplicateBearerHeaders() -> HTTPFields {
        var headers = HTTPFields()
        headers[values: .authorization] = ["Bearer operator-secret", "Bearer operator-secret"]
        return headers
    }

    private static func jsonBearerHeaders(_ token: String) -> HTTPFields {
        var headers = Self.bearerHeaders(token)
        headers[.contentType] = "application/json; charset=utf-8"
        return headers
    }

    private static func status(from buffer: ByteBuffer) throws -> String {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: buffer)) as? [String: Any])
        return try XCTUnwrap(object["status"] as? String)
    }

    private static func assertNoRegularFile(
        under root: URL,
        contains needle: Data
    ) throws {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey]
        ) else {
            XCTFail("unable to inspect management fixture")
            return
        }
        for case let file as URL in enumerator {
            guard try file.resourceValues(forKeys: [.isRegularFileKey])
                .isRegularFile == true else { continue }
            XCTAssertNil(try Data(contentsOf: file).range(of: needle))
        }
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private static let aliceDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let testVerifier = "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
}

private actor TestManagementPLCProvisioning: SwanManagementPLCProvisioning {
    enum Failure {
        case unavailable
    }

    private(set) var prepareCount = 0
    private(set) var activateCount = 0
    private var failure: Failure?

    func setFailure(_ failure: Failure?) {
        self.failure = failure
    }

    func prepare(
        _ input: SwanManagementPLCPrepareInput
    ) async throws -> SwanManagementPLCPrepareResult {
        prepareCount += 1
        if failure != nil { throw PLCAccountPreparationError.unavailable }
        return .init(
            requestId: input.requestID,
            did: "did:plc:zyxwvutsrqponmlkjihgfedc",
            canonicalHandle: input.handle,
            pdsOrigin: input.pdsOrigin.absoluteString,
            repositoryRevision: input.repositoryRevision,
            plcOperationCID: "bafyreihmanagementoperation",
            publicGenesisCommitCID: "bafyreihmanagementgenesis"
        )
    }

    func activate(
        _: SwanManagementPLCActivateInput
    ) async throws -> SwanManagementPLCActivateResult {
        activateCount += 1
        if failure != nil { throw PLCAccountActivationError.unavailable }
        return .init(
            did: "did:plc:zyxwvutsrqponmlkjihgfedc",
            canonicalHandle: "alice.test",
            status: "active",
            publicGenesisCommitCID: "bafyreihmanagementgenesis",
            publicGenesisRevision: "3lqby3xuo4k2a",
            recovered: true
        )
    }
}

private func httpMethod(for descriptor: XRPCMethodDescriptor) -> HTTPRequest.Method {
    switch descriptor.kind {
    case .query, .subscription:
        .get
    case .procedure:
        .post
    }
}
