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

final class GetSpaceHTTPTests: XCTestCase, @unchecked Sendable {
    private static let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let otherAuthority = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let privateMember = "did:plc:cdefghijklmnopqrstuvwxyz"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let path = "/xrpc/com.atproto.space.getSpace"

    func testAuthenticatedAuthorityGetsOnlyGeneratedSpaceDescriptionUsingConfiguredDPoPTarget() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let server = try makeServer(fixture: fixture)
            let now = Date()
            let proof = try issueProof(
                fixture: fixture,
                subject: Self.authority,
                nonce: fixture.runtime.dpopNonceService.issue(now: now),
                jti: "get-space-success",
                now: now
            )
            var mutableHeaders = authorizationHeaders(token: fixture.authorityToken, proof: proof)
            // The authorizer must not derive DPoP htu from this hostile header
            // or the query-bearing request target below.
            mutableHeaders[HTTPField.Name("Host")!] = "attacker.invalid"
            let headers = mutableHeaders
            let encodedSpace = percentEncode(fixture.space.rawValue)

            let app = server.buildApplication(logger: Logger(label: "GetSpaceHTTPTests.success"))
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "\(Self.path)?space=\(encodedSpace)",
                    method: .get,
                    headers: headers
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                    let object = try self.jsonObject(response.body)
                    XCTAssertEqual(Set(object.keys), ["uri", "config"])
                    XCTAssertEqual(object["uri"] as? String, fixture.space.rawValue)
                    let config = try XCTUnwrap(object["config"] as? [String: Any])
                    XCTAssertEqual(config["$type"] as? String, "com.atproto.simplespace.defs#spaceConfig")
                    XCTAssertEqual(config["policy"] as? String, "member-list")
                    XCTAssertNil(config["managingApp"])
                    let appAccess = try XCTUnwrap(config["appAccess"] as? [String: Any])
                    XCTAssertEqual(appAccess["$type"] as? String, "com.atproto.simplespace.defs#allowList")
                    XCTAssertEqual(appAccess["allowed"] as? [String], ["https://reader.example", "https://writer.example"])

                    let rendered = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertFalse(rendered.contains(Self.privateMember))
                    XCTAssertFalse(rendered.contains("owner"))
                    XCTAssertFalse(rendered.contains("revision"))
                    XCTAssertFalse(rendered.contains("deleted"))
                }
            }
            try await fixture.directory.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.directory.close()
            try? await fixture.control.close()
            throw error
        }
    }

    func testGetSpaceRejectsMalformedQueriesBeforeAuthentication() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture: fixture)
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.query"))
            let valid = percentEncode(fixture.space.rawValue)
            let invalidQueries = [
                "",
                "other=\(valid)",
                "space=\(valid)&space=\(valid)",
                "space=\(valid)&other=value",
                "space=%",
                "space=%GG",
                "space=%00",
                "space=not-an-at-uri",
            ]
            try await app.test(.router) { client in
                for query in invalidQueries {
                    let suffix = query.isEmpty ? "" : "?\(query)"
                    try await client.execute(uri: "\(Self.path)\(suffix)", method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest, query)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                        XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                    }
                }
            }
            try await fixture.directory.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.directory.close()
            try? await fixture.control.close()
            throw error
        }
    }

    func testGetSpaceRequiresAuthorityBoundDPoPAndDoesNotExposeExistenceToAnotherAccount() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture: fixture)
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.auth"))
            let uri = "\(Self.path)?space=\(percentEncode(fixture.space.rawValue))"
            let missingProof = authorizationHeaders(token: fixture.authorityToken)
            let malformedProof = authorizationHeaders(token: fixture.authorityToken, proof: "not-a-compact-jwt")
            let validAuthority = try signedHeaders(
                fixture: fixture,
                subject: Self.authority,
                jti: "get-space-replay"
            )
            let wrongAuthority = try signedHeaders(
                fixture: fixture,
                subject: Self.otherAuthority,
                jti: "get-space-wrong-authority"
            )

            try await app.test(.router) { client in
                for headers in [missingProof, malformedProof] {
                    try await client.execute(uri: uri, method: .get, headers: headers) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(response.headers[.wwwAuthenticate], "DPoP error=\"use_dpop_nonce\"")
                        XCTAssertNotNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                        XCTAssertEqual(try self.errorCode(response.body), "use_dpop_nonce")
                    }
                }
                try await client.execute(uri: uri, method: .get, headers: validAuthority) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                }
                // A verified replay is generic denial rather than another
                // challenge, and cannot cause another directory lookup.
                try await client.execute(uri: uri, method: .get, headers: validAuthority) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                try await client.execute(uri: uri, method: .get, headers: wrongAuthority) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
            }
            try await fixture.directory.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.directory.close()
            try? await fixture.control.close()
            throw error
        }
    }

    func testGetSpaceFailsClosedForAccountLifecycleAndAbsentOrDeletedSpaces() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let deletedFixture = try await makeFixture(spaceDeleted: true)
        defer { try? FileManager.default.removeItem(at: deletedFixture.root) }
        do {
            let app = try makeServer(fixture: fixture)
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.absent"))
            let missing = try SpaceURI(
                authority: Self.authority,
                spaceType: "app.bsky.bookmarks",
                skey: "missing"
            )
            let missingHeaders = try signedHeaders(fixture: fixture, subject: Self.authority, jti: "get-space-missing")
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "\(Self.path)?space=\(self.percentEncode(missing.rawValue))",
                    method: .get,
                    headers: missingHeaders
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
            }

            _ = try await fixture.control.transitionStatus(
                did: Self.authority,
                to: .deactivated,
                declaration: .init(),
                now: Date()
            )
            let inactiveHeaders = try signedHeaders(fixture: fixture, subject: Self.authority, jti: "get-space-inactive")
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "\(Self.path)?space=\(self.percentEncode(fixture.space.rawValue))",
                    method: .get,
                    headers: inactiveHeaders
                ) { response in
                    // Lifecycle denial happens in the resource authorizer,
                    // before any account database is selected.
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
            }

            let deletedApp = try makeServer(fixture: deletedFixture)
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.deleted"))
            let deletedHeaders = try signedHeaders(fixture: deletedFixture, subject: Self.authority, jti: "get-space-deleted")
            try await deletedApp.test(.router) { client in
                try await client.execute(
                    uri: "\(Self.path)?space=\(self.percentEncode(deletedFixture.space.rawValue))",
                    method: .get,
                    headers: deletedHeaders
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
            }
            try await fixture.directory.close()
            try await fixture.control.close()
            try await deletedFixture.directory.close()
            try await deletedFixture.control.close()
        } catch {
            try? await fixture.directory.close()
            try? await fixture.control.close()
            try? await deletedFixture.directory.close()
            try? await deletedFixture.control.close()
            throw error
        }
    }

    func testGetSpaceMapsDirectoryFailuresWithoutDisclosureAndStaysClosedByDefault() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let uri = "\(Self.path)?space=\(percentEncode(fixture.space.rawValue))"
            let deniedHeaders = try signedHeaders(fixture: fixture, subject: Self.authority, jti: "get-space-directory-denied")
            let deniedApp = try makeServer(fixture: fixture, directory: TestDirectory.failure(.denied))
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.directory-denied"))
            try await deniedApp.test(.router) { client in
                try await client.execute(uri: uri, method: .get, headers: deniedHeaders) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                try await client.execute(uri: uri, method: .post) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
            }

            let unavailableHeaders = try signedHeaders(fixture: fixture, subject: Self.authority, jti: "get-space-directory-unavailable")
            let unavailableApp = try makeServer(fixture: fixture, directory: TestDirectory.failure(.unavailable))
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.directory-unavailable"))
            try await unavailableApp.test(.router) { client in
                try await client.execute(uri: uri, method: .get, headers: unavailableHeaders) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }

            let mismatchedHeaders = try signedHeaders(fixture: fixture, subject: Self.authority, jti: "get-space-directory-mismatched")
            let mismatchedApp = try makeServer(fixture: fixture, directory: TestDirectory.failure(.mismatched))
                .buildApplication(logger: Logger(label: "GetSpaceHTTPTests.directory-mismatched"))
            try await mismatchedApp.test(.router) { client in
                try await client.execute(uri: uri, method: .get, headers: mismatchedHeaders) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }

            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
            )
            let closedServer = SwanHTTPServer(
                profile: profile,
                configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
                oauthRuntime: fixture.runtime
            )
            let closedApp = closedServer.buildApplication(logger: Logger(label: "GetSpaceHTTPTests.closed"))
            try await closedApp.test(.router) { client in
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
                try await client.execute(uri: uri, method: .post) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }

            // A remote cleartext resource URL cannot receive the opt-in
            // handler, even if an active-directory capability is supplied.
            let cleartextServer = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "0.0.0.0",
                    port: 3_000,
                    publicURL: URL(string: "http://swan.example")!
                ),
                oauthRuntime: fixture.runtime,
                authenticatedGetSpaceDirectory: fixture.directory,
                accountControlStore: fixture.control
            )
            let cleartextApp = cleartextServer.buildApplication(logger: Logger(label: "GetSpaceHTTPTests.cleartext"))
            try await cleartextApp.test(.router) { client in
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
            }

            // A loopback public URL is insufficient if Hummingbird itself is
            // exposed on a non-loopback bind address.
            let loopbackIdentityRemoteBindServer = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "0.0.0.0",
                    port: 3_000,
                    publicURL: URL(string: "http://127.0.0.1:3000")!
                ),
                oauthRuntime: fixture.runtime,
                authenticatedGetSpaceDirectory: fixture.directory,
                accountControlStore: fixture.control
            )
            let loopbackIdentityRemoteBindApp = loopbackIdentityRemoteBindServer.buildApplication(
                logger: Logger(label: "GetSpaceHTTPTests.loopback-identity-remote-bind")
            )
            try await loopbackIdentityRemoteBindApp.test(.router) { client in
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
            }
            try await fixture.directory.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.directory.close()
            try? await fixture.control.close()
            throw error
        }
    }

    private func makeFixture(spaceDeleted: Bool = false) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "GetSpaceHTTPTests-\(UUID().uuidString)")
        let space = try SpaceURI(
            authority: Self.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "authenticated-http"
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(registration(did: Self.authority, handle: "alice.example.com"))
            _ = try await control.createAccount(registration(did: Self.otherAuthority, handle: "bob.example.com"))
            try await installAuthorityDatabase(root: root, space: space, spaceDeleted: spaceDeleted)
            try await installEmptyAccountDatabase(root: root, did: Self.otherAuthority)
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0xC9, count: 32)
            )
            let authorityToken = try await issueToken(
                runtime: runtime,
                subject: Self.authority
            )
            let otherToken = try await issueToken(
                runtime: runtime,
                subject: Self.otherAuthority
            )
            let authorizer = try SwanOAuthResourceAuthorizer(
                publicURL: Self.publicURL,
                runtime: runtime,
                accountControlStore: control
            )
            return Fixture(
                root: root,
                space: space,
                control: control,
                directory: directory,
                runtime: runtime,
                authorizer: authorizer,
                authorityToken: authorityToken.token,
                authorityKey: authorityToken.key,
                authorityJWK: authorityToken.jwk,
                otherToken: otherToken.token,
                otherKey: otherToken.key,
                otherJWK: otherToken.jwk
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func makeServer(
        fixture: Fixture,
        directory: (any AuthorizedSimpleSpaceDirectory)? = nil
    ) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: directory ?? fixture.directory,
            accountControlStore: fixture.control
        )
    }

    private func installAuthorityDatabase(
        root: URL,
        space: SpaceURI,
        spaceDeleted: Bool
    ) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: Self.authority)
        do {
            let authority = try DurableSimpleSpaceAuthority(
                database: database,
                credentialSecret: Data(repeating: 0xA9, count: 32)
            )
            let authorization: AuthorizationContext = .accountOAuth(
                subject: Self.authority,
                scopes: ["atproto"]
            )
            _ = try await authority.create(
                space: space,
                owner: Self.authority,
                configuration: try SimpleSpaceConfiguration(
                    policy: .memberList,
                    appAccess: .allowList(["https://writer.example", "https://reader.example"])
                ),
                authorization: authorization
            )
            _ = try await authority.addMember(
                space: space,
                member: Self.privateMember,
                authorization: authorization
            )
            if spaceDeleted {
                _ = try await authority.delete(space: space, authorization: authorization)
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func installEmptyAccountDatabase(root: URL, did: String) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        try await database.close()
    }

    private func issueToken(runtime: SwanOAuthRuntime, subject: String) async throws -> TokenMaterial {
        let key = P256.Signing.PrivateKey()
        let jwk = try makeJWK(key)
        let now = Date()
        let session = try OAuthValidatedSession(
            issuer: Self.publicURL.absoluteString,
            client: OAuthResolvedClientMetadata(
                metadata: try OAuthClientMetadata(
                    clientID: URL(string: "https://client.example/metadata")!,
                    redirectURIs: [URL(string: "https://client.example/callback")!],
                    grantTypes: ["authorization_code", "refresh_token"],
                    responseTypes: ["code"],
                    scopes: ["atproto"],
                    dpopBoundAccessTokens: true
                ),
                keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: ["atproto"],
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: jwk.thumbprint(),
                jwtID: "get-space-issue-\(UUID().uuidString)",
                issuedAt: now
            ),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(subject: subject, session: session, now: now)
        return TokenMaterial(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func issueProof(
        fixture: Fixture,
        subject: String,
        nonce: String,
        jti: String,
        now: Date
    ) throws -> String {
        let material = if subject == Self.authority {
            TokenMaterial(token: fixture.authorityToken, key: fixture.authorityKey, jwk: fixture.authorityJWK)
        } else {
            TokenMaterial(token: fixture.otherToken, key: fixture.otherKey, jwk: fixture.otherJWK)
        }
        struct Header: Encodable {
            let alg = "ES256"
            let typ = OAuthDPoPProofValidator.proofType
            let jwk: OAuthJSONWebKey
        }
        struct Claims: Encodable {
            let jti: String
            let iat: Int64
            let htm: String
            let htu: String
            let nonce: String
            let ath: String
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: material.jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            jti: jti,
            iat: Int64(now.timeIntervalSince1970),
            htm: "GET",
            htu: "https://swan.example\(Self.path)",
            nonce: nonce,
            ath: Data(SHA256.hash(data: Data(material.token.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let signingInput = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(signingInput.utf8), using: material.key)
            .base64URLEncodedString()
        return "\(signingInput).\(signature)"
    }

    private func authorizationHeaders(token: String, proof: String? = nil) -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token)"
        if let proof { headers[HTTPField.Name("DPoP")!] = proof }
        return headers
    }

    private func signedHeaders(
        fixture: Fixture,
        subject: String,
        jti: String
    ) throws -> HTTPFields {
        let now = Date()
        return authorizationHeaders(
            token: subject == Self.authority ? fixture.authorityToken : fixture.otherToken,
            proof: try issueProof(
                fixture: fixture,
                subject: subject,
                nonce: fixture.runtime.dpopNonceService.issue(now: now),
                jti: jti,
                now: now
            )
        )
    }

    private func registration(did: String, handle: String) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func makeJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey {
        let representation = key.publicKey.x963Representation
        return try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
    }

    private func percentEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func jsonObject(_ body: ByteBuffer) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
    }

    private func errorCode(_ body: ByteBuffer) throws -> String {
        try XCTUnwrap(jsonObject(body)["error"] as? String)
    }

    private func assertNoStore(
        _ response: TestResponse,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private struct TokenMaterial: Sendable {
    let token: String
    let key: P256.Signing.PrivateKey
    let jwk: OAuthJSONWebKey
}

private struct Fixture: Sendable {
    let root: URL
    let space: SpaceURI
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let runtime: SwanOAuthRuntime
    let authorizer: SwanOAuthResourceAuthorizer
    let authorityToken: String
    let authorityKey: P256.Signing.PrivateKey
    let authorityJWK: OAuthJSONWebKey
    let otherToken: String
    let otherKey: P256.Signing.PrivateKey
    let otherJWK: OAuthJSONWebKey
}

private struct TestDirectory: AuthorizedSimpleSpaceDirectory {
    enum Failure: Sendable {
        case denied
        case unavailable
        case mismatched
    }

    let failure: Failure

    static func failure(_ failure: Failure) -> TestDirectory {
        TestDirectory(failure: failure)
    }

    func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? {
        switch failure {
        case .denied:
            throw SwanError.unauthorized("test directory denial")
        case .unavailable:
            throw SwanError.unavailable("test directory unavailable")
        case .mismatched:
            let otherSpace = try SpaceURI(
                authority: "did:plc:bcdefghijklmnopqrstuvwxy",
                spaceType: space.spaceType,
                skey: "wrong-space"
            )
            return AuthenticatedSimpleSpaceDescription(
                space: otherSpace,
                configuration: try SimpleSpaceConfiguration(policy: .public, appAccess: .open)
            )
        }
    }

    func close() async throws {}
}
