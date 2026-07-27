import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import XCTest
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

final class SpaceDelegationMintingHTTPTests: XCTestCase, @unchecked Sendable {
    fileprivate static let user = "did:plc:abcdefghijklmnopqrstuvwx"
    fileprivate static let authority = "did:plc:bcdefghijklmnopqrstuvwxy"
    fileprivate static let unknown = "did:plc:cdefghijklmnopqrstuvwxyz"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let path = "/xrpc/com.atproto.space.getDelegationToken"

    func testMintsAndVerifiesShortLivedDelegationsForBroadAndWholeSpaceReadScopes() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "SpaceDelegationMintingHTTPTests.success")
            )
            let verifier = DurableSpaceDelegationVerifier(
                publicKeys: fixture.localDelegationPublicKeys
            )
            let scopes = [
                Set(["atproto"]),
                Set([wholeSpaceReadScope(for: fixture.space)]),
            ]

            try await app.test(.router) { client in
                for (index, scope) in scopes.enumerated() {
                    let access = try await issueToken(
                        runtime: fixture.runtime,
                        subject: Self.user,
                        scopes: scope
                    )
                    let headers = try dpopHeaders(
                        token: access.token,
                        key: access.key,
                        jwk: access.jwk,
                        nonce: fixture.runtime.dpopNonceService.issue(),
                        jti: "delegation-success-\(index)",
                        path: Self.path
                    )
                    try await client.execute(
                        uri: delegationURI(fixture.space),
                        method: .get,
                        headers: headers
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        self.assertNoStore(response)
                        let token = try XCTUnwrap(try self.jsonObject(response.body)["token"] as? String)
                        let inspection = try PermissionedDataJWT.inspectDelegationToken(token)
                        XCTAssertEqual(inspection.header.alg, "ES256")
                        XCTAssertEqual(inspection.header.typ, PermissionedDataJWT.delegationType)
                        XCTAssertEqual(inspection.header.kid, PermissionedDataJWT.delegationKeyID)
                        XCTAssertEqual(inspection.claims.iss, Self.user)
                        XCTAssertEqual(
                            inspection.claims.aud,
                            "\(Self.authority)#atproto_space_host"
                        )
                        XCTAssertEqual(inspection.claims.sub, fixture.space.rawValue)
                        XCTAssertEqual(inspection.claims.exp - inspection.claims.iat, 60)
                        XCTAssertNotNil(UUID(uuidString: inspection.claims.jti))

                        let verified = try await verifier.verifiedDelegation(
                            for: token,
                            expectedSpace: fixture.space,
                            now: Date()
                        )
                        XCTAssertEqual(verified.issuer, Self.user)
                        XCTAssertEqual(verified.space, fixture.space)
                    }
                }
            }
            try await fixture.assertNoPrivateMaterialPersistence()
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testRejectsNarrowForeignAndMalformedScopesBeforeSigning() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "SpaceDelegationMintingHTTPTests.scope")
            )
            let narrowCollection = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read&collection=app.bsky.feed.post"
            let wildcardCollection = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read&collection=*"
            let readSelf = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read_self&collection=app.bsky.feed.post"
            let foreign = "space:\(fixture.space.spaceType)?authority=\(Self.unknown)&skey=\(fixture.space.skey)&action=read"
            let percentDuplicate = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&%61uthority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read"
            for (index, scope) in [narrowCollection, wildcardCollection, readSelf, foreign, percentDuplicate].enumerated() {
                let access = try await issueToken(
                    runtime: fixture.runtime,
                    subject: Self.user,
                    scopes: [scope]
                )
                let headers = try dpopHeaders(
                    token: access.token,
                    key: access.key,
                    jwk: access.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "delegation-denied-scope-\(index)",
                    path: Self.path
                )
                try await app.test(.router) { client in
                    try await client.execute(
                        uri: delegationURI(fixture.space),
                        method: .get,
                        headers: headers
                    ) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                        XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("key"))
                    }
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testQueryDPoPAndLifecycleFailuresStayOpaqueAndDoNotReserveBadProofs() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "SpaceDelegationMintingHTTPTests.boundary")
            )
            let access = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.user,
                scopes: ["atproto"]
            )
            try await app.test(.router) { client in
                for uri in [
                    Self.path,
                    "\(Self.path)?space=at%3A%2F%2Fbad&space=at%3A%2F%2Fbad",
                    "\(Self.path)?space=at%3A%2F%2Fbad&extra=x",
                    "\(Self.path)?space=%ZZ",
                ] {
                    try await client.execute(uri: uri, method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                        XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                    }
                }

                let nonce = fixture.runtime.dpopNonceService.issue()
                let badTarget = try dpopHeaders(
                    token: access.token,
                    key: access.key,
                    jwk: access.jwk,
                    nonce: nonce,
                    jti: "delegation-bad-target",
                    path: "/xrpc/com.atproto.space.getSpace"
                )
                try await client.execute(
                    uri: delegationURI(fixture.space), method: .get, headers: badTarget
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }

                // A proof rejected for its configured htu must not reserve
                // its JTI.  Reusing the same ID on the correct fixed route
                // therefore succeeds once, while the second valid request is
                // the actual replay denial.
                let valid = try dpopHeaders(
                    token: access.token,
                    key: access.key,
                    jwk: access.jwk,
                    nonce: nonce,
                    jti: "delegation-bad-target",
                    path: Self.path
                )
                try await client.execute(
                    uri: delegationURI(fixture.space), method: .get, headers: valid
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                }
                try await client.execute(
                    uri: delegationURI(fixture.space), method: .get, headers: valid
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
            }

            _ = try await fixture.control.transitionStatus(
                did: Self.user,
                to: .deactivated,
                declaration: .init(),
                now: Date()
            )
            let inactive = try dpopHeaders(
                token: access.token,
                key: access.key,
                jwk: access.jwk,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "delegation-inactive",
                path: Self.path
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: delegationURI(fixture.space), method: .get, headers: inactive
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testFailsClosedForUnknownMissingPreopenedDatabaseMissingKeyAndDefaultRoute() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let enabled = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "SpaceDelegationMintingHTTPTests.availability")
            )
            let unknown = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.unknown,
                scopes: ["atproto"]
            )
            try await enabled.test(.router) { client in
                try await client.execute(
                    uri: delegationURI(fixture.space),
                    method: .get,
                    headers: try dpopHeaders(
                        token: unknown.token, key: unknown.key, jwk: unknown.jwk,
                        nonce: fixture.runtime.dpopNonceService.issue(),
                        jti: "delegation-unknown", path: Self.path
                    )
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
            }

            let active = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.user,
                scopes: ["atproto"]
            )
            let accountDatabase = SQLiteLayout.accountDatabase(in: fixture.root, did: Self.user)
            try FileManager.default.removeItem(at: accountDatabase)
            try await enabled.test(.router) { client in
                try await client.execute(
                    uri: delegationURI(fixture.space),
                    method: .get,
                    headers: try dpopHeaders(
                        token: active.token, key: active.key, jwk: active.jwk,
                        nonce: fixture.runtime.dpopNonceService.issue(),
                        jti: "delegation-missing-database", path: Self.path
                    )
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: accountDatabase.path))
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }

        // A separate fixture isolates key removal from the preopened-database
        // check above and proves the encrypted AccountKeyStore, not config,
        // is the final minting dependency.
        let missingKey = try await Fixture.make()
        defer { missingKey.cleanup() }
        do {
            let app = try makeServer(missingKey, enabled: true).buildApplication(
                logger: Logger(label: "SpaceDelegationMintingHTTPTests.key")
            )
            try missingKey.removeSigningEnvelope()
            let access = try await issueToken(
                runtime: missingKey.runtime,
                subject: Self.user,
                scopes: ["atproto"]
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: delegationURI(missingKey.space),
                    method: .get,
                    headers: try dpopHeaders(
                        token: access.token, key: access.key, jwk: access.jwk,
                        nonce: missingKey.runtime.dpopNonceService.issue(),
                        jti: "delegation-missing-key", path: Self.path
                    )
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("private"))
                }
            }
            try await missingKey.close()
        } catch {
            try? await missingKey.close()
            throw error
        }

        let closedFixture = try await Fixture.make()
        defer { closedFixture.cleanup() }
        do {
            let closed = try makeServer(closedFixture, enabled: false).buildApplication(
                logger: Logger(label: "SpaceDelegationMintingHTTPTests.closed")
            )
            try await closed.test(.router) { client in
                try await client.execute(uri: delegationURI(closedFixture.space), method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
                try await client.execute(uri: delegationURI(closedFixture.space), method: .post) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
            }
            try await closedFixture.close()
        } catch {
            try? await closedFixture.close()
            throw error
        }
    }

    private func makeServer(_ fixture: Fixture, enabled: Bool) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.preopenedDirectory,
            accountControlStore: fixture.control,
            spaceDelegationConfiguration: enabled
                ? .init(tokenIssuer: fixture.tokenIssuer)
                : nil
        )
    }

    private func wholeSpaceReadScope(for space: SpaceURI) -> String {
        "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&action=read"
    }

    private func delegationURI(_ space: SpaceURI) -> String {
        "\(Self.path)?space=\(percentEncode(space.rawValue))"
    }

    private func issueToken(
        runtime: SwanOAuthRuntime,
        subject: String,
        scopes: Set<String>
    ) async throws -> AccessTokenMaterial {
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
                    scopes: scopes.union(["atproto"]),
                    dpopBoundAccessTokens: true
                ),
                keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: scopes,
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: jwk.thumbprint(),
                jwtID: "delegation-token-issue-\(UUID().uuidString)",
                issuedAt: now
            ),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(
            subject: subject,
            session: session,
            now: now
        )
        return .init(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func dpopHeaders(
        token: String,
        key: P256.Signing.PrivateKey,
        jwk: OAuthJSONWebKey,
        nonce: String,
        jti: String,
        path: String,
        method: String = "GET"
    ) throws -> HTTPFields {
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
        let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            jti: jti,
            iat: Int64(Date().timeIntervalSince1970),
            htm: method,
            htu: "\(Self.publicURL.absoluteString)\(path)",
            nonce: nonce,
            ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let proof = "\(input).\(try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString())"
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token)"
        headers[HTTPField.Name("DPoP")!] = proof
        return headers
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
        URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }
}

private struct AccessTokenMaterial: Sendable {
    let token: String
    let key: P256.Signing.PrivateKey
    let jwk: OAuthJSONWebKey
}

private struct Fixture: Sendable {
    let root: URL
    let space: SpaceURI
    let control: SQLiteControlDatabase
    let keyStore: FileAccountKeyStore
    let accountDirectory: DurableAccountDirectory
    let preopenedDirectory: SQLitePreMigratedAccountDirectory
    let runtime: SwanOAuthRuntime
    let tokenIssuer: LocalAccountSpaceDelegationTokenIssuer
    let localDelegationPublicKeys: LocalAccountSpaceDelegationPublicKeyResolver
    let signingReference: AccountKeyReference

    static func make() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SpaceDelegationMintingHTTPTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let keyStore = try FileAccountKeyStore(
                root: root.appending(path: "keys"),
                configuration: try AccountKeyEncryptionConfiguration(
                    activeKeyID: "delegation-test-kek",
                    activeKey: Data(repeating: 0xA7, count: 32)
                )
            )
            let keys = try await AccountKeyProvisioner(keyStore: keyStore)
                .provisionInitial(accountDID: SpaceDelegationMintingHTTPTests.user)
            _ = try await control.createAccount(
                try registration(
                    did: SpaceDelegationMintingHTTPTests.user,
                    handle: "delegation-user.example.com",
                    signing: keys.signingReference,
                    rotation: keys.rotationReference
                )
            )
            let accountDatabase = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: SpaceDelegationMintingHTTPTests.user
            )
            try await accountDatabase.close()
            let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let accounts = DurableAccountDirectory(
                store: control,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(
                    hasher: hasher,
                    maximumConcurrentVerifications: 1,
                    maximumQueuedVerifications: 1
                )
            )
            let preopened = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x7C, count: 32)
            )
            return Fixture(
                root: root,
                space: try SpaceURI(
                    authority: SpaceDelegationMintingHTTPTests.authority,
                    spaceType: "app.bsky.bookmarks",
                    skey: "delegation"
                ),
                control: control,
                keyStore: keyStore,
                accountDirectory: accounts,
                preopenedDirectory: preopened,
                runtime: runtime,
                tokenIssuer: LocalAccountSpaceDelegationTokenIssuer(
                    accounts: accounts,
                    keyStore: keyStore
                ),
                localDelegationPublicKeys: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: accounts,
                    publicKeyStore: keyStore
                ),
                signingReference: keys.signingReference
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func removeSigningEnvelope() throws {
        let identity = [
            FileAccountKeyStore.envelopeFormat,
            signingReference.accountDID,
            signingReference.purpose.rawValue,
            String(signingReference.generation),
        ].joined(separator: "\u{0}")
        let filename = "\(Hex.encode(SHA256.hash(data: Data(identity.utf8)))).key"
        let file = root.appending(path: "keys").appending(path: filename)
        guard FileManager.default.fileExists(atPath: file.path) else {
            throw XCTSkip("signing envelope was not installed")
        }
        try FileManager.default.removeItem(at: file)
    }

    func assertNoPrivateMaterialPersistence() async throws {
        let sqliteFiles = Self.sqliteFiles(in: root)
        let signing = try await keyStore.key(for: signingReference)
        for file in sqliteFiles {
            let data = try Data(contentsOf: file)
            XCTAssertNil(data.range(of: signing), "private scalar leaked to \(file.lastPathComponent)")
        }
    }

    func close() async throws {
        try await preopenedDirectory.close()
        try await control.close()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }

    private static func registration(
        did: String,
        handle: String,
        signing: AccountKeyReference,
        rotation: AccountKeyReference
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try .init(purpose: .signing, generation: signing.generation),
            rotationKey: try .init(purpose: .rotation, generation: rotation.generation),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private static func sqliteFiles(in root: URL) -> [URL] {
        let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        return (enumerator?.allObjects as? [URL] ?? []).filter {
            $0.lastPathComponent.contains(".sqlite")
        }
    }
}
