import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
@testable import SwanSpaces
import SwanStorage
import XCTest

/// Shared fixture for the three permissioned-scope suites: the bulleted.app
/// acceptance test (§7.4), the §9-D23 provenance-durability blocker, and the
/// §9-D20 refresh-survival blocker.
///
/// §7.1 says to reuse `LocalhostOAuthBrowserHTTPTests`'s harness rather than
/// inventing a third. Its helpers are `private`, so this file reproduces that
/// shape — same control database, same provisioned account, same runtime, same
/// localhost client construction — in one place all three suites share.
///
/// The one capability added beyond that harness is
/// ``PermissionedScopeFixture/reopeningStorage()``: closing the control database
/// and reopening it from the same directory. §9-D23 turns on a genuine
/// **reload from storage**, and a fixture that keeps one live handle cannot
/// exercise it — an in-memory value that never round-tripped through SQLite
/// would carry provenance the persisted row does not.
struct PermissionedScopeFixture: Sendable {
    let root: URL
    let control: SQLiteControlDatabase
    let runtime: SwanOAuthRuntime
    let authorizer: SwanOAuthResourceAuthorizer
    let accounts: DurableAccountDirectory

    static let issuer = URL(string: "https://swan.example")!
    static let redirectURI = URL(string: "http://127.0.0.1/callback")!
    static let subject = "did:plc:abcdefghijklmnopqrstuvwx"
    static let handle = "alice.swan.test"
    static let password = "correct horse battery staple"
    static let serverKey = Data(repeating: 0xD5, count: 32)

    /// The resolver this fixture's runtime was built with, so a test can change
    /// the documents it serves between mint and refresh — which is the only way
    /// to witness a permission set being *narrowed* by its authority.
    let lexiconResolver: (any SwanLexiconResolving)?

    static func make(
        lexiconResolver: (any SwanLexiconResolving)? = nil
    ) async throws -> PermissionedScopeFixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedScope-\(UUID().uuidString)")
        return try await open(
            root: root, provisionAccount: true, lexiconResolver: lexiconResolver
        )
    }

    /// Closes this fixture's handle and returns a fresh one over the same
    /// on-disk database. Everything a later assertion reads therefore came back
    /// out of SQLite rather than out of the process that wrote it.
    func reopeningStorage() async throws -> PermissionedScopeFixture {
        try await control.close()
        return try await Self.open(
            root: root, provisionAccount: false, lexiconResolver: lexiconResolver
        )
    }

    func tearDown() async {
        try? await control.close()
        try? FileManager.default.removeItem(at: root)
    }

    private static func open(
        root: URL,
        provisionAccount: Bool,
        lexiconResolver: (any SwanLexiconResolving)?
    ) async throws -> PermissionedScopeFixture {
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let directory = DurableAccountDirectory(
                store: control,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher),
                loginAdmissionService: AccountLoginAdmissionService(
                    store: control,
                    key: try AccountLoginAdmissionKey(Data(repeating: 0xD5, count: 32))
                )
            )
            if provisionAccount {
                _ = try await directory.registerProvisionedAccount(
                    did: subject,
                    canonicalHandle: handle,
                    password: password,
                    signingReference: try AccountKeyReference(
                        accountDID: subject, purpose: .signing, generation: 1
                    ),
                    rotationReference: try AccountKeyReference(
                        accountDID: subject, purpose: .rotation, generation: 1
                    )
                )
            }
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: serverKey,
                lexiconResolver: lexiconResolver
            )
            let authorizer = try SwanOAuthResourceAuthorizer(
                publicURL: issuer,
                runtime: runtime,
                accountControlStore: control
            )
            return PermissionedScopeFixture(
                root: root,
                control: control,
                runtime: runtime,
                authorizer: authorizer,
                accounts: directory,
                lexiconResolver: lexiconResolver
            )
        } catch {
            try? await control.close()
            throw error
        }
    }

    /// The HTTP surface, for the stages of §7.4 that must go over the wire:
    /// discovery (Stage 0), PAR (Stage 3), consent (Stage 4) and token mint
    /// (Stage 5). Built from this fixture's own runtime, so a token minted
    /// through the wire is the same durable family the resource-plane assertions
    /// then read back.
    func buildServer() throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: Self.packageRoot()
                .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.issuer),
            oauthRuntime: runtime,
            localhostOAuthConfiguration: try SwanLocalhostOAuthConfiguration(
                issuer: Self.issuer,
                accounts: accounts
            ),
            loginClientIdentityPolicy: SwanLoginClientIdentityPolicy.direct
        )
    }

    /// The **remote** authorization-server surface: `/oauth/par`,
    /// `/oauth/authorize`, `/oauth/authorize/consent`, `/oauth/token`, driven
    /// against a real `https://` client whose metadata document is served to the
    /// AS through a stub resolver and transport.
    ///
    /// §7.4 Stage 2 requires this rather than a localhost virtual client. The
    /// stubs replace only the network — the AS still fetches, parses and
    /// validates the document through `OAuthClientMetadataLoader` exactly as it
    /// would in production, which is the part under test.
    func buildRemoteAuthorizationServer(
        clientMetadata: OAuthClientMetadata,
        scopesSupported: [String] = ["atproto"]
    ) async throws -> SwanHTTPServer {
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let loader = try OAuthClientMetadataLoader(
            fetcher: .init(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: ScopeE2EHostnameResolver(answers: Array(repeating: [peer], count: 64)),
                transport: ScopeE2ERemoteTransport(
                    response: .init(
                        status: 200,
                        headers: ["content-type": ["application/json"]],
                        body: try JSONEncoder().encode(clientMetadata),
                        responseURL: clientMetadata.clientID,
                        connectedPeerAddress: peer
                    )
                )
            ),
            controlStore: control
        )
        let profile = try ProtocolProfile.load(
            from: Self.packageRoot()
                .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.issuer),
            oauthRuntime: runtime,
            authorizationServerConfiguration: try SwanOAuthAuthorizationServerConfiguration(
                issuer: Self.issuer,
                protectedResource: Self.issuer,
                accounts: accounts,
                clientMetadataLoader: loader,
                scopesSupported: scopesSupported
            ),
            loginClientIdentityPolicy: SwanLoginClientIdentityPolicy.direct
        )
    }

    static func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

/// Stub DNS for the client-metadata fetch. Replaces the network, not the
/// admission policy: the loader still applies `OAuthRemoteFetchPolicy` to the
/// answer, so a test cannot accidentally exempt itself from the SSRF fence.
actor ScopeE2EHostnameResolver: OAuthHostnameResolving {
    private let answers: [[OAuthIPAddress]]
    private var index = 0

    init(answers: [[OAuthIPAddress]]) { self.answers = answers }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        guard !answers.isEmpty else { throw SwanError.unavailable("missing test DNS response") }
        defer { index += 1 }
        return answers[min(index, answers.count - 1)]
    }
}

/// Serves the one client-metadata document. Counts requests so a test can assert
/// the AS is not refetching per request.
actor ScopeE2ERemoteTransport: OAuthRemoteTransport {
    private let response: OAuthRemoteHTTPResponse
    private var requests = 0

    init(response: OAuthRemoteHTTPResponse) { self.response = response }

    func get(
        url _: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
        return response
    }

    func requestCount() -> Int { requests }
}

/// A client plus its DPoP key, built around one requested scope set — in either
/// of the two shapes Swan admits.
///
/// **`.remoteHTTPS` is the default for the acceptance test, and the distinction
/// is load-bearing.** §7.4 Stage 2 requires a genuinely remote HTTPS client
/// (`https://bulleted.app/client-metadata.json`), because that is the shape that
/// fails hardest today: `OAuthClientMetadata.swift:343-344` gates the issuable
/// disjunct behind `isLocalhostDevelopmentClient &&`, so a remote client can
/// carry only bare `atproto`. A localhost fixture would sail through every stage
/// while proving nothing about the change under test.
///
/// `.localhostBridge` exists for the two places that genuinely require it:
/// §9-D20's binding comparison lives on `redeemLocalhostPublicRefresh`
/// (`DurableOAuthTokenService.swift:770`), and §7.4 S4.5's *second* consent
/// renderer is `SwanLocalhostOAuthHTTP.consentPage`.
struct PermissionedScopeClient: Sendable {
    enum Kind: Sendable {
        /// `https://bulleted.app/client-metadata.json`, served to the AS through
        /// a stub resolver + transport. Not a virtual client.
        case remoteHTTPS
        /// `http://localhost?scope=…`, the development bridge.
        case localhostBridge
    }

    let kind: Kind
    let clientID: URL
    let redirectURI: URL
    let scopes: [String]
    let signingKey: P256.Signing.PrivateKey
    let jwk: OAuthJSONWebKey

    static let remoteClientID = URL(string: "https://bulleted.app/client-metadata.json")!
    static let remoteRedirectURI = URL(string: "https://bulleted.app/callback")!

    init(scopes: [String], kind: Kind = .remoteHTTPS) throws {
        self.scopes = scopes
        self.kind = kind
        signingKey = P256.Signing.PrivateKey()
        jwk = try OAuthJSONWebKey.from(signingKey)
        switch kind {
        case .remoteHTTPS:
            clientID = Self.remoteClientID
            redirectURI = Self.remoteRedirectURI
        case .localhostBridge:
            redirectURI = PermissionedScopeFixture.redirectURI
            let scopeParameter = scopes.joined(separator: " ")
            clientID = try XCTUnwrap(
                URL(
                    // `%20`, NOT `+`, for the separator between scopes.
                    // `localhostDevelopmentMetadata` reads the scope through
                    // `URLComponents.queryItems` (`OAuthClientMetadata.swift:265`,
                    // `:298`), and Foundation does **not** fold `+` to SPACE
                    // there. A `+`-joined multi-scope client id therefore
                    // registers as ONE mangled token and every request against it
                    // fails "requested scope is not registered" — a harness
                    // artefact that looks exactly like a real subset-check bug.
                    // Single-scope clients never hit it, which is why it stayed
                    // hidden until a two-scope fixture.
                    string: "http://localhost?scope=\(scopeQueryEncode(scopeParameter))"
                        + "&redirect_uri=\(scopeFormEncode(PermissionedScopeFixture.redirectURI.absoluteString))"
                )
            )
        }
    }

    var scopeSet: Set<String> { Set(scopes) }

    func metadata() throws -> OAuthClientMetadata {
        switch kind {
        case .remoteHTTPS:
            // A public client: no JWKS, so `confidentialClientKey` is nil and the
            // token exchange needs no client assertion. That is the shape
            // bulleted.app actually ships.
            try OAuthClientMetadata(
                clientID: Self.remoteClientID,
                redirectURIs: [Self.remoteRedirectURI],
                grantTypes: ["authorization_code", "refresh_token"],
                responseTypes: ["code"],
                scopes: scopeSet,
                dpopBoundAccessTokens: true
            )
        case .localhostBridge:
            try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        }
    }

    func session(proofID: String, now: Date = Date()) throws -> OAuthValidatedSession {
        try OAuthValidatedSession(
            issuer: PermissionedScopeFixture.issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: try metadata(), keySet: nil),
            redirectURI: redirectURI,
            scopes: scopeSet,
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: jwk.thumbprint(),
                jwtID: proofID,
                issuedAt: now
            ),
            now: now
        )
    }
}

extension PermissionedScopeFixture {
    /// Mints a token family through the real authorization-code path, so the
    /// grant that lands in `oauth_control_token_families` went through the same
    /// `self`-resolution and persistence Swan performs in production (§6.4,
    /// §6.7). Returns the issued pair.
    func mint(
        client: PermissionedScopeClient,
        proofID: String,
        now: Date = Date()
    ) async throws -> OAuthTokenGrantResult {
        let verifier = "swan-permissioned-scope-verifier-\(UUID().uuidString.prefix(16))"
        let session = try client.session(proofID: proofID, now: now)
        let code = try await runtime.tokenService.issueAuthorizationCode(
            subject: Self.subject,
            session: session,
            codeChallengeS256: Data(SHA256.hash(data: Data(verifier.utf8)))
                .base64URLEncodedString(),
            now: now
        )
        return try await runtime.tokenService.redeemAuthorizationCodeForClient(
            code,
            verifier: verifier,
            redirectURI: client.redirectURI,
            authorizationServerIssuer: Self.issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: try client.metadata(), keySet: nil),
            dpopProof: session.dpopProof,
            clientAssertion: nil,
            now: now
        )
    }

    /// Drives a real resource request through
    /// `SwanOAuthResourceAuthorizer.authorize` — §7.4 Stage 6's "the single
    /// point where a validated scope set reaches a handler" — and returns the
    /// resulting `AuthorizationContext`.
    ///
    /// Enforcement assertions must go through this rather than re-deriving a
    /// `SwanScopePermissions` in the test: re-deriving is precisely the step that
    /// would reconstruct provenance from the persisted string and hide the
    /// §9-D23 defect.
    func authorizeResourceRequest(
        accessToken: String,
        client: PermissionedScopeClient,
        jti: String,
        fixedPath: String = "/xrpc/com.atproto.space.getDelegationToken",
        method: String = "GET",
        now: Date = Date()
    ) async throws -> AuthorizationContext {
        let nonce = runtime.dpopNonceService.issue(now: now)
        let proof = try makeScopeDPoPProof(
            key: client.signingKey,
            jwk: client.jwk,
            jti: jti,
            nonce: nonce,
            method: method,
            target: Self.issuer.appending(path: fixedPath.dropFirst()).absoluteString,
            accessToken: accessToken,
            now: now
        )
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(accessToken)"
        headers[HTTPField.Name("DPoP")!] = proof
        let request = Request(
            head: HTTPRequest(
                method: method == "GET" ? .get : .post,
                scheme: "https",
                authority: "swan.example",
                path: fixedPath,
                headerFields: headers
            ),
            body: .init(buffer: ByteBuffer())
        )
        return try await authorizer.authorize(
            request: request,
            method: method,
            fixedPath: fixedPath,
            now: now
        )
    }

    /// The permissions value the resource plane built for this token. Fails the
    /// test if the boundary produced anything other than an account OAuth
    /// context, since every enforcement assertion depends on that shape.
    func permissions(
        accessToken: String,
        client: PermissionedScopeClient,
        jti: String,
        now: Date = Date(),
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws -> SwanScopePermissions {
        let context = try await authorizeResourceRequest(
            accessToken: accessToken,
            client: client,
            jti: jti,
            now: now
        )
        guard case let .accountOAuth(_, permissions) = context else {
            XCTFail("expected an account OAuth context, got \(context)", file: file, line: line)
            throw SwanResourceAuthorizationFailure.denied
        }
        return permissions
    }
}

// MARK: - Shared helpers

/// Percent-encodes for a URL **query component** read back by
/// `URLComponents.queryItems`: SPACE becomes `%20`, never `+`. Distinct from
/// `scopeFormEncode`, which is `application/x-www-form-urlencoded` for request
/// BODIES. The two differ on exactly one byte and confusing them is silent.
func scopeQueryEncode(_ value: String) -> String {
    value.utf8.map { byte in
        switch byte {
        case 65 ... 90, 97 ... 122, 48 ... 57, 45, 46, 95, 126:
            String(UnicodeScalar(byte))
        default:
            String(format: "%%%02X", byte)
        }
    }.joined()
}

func scopeFormEncode(_ value: String) -> String {
    value.utf8.map { byte in
        switch byte {
        case 65 ... 90, 97 ... 122, 48 ... 57, 45, 46, 95, 126:
            String(UnicodeScalar(byte))
        case 32:
            "+"
        default:
            String(format: "%%%02X", byte)
        }
    }.joined()
}

func makeScopeDPoPProof(
    key: P256.Signing.PrivateKey,
    jwk: OAuthJSONWebKey,
    jti: String,
    nonce: String,
    method: String,
    target: String,
    accessToken: String? = nil,
    now: Date = Date()
) throws -> String {
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
        let ath: String?
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
    let claims = try encoder.encode(
        Claims(
            jti: jti,
            iat: Int64(now.timeIntervalSince1970),
            htm: method,
            htu: target,
            nonce: nonce,
            ath: accessToken.map { Data(SHA256.hash(data: Data($0.utf8))).base64URLEncodedString() }
        )
    ).base64URLEncodedString()
    let input = "\(header).\(claims)"
    return "\(input).\(try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString())"
}

extension OAuthJSONWebKey {
    static func from(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey {
        let representation = key.publicKey.x963Representation
        return try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
    }
}

/// bulleted.app's five real scopes (§1, §7.4). Mirrors the `BulletedAppScopes`
/// declared in `SwanOAuthTests`; the two targets cannot share a type, so the
/// acceptance test asserts its `space:` canonical form against the golden corpus
/// rather than against this constant.
enum BulletedApp {
    static let base = "atproto"
    static let includeAuthFull = "include:app.bulleted.authFull"
    static let blobImages = "blob:image/*"
    static let includeSpaceAccess = "include:app.bulleted.spaceAccess"
    static let space =
        "space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self"

    static let all = [base, includeAuthFull, blobImages, includeSpaceAccess, space]

    /// `action` precedes `manage` by schema declaration order, and `manage`
    /// follows `SPACE_MANAGE_OPS` canonical order — not input order (§7.4 Stage 1).
    static let canonicalSpace =
        "space:app.bulleted.space?action=read_self&manage=create&manage=update&manage=delete"

    static let spaceType = "app.bulleted.space"
    static let includeNSIDs = ["app.bulleted.authFull", "app.bulleted.spaceAccess"]
}
