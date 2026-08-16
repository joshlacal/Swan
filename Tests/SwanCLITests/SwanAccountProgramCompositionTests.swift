import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import SwanAccounts
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanPublicFirehose
import SwanSQLite
import SwanSpaces
import SwanStorage
@testable import swan
import XCTest

/// Task 1 of the Swan account-program runtime integration: freeze the
/// production-composition contract in red tests.
///
/// Every server here is constructed through `SwanHTTPServer` — the type
/// `swan serve` builds via `ServePermissionedRuntime.makeServer` — with the
/// same argument kinds the CLI passes (profile, configuration, oauthRuntime,
/// accountControlStore, directory, portal, pipethrough, firehose). The lane
/// adapters are never constructed directly; the portal service and proxy
/// transport are test doubles because their production facades are later
/// tasks (T5 portal facade, T4 legacy sessions, T3 signup).
final class SwanAccountProgramCompositionTests: XCTestCase, @unchecked Sendable {
    // MARK: - Route precedence through the production router

    /// The portal owns `/account/**` and is installed before every XRPC or
    /// proxy fallback. It must serve the compiled bundle without shadowing
    /// the portal's own API routes, `/xrpc/*`, health, discovery, OAuth, or
    /// the WebSocket route.
    func testPortalServesCompiledBundleWithoutShadowingAPIXRPCHealthDiscoveryOAuthOrWebSockets() async throws {
        let fixture = try await makeServer(signupPolicy: .openProtected, installFirehose: true)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.routes")
            )
            try await app.test(.router) { client in
                // The compiled bundle is served at /account/ and /account.
                for uri in ["/account/", "/account"] {
                    try await client.execute(uri: uri, method: .get) { response in
                        XCTAssertEqual(response.status, .ok, uri)
                        XCTAssertTrue(
                            response.headers[.contentType]?.hasPrefix("text/html") == true,
                            uri
                        )
                        let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                        XCTAssertTrue(body.contains("<!doctype html>"), uri)
                    }
                }
                // The portal's API routes beat the SPA fallback: bootstrap is
                // JSON, never the shell.
                try await client.execute(uri: "/account/api/bootstrap", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("\"csrf\""))
                }
                // The policy endpoint advertises the configured policy.
                try await client.execute(uri: "/account/api/signup/policy", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("openProtected"))
                }
                // Unknown API paths are a JSON 404, never the SPA shell.
                try await client.execute(uri: "/account/api/unknown/deep", method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                }
                // /xrpc/* is untouched by the portal: describeServer still
                // answers with the profile.
                try await client.execute(uri: "/xrpc/com.atproto.server.describeServer", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Health and discovery still answer.
                try await client.execute(uri: "/health", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "/.well-known/did.json", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // OAuth is closed but present, never shadowed by the portal.
                try await client.execute(uri: "/oauth/authorize", method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
                try await client.execute(uri: "/.well-known/oauth-protected-resource", method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
                // The WebSocket route keeps its own shape: a plain GET is 405.
                try await client.execute(uri: "/xrpc/com.atproto.sync.subscribeRepos", method: .get) { response in
                    XCTAssertEqual(response.status, .methodNotAllowed)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    // MARK: - Credential isolation

    /// `createSession` and `createAccount` carry credentials. Until their
    /// durable services are assembled (later tasks), they must remain a
    /// stable local refusal — never forwarded to a service the client names
    /// in `atproto-proxy`, even when the proxy authorizer would admit the
    /// request and the attacker's DID document resolves.
    func testCreateSessionAndCreateAccountAreStableLocalRefusalsNeverProxied() async throws {
        let fixture = try await makeServer(signupPolicy: .openProtected, installPipethrough: true)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.credentials")
            )
            try await app.test(.router) { client in
                var steered = HTTPFields()
                steered[.contentType] = "application/json"
                steered[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                // createSession carries a password; it must never leave this host.
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"identifier":"alice.test","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
                // createAccount carries signup credentials; likewise local-only.
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            // Nothing left the host: the sender was never consulted, even
            // though the authorizer would have admitted the request.
            XCTAssertEqual(fixture.sender.recorded().count, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The assembled-state expectation: once the durable services are wired
    /// (later tasks), these routes answer locally with a real status — never
    /// a bare 404. RED until then: both are 404 today.
    func testCreateSessionAndCreateAccountAnswerLocallyOnceAssembled() async throws {
        let fixture = try await makeServer(signupPolicy: .openProtected, installPipethrough: true)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.assembled")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"identifier":"alice.test","password":"hunter2"}"#)
                ) { response in
                    XCTAssertNotEqual(response.status, .notFound)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertNotEqual(response.status, .notFound)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    // MARK: - Configuration truth (the red assertion)

    /// `describeServer.inviteCodeRequired` must be derived from the same
    /// `SignupPolicy` that governs signup admission. The portal advertises
    /// the policy truthfully; the server's describeServer must agree.
    ///
    /// Today `swan serve` never sets `SwanHTTPConfiguration.inviteCodeRequired`
    /// from policy, so this is RED: the factory mirrors the CLI's current
    /// construction (configuration default `false`), and the assertion
    /// `inviteCodeRequired == policy.advertisesInviteCodeRequired` fails.
    /// Once the CLI derives the configuration value from the same policy
    /// (and the factory mirror follows), the test goes green.
    func testDescribeServerInviteCodeRequiredIsDerivedFromSignupPolicy() async throws {
        let policy = SignupPolicy.inviteRequired
        let fixture = try await makeServer(signupPolicy: policy)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.invite")
            )
            try await app.test(.router) { client in
                // The portal itself advertises the policy truthfully.
                try await client.execute(uri: "/account/api/signup/policy", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("\"inviteCodeRequired\":true"))
                }
                // describeServer must agree with the same policy.
                try await client.execute(uri: "/xrpc/com.atproto.server.describeServer", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let description = try JSONDecoder().decode(
                        DescribeServerBody.self,
                        from: Data(buffer: response.body)
                    )
                    XCTAssertEqual(
                        description.inviteCodeRequired,
                        policy.advertisesInviteCodeRequired
                    )
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The companion: a closed policy advertises no invite codes, so the
    /// default `false` is truthful. This keeps the red test above honest —
    /// it is not asserting a constant.
    func testDescribeServerInviteCodeRequiredStaysFalseForClosedPolicy() async throws {
        let fixture = try await makeServer(signupPolicy: .closed)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.closed")
            )
            try await app.test(.router) { client in
                try await client.execute(uri: "/xrpc/com.atproto.server.describeServer", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let description = try JSONDecoder().decode(
                        DescribeServerBody.self,
                        from: Data(buffer: response.body)
                    )
                    XCTAssertEqual(description.inviteCodeRequired, false)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    // MARK: - Fixture

    private struct DescribeServerBody: Decodable {
        let did: String
        let availableUserDomains: [String]
        let inviteCodeRequired: Bool
        let swanProfile: String
    }

    private struct CompositionFixture {
        let root: URL
        let control: SQLiteControlDatabase
        let directory: SQLitePreMigratedAccountDirectory
        let firehose: SQLiteFirehoseDatabase?
        let sender: RecordingProxySender
        let server: SwanHTTPServer

        func close() async throws {
            try await directory.close()
            try await control.close()
            try await firehose?.close()
        }

        func cleanup() {
            try? FileManager.default.removeItem(at: root)
        }
    }

    /// Constructs the server through `ServePermissionedRuntime.makeServer` —
    /// the exact production composition function `swan serve` calls — with
    /// the same argument kinds the CLI passes (profile, configuration,
    /// oauthRuntime, directory, accountControlStore, accountPortalHTTP,
    /// xrpcPipethrough, loginClientIdentityPolicy, publicFirehoseStreaming).
    /// The portal service and proxy transport are test doubles; the server
    /// type, the composition function, and every argument kind are
    /// production.
    private func makeServer(
        signupPolicy: SignupPolicy = .closed,
        installPipethrough: Bool = false,
        installFirehose: Bool = false,
        inviteCodeRequired: Bool = false,
        publicURL: URL = URL(string: "https://swan.example")!,
        port: Int = 3000
    ) async throws -> CompositionFixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountProgramCompositionTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        var directory: SQLitePreMigratedAccountDirectory?
        var firehose: SQLiteFirehoseDatabase?
        do {
            directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            if installFirehose {
                firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
            }
            let hub = PublicFirehoseWakeupHub()
            let sender = RecordingProxySender()
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let oauthRuntime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5C, count: 32)
            )
            let portal: SwanAccountPortalHTTP
            let sessions = SwanManagementSessionRuntime(
                store: PortalMemorySessionStore(),
                preAuthStore: SwanInMemoryManagementPreAuthStore(),
                csrfStore: SwanInMemoryManagementCSRFStore()
            )
            let configuration = try SwanAccountPortalConfiguration(
                publicOrigin: publicURL,
                staticDirectory: packageRoot().appending(path: "web/build"),
                signupPolicy: signupPolicy
            )
            portal = SwanAccountPortalHTTP(
                configuration: configuration,
                sessions: sessions,
                service: PortalMemoryService()
            )
            let pipethrough: SwanXRPCPipethroughServer?
            if installPipethrough {
                pipethrough = SwanXRPCPipethroughServer(
                    authorizer: PipethroughAuthorizer(
                        result: .success(
                            .accountOAuth(subject: "did:plc:alice", scopes: ["atproto"])
                        )
                    ),
                    tokens: TestProxyServiceTokenIssuer(),
                    sender: sender,
                    resolver: SwanServiceEndpointResolver(
                        documents: StubDIDDocuments(
                            documents: [
                                "did:web:attacker.example": Data(
                                    """
                                    {"id":"did:web:attacker.example","service":[
                                      {"id":"#svc","type":"AtprotoPersonalDataServer",
                                       "serviceEndpoint":"https://attacker.example"}]}
                                    """.utf8
                                )
                            ]
                        )
                    ),
                    appView: try SwanAppViewConfiguration()
                )
            } else {
                pipethrough = nil
            }
            let streamingRuntime: SwanPublicFirehoseStreamingRuntime?
            if let firehose {
                streamingRuntime = SwanPublicFirehoseStreamingRuntime(
                    database: firehose,
                    hub: hub,
                    limits: PublicFirehoseStreamingLimits.standard,
                    logger: Logger(label: "SwanAccountProgramCompositionTests.firehose")
                )
            } else {
                streamingRuntime = nil
            }
            // The production composition function, with no lane adapters
            // constructed directly. The runtime carries no permissioned
            // configurations (nil), exactly like a `serve` invocation with
            // no local-space/notification/public-mutation features enabled.
            let permissionedRuntime = ServePermissionedRuntime(
                credentialConfiguration: nil,
                credentialExchangeConfiguration: nil,
                delegationConfiguration: nil,
                repositorySyncConfiguration: nil,
                repositoryCredentialConfiguration: nil,
                notificationConfiguration: nil,
                checkUserAccessConfiguration: nil
            )
            let server = permissionedRuntime.makeServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: port,
                    publicURL: publicURL,
                    inviteCodeRequired: inviteCodeRequired,
                    publicRouteSurface: .default
                ),
                oauthRuntime: oauthRuntime,
                directory: try XCTUnwrap(directory),
                accountControlStore: control,
                accountPortalHTTP: portal,
                xrpcPipethrough: pipethrough,
                loginClientIdentityPolicy: .direct,
                publicFirehoseStreaming: streamingRuntime
            )
            return CompositionFixture(
                root: root,
                control: control,
                directory: try XCTUnwrap(directory),
                firehose: firehose,
                sender: sender,
                server: server
            )
        } catch {
            try? await firehose?.close()
            try? await directory?.close()
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

// MARK: - Test doubles

private actor PortalMemorySessionStore: ManagementSessionStore {
    private var values: [Data: ManagementSessionMetadata] = [:]
    func createManagementSession(_ session: ManagementSessionMetadata, sessionDigest: Data, csrfDigest _: Data, now _: Date) async throws { values[sessionDigest] = session }
    func managementSession(digest: Data, now _: Date) async throws -> ManagementSessionMetadata? { values[digest] }
    func revokeManagementSession(digest: Data, now _: Date) async throws { values.removeValue(forKey: digest) }
    func revokeOtherManagementSessions(accountDID: String, except sessionID: ManagementSessionID, now _: Date) async throws { values = values.filter { $0.value.accountDID != accountDID || $0.value.sessionID == sessionID } }
    func purgeExpiredManagementSessions(now _: Date) async throws {}
}

private struct PortalMemoryService: SwanAccountPortalServing {
    func bootstrap(now _: Date) async throws -> SwanAccountPortalBootstrap { SwanAccountPortalBootstrap(csrf: "csrf") }
    func authenticate(handle _: String, password _: String, authFactorToken _: String?, now _: Date) async throws -> SwanAccountPortalAuthentication { throw SwanManagementSessionError.unauthorized }
    func portal(accountDID: String, now _: Date) async throws -> SwanAccountPortalSnapshot {
        .init(account: .init(did: accountDID, handle: "alice.example", email: nil, lifecycle: "active"), identity: nil, strength: "password", factors: [], sessions: [], apps: [], passwords: [])
    }
    func mutate(path _: String, context _: SwanAccountPortalMutationContext, payload _: Data?, now _: Date) async throws -> SwanAccountPortalMutation { .init() }
}

/// Admits every pipethrough request, so a fail-open route would really reach
/// the sender. The credential-isolation tests assert the sender is never
/// consulted despite this permissive authorizer.
///
/// Sibling copies: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private struct PipethroughAuthorizer: SwanXRPCPipethroughResourceAuthorizing {
    let result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>

    init(result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>) {
        self.result = result
    }

    func authorizePipethrough(
        request _: Request,
        method _: String,
        fixedPath _: String,
        now _: Date
    ) async throws -> AuthorizationContext {
        try result.get()
    }

    func issuePipethroughNonce(now _: Date) async -> String { "test-nonce" }
}

/// Mints a real `ProxyServiceJWT` from a per-process test key, so the proxy
/// path is exercised with actual signed claims rather than a placeholder.
///
/// Sibling copies: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private struct TestProxyServiceTokenIssuer: SwanProxyServiceTokenIssuing {
    static let key = P256.Signing.PrivateKey()

    func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date
    ) async throws -> String {
        try ProxyServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            eventID: UUID().uuidString,
            key: Self.key,
            now: now
        )
    }
}

/// Sibling copies: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private struct StubDIDDocuments: SwanDIDDocumentFetching {
    let documents: [String: Data]

    func documentJSON(forDID did: String) async throws -> Data {
        guard let data = documents[did] else {
            throw SwanError.unavailable("no stub DID document")
        }
        return data
    }
}

/// Records every outbound proxy request. The credential-isolation tests
/// assert `recorded().isEmpty` — nothing left the host.
///
/// Sibling copies: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private final class RecordingProxySender: SwanProxySending, @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [SwanProxyRequest] = []
    private let result: Result<OAuthRemoteHTTPResponse, any Error>

    init(result: Result<OAuthRemoteHTTPResponse, any Error>? = nil) {
        self.result = result
            ?? .success(
                OAuthRemoteHTTPResponse(
                    status: 200,
                    headers: ["Content-Type": ["application/json"]],
                    body: Data(#"{"feed":[]}"#.utf8),
                    responseURL: URL(string: "https://api.bsky.app/xrpc/x")!
                )
            )
    }

    func send(
        _ request: SwanProxyRequest, timeout _: TimeInterval, maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        record(request)
        return try result.get()
    }

    private func record(_ request: SwanProxyRequest) {
        lock.lock()
        defer { lock.unlock() }
        requests.append(request)
    }

    func recorded() -> [SwanProxyRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }
}
