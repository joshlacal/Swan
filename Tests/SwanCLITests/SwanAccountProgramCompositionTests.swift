import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import PetrelCrypto
import PetrelFirehose
import SwanAccounts
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest
@testable import swan

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
    func testAccountRouteAssemblyUsesExplicitOrderedRegistrationPhases() {
        XCTAssertEqual(
            SwanAccountPortalHTTP.registrationPhases,
            [.api, .assets, .unknownGuards]
        )
        XCTAssertEqual(
            SwanDidWebIdentityHTTP.registrationPhases,
            [.publicClaim, .api]
        )
    }

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

    /// `createSession` and `createAccount` carry credentials. They must
    /// remain a stable local refusal — never forwarded to a service the
    /// client names in `atproto-proxy`, even when the proxy authorizer would
    /// admit the request and the attacker's DID document resolves.
    /// `createAccount` is registered by Task 3 and fails closed (422 for a
    /// body that cannot satisfy the openProtected policy); `createSession`
    /// stays a bare 404 until Task 4 assembles the legacy session service.
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
                // The registered route fails closed on the missing verified
                // email proof rather than proxying.
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertNotEqual(response.status, .notFound)
                    XCTAssertEqual(response.status, .unprocessableContent)
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

    /// The assembled-state expectation: once the durable services are wired,
    /// these routes answer locally with a real status — never a bare 404.
    /// Task 3 registers `createAccount` (fails closed on the missing proof);
    /// `createSession` stays 404 until Task 4.
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
                    XCTAssertEqual(response.status, .notFound)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertNotEqual(response.status, .notFound)
                    XCTAssertEqual(response.status, .unprocessableContent)
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

    // MARK: - Task 7: legacy and did:web route precedence

    /// With the legacy-auth surface installed, `createSession` answers
    /// locally with a real status — never a bare 404 and never proxied —
    /// even when the pipethrough authorizer would admit the request.
    func testLegacyCreateSessionAnswersLocallyAndIsNeverProxied() async throws {
        let fixture = try await makeServer(
            signupPolicy: .closed,
            installPipethrough: true,
            installLegacy: true
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.legacy")
            )
            try await app.test(.live) { client in
                var steered = HTTPFields()
                steered[.contentType] = "application/json"
                steered[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"identifier":"alice.test","password":"password"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("\"accessJwt\""), body)
                }
                // A wrong password is a stable local 401, never proxied.
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"identifier":"alice.test","password":"wrong"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            XCTAssertEqual(fixture.sender.recorded().count, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// `com.atproto.server.refreshSession` is bodyless: the generated client
    /// sends the refresh JWT in `Authorization: Bearer ...` (the lexicon
    /// declares no input schema). The local route must accept that header and
    /// must not require a JSON body — a bodyless request with the bearer
    /// header refreshes, and a JSON body is refused.
    func testLegacyRefreshSessionAcceptsBearerHeaderAndBodylessRequest() async throws {
        let fixture = try await makeServer(
            signupPolicy: .closed,
            installPipethrough: true,
            installLegacy: true
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.refresh")
            )
            try await app.test(.live) { client in
                // Establish a legacy session to obtain a real refresh JWT.
                var refreshJwt: String?
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"identifier":"alice.test","password":"password"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("\"refreshJwt\""), body)
                    let object = try? JSONSerialization.jsonObject(
                        with: Data(body.utf8)
                    ) as? [String: Any]
                    refreshJwt = object?["refreshJwt"] as? String
                }
                let token = try XCTUnwrap(refreshJwt)

                // Bodyless request with the refresh JWT in the bearer header.
                var steered = HTTPFields()
                steered[.authorization] = "Bearer \(token)"
                steered[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.refreshSession",
                    method: .post,
                    headers: steered
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("\"accessJwt\""), body)
                    XCTAssertTrue(body.contains("\"refreshJwt\""), body)
                }

                // A consumed refresh token is rejected locally; the canonical
                // route does not proxy a body-bearing retry.
                var withBody = HTTPFields()
                withBody[.authorization] = "Bearer \(token)"
                withBody[.contentType] = "application/json"
                withBody[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.refreshSession",
                    method: .post,
                    headers: withBody,
                    body: ByteBuffer(string: #"{"refreshJwt":"\(token)"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }

                // A missing bearer header is a stable local refusal.
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.refreshSession",
                    method: .post
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
            }
            XCTAssertEqual(fixture.sender.recorded().count, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The CLI's assembled legacy surface must carry the same encrypted
    /// account-key-backed issuer used by the AppView proxy. This exercises the
    /// real FileAccountKeyStore, DurableAccountDirectory, session service,
    /// and SwanHTTPServer composition rather than injecting a token issuer
    /// directly into a handler fixture.
    func testProductionCompositionWiresAccountKeyBackedServiceAuthIssuer() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountProgramCompositionTests-service-auth-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        var directory: SQLitePreMigratedAccountDirectory?
        do {
            directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            let keyDirectory = root.appending(path: "keys")
            try FileManager.default.createDirectory(
                at: keyDirectory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let keyStore = try FileAccountKeyStore(
                root: keyDirectory,
                configuration: try AccountKeyEncryptionConfiguration(
                    activeKeyID: "primary",
                    activeKey: Data(repeating: 0xA7, count: 32)
                )
            )
            let did = "did:plc:abcdefghijklmnopqrstuvwx"
            let keys = try await AccountKeyProvisioner(keyStore: keyStore)
                .provisionInitial(accountDID: did)
            let passwordHasher = try LibsodiumArgon2idHasher()
            _ = try await control.createAccount(
                try AccountControlRegistration(
                    did: did,
                    canonicalHandle: "service-auth.example",
                    passwordVerifier: try passwordHasher.hash("account-password"),
                    signingKey: try AccountControlKeyReference(
                        purpose: .signing,
                        generation: keys.signingReference.generation
                    ),
                    rotationKey: try AccountControlKeyReference(
                        purpose: .rotation,
                        generation: keys.rotationReference.generation
                    )
                )
            )
            let credentials = try AppPasswordCredentials()
            let audience = "did:web:remote.example#pds"
            let method = "com.atproto.repo.getRecord"
            let issuance = try await credentials.issue(
                did: did,
                name: "service-auth-test",
                scopes: "atproto rpc:\(method)?aud=did:web:remote.example%23pds",
                into: control
            )
            let factorTokens = FactorTokenService(store: control)
            let accounts = DurableAccountDirectory(
                store: control,
                passwordHasher: passwordHasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher),
                loginFactorTokenVerifier: factorTokens,
                authenticationFactors: control
            )
            let issuer = LocalAccountProxyServiceTokenIssuer(
                accounts: accounts,
                keyStore: keyStore
            )
            let legacy = SwanLegacySessionXRPCServer(
                sessions: try DurableLegacySessionService(
                    store: control,
                    appPasswords: control,
                    accountControlStore: control,
                    serviceDID: "did:web:swan.example",
                    serverKey: Data(repeating: 0x3C, count: 32)
                ),
                credentials: credentials,
                appPasswords: control,
                accounts: accounts,
                directory: SwanDurableLegacySessionDirectory(store: control),
                rateLimiter: SwanInProcessLegacySessionRateLimiter(),
                serviceAuthIssuer: issuer,
                minimumFailedLoginDuration: .milliseconds(1)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let oauthRuntime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5C, count: 32)
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 0,
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: oauthRuntime,
                authenticatedGetSpaceDirectory: try XCTUnwrap(directory),
                accountControlStore: control,
                publicRepositoryReadDirectory: try XCTUnwrap(directory),
                legacySessionXRPC: legacy
            )
            let app = server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.service-auth")
            )
            try await app.test(.live) { client in
                var accessJWT = ""
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(
                        string: "{\"identifier\":\"service-auth.example\",\"password\":\"\(issuance.password)\"}"
                    )
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try XCTUnwrap(
                        JSONSerialization.jsonObject(
                            with: Data(response.body.readableBytesView)
                        ) as? [String: Any]
                    )
                    accessJWT = try XCTUnwrap(body["accessJwt"] as? String)
                }
                let encodedAudience = try XCTUnwrap(
                    audience.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
                )
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.getServiceAuth?aud=\(encodedAudience)&lxm=\(method)",
                    method: .get,
                    headers: [.authorization: "Bearer \(accessJWT)"]
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try XCTUnwrap(
                        JSONSerialization.jsonObject(
                            with: Data(response.body.readableBytesView)
                        ) as? [String: Any]
                    )
                    let token = try XCTUnwrap(body["token"] as? String)
                    let pieces = token.split(separator: ".")
                    XCTAssertEqual(pieces.count, 3)
                    let claims = try XCTUnwrap(
                        JSONSerialization.jsonObject(
                            with: try XCTUnwrap(Data(base64URLEncoded: String(pieces[1])))
                        ) as? [String: Any]
                    )
                    XCTAssertEqual(claims["iss"] as? String, did)
                    XCTAssertEqual(claims["aud"] as? String, audience)
                    XCTAssertEqual(claims["lxm"] as? String, method)
                    let issuedAt = try XCTUnwrap(claims["iat"] as? NSNumber).int64Value
                    let expiresAt = try XCTUnwrap(claims["exp"] as? NSNumber).int64Value
                    XCTAssertEqual(expiresAt - issuedAt, 60)
                }
                let requestedExpiry = Int(Date().timeIntervalSince1970) + 30
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.getServiceAuth?aud=\(encodedAudience)&lxm=\(method)&exp=\(requestedExpiry)",
                    method: .get,
                    headers: [.authorization: "Bearer \(accessJWT)"]
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try XCTUnwrap(
                        JSONSerialization.jsonObject(
                            with: Data(response.body.readableBytesView)
                        ) as? [String: Any]
                    )
                    let token = try XCTUnwrap(body["token"] as? String)
                    let pieces = token.split(separator: ".")
                    let claims = try XCTUnwrap(
                        JSONSerialization.jsonObject(
                            with: try XCTUnwrap(Data(base64URLEncoded: String(pieces[1])))
                        ) as? [String: Any]
                    )
                    let issuedAt = try XCTUnwrap(claims["iat"] as? NSNumber).int64Value
                    let expiresAt = try XCTUnwrap(claims["exp"] as? NSNumber).int64Value
                    XCTAssertEqual(expiresAt - issuedAt, 30)
                }
            }
            try await directory?.close()
            try await control.close()
        } catch {
            try? await directory?.close()
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
        try? FileManager.default.removeItem(at: root)
    }

    /// The canonical legacy app-password XRPC methods stay local when no
    /// bearer session is presented. They reject the request before the proxy
    /// fallback, rather than reviving the retired management-context adapter.
    func testLegacyAppPasswordMethodsFailClosedNeverProxied() async throws {
        let fixture = try await makeServer(
            signupPolicy: .closed,
            installPipethrough: true,
            installLegacy: true
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.apppasswords")
            )
            try await app.test(.router) { client in
                var steered = HTTPFields()
                steered[.contentType] = "application/json"
                steered[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                for (uri, method) in [
                    ("/xrpc/com.atproto.server.createAppPassword", HTTPRequest.Method.post),
                    ("/xrpc/com.atproto.server.listAppPasswords", HTTPRequest.Method.get),
                    ("/xrpc/com.atproto.server.revokeAppPassword", HTTPRequest.Method.post),
                ] {
                    try await client.execute(
                        uri: uri,
                        method: method,
                        headers: steered,
                        body: ByteBuffer(string: #"{"name":"test"}"#)
                    ) { response in
                        XCTAssertEqual(response.status, .forbidden, uri)
                    }
                }
            }
            XCTAssertEqual(fixture.sender.recorded().count, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The did:web public claim endpoint is registered before the fallback:
    /// an unknown nonce is a JSON 404 from the claim endpoint, and the
    /// management-session identity routes enforce the account-API policy
    /// (403 without a valid session cookie/CSRF pair).
    func testDidWebClaimEndpointAndIdentityRoutesAreRegisteredBeforeFallback() async throws {
        let fixture = try await makeServer(
            signupPolicy: .closed,
            installPipethrough: true,
            installDidWeb: true
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.didweb")
            )
            try await app.test(.router) { client in
                // Unknown nonce: the claim endpoint answers 404 JSON.
                try await client.execute(
                    uri: "/.well-known/swan/did-web-claim/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                }
                // Identity mutations without a management session are 403.
                try await client.execute(
                    uri: "/account/api/identity/reserve",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"requestID":"r","targetDID":"did:web:example.com","handle":"alice.test","expiresAt":4102444800}"#)
                ) { response in
                    XCTAssertEqual(response.status, .forbidden)
                }
                // The portal API still owns /account/api/*: an unknown API
                // path is a JSON 404, never the SPA shell.
                try await client.execute(uri: "/account/api/unknown/deep", method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                }
            }
            XCTAssertEqual(fixture.sender.recorded().count, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Malformed, missing, or wrongly typed did:web mutation payloads are
    /// client validation failures: the admitted JSON body decodes to a typed
    /// 422 `unprocessable_entity`, never a 503 infrastructure outage.
    func testDidWebIdentityRoutesMapMalformedBodiesToUnprocessable() async throws {
        let fixture = try await makeServer(
            signupPolicy: .closed,
            installPipethrough: true,
            installDidWeb: true
        )
        defer { fixture.cleanup() }
        do {
            let issued = try await fixture.sessions.issue(
                accountDID: "did:plc:abcdefghijklmnopqrstuvwx"
            )
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.didweb422")
            )
            try await app.test(.router) { client in
                var headers = HTTPFields()
                headers[HTTPField.Name("Origin")!] = "https://swan.example"
                headers[HTTPField.Name("Sec-Fetch-Site")!] = "same-origin"
                headers[.contentType] = "application/json"
                headers[.cookie] = "\(SwanManagementSessionRuntime.sessionCookieName)=\(issued.sessionValue); \(SwanManagementSessionRuntime.csrfCookieName)=\(issued.csrfValue)"
                headers[HTTPField.Name("X-Swan-CSRF")!] = issued.csrfValue

                // Wrongly typed field (expiresAt is a string, not a number).
                try await client.execute(
                    uri: "/account/api/identity/reserve",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: #"{"requestID":"r","targetDID":"did:web:example.com","handle":"alice.test","expiresAt":"not-a-date"}"#)
                ) { response in
                    XCTAssertEqual(response.status.code, 422)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("unprocessable_entity"), body)
                }
                // Missing required keys.
                try await client.execute(
                    uri: "/account/api/identity/claim",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: #"{"requestID":42}"#)
                ) { response in
                    XCTAssertEqual(response.status.code, 422)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("unprocessable_entity"), body)
                }
                // Malformed JSON.
                try await client.execute(
                    uri: "/account/api/identity/rotate",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: "not-json")
                ) { response in
                    XCTAssertEqual(response.status.code, 422)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("unprocessable_entity"), body)
                }
                // Wrongly typed field (stepUpReceipt is a number).
                try await client.execute(
                    uri: "/account/api/identity/remove",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: #"{"stepUpReceipt":7}"#)
                ) { response in
                    XCTAssertEqual(response.status.code, 422)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("unprocessable_entity"), body)
                }
            }
            XCTAssertEqual(fixture.sender.recorded().count, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The portal's DELETE wildcard routes (`/account/api/{sessions,
    /// app-passwords, factors/passkeys}/*`) must find the management session
    /// and CSRF cookies when Hummingbird surfaces them as genuinely separate
    /// `Cookie` header values — a real browser may send the management
    /// session and CSRF cookies in distinct header lines. The parser searches
    /// every value and every semicolon-delimited part, and the CSRF header is
    /// compared in constant time: a request carrying both cookies in separate
    /// values reaches the mutation path instead of falsely 403ing.
    func testPortalDeleteWildcardAcceptsSeparateCookieHeaderValues() async throws {
        let fixture = try await makeServer(
            signupPolicy: .closed,
            installPipethrough: true
        )
        defer { fixture.cleanup() }
        do {
            let issued = try await fixture.sessions.issue(
                accountDID: "did:plc:abcdefghijklmnopqrstuvwx"
            )
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanAccountProgramCompositionTests.portal-delete")
            )
            try await app.test(.router) { client in
                // Genuinely separate Cookie header values: the management
                // session and the CSRF cookie arrive in distinct header
                // lines, exactly as Hummingbird may surface a browser's
                // `Cookie: a=1; b=2` header.
                var headers = HTTPFields()
                headers[HTTPField.Name("Origin")!] = "https://swan.example"
                headers[HTTPField.Name("Sec-Fetch-Site")!] = "same-origin"
                headers[.contentType] = "application/json"
                headers[values: .cookie] = [
                    "\(SwanManagementSessionRuntime.sessionCookieName)=\(issued.sessionValue)",
                    "\(SwanManagementSessionRuntime.csrfCookieName)=\(issued.csrfValue)",
                ]
                headers[HTTPField.Name("X-Swan-CSRF")!] = issued.csrfValue

                // The mutating DELETE reaches the portal service: both
                // cookies are found across the separate values, the CSRF
                // header matches in constant time, and the session accepts
                // the CSRF — the mutation is accepted, never a false 403.
                try await client.execute(
                    uri: "/account/api/sessions/current",
                    method: .delete,
                    headers: headers,
                    body: ByteBuffer(string: "{}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("\"accepted\":true"), body)
                }

                // The origin/CSRF checks still fail closed: a mismatched CSRF
                // header with the same separate cookie values is a 403.
                var mismatched = headers
                mismatched[HTTPField.Name("X-Swan-CSRF")!] = "not-the-csrf"
                try await client.execute(
                    uri: "/account/api/sessions/current",
                    method: .delete,
                    headers: mismatched,
                    body: ByteBuffer(string: "{}")
                ) { response in
                    XCTAssertEqual(response.status, .forbidden)
                }
            }
            XCTAssertEqual(fixture.sender.recorded().count, 0)
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
        let sessions: SwanManagementSessionRuntime
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
        installLegacy: Bool = false,
        installDidWeb: Bool = false,
        publicURL: URL = URL(string: "https://swan.example")!,
        port: Int = 0
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
            // Keep the fixture self-contained: the checked-in source tree does
            // not contain the generated Svelte build, while production mounts
            // the compiled assets at this boundary.
            let portalDirectory = root.appending(path: "portal-assets")
            try FileManager.default.createDirectory(
                at: portalDirectory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            try Data("<!doctype html><title>Swan account</title>".utf8)
                .write(to: portalDirectory.appending(path: "index.html"))
            let configuration = try SwanAccountPortalConfiguration(
                publicOrigin: publicURL,
                staticDirectory: portalDirectory,
                signupPolicy: signupPolicy
            )
            portal = SwanAccountPortalHTTP(
                configuration: configuration,
                sessions: sessions,
                service: PortalMemoryService()
            )
            // The legacy XRPC surface is installed through the canonical
            // production session service (SwanLegacySessionXRPCServer).
            let legacySessionXRPC: SwanLegacySessionXRPCServer?
            if installLegacy {
                // The legacy session family row has an FK to `accounts(did)`;
                // create the fixture account so the durable session store
                // accepts the login.
                let passwordHasher = try LibsodiumArgon2idHasher()
                _ = try await control.createAccount(try AccountControlRegistration(
                    did: "did:plc:abcdefghijklmnopqrstuvwx",
                    canonicalHandle: "alice.test",
                    passwordVerifier: try passwordHasher.hash("password"),
                    signingKey: try AccountControlKeyReference(
                        purpose: .signing,
                        generation: 1
                    ),
                    rotationKey: try AccountControlKeyReference(
                        purpose: .rotation,
                        generation: 1
                    )
                ))
                let credentials = try AppPasswordCredentials()
                let factorTokens = FactorTokenService(store: control)
                let accounts = DurableAccountDirectory(
                    store: control,
                    passwordHasher: passwordHasher,
                    verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher),
                    loginFactorTokenVerifier: factorTokens,
                    authenticationFactors: control
                )
                legacySessionXRPC = SwanLegacySessionXRPCServer(
                    sessions: try DurableLegacySessionService(
                        store: control,
                        appPasswords: control,
                        accountControlStore: control,
                        credentials: credentials,
                        serviceDID: SwanServiceIdentity(publicURL: publicURL).did,
                        serverKey: Data(repeating: 0x6E, count: 32)
                    ),
                    credentials: credentials,
                    appPasswords: control,
                    accounts: accounts,
                    directory: SwanDurableLegacySessionDirectory(store: control),
                    rateLimiter: SwanInProcessLegacySessionRateLimiter(),
                    minimumFailedLoginDuration: .milliseconds(1)
                )
            } else {
                legacySessionXRPC = nil
            }
            let didWebIdentityHTTP: SwanDidWebIdentityHTTP?
            if installDidWeb {
                let didWebSecret = Data(repeating: 0x7D, count: 32)
                let provider = try ServeDidWebSigningKeyProvider(secret: didWebSecret)
                let reservations = SwanDurableSigningKeyReservationAdapter(
                    store: control,
                    provider: provider
                )
                let identityService = SwanDidWebIdentityService(
                    reservations: reservations,
                    bindings: control,
                    publicPDSURL: publicURL.absoluteString,
                    publicURL: publicURL.absoluteString,
                    gracePeriod: 86_400,
                    replacementAuthorizer: SwanDurableDidWebReplacementAuthorizer(
                        verifier: control
                    ),
                    stepUps: SwanDurableStepUpReceiptConsumer(store: control),
                    signingKeyProvider: provider
                )
                didWebIdentityHTTP = SwanDidWebIdentityHTTP(
                    service: identityService,
                    sessions: sessions,
                    documents: StubDidWebDocuments(),
                    reservations: reservations,
                    bindings: control
                )
            } else {
                didWebIdentityHTTP = nil
            }
            let pipethrough: SwanXRPCPipethroughServer?
            if installPipethrough {
                pipethrough = SwanXRPCPipethroughServer(
                    authorizer: PipethroughAuthorizer(
                        result: .success(
                            .accountOAuth(
                                subject: "did:plc:alice",
                                permissions: SwanScopePermissions(
                                    rawScopes: ["atproto"],
                                    subject: "did:plc:alice"
                                )
                            )
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
            // Task 3: a public signup policy assembles the lifecycle XRPC
            // adapter through the same production conformers `swan serve`
            // constructs. The key store is a real FileAccountKeyStore under
            // the fixture root; the session runtime uses the real control
            // database so the atomic signup transaction owns the session row.
            let accountLifecycleXRPC: SwanAccountLifecycleXRPCAdapter?
            if signupPolicy != .closed {
                let keyDirectory = root.appending(path: "signup-keys")
                try FileManager.default.createDirectory(
                    at: keyDirectory,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                let keyStore = try FileAccountKeyStore(
                    root: keyDirectory,
                    configuration: try AccountKeyEncryptionConfiguration(
                        activeKeyID: "primary",
                        activeKey: Data(repeating: 0x42, count: 32)
                    )
                )
                let signupSecret = try SignupSecret(Data(repeating: 0x24, count: 32))
                let passwordHasher = try LibsodiumArgon2idHasher()
                let proofService = SignupEmailProofService(secret: signupSecret)
                let extractor = try SocketAddressSignupPeerExtractor(
                    serverSecret: Data(repeating: 0x5C, count: 32)
                )
                let policyService = try SignupPolicyService(policy: signupPolicy)
                let turnstile: TurnstileVerifier?
                if signupPolicy == .openProtected {
                    turnstile = try TurnstileVerifier(
                        secret: Data(repeating: 0x11, count: 32),
                        hostname: publicURL.host ?? "swan.example",
                        action: "signup",
                        transport: StubTurnstileTransport(
                            response: .init(
                                success: true,
                                challengeTimestamp: Date(),
                                hostname: publicURL.host ?? "swan.example",
                                action: "signup"
                            )
                        )
                    )
                } else {
                    turnstile = nil
                }
                let sessions = SwanManagementSessionRuntime(
                    store: control,
                    preAuthStore: control,
                    csrfStore: control,
                    preAuthSessionCoordinator: control
                )
                let provisioning = SwanCreateAccountProvisioningProduction(
                    passwordHasher: passwordHasher,
                    keyProvisioner: AccountKeyProvisioner(keyStore: keyStore),
                    sessionRuntime: sessions,
                    database: control,
                    signupSecret: signupSecret
                )
                let service = SignupService(
                    policy: policyService,
                    store: control,
                    turnstile: turnstile,
                    proofVerifier: BoundedSignupEmailProofVerifier(store: control),
                    proofService: proofService
                )
                let authorization = SwanCreateAccountAuthorizationPipelineProduction(
                    service: service,
                    extractor: extractor,
                    proofService: proofService,
                    signupSecret: signupSecret
                )
                let lifecycle = AccountLifecycleService(
                    store: control,
                    deletion: control,
                    invites: SignupInviteService(secret: signupSecret),
                    invitePersistence: control
                )
                accountLifecycleXRPC = SwanAccountLifecycleXRPCAdapter(
                    lifecycle: lifecycle,
                    provisioning: provisioning,
                    authorization: authorization,
                    capabilityVerifier: try SwanAccountLifecycleCapabilityVerifier(
                        sessionStore: control,
                        stepUpStore: control
                    )
                )
            } else {
                accountLifecycleXRPC = nil
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
                    // Mirrors the CLI derivation (spec §4.1): the
                    // configuration value is derived from the same policy the
                    // portal advertises, never set independently.
                    inviteCodeRequired: signupPolicy == .inviteRequired,
                    publicRouteSurface: .default
                ),
                oauthRuntime: oauthRuntime,
                directory: try XCTUnwrap(directory),
                accountControlStore: control,
                legacySessionXRPC: legacySessionXRPC,
                accountPortalHTTP: portal,
                accountLifecycleXRPC: accountLifecycleXRPC,
                didWebIdentityHTTP: didWebIdentityHTTP,
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
                sessions: sessions,
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
    func revokeManagementSession(digest: Data, accountDID: String, now _: Date) async throws {
        guard let session = values[digest], session.accountDID == accountDID else { return }
        values.removeValue(forKey: digest)
    }
    func managementSessions(accountDID: String, now _: Date) async throws -> [ManagementSessionMetadata] {
        values.values.filter { $0.accountDID == accountDID }
    }
    func revokeOtherManagementSessions(accountDID: String, except sessionID: ManagementSessionID, now _: Date) async throws { values = values.filter { $0.value.accountDID != accountDID || $0.value.sessionID == sessionID } }
    func purgeExpiredManagementSessions(now _: Date) async throws {}
}

private struct PortalMemoryService: SwanAccountPortalServing {
    func bootstrap(now _: Date) async throws -> SwanAccountPortalBootstrap { SwanAccountPortalBootstrap(csrf: "csrf") }
    func authenticate(handle _: String, password _: String, authFactorToken _: String?, now _: Date) async throws -> SwanAccountPortalAuthentication { throw SwanManagementSessionError.unauthorized }
    func portal(accountDID: String, currentSessionID _: String?, now _: Date) async throws -> SwanAccountPortalSnapshot {
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

/// Conforms to the did:web identity surface's `SwanDidWebDocumentFetching`
/// (the OAuth `SwanDIDDocumentFetching` is a different protocol). The
/// composition fixture never fetches a real document, so an empty stub is
/// sufficient for route-precedence assertions.
private struct StubDidWebDocuments: SwanDidWebDocumentFetching {
    func documentJSON(forDID did: String) async throws -> Data {
        throw SwanError.unavailable("no stub did:web document")
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
private final class RecordingProxySender: SwanProxySending, @unchecked Sendable {    private let lock = NSLock()
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

/// Serves a canned Turnstile siteverify response so the openProtected
/// composition fixture never contacts Cloudflare.
private struct StubTurnstileTransport: TurnstileHTTPTransport {
    let response: TurnstileSiteVerifyResponse
    func verify(_: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        response
    }
}
