import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

final class SimpleSpaceLifecycleHTTPTests: XCTestCase, @unchecked Sendable {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let type = "app.bsky.bookmarks"
    private static let createPath = "/xrpc/com.atproto.simplespace.createSpace"
    private static let updatePath = "/xrpc/com.atproto.simplespace.updateSpace"
    private static let deletePath = "/xrpc/com.atproto.simplespace.deleteSpace"
    private static let addPath = "/xrpc/com.atproto.simplespace.addMember"
    private static let removePath = "/xrpc/com.atproto.simplespace.removeMember"
    private static let listPath = "/xrpc/com.atproto.simplespace.listMembers"

    func testLifecycleWriteAdmissionReturnsTemporaryUnavailableBeforeDecode() async throws {
        let maximum = authenticatedSpaceWriteMaximumJSONBytes
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let server = try makeServer(
                fixture,
                jsonWriteAdmission: admission
            )
            XCTAssertTrue(server.jsonWriteAdmission === admission)
            XCTAssertTrue(
                server.authenticatedSimpleSpaceLifecycle?.jsonWriteAdmission
                    === admission
            )
            let held = try XCTUnwrap(
                admission.reserve(maximumRequestBytes: maximum)
            )
            let app = server.buildApplication(
                logger: Logger(label: "SimpleSpaceLifecycleWriteAdmissionTests")
            )
            try await app.test(.router) { client in
                let response = try await client.execute(
                    uri: Self.createPath,
                    method: .post,
                    headers: try self.postHeaders(
                        fixture,
                        path: Self.createPath,
                        jti: "lifecycle-write-admission"
                    ),
                    body: ByteBuffer(string: "{}")
                )
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "temporarily_unavailable"
                )
            }
            held.release()
            XCTAssertEqual(admission.snapshot, .init(
                activeLeases: 0,
                reservedRequestBytes: 0
            ))
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleMembershipPaginationAndNonDestructiveConfigPatch() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.success"))
            let create = #"{"did":"\#(Self.alice)","type":"\#(Self.type)"}"#
            let managingConfig = #"{"space":"PLACEHOLDER","policy":"managing-app","managingApp":"did:web:manager.example","appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.createPath,
                    method: .post,
                    headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-generated"),
                    body: ByteBuffer(string: create)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
                    let space = try SpaceURI(uri)
                    XCTAssertEqual(space.authority, Self.alice)
                    XCTAssertEqual(space.spaceType, Self.type)
                    XCTAssertFalse(space.skey.isEmpty)

                    let configure = managingConfig.replacingOccurrences(of: "PLACEHOLDER", with: uri)
                    let configHeaders = try self.postHeaders(fixture, path: Self.updatePath, jti: "configure-managing")
                    try await client.execute(uri: Self.updatePath, method: .post, headers: configHeaders, body: ByteBuffer(string: configure)) { response in
                        XCTAssertEqual(response.status, .ok)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    }
                    // Omit policy/managingApp: appAccess changes, while the
                    // existing managing-app facts must remain intact.
                    let patch = #"{"space":"\#(uri)","appAccess":{"$type":"com.atproto.simplespace.defs#allowList","allowed":["https://client.example"]}}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "patch-app"), body: ByteBuffer(string: patch)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    let getPath = "/xrpc/com.atproto.space.getSpace?space=\(self.percentEncode(uri))"
                    try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.space.getSpace", jti: "get-patched")) { response in
                        XCTAssertEqual(response.status, .ok)
                        let config = try XCTUnwrap((try self.jsonObject(response.body))["config"] as? [String: Any])
                        XCTAssertEqual(config["policy"] as? String, "managing-app")
                        XCTAssertEqual(config["managingApp"] as? String, "did:web:manager.example")
                    }

                    // Pinned updateSpace patches each property independently:
                    // changing policy must not erase an omitted managingApp.
                    let policyOnly = #"{"space":"\#(uri)","policy":"public"}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "policy-only-public"), body: ByteBuffer(string: policyOnly)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.space.getSpace", jti: "get-policy-only-public")) { response in
                        XCTAssertEqual(response.status, .ok)
                        let config = try XCTUnwrap((try self.jsonObject(response.body))["config"] as? [String: Any])
                        XCTAssertEqual(config["policy"] as? String, "public")
                        XCTAssertEqual(config["managingApp"] as? String, "did:web:manager.example")
                    }
                    let restoreManagingPolicy = #"{"space":"\#(uri)","policy":"managing-app"}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "policy-only-managing"), body: ByteBuffer(string: restoreManagingPolicy)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }

                    // Match the pinned TypeScript handler: an empty
                    // managingApp is an explicit clear rather than an
                    // omitted-field reset, and it does not rewrite policy.
                    let clearManagingApp = #"{"space":"\#(uri)","managingApp":""}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "clear-managing"), body: ByteBuffer(string: clearManagingApp)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.space.getSpace", jti: "get-cleared")) { response in
                        XCTAssertEqual(response.status, .ok)
                        let config = try XCTUnwrap((try self.jsonObject(response.body))["config"] as? [String: Any])
                        XCTAssertEqual(config["policy"] as? String, "managing-app")
                        XCTAssertNil(config["managingApp"])
                    }

                    let add = #"{"space":"\#(uri)","did":"\#(Self.bob)"}"#
                    try await client.execute(uri: Self.addPath, method: .post, headers: try self.postHeaders(fixture, path: Self.addPath, jti: "add-member"), body: ByteBuffer(string: add)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    // add is idempotent.
                    try await client.execute(uri: Self.addPath, method: .post, headers: try self.postHeaders(fixture, path: Self.addPath, jti: "add-member-again"), body: ByteBuffer(string: add)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    let first = "\(Self.listPath)?space=\(self.percentEncode(uri))&limit=1"
                    try await client.execute(uri: first, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-first")) { response in
                        XCTAssertEqual(response.status, .ok)
                        self.assertNoStore(response)
                        let body = try self.jsonObject(response.body)
                        XCTAssertEqual((body["members"] as? [[String: String]])?.map(\.["did"]), [Self.alice])
                        XCTAssertEqual(body["cursor"] as? String, Self.alice)
                    }
                    let second = "\(Self.listPath)?space=\(self.percentEncode(uri))&limit=1&cursor=\(self.percentEncode(Self.alice))"
                    try await client.execute(uri: second, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-second")) { response in
                        XCTAssertEqual(response.status, .ok)
                        XCTAssertEqual(((try self.jsonObject(response.body))["members"] as? [[String: String]])?.map(\.["did"]), [Self.bob])
                    }
                    let ownerRemoval = #"{"space":"\#(uri)","did":"\#(Self.alice)"}"#
                    try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-owner"), body: ByteBuffer(string: ownerRemoval)) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                    try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-member"), body: ByteBuffer(string: add)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    // remove is idempotent.
                    try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-member-again"), body: ByteBuffer(string: add)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    let delete = #"{"space":"\#(uri)"}"#
                    try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(fixture, path: Self.deletePath, jti: "delete"), body: ByteBuffer(string: delete)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(fixture, path: Self.deletePath, jti: "delete-again"), body: ByteBuffer(string: delete)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleScopesAuthorityPrivacyAndRequestValidation() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let space = try SpaceURI(authority: Self.alice, spaceType: Self.type, skey: "scoped")
            let createScope = managementScope(space, operation: "create")
            let updateScope = managementScope(space, operation: "update")
            let deleteScope = managementScope(space, operation: "delete")
            let createToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [createScope])
            let updateToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [updateScope])
            let deleteToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [deleteScope])
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.scopes"))
            let create = #"{"did":"\#(Self.alice)","type":"\#(Self.type)","skey":"scoped"}"#
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(createToken, fixture: fixture, path: Self.createPath, jti: "scoped-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let member = #"{"space":"\#(space.rawValue)","did":"\#(Self.bob)"}"#
                try await client.execute(uri: Self.addPath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.addPath, jti: "update-scope-add"), body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let memberList = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))"
                try await client.execute(uri: memberList, method: .get, headers: try self.getHeaders(updateToken, fixture: fixture, path: Self.listPath, jti: "update-scope-list")) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(((try self.jsonObject(response.body))["members"] as? [[String: String]])?.map { $0["did"] }, [Self.alice, Self.bob])
                }
                try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.removePath, jti: "update-scope-remove"), body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let update = #"{"space":"\#(space.rawValue)","policy":"public"}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(createToken, fixture: fixture, path: Self.updatePath, jti: "wrong-manage"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.updatePath, jti: "right-manage"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let replayHeaders = try self.postHeaders(updateToken, fixture: fixture, path: Self.addPath, jti: "add-replay")
                try await client.execute(uri: Self.addPath, method: .post, headers: replayHeaders, body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: Self.addPath, method: .post, headers: replayHeaders, body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                let delete = #"{"space":"\#(space.rawValue)"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(deleteToken, fixture: fixture, path: Self.deletePath, jti: "delete-manage"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }

                let foreign = try self.postHeaders(fixture, subject: Self.bob, path: Self.createPath, jti: "foreign-authority")
                try await client.execute(uri: Self.createPath, method: .post, headers: foreign, body: ByteBuffer(string: create.replacingOccurrences(of: Self.alice, with: Self.alice))) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                let duplicate = #"{"did":"\#(Self.alice)","did":"\#(Self.bob)","type":"\#(Self.type)"}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "duplicate-body"), body: ByteBuffer(string: duplicate)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                var oversized = try self.postHeaders(fixture, path: Self.createPath, jti: "oversized")
                oversized[.contentLength] = "1048577"
                try await client.execute(uri: Self.createPath, method: .post, headers: oversized, body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                // Hummingbird's router test client fragments large bodies in
                // 32 KiB chunks. This exercises the streaming body limit with
                // a real oversized payload, rather than only trusting a
                // forged Content-Length header.
                let chunkedOversized = String(repeating: " ", count: 1_048_577)
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "chunked-oversized"), body: ByteBuffer(string: chunkedOversized)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                let malformedQuery = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))&space=\(self.percentEncode(space.rawValue))"
                try await client.execute(uri: malformedQuery, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "duplicate-query")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                let malformedCursor = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))&cursor=not-a-did"
                try await client.execute(uri: malformedCursor, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "bad-cursor")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                try await client.execute(uri: Self.createPath, method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
                let wrongTarget = try self.getHeaders(fixture, path: Self.updatePath, jti: "wrong-dpop", method: "POST")
                try await client.execute(uri: Self.createPath, method: .post, headers: self.withJSON(wrongTarget), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleFailsClosedForDeactivationAndVanishedPreopenedDatabase() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.closed"))
            let create = #"{"did":"\#(Self.alice)","type":"\#(Self.type)","skey":"closed"}"#
            _ = try await fixture.control.transitionStatus(
                did: Self.alice,
                to: .deactivated,
                declaration: .init(),
                now: Date()
            )
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "deactivated"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            _ = try await fixture.control.transitionStatus(
                did: Self.alice,
                to: .active,
                declaration: .init(),
                now: Date()
            )
            // Deactivation revokes the entire OAuth family. Reactivation
            // therefore requires a fresh authorization grant before the
            // request can reach the preopened-database availability check.
            let reactivated = try await issueToken(fixture.runtime, subject: Self.alice, scopes: ["atproto"])
            try FileManager.default.removeItem(at: SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice))
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(reactivated, fixture: fixture, path: Self.createPath, jti: "missing-db"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertFalse(FileManager.default.fileExists(atPath: SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice).path))
                }
                try await client.execute(uri: "/xrpc/com.atproto.repo.getRecord?repo=\(Self.alice)&collection=\(Self.type)&rkey=closed", method: .get) { response in
                    XCTAssertNotEqual(response.status, .ok)
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("closed"))
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    private func makeFixture() async throws -> SimpleSpaceFixture {
        let root = FileManager.default.temporaryDirectory.appending(path: "SimpleSpaceLifecycleHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(registration(did: Self.alice, handle: "alice.example.com"))
            _ = try await control.createAccount(registration(did: Self.bob, handle: "bob.example.com"))
            for did in [Self.alice, Self.bob] {
                let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
                try await database.close()
            }
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0x5A, count: 32))
            let alice = try await issueToken(runtime, subject: Self.alice, scopes: ["atproto"])
            let bob = try await issueToken(runtime, subject: Self.bob, scopes: ["atproto"])
            return .init(root: root, control: control, directory: directory, runtime: runtime, alice: alice, bob: bob)
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func makeServer(
        _ fixture: SimpleSpaceFixture,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil
    ) throws -> SwanHTTPServer {
        SwanHTTPServer(
            profile: try ProtocolProfile.load(from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")),
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control,
            jsonWriteAdmission: jsonWriteAdmission
        )
    }

    private func issueToken(_ runtime: SwanOAuthRuntime, subject: String, scopes: Set<String>) async throws -> SimpleSpaceTokenMaterial {
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
                ), keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: scopes,
            dpopProof: OAuthValidatedDPoPProof(keyThumbprint: jwk.thumbprint(), jwtID: "simple-space-\(UUID().uuidString)", issuedAt: now),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(subject: subject, session: session, now: now)
        return .init(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func postHeaders(_ fixture: SimpleSpaceFixture, path: String, jti: String) throws -> HTTPFields {
        try postHeaders(fixture, subject: Self.alice, path: path, jti: jti)
    }

    private func postHeaders(_ fixture: SimpleSpaceFixture, subject: String, path: String, jti: String) throws -> HTTPFields {
        withJSON(try signedHeaders(subject == Self.alice ? fixture.alice : fixture.bob, fixture: fixture, path: path, jti: jti, method: "POST"))
    }

    private func postHeaders(_ token: SimpleSpaceTokenMaterial, fixture: SimpleSpaceFixture, path: String, jti: String) throws -> HTTPFields {
        withJSON(try signedHeaders(token, fixture: fixture, path: path, jti: jti, method: "POST"))
    }

    private func getHeaders(_ fixture: SimpleSpaceFixture, path: String, jti: String, method: String = "GET") throws -> HTTPFields {
        try signedHeaders(fixture.alice, fixture: fixture, path: path, jti: jti, method: method)
    }

    private func getHeaders(_ token: SimpleSpaceTokenMaterial, fixture: SimpleSpaceFixture, path: String, jti: String) throws -> HTTPFields {
        try signedHeaders(token, fixture: fixture, path: path, jti: jti, method: "GET")
    }

    private func signedHeaders(_ token: SimpleSpaceTokenMaterial, fixture: SimpleSpaceFixture, path: String, jti: String, method: String) throws -> HTTPFields {
        struct Header: Encodable { let alg = "ES256"; let typ = OAuthDPoPProofValidator.proofType; let jwk: OAuthJSONWebKey }
        struct Claims: Encodable { let jti: String; let iat: Int64; let htm: String; let htu: String; let nonce: String; let ath: String }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: token.jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(jti: jti, iat: Int64(Date().timeIntervalSince1970), htm: method, htu: "\(Self.publicURL.absoluteString)\(path)", nonce: fixture.runtime.dpopNonceService.issue(), ath: Data(SHA256.hash(data: Data(token.token.utf8))).base64URLEncodedString())).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: token.key).base64URLEncodedString()
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token.token)"
        headers[HTTPField.Name("DPoP")!] = "\(input).\(signature)"
        return headers
    }

    private func withJSON(_ headers: HTTPFields) -> HTTPFields { var value = headers; value[.contentType] = "application/json"; return value }
    private func managementScope(_ space: SpaceURI, operation: String) -> String { "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&manage=\(operation)" }
    private func registration(did: String, handle: String) throws -> AccountControlRegistration { try .init(did: did, canonicalHandle: handle, passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", signingKey: try .init(purpose: .signing, generation: 1), rotationKey: try .init(purpose: .rotation, generation: 1), createdAt: Date(timeIntervalSince1970: 1_750_000_000)) }
    private func makeJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey { let value = key.publicKey.x963Representation; return try .init(x: Data(value[1 ..< 33]).base64URLEncodedString(), y: Data(value[33 ..< 65]).base64URLEncodedString()) }
    private func close(_ fixture: SimpleSpaceFixture) async throws { try await fixture.directory.close(); try await fixture.control.close() }
    private func percentEncode(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)! }
    private func jsonObject(_ body: ByteBuffer) throws -> [String: Any] { try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any]) }
    private func errorCode(_ body: ByteBuffer) throws -> String { try XCTUnwrap(jsonObject(body)["error"] as? String) }
    private func assertNoStore(_ response: TestResponse, file: StaticString = #filePath, line: UInt = #line) { XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line); XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line) }
    private func packageRoot() -> URL { URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
}

private struct SimpleSpaceTokenMaterial: Sendable { let token: String; let key: P256.Signing.PrivateKey; let jwk: OAuthJSONWebKey }
private struct SimpleSpaceFixture: Sendable { let root: URL; let control: SQLiteControlDatabase; let directory: SQLitePreMigratedAccountDirectory; let runtime: SwanOAuthRuntime; let alice: SimpleSpaceTokenMaterial; let bob: SimpleSpaceTokenMaterial }
