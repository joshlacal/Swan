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

final class SpaceListHTTPTests: XCTestCase, @unchecked Sendable {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let path = "/xrpc/com.atproto.space.listSpaces"

    func testOwnerAppearsBeforeWriteAndMemberAppearsOnlyAfterLocalRepositoryState() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SpaceListHTTPTests.success"))
            let headers = try signedHeaders(fixture.token, path: Self.path, runtime: fixture.runtime, jti: "owner-and-member")
            try await app.test(.router) { client in
                try await client.execute(uri: Self.path, method: .get, headers: headers) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.json(response.body)
                    XCTAssertEqual(Set(body.keys), ["cursor", "spaces"])
                    let spaces = try XCTUnwrap(body["spaces"] as? [[String: Any]])
                    XCTAssertEqual(spaces.map { $0["uri"] as? String }, [fixture.owner.rawValue, fixture.remote.rawValue])
                    XCTAssertEqual(spaces.map { $0["isOwner"] as? Bool }, [true, false])
                    XCTAssertTrue(spaces.allSatisfy { Set($0.keys) == ["uri", "isOwner"] })
                    let rendered = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    for forbidden in ["cid", "blob", "policy", "member", "value", "record"] {
                        XCTAssertFalse(rendered.localizedCaseInsensitiveContains(forbidden), forbidden)
                    }
                }
            }
            try await close(fixture)
        } catch { try? await close(fixture); throw error }
    }

    func testStrictFiltersPagingScopesAndNoBearerCredentialPath() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SpaceListHTTPTests.strict"))
            try await app.test(.router) { client in
                let first = try signedHeaders(fixture.token, path: Self.path, runtime: fixture.runtime, jti: "page-one")
                try await client.execute(uri: "\(Self.path)?limit=1", method: .get, headers: first) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.json(response.body)
                    XCTAssertEqual((body["spaces"] as? [[String: Any]])?.count, 1)
                    XCTAssertEqual(body["cursor"] as? String, fixture.owner.rawValue)
                }
                let next = try signedHeaders(fixture.token, path: Self.path, runtime: fixture.runtime, jti: "page-two")
                try await client.execute(uri: "\(Self.path)?cursor=\(self.percent(fixture.owner.rawValue))", method: .get, headers: next) { response in
                    XCTAssertEqual(response.status, .ok)
                    let spaces = try XCTUnwrap(self.json(response.body)["spaces"] as? [[String: Any]])
                    XCTAssertEqual(spaces.count, 1)
                    XCTAssertEqual(spaces[0]["uri"] as? String, fixture.remote.rawValue)
                    XCTAssertEqual(spaces[0]["isOwner"] as? Bool, false)
                }
                let filtered = try signedHeaders(fixture.token, path: Self.path, runtime: fixture.runtime, jti: "filter")
                try await client.execute(uri: "\(Self.path)?type=app.example.space&did=\(Self.bob)", method: .get, headers: filtered) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(((try self.json(response.body))["spaces"] as? [[String: Any]])?.map { $0["uri"] as? String }, [fixture.remote.rawValue])
                }
                for query in ["?unknown=x", "?limit=0", "?limit=1&limit=2", "?type=invalid", "?did=not-a-did", "?cursor=not-an-at-uri", "?did=\(Self.bob)&cursor=\(self.percent(fixture.owner.rawValue))"] {
                    try await client.execute(uri: "\(Self.path)\(query)", method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest, query)
                    }
                }
                var bearer = HTTPFields(); bearer[.authorization] = "Bearer not-a-space-credential"
                try await client.execute(uri: Self.path, method: .get, headers: bearer) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                let narrowScope = "space:app.example.space?authority=\(Self.bob)&skey=*&action=read"
                let narrow = try await issueToken(fixture.runtime, scopes: [narrowScope])
                let narrowHeaders = try signedHeaders(narrow, path: Self.path, runtime: fixture.runtime, jti: "narrow-allowed")
                try await client.execute(uri: "\(Self.path)?type=app.example.space&did=\(Self.bob)", method: .get, headers: narrowHeaders) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let deniedHeaders = try signedHeaders(narrow, path: Self.path, runtime: fixture.runtime, jti: "narrow-denied")
                try await client.execute(uri: Self.path, method: .get, headers: deniedHeaders) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                let wrongMethod = try signedHeaders(fixture.token, path: Self.path, runtime: fixture.runtime, jti: "wrong-method", method: "POST")
                try await client.execute(uri: Self.path, method: .post, headers: wrongMethod) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            try await close(fixture)
        } catch { try? await close(fixture); throw error }
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appending(path: "SpaceListHTTPTests-\(UUID().uuidString)")
        let owner = try SpaceURI(authority: Self.alice, spaceType: "app.example.space", skey: "owner")
        let remote = try SpaceURI(authority: Self.bob, spaceType: "app.example.space", skey: "remote")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try registration(did: Self.alice, handle: "alice.example.com"))
            let database = try await SQLiteAccountDatabase(dataDirectory: root, did: Self.alice)
            _ = try await database.createSimpleSpace(space: owner, owner: Self.alice, configuration: .init(policy: .public, appAccess: .open), authorization: .accountOAuth(subject: Self.alice, scopes: ["atproto"]))
            let repository = try DurableSpaceRepository(database: database, space: remote, author: Self.alice)
            let uri = try SpaceRecordURI(space: remote, author: Self.alice, collection: "app.example.records", rkey: "one")
            _ = try await repository.apply(.put(uri: uri, value: Data([0xa0])), expectedRevision: 0, requestID: UUID(), wireRevision: try TID(tidString: "3k2l5u2q6za2y"), authorization: .accountOAuth(subject: Self.alice, scopes: ["atproto"]))
            try await database.close()
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(dataDirectory: root, controlStore: control)
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xD1, count: 32))
            return .init(root: root, owner: owner, remote: remote, control: control, directory: directory, runtime: runtime, token: try await issueToken(runtime, scopes: ["atproto"]))
        } catch { try? await control.close(); try? FileManager.default.removeItem(at: root); throw error }
    }

    private func makeServer(_ fixture: Fixture) throws -> SwanHTTPServer {
        try SwanHTTPServer(profile: ProtocolProfile.load(from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")), configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL), oauthRuntime: fixture.runtime, authenticatedGetSpaceDirectory: fixture.directory, accountControlStore: fixture.control)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private func issueToken(_ runtime: SwanOAuthRuntime, scopes: Set<String>) async throws -> Token {
        let key = P256.Signing.PrivateKey(); let jwk = try makeJWK(key); let now = Date()
        let metadata = try OAuthClientMetadata(clientID: URL(string: "https://client.example/metadata")!, redirectURIs: [URL(string: "https://client.example/callback")!], grantTypes: ["authorization_code"], responseTypes: ["code"], scopes: scopes.union(["atproto"]), dpopBoundAccessTokens: true)
        let session = try OAuthValidatedSession(issuer: Self.publicURL.absoluteString, client: .init(metadata: metadata, keySet: nil), redirectURI: URL(string: "https://client.example/callback")!, scopes: scopes, dpopProof: .init(keyThumbprint: jwk.thumbprint(), jwtID: UUID().uuidString, issuedAt: now), now: now)
        return .init(access: try await runtime.tokenService.issue(subject: Self.alice, session: session, now: now).accessToken, key: key, jwk: jwk)
    }

    private func registration(did: String, handle: String) throws -> AccountControlRegistration {
        try .init(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try .init(purpose: .signing, generation: 1),
            rotationKey: try .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func makeJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey {
        let representation = key.publicKey.x963Representation
        return try .init(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
    }

    private func signedHeaders(_ token: Token, path: String, runtime: SwanOAuthRuntime, jti: String, method: String = "GET") throws -> HTTPFields {
        struct Header: Encodable { let alg = "ES256"; let typ = OAuthDPoPProofValidator.proofType; let jwk: OAuthJSONWebKey }
        struct Claims: Encodable { let jti: String; let iat: Int64; let htm: String; let htu: String; let nonce: String; let ath: String }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: token.jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(jti: jti, iat: Int64(Date().timeIntervalSince1970), htm: method, htu: "\(Self.publicURL.absoluteString)\(path)", nonce: runtime.dpopNonceService.issue(), ath: Data(SHA256.hash(data: Data(token.access.utf8))).base64URLEncodedString())).base64URLEncodedString()
        let input = "\(header).\(claims)"; let signature = try P256WireSignature.sign(Data(input.utf8), using: token.key).base64URLEncodedString()
        var headers = HTTPFields(); headers[.authorization] = "DPoP \(token.access)"; headers[HTTPField.Name("DPoP")!] = "\(input).\(signature)"; return headers
    }

    private func close(_ fixture: Fixture) async throws { try await fixture.directory.close(); try await fixture.control.close() }
    private func json(_ body: ByteBuffer) throws -> [String: Any] { try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(body.readableBytesView)) as? [String: Any]) }
    private func percent(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value }
}

private struct SpaceListFixture: Sendable { let root: URL; let owner: SpaceURI; let remote: SpaceURI; let control: SQLiteControlDatabase; let directory: SQLitePreMigratedAccountDirectory; let runtime: SwanOAuthRuntime; let token: SpaceListToken }
private struct SpaceListToken: Sendable { let access: String; let key: P256.Signing.PrivateKey; let jwk: OAuthJSONWebKey }
private typealias Fixture = SpaceListFixture
private typealias Token = SpaceListToken
