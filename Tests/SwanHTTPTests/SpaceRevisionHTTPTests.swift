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

/// atproto#5574 over HTTP, against the real preopened SQLite directory:
/// notifyWrite (repo host -> space host) and listRepos paging by `spaceRev`.
final class SpaceRevisionHTTPTests: XCTestCase, @unchecked Sendable {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let dan = "did:plc:cdefghijklmnopqrstuvwxyz"

    func testNotifyWriteSequencesAndListReposPagesBySpaceRevision() async throws {
        let fixture = try await SpaceRevisionHTTPFixture.make(authority: authority, members: [bob, dan])
        do {
            let app = try fixture.server().buildApplication(logger: Logger(label: "SpaceRevisionHTTPTests"))
            let bobRev = Self.tid(at: Date().addingTimeInterval(-20))
            let danRev = Self.tid(at: Date().addingTimeInterval(-10))
            try await app.test(.router) { client in
                // October 22 (atproto ac0c9f15, guide sections 3 and 4a):
                // the retired `#atproto_space_host` audience and the
                // pre-rename `hash` body are refused before anything is
                // sequenced.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: "\(self.authority)#atproto_space_host", jti: "bob-retired-audience"),
                    body: fixture.writeBody(repo: self.bob, repoRev: bobRev)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: "\(self.authority)#atproto_pds", jti: "bob-legacy-hash"),
                    body: fixture.legacyHashWriteBody(repo: self.bob, repoRev: bobRev)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try Self.json(response.body)["error"] as? String, "InvalidRequest")
                }
                // The reference sender's audience, then the bare DID: both
                // name this space host in the hardened posture.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: "\(self.authority)#atproto_pds", jti: "bob-1"),
                    body: fixture.writeBody(repo: self.bob, repoRev: bobRev)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.dan, audience: self.authority, jti: "dan-1"),
                    body: fixture.writeBody(repo: self.dan, repoRev: danRev)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Another authority's space-host identifier is not this one.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: "did:plc:zyxwvutsrqponmlkjihgfedc#atproto_pds", jti: "bob-foreign"),
                    body: fixture.writeBody(repo: self.bob, repoRev: Self.tid(at: Date()))
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }

                let listURI = "/xrpc/com.atproto.space.listRepos?space=\(fixture.encodedSpace)"
                var checkpoint = ""
                try await client.execute(uri: listURI, method: .get, headers: try fixture.credentialHeaders()) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try Self.json(response.body)
                    XCTAssertEqual(Set(value.keys), ["repos", "cursor"], "no top-level spaceRev")
                    let repos = try XCTUnwrap(value["repos"] as? [[String: Any]])
                    XCTAssertEqual(repos.compactMap { $0["did"] as? String }, [self.bob, self.dan])
                    XCTAssertEqual(repos.compactMap { $0["repoRev"] as? String }, [bobRev, danRev])
                    let revisions = repos.compactMap { $0["spaceRev"] as? String }
                    XCTAssertEqual(revisions.count, 2)
                    // Indexing an empty page would trap and take every later
                    // SwanHTTPTests class down with it.
                    if revisions.count == 2 {
                        XCTAssertLessThan(revisions[0], revisions[1])
                    }
                    for repo in repos {
                        // The generated encoder also writes the object's
                        // `$type`, which Lexicon permits on a ref. October 22
                        // renamed the entry's `hash` to `data`.
                        XCTAssertEqual(
                            Set(repo.keys).subtracting(["$type"]),
                            ["did", "repoRev", "data", "spaceRev"]
                        )
                        XCTAssertNil(repo["rev"])
                    }
                    XCTAssertEqual(value["cursor"] as? String, revisions.last)
                    checkpoint = try XCTUnwrap(value["cursor"] as? String)
                }
                // A short page still returns its last spaceRev as the cursor.
                try await client.execute(uri: "\(listURI)&limit=1", method: .get, headers: try fixture.credentialHeaders()) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try Self.json(response.body)
                    let repos = try XCTUnwrap(value["repos"] as? [[String: Any]])
                    XCTAssertEqual(repos.count, 1)
                    XCTAssertEqual(value["cursor"] as? String, repos.first?["spaceRev"] as? String)
                }
                // Caught up: an empty page omits the cursor entirely.
                try await client.execute(uri: "\(listURI)&cursor=\(checkpoint)", method: .get, headers: try fixture.credentialHeaders()) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try Self.json(response.body)
                    XCTAssertEqual(Set(value.keys), ["repos"])
                    XCTAssertEqual((value["repos"] as? [Any])?.count, 0)
                }
                // A newer repoRev is listed after the checkpoint; a replay of
                // an already-accepted one is not.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: self.authority, jti: "bob-replayed-state"),
                    body: fixture.writeBody(repo: self.bob, repoRev: bobRev)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "\(listURI)&cursor=\(checkpoint)", method: .get, headers: try fixture.credentialHeaders()) { response in
                    XCTAssertEqual((try Self.json(response.body)["repos"] as? [Any])?.count, 0)
                }
                let bobNewer = Self.tid(at: Date())
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: self.authority, jti: "bob-2"),
                    body: fixture.writeBody(repo: self.bob, repoRev: bobNewer)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "\(listURI)&cursor=\(checkpoint)", method: .get, headers: try fixture.credentialHeaders()) { response in
                    let value = try Self.json(response.body)
                    let repos = try XCTUnwrap(value["repos"] as? [[String: Any]])
                    XCTAssertEqual(repos.compactMap { $0["did"] as? String }, [self.bob])
                    XCTAssertEqual(repos.first?["repoRev"] as? String, bobNewer)
                    let spaceRev = try XCTUnwrap(repos.first?["spaceRev"] as? String)
                    XCTAssertGreaterThan(spaceRev, checkpoint)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testNotifyWriteAnswersFutureRevAndSpaceNotFound() async throws {
        let fixture = try await SpaceRevisionHTTPFixture.make(authority: authority, members: [bob])
        do {
            let app = try fixture.server().buildApplication(logger: Logger(label: "SpaceRevisionHTTPTests"))
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: self.authority, jti: "future"),
                    body: fixture.writeBody(repo: self.bob, repoRev: Self.tid(at: Date().addingTimeInterval(600)))
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try Self.json(response.body)["error"] as? String, "FutureRev")
                }
                // Positive control: inside the five-minute allowance.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: self.authority, jti: "skewed"),
                    body: fixture.writeBody(repo: self.bob, repoRev: Self.tid(at: Date().addingTimeInterval(60)))
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let unknownSpace = try SpaceURI(authority: self.authority, spaceType: "app.bsky.bookmarks", skey: "missing")
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: self.authority, jti: "unknown-space"),
                    body: fixture.writeBody(repo: self.bob, repoRev: Self.tid(at: Date()), space: unknownSpace)
                ) { response in
                    XCTAssertEqual(try Self.json(response.body)["error"] as? String, "SpaceNotFound")
                }
                let foreignAuthority = "did:plc:zyxwvutsrqponmlkjihgfedc"
                let foreignSpace = try SpaceURI(authority: foreignAuthority, spaceType: "app.bsky.bookmarks", skey: "elsewhere")
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite", method: .post,
                    headers: Self.serviceHeaders(issuer: self.bob, audience: foreignAuthority, jti: "unhosted-authority"),
                    body: fixture.writeBody(repo: self.bob, repoRev: Self.tid(at: Date()), space: foreignSpace)
                ) { response in
                    XCTAssertEqual(try Self.json(response.body)["error"] as? String, "SpaceNotFound")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// A TID for `date` (clock ID 0): 53-bit microseconds, 10-bit clock ID,
    /// 13 base32-sortable characters.
    static func tid(at date: Date) -> String {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        var value = UInt64(date.timeIntervalSince1970 * 1_000_000) << 10
        var characters = [Character](repeating: "2", count: 13)
        for index in stride(from: 12, through: 0, by: -1) {
            characters[index] = alphabet[Int(value & 31)]
            value >>= 5
        }
        return String(characters)
    }

    static func serviceHeaders(issuer: String, audience: String, jti: String) -> HTTPFields {
        var fields: HTTPFields = [.contentType: "application/json"]
        fields[.authorization] = "Bearer svc~\(issuer)~\(audience)~\(jti)"
        return fields
    }

    static func json(_ body: ByteBuffer) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
    }
}

private struct SpaceRevisionHTTPFixture {
    let root: URL
    let authority: String
    let space: SpaceURI
    let key: P256.Signing.PrivateKey
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let runtime: SwanOAuthRuntime

    var encodedSpace: String {
        space.rawValue.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    static func make(authority: String, members: [String]) async throws -> SpaceRevisionHTTPFixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceRevisionHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try .init(
                did: authority,
                canonicalHandle: "authority.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "sequenced")
            let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
            let owner = AuthorizationContext.accountOAuthForTesting(subject: authority, scopes: ["atproto"])
            let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
            _ = try await lifecycle.create(
                space: space,
                owner: authority,
                configuration: try .init(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
                authorization: owner
            )
            for member in members {
                _ = try await lifecycle.addMember(space: space, member: member, authorization: owner)
            }
            try await database.close()
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            return SpaceRevisionHTTPFixture(
                root: root,
                authority: authority,
                space: space,
                key: P256.Signing.PrivateKey(),
                control: control,
                directory: directory,
                runtime: try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xA7, count: 32))
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func server() throws -> SwanHTTPServer {
        SwanHTTPServer(
            profile: try ProtocolProfile.load(from: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appending(path: "Profiles/permissioned-data-0016-2026-10-01.json")),
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: URL(string: "https://swan.example")!),
            oauthRuntime: runtime,
            authenticatedGetSpaceDirectory: directory,
            accountControlStore: control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: SpaceRevisionNoSigningKeys(),
                delegationPublicKeys: UnavailableSpaceDelegationPublicKeyResolver(),
                credentialPublicKeys: try PinnedSpaceCredentialPublicKeyResolver(pins: [
                    try .init(authority: authority, generation: 1, publicKey: key.publicKey),
                ])
            ),
            spaceNotificationConfiguration: .init(serviceAuthentication: EchoingServiceVerifier())
        )
    }

    /// listRepos is a space-host operation: the signed audience is the
    /// authority's bare DID.
    func credentialHeaders() throws -> HTTPFields {
        let credential = try PermissionedDataJWT.createSpaceCredential(
            issuer: authority, space: space, key: key,
            confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
        )
        return try SpaceCredentialSignatureTestSupport.headers(token: credential, audience: authority)
    }

    /// The October 22 notifyWrite body: the set-hash digest is `data`.
    func writeBody(repo: String, repoRev: String, space: SpaceURI? = nil) -> ByteBuffer {
        writeBody(repo: repo, repoRev: repoRev, space: space, digestKey: "data")
    }

    /// The pre-October 22 body, which named the same digest `hash`.
    func legacyHashWriteBody(repo: String, repoRev: String) -> ByteBuffer {
        writeBody(repo: repo, repoRev: repoRev, space: nil, digestKey: "hash")
    }

    private func writeBody(repo: String, repoRev: String, space: SpaceURI?, digestKey: String) -> ByteBuffer {
        let digest = Data(repeating: 0x5C, count: 32).base64EncodedString()
        let target = (space ?? self.space).rawValue
        return ByteBuffer(string: #"{"space":"\#(target)","repo":"\#(repo)","repoRev":"\#(repoRev)","\#(digestKey)":{"$bytes":"\#(digest)"}}"#)
    }

    func close() async throws {
        defer { try? FileManager.default.removeItem(at: root) }
        try await directory.close()
        try await control.close()
    }
}

private struct SpaceRevisionNoSigningKeys: SpaceCredentialSigningKeyResolver {
    func signingKey(for _: String) async throws -> SpaceCredentialAuthoritySigningKey? { nil }
}

/// `svc~<iss>~<aud>~<jti>` stands for a verified service JWT that binds
/// whatever body digest the route expects; signature verification itself is
/// covered by the SwanOAuth service-auth tests.
private struct EchoingServiceVerifier: SpaceServiceAuthenticationVerifier {
    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        expectedRequestBodyDigest: String?,
        now: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        let parts = compact.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 4, parts[0] == "svc",
              expectedAudience.map({ $0 == parts[2] }) ?? true else {
            throw SwanError.unauthorized("service authentication is invalid")
        }
        return VerifiedSpaceServiceAuthentication(
            issuer: parts[1],
            audience: parts[2],
            method: expectedMethod,
            eventID: parts[3],
            requestBodyDigest: expectedRequestBodyDigest,
            expiresAt: now.addingTimeInterval(60)
        )
    }
}
