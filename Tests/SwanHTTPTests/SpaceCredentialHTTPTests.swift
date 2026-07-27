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

final class SpaceCredentialHTTPTests: XCTestCase, @unchecked Sendable {
    static let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    static let member = "did:plc:bcdefghijklmnopqrstuvwxy"
    static let outsider = "did:plc:cdefghijklmnopqrstuvwxyz"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let credentialPath = "/xrpc/com.atproto.space.getSpaceCredential"
    private static let getPath = "/xrpc/com.atproto.space.getRecord"
    private static let listPath = "/xrpc/com.atproto.space.listRecords"

    func testPublicAndMemberDelegationExchangeIssueCredentialsForCrossRepositoryReads() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.reads")
            )
            let publicDelegation = try delegation(
                fixture,
                user: Self.outsider,
                space: fixture.publicSpace
            )
            let memberDelegation = try delegation(
                fixture,
                user: Self.member,
                space: fixture.memberSpace
            )

            let publicCredential = StringBox()
            let memberCredential = StringBox()
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: exchangeHeaders(publicDelegation),
                    body: exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    XCTAssertEqual(Set(body.keys), ["credential"])
                    publicCredential.set(try XCTUnwrap(body["credential"] as? String))
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: exchangeHeaders(memberDelegation),
                    body: exchangeBody(space: fixture.memberSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    memberCredential.set(try XCTUnwrap(self.jsonObject(response.body)["credential"] as? String))
                }

                let publicToken = try XCTUnwrap(publicCredential.value)
                let memberToken = try XCTUnwrap(memberCredential.value)
                let publicReadHeaders = bearerHeaders(publicToken, dpop: "intentionally-not-a-dpop-proof")
                let memberReadHeaders = bearerHeaders(memberToken)
                try await client.execute(
                    uri: self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public"),
                    method: .get,
                    headers: publicReadHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    XCTAssertEqual(
                        (try self.jsonObject(response.body))["uri"] as? String,
                        fixture.publicRecord.rawValue
                    )
                }
                try await client.execute(
                    uri: self.listURI(space: fixture.memberSpace, repo: Self.member),
                    method: .get,
                    headers: memberReadHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let records = try XCTUnwrap(
                        (try self.jsonObject(response.body))["records"] as? [[String: Any]]
                    )
                    XCTAssertEqual(records.count, 1)
                    XCTAssertEqual(records[0]["rkey"] as? String, "member")
                }
            }
            let inspection = try PermissionedDataJWT.inspectSpaceCredential(
                try XCTUnwrap(publicCredential.value)
            )
            XCTAssertEqual(inspection.claims.iss, Self.authority)
            XCTAssertEqual(inspection.claims.sub, fixture.publicSpace.rawValue)
            XCTAssertEqual(inspection.header.kid, PermissionedDataJWT.spaceCredentialKeyID)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testCredentialExchangeRejectsPolicyAndAttestationBoundariesWithoutStateChanges() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.policy")
            )
            let outsiderMember = try delegation(fixture, user: Self.outsider, space: fixture.memberSpace)
            let outsiderAllow = try delegation(fixture, user: Self.outsider, space: fixture.allowListSpace)
            let memberManaged = try delegation(fixture, user: Self.member, space: fixture.managingSpace)
            try await app.test(.router) { client in
                for (delegation, space) in [
                    (outsiderMember, fixture.memberSpace),
                    (outsiderAllow, fixture.allowListSpace),
                    (memberManaged, fixture.managingSpace),
                ] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(delegation),
                        body: self.exchangeBody(space: space)
                    ) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "NotAuthorized")
                    }
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(outsiderAllow),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: "not-a-verified-attestation"
                    )
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidClientAttestation")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testDelegationValidationRejectsWrongIssuerKeyAudienceSpaceExpiryAndTampering() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.delegation")
            )
            let valid = try delegation(fixture, user: Self.member, space: fixture.publicSpace)
            let otherSpace = try SpaceURI(
                authority: Self.authority,
                spaceType: fixture.publicSpace.spaceType,
                skey: "other-space"
            )
            let wrongSpace = try delegation(fixture, user: Self.member, space: otherSpace)
            let wrongAudience = try signedDelegation(
                issuer: Self.member,
                audience: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey
            )
            let wrongKey = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: P256.Signing.PrivateKey()
            )
            let unknownIssuer = try signedDelegation(
                issuer: "did:plc:defghijklmnopqrstuvwxyz2",
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey
            )
            let excessiveLifetime = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                lifetime: 61
            )
            let futureIssued = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                issuedAt: Int64(Date().timeIntervalSince1970) + 120
            )
            let noncanonicalJTI = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                jti: "not-a-canonical-uuid"
            )
            let expired = try PermissionedDataJWT.createDelegationToken(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                now: Date(timeIntervalSinceNow: -180)
            )
            let tampered = tamperedToken(valid, offsetFromEnd: 5)

            try await app.test(.router) { client in
                for delegation in [
                    wrongSpace, wrongAudience, wrongKey, unknownIssuer,
                    excessiveLifetime, futureIssued, noncanonicalJTI, expired,
                    tampered,
                ] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(delegation),
                        body: self.exchangeBody(space: fixture.publicSpace)
                    ) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidDelegationToken")
                    }
                }

                var first: String?
                var second: String?
                for index in 0 ..< 2 {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(valid),
                        body: self.exchangeBody(space: fixture.publicSpace)
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        let value = try XCTUnwrap(self.jsonObject(response.body)["credential"] as? String)
                        if index == 0 { first = value } else { second = value }
                    }
                }
                // Proposal 0016 and the pinned reference treat delegations as
                // stateless 60-second proofs. Replaying one valid exchange is
                // therefore permitted and must issue fresh credential JTIs.
                XCTAssertNotEqual(first, second)
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testCredentialReadRejectsWrongSpaceExpiredTamperingAndWrites() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.credential-negative")
            )
            let credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: Self.authority,
                space: fixture.publicSpace,
                key: fixture.authorityKey
            )
            let expired = try PermissionedDataJWT.createSpaceCredential(
                issuer: Self.authority,
                space: fixture.publicSpace,
                key: fixture.authorityKey,
                now: Date(timeIntervalSinceNow: -7_300),
                lifetime: 60
            )
            let tampered = tamperedToken(credential, offsetFromEnd: 6)

            try await app.test(.router) { client in
                for (token, uri) in [
                    (credential, self.getURI(space: fixture.memberSpace, repo: Self.member, rkey: "member")),
                    (expired, self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public")),
                    (tampered, self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public")),
                ] {
                    try await client.execute(uri: uri, method: .get, headers: self.bearerHeaders(token)) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                        XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                    }
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.createRecord",
                    method: .post,
                    headers: self.bearerHeaders(credential, contentType: true),
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.publicSpace.rawValue)\",\"repo\":\"\(Self.member)\",\"collection\":\"app.bsky.feed.post\",\"rkey\":\"blocked\",\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"blocked\"}}")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.getDelegationToken?space=\(self.percentEncode(fixture.publicSpace.rawValue))",
                    method: .get,
                    headers: self.bearerHeaders(credential)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testExchangeRejectsDuplicateAndOversizeBodiesAndReadNeverOpensMissingAccountDatabase() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.bounds")
            )
            let delegation = try delegation(fixture, user: Self.outsider, space: fixture.publicSpace)
            let credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: Self.authority,
                space: fixture.publicSpace,
                key: fixture.authorityKey
            )
            let duplicate = "{\"space\":\"\(fixture.publicSpace.rawValue)\",\"space\":\"\(fixture.publicSpace.rawValue)\"}"
            let oversized = "{\"space\":\"\(String(repeating: "a", count: SwanSpaceCredentialHTTP.maximumJSONBytes))\"}"
            try await app.test(.router) { client in
                for body in [duplicate, oversized] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(delegation),
                        body: ByteBuffer(string: body)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                }
            }

            let memberDatabase = SQLiteLayout.accountDatabase(
                in: fixture.root,
                did: Self.member
            )
            try FileManager.default.removeItem(at: memberDatabase)
            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public"),
                    method: .get,
                    headers: self.bearerHeaders(credential)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: memberDatabase.path))
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    private func makeServer(_ fixture: Fixture) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        let signing = StaticSigningKeyResolver(
            authority: Self.authority,
            key: fixture.authorityKey
        )
        let delegationKeys = try PinnedSpaceDelegationPublicKeyResolver(pins: [
            try .init(issuer: Self.member, generation: 1, publicKey: fixture.memberKey.publicKey),
            try .init(issuer: Self.outsider, generation: 1, publicKey: fixture.outsiderKey.publicKey),
        ])
        let credentialKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: Self.authority, generation: 1, publicKey: fixture.authorityKey.publicKey),
        ])
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: signing,
                delegationPublicKeys: delegationKeys,
                credentialPublicKeys: credentialKeys
            )
        )
    }

    private func delegation(
        _ fixture: Fixture,
        user: String,
        space: SpaceURI
    ) throws -> String {
        let key: P256.Signing.PrivateKey = user == Self.member
            ? fixture.memberKey
            : fixture.outsiderKey
        return try PermissionedDataJWT.createDelegationToken(
            issuer: user,
            audience: "\(space.authority)#atproto_space_host",
            space: space,
            key: key
        )
    }

    private func signedDelegation(
        issuer: String,
        audience: String,
        space: SpaceURI,
        key: P256.Signing.PrivateKey,
        issuedAt: Int64? = nil,
        lifetime: Int64 = 60,
        jti: String = UUID().uuidString
    ) throws -> String {
        struct Header: Encodable {
            let alg = "ES256"
            let typ = PermissionedDataJWT.delegationType
            let kid = PermissionedDataJWT.delegationKeyID
        }
        struct Claims: Encodable {
            let iss: String
            let aud: String
            let sub: String
            let iat: Int64
            let exp: Int64
            let jti: String
        }
        let now = issuedAt ?? Int64(Date().timeIntervalSince1970)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header()).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            iss: issuer,
            aud: audience,
            sub: space.rawValue,
            iat: now,
            exp: now + lifetime,
            jti: jti
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(
            Data(input.utf8),
            using: key
        ).base64URLEncodedString()
        return "\(input).\(signature)"
    }

    private func exchangeHeaders(_ token: String) -> HTTPFields {
        bearerHeaders(token, contentType: true)
    }

    private func bearerHeaders(
        _ token: String,
        dpop: String? = nil,
        contentType: Bool = false
    ) -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "Bearer \(token)"
        if contentType { headers[.contentType] = "application/json" }
        if let dpop { headers[HTTPField.Name("DPoP")!] = dpop }
        return headers
    }

    private func exchangeBody(
        space: SpaceURI,
        clientAttestation: String? = nil
    ) -> ByteBuffer {
        let fields = [
            "\"space\":\"\(space.rawValue)\"",
            clientAttestation.map { "\"clientAttestation\":\"\($0)\"" },
        ].compactMap { $0 }
        return ByteBuffer(string: "{\(fields.joined(separator: ","))}")
    }

    private func getURI(space: SpaceURI, repo: String, rkey: String) -> String {
        "\(Self.getPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)&collection=app.bsky.feed.post&rkey=\(rkey)"
    }

    private func listURI(space: SpaceURI, repo: String) -> String {
        "\(Self.listPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)"
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

    private func recordCBOR(_ text: String) -> Data {
        Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, UInt8(0x60 + text.utf8.count)]) + Data(text.utf8)
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

    private func percentEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private func tamperedToken(_ token: String, offsetFromEnd: Int) -> String {
        var result = token
        let index = result.index(result.endIndex, offsetBy: -offsetFromEnd)
        result.replaceSubrange(index ... index, with: result[index] == "A" ? "B" : "A")
        return result
    }
}

private final class StringBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: String?

    func set(_ value: String) {
        lock.lock()
        storage = value
        lock.unlock()
    }

    var value: String? {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private struct StaticSigningKeyResolver: SpaceCredentialSigningKeyResolver {
    let authority: String
    let key: P256.Signing.PrivateKey

    func signingKey(
        for authority: String
    ) async throws -> SpaceCredentialAuthoritySigningKey? {
        guard authority == self.authority else { return nil }
        return SpaceCredentialAuthoritySigningKey(
            authority: authority,
            privateKey: key
        )
    }
}

private struct Fixture: Sendable {
    let root: URL
    let publicSpace: SpaceURI
    let memberSpace: SpaceURI
    let allowListSpace: SpaceURI
    let managingSpace: SpaceURI
    let publicRecord: SpaceRecordURI
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let runtime: SwanOAuthRuntime
    let authorityKey: P256.Signing.PrivateKey
    let memberKey: P256.Signing.PrivateKey
    let outsiderKey: P256.Signing.PrivateKey

    static func make() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SpaceCredentialHTTPTests-\(UUID().uuidString)")
        let publicSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-public"
        )
        let memberSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-member"
        )
        let allowListSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-app"
        )
        let managingSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-managed"
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try registration(
                did: SpaceCredentialHTTPTests.authority,
                handle: "authority.example.com"
            ))
            _ = try await control.createAccount(try registration(
                did: SpaceCredentialHTTPTests.member,
                handle: "member.example.com"
            ))
            let authorityDatabase = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: SpaceCredentialHTTPTests.authority
            )
            let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: authorityDatabase)
            let controlAuthorization: AuthorizationContext = .accountOAuth(
                subject: SpaceCredentialHTTPTests.authority,
                scopes: ["atproto"]
            )
            _ = try await authority.create(
                space: publicSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(policy: .public, appAccess: .open),
                authorization: controlAuthorization
            )
            _ = try await authority.create(
                space: memberSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(policy: .memberList, appAccess: .open),
                authorization: controlAuthorization
            )
            _ = try await authority.addMember(
                space: memberSpace,
                member: SpaceCredentialHTTPTests.member,
                authorization: controlAuthorization
            )
            _ = try await authority.create(
                space: allowListSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(
                    policy: .public,
                    appAccess: .allowList(["https://reader.example/client-metadata.json"])
                ),
                authorization: controlAuthorization
            )
            _ = try await authority.create(
                space: managingSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(
                    policy: .managingApp,
                    appAccess: .open,
                    managingApp: "did:web:managing.example#space"
                ),
                authorization: controlAuthorization
            )
            try await authorityDatabase.close()

            let memberDatabase = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: SpaceCredentialHTTPTests.member
            )
            let publicRecord = try SpaceRecordURI(
                space: publicSpace,
                author: SpaceCredentialHTTPTests.member,
                collection: "app.bsky.feed.post",
                rkey: "public"
            )
            let memberRecord = try SpaceRecordURI(
                space: memberSpace,
                author: SpaceCredentialHTTPTests.member,
                collection: "app.bsky.feed.post",
                rkey: "member"
            )
            let memberAuthorization: AuthorizationContext = .accountOAuth(
                subject: SpaceCredentialHTTPTests.member,
                scopes: ["atproto"]
            )
            let publicRepository = try DurableSpaceRepository(
                database: memberDatabase,
                space: publicSpace,
                author: SpaceCredentialHTTPTests.member
            )
            _ = try await publicRepository.apply(
                .put(uri: publicRecord, value: recordCBOR("public")),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                authorization: memberAuthorization
            )
            let memberRepository = try DurableSpaceRepository(
                database: memberDatabase,
                space: memberSpace,
                author: SpaceCredentialHTTPTests.member
            )
            _ = try await memberRepository.apply(
                .put(uri: memberRecord, value: recordCBOR("member")),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                authorization: memberAuthorization
            )
            try await memberDatabase.close()

            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0xC3, count: 32)
            )
            return Fixture(
                root: root,
                publicSpace: publicSpace,
                memberSpace: memberSpace,
                allowListSpace: allowListSpace,
                managingSpace: managingSpace,
                publicRecord: publicRecord,
                control: control,
                directory: directory,
                runtime: runtime,
                authorityKey: P256.Signing.PrivateKey(),
                memberKey: P256.Signing.PrivateKey(),
                outsiderKey: P256.Signing.PrivateKey()
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func close() async throws {
        try await directory.close()
        try await control.close()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }

    private static func registration(
        did: String,
        handle: String
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private static func recordCBOR(_ text: String) -> Data {
        Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, UInt8(0x60 + text.utf8.count)]) + Data(text.utf8)
    }
}
