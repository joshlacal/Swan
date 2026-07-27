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

final class PermissionedRecordReadHTTPTests: XCTestCase, @unchecked Sendable {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let getPath = "/xrpc/com.atproto.space.getRecord"
    private static let listPath = "/xrpc/com.atproto.space.listRecords"
    private static let collection = "app.bsky.feed.post"
    private static let otherCollection = "app.example.records.item"

    func testDurableOAuthGetAndListUseExactWireProjectionAndReferencePagination() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordReadHTTPTests.success")
            )
            let getURI = getURI(fixture, collection: Self.collection, rkey: "first")
            let getHeaders = try signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "get-success")
            let listHeaders = try signedHeaders(fixture, subject: Self.alice, path: Self.listPath, jti: "list-default")

            try await app.test(.router) { client in
                try await client.execute(uri: getURI, method: .get, headers: getHeaders) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    XCTAssertEqual(Set(body.keys), ["uri", "cid", "value"])
                    XCTAssertEqual(body["uri"] as? String, fixture.recordURIs[0].rawValue)
                    XCTAssertNotNil(body["cid"] as? String)
                    XCTAssertEqual((body["value"] as? [String: Any])?["text"] as? String, "first")
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("$type"))
                }

                try await client.execute(uri: listURI(fixture, limit: 2), method: .get, headers: listHeaders) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    let records = try XCTUnwrap(body["records"] as? [[String: Any]])
                    XCTAssertEqual(records.count, 2)
                    // The pinned reader is descending by default.
                    XCTAssertEqual(records.map { "\($0["collection"] as! String)/\($0["rkey"] as! String)" }, [
                        "\(Self.otherCollection)/third",
                        "\(Self.collection)/second",
                    ])
                    XCTAssertEqual(body["cursor"] as? String, "\(Self.collection)/second")
                    XCTAssertFalse(records.flatMap(\.keys).contains("$type"))
                }

                let nextHeaders = try self.signedHeaders(fixture, subject: Self.alice, path: Self.listPath, jti: "list-next")
                try await client.execute(
                    uri: self.listURI(fixture, limit: 2, cursor: "\(Self.collection)/second"),
                    method: .get,
                    headers: nextHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let records = try XCTUnwrap((try self.jsonObject(response.body))["records"] as? [[String: Any]])
                    XCTAssertEqual(records.map { $0["rkey"] as? String }, ["first"])
                    XCTAssertEqual((try self.jsonObject(response.body))["cursor"] as? String, "\(Self.collection)/first")
                }

                let reverseHeaders = try self.signedHeaders(fixture, subject: Self.alice, path: Self.listPath, jti: "list-reverse")
                try await client.execute(
                    uri: self.listURI(fixture, collection: Self.collection, limit: 2, reverse: true),
                    method: .get,
                    headers: reverseHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let records = try XCTUnwrap((try self.jsonObject(response.body))["records"] as? [[String: Any]])
                    XCTAssertEqual(records.map { $0["rkey"] as? String }, ["first", "second"])
                }

                let excludedHeaders = try self.signedHeaders(fixture, subject: Self.alice, path: Self.listPath, jti: "list-excluded")
                try await client.execute(
                    uri: self.listURI(fixture, collection: Self.collection, excludeValues: true),
                    method: .get,
                    headers: excludedHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let records = try XCTUnwrap((try self.jsonObject(response.body))["records"] as? [[String: Any]])
                    XCTAssertTrue(records.allSatisfy { $0["value"] == nil })
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testSelfOnlyAndNarrowSpaceReadGrantsCannotRevealOtherRepositoriesOrCollections() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordReadHTTPTests.scope")
            )
            let broadOther = try signedHeaders(fixture, subject: Self.bob, path: Self.getPath, jti: "other-repository")
            let narrowScope = "space:app.bsky.bookmarks?authority=\(Self.alice)&skey=record-read&action=read&collection=\(Self.collection)"
            let narrow = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [narrowScope])
            let narrowGet = try signedHeaders(
                token: narrow.token,
                key: narrow.key,
                jwk: narrow.jwk,
                path: Self.getPath,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "narrow-get"
            )
            let narrowList = try signedHeaders(
                token: narrow.token,
                key: narrow.key,
                jwk: narrow.jwk,
                path: Self.listPath,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "narrow-list"
            )
            let narrowOtherCollection = try signedHeaders(
                token: narrow.token,
                key: narrow.key,
                jwk: narrow.jwk,
                path: Self.getPath,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "narrow-other"
            )

            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: "first"),
                    method: .get,
                    headers: broadOther
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: "first"),
                    method: .get,
                    headers: narrowGet
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                }
                try await client.execute(
                    uri: self.listURI(fixture, collection: Self.collection),
                    method: .get,
                    headers: narrowList
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let records = try XCTUnwrap((try self.jsonObject(response.body))["records"] as? [[String: Any]])
                    XCTAssertEqual(records.count, 2)
                }
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.otherCollection, rkey: "third"),
                    method: .get,
                    headers: narrowOtherCollection
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testRecordReadInputAndAuthorizationFailuresStayOpaqueAndClosed() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordReadHTTPTests.failures")
            )
            let validGet = getURI(fixture, collection: Self.collection, rkey: "first")
            let validList = listURI(fixture)
            let invalidGetQueries = [
                "",
                "space=bad&repo=\(Self.alice)&collection=\(Self.collection)&rkey=first",
                "space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&repo=\(Self.alice)&collection=\(Self.collection)&rkey=first",
                "space=%&repo=\(Self.alice)&collection=\(Self.collection)&rkey=first",
                "space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&collection=\(Self.collection)&rkey=first&other=value",
            ]
            let invalidListQueries = [
                "space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&limit=0",
                "space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&limit=101",
                "space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&reverse=yes",
                "space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&cursor=%00",
            ]
            let missingProof = authorizationHeaders(token: fixture.aliceToken)
            let replay = try signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "replay")
            let badTarget = try signedHeaders(fixture, subject: Self.alice, path: "/xrpc/not-this", jti: "bad-target")
            let expired = try signedHeaders(
                fixture,
                subject: Self.alice,
                path: Self.getPath,
                jti: "expired-proof",
                issuedAt: Date(timeIntervalSinceNow: -3_600)
            )

            try await app.test(.router) { client in
                for query in invalidGetQueries {
                    let suffix = query.isEmpty ? "" : "?\(query)"
                    try await client.execute(uri: "\(Self.getPath)\(suffix)", method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest, query)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                }
                for query in invalidListQueries {
                    try await client.execute(uri: "\(Self.listPath)?\(query)", method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest, query)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                }
                try await client.execute(uri: validGet, method: .get, headers: missingProof) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(response.headers[.wwwAuthenticate], "DPoP error=\"use_dpop_nonce\"")
                    XCTAssertNotNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                }
                try await client.execute(uri: validGet, method: .get, headers: badTarget) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                try await client.execute(uri: validGet, method: .get, headers: expired) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                let missingHeaders = try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "missing-record")
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: "missing"),
                    method: .get,
                    headers: missingHeaders
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "RecordNotFound")
                }
                try await client.execute(uri: validGet, method: .get, headers: replay) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: validGet, method: .get, headers: replay) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                let malformedCursorHeaders = try self.signedHeaders(fixture, subject: Self.alice, path: Self.listPath, jti: "cursor-tolerant")
                try await client.execute(
                    uri: "\(validList)&cursor=not-a-valid-cursor",
                    method: .get,
                    headers: malformedCursorHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let records = try XCTUnwrap((try self.jsonObject(response.body))["records"] as? [[String: Any]])
                    XCTAssertEqual(records.count, 3)
                }
                try await client.execute(uri: validList, method: .post) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
            }

            _ = try await fixture.control.transitionStatus(
                did: Self.alice,
                to: .deactivated,
                declaration: .init(),
                now: Date()
            )
            let inactive = try signedHeaders(fixture, subject: Self.alice, path: Self.listPath, jti: "inactive")
            try await app.test(.router) { client in
                try await client.execute(uri: validList, method: .get, headers: inactive) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                // The general public repository route has no permissioned
                // backing and cannot reveal a value by substituting its URI.
                try await client.execute(
                    uri: "/xrpc/com.atproto.repo.getRecord?repo=\(Self.alice)&collection=\(Self.collection)&rkey=first",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("first"))
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testUnavailablePreopenedDirectoryStaysClosedWithoutRecreatingAccountDatabase() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordReadHTTPTests.unavailable")
            )
            let accountPath = SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice)
            try FileManager.default.removeItem(at: accountPath)
            let headers = try signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "missing-db")
            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: "first"),
                    method: .get,
                    headers: headers
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: accountPath.path))

            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
            )
            let closed = SwanHTTPServer(
                profile: profile,
                configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
                oauthRuntime: fixture.runtime
            ).buildApplication(logger: Logger(label: "PermissionedRecordReadHTTPTests.closed"))
            try await closed.test(.router) { client in
                try await client.execute(
                    uri: self.listURI(fixture),
                    method: .get
                ) { response in
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

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedRecordReadHTTPTests-\(UUID().uuidString)")
        let space = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "record-read")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(registration(did: Self.alice, handle: "alice.example.com"))
            _ = try await control.createAccount(registration(did: Self.bob, handle: "bob.example.com"))
            let records = try await installRecords(root: root, space: space)
            try await installEmptyAccountDatabase(root: root, did: Self.bob)
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(dataDirectory: root, controlStore: control)
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xB7, count: 32))
            let alice = try await issueToken(runtime, subject: Self.alice, scopes: ["atproto"])
            let bob = try await issueToken(runtime, subject: Self.bob, scopes: ["atproto"])
            return Fixture(
                root: root,
                space: space,
                control: control,
                directory: directory,
                runtime: runtime,
                aliceToken: alice.token,
                aliceKey: alice.key,
                aliceJWK: alice.jwk,
                bobToken: bob.token,
                bobKey: bob.key,
                bobJWK: bob.jwk,
                recordURIs: records
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func installRecords(root: URL, space: SpaceURI) async throws -> [SpaceRecordURI] {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: Self.alice)
        do {
            let repository = try DurableSpaceRepository(database: database, space: space, author: Self.alice)
            let records = [
                try SpaceRecordURI(space: space, author: Self.alice, collection: Self.collection, rkey: "first"),
                try SpaceRecordURI(space: space, author: Self.alice, collection: Self.collection, rkey: "second"),
                try SpaceRecordURI(space: space, author: Self.alice, collection: Self.otherCollection, rkey: "third"),
            ]
            let values = ["first", "second", "third"]
            for (index, record) in records.enumerated() {
                _ = try await repository.apply(
                    .put(uri: record, value: recordCBOR(values[index])),
                    expectedRevision: UInt64(index),
                    requestID: UUID(),
                    wireRevision: try tid(index),
                    authorization: .accountOAuth(subject: Self.alice, scopes: ["atproto"])
                )
            }
            try await database.close()
            return records
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func recordCBOR(_ text: String) -> Data {
        // Canonical DAG-CBOR for {"text": text}; fixtures use only these
        // short ASCII literals, keeping the durable source explicit.
        Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, UInt8(0x60 + text.utf8.count)]) + Data(text.utf8)
    }

    private func installEmptyAccountDatabase(root: URL, did: String) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        try await database.close()
    }

    private func makeServer(_ fixture: Fixture) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control
        )
    }

    private func issueToken(
        _ runtime: SwanOAuthRuntime,
        subject: String,
        scopes: Set<String>
    ) async throws -> TokenMaterial {
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
                    // Client metadata retains the mandatory base AT Protocol
                    // capability even when this individual token asks only
                    // for a narrow permissioned-space grant.
                    scopes: scopes.union(["atproto"]),
                    dpopBoundAccessTokens: true
                ),
                keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: scopes,
            dpopProof: OAuthValidatedDPoPProof(keyThumbprint: jwk.thumbprint(), jwtID: "record-read-issue-\(UUID().uuidString)", issuedAt: now),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(subject: subject, session: session, now: now)
        return TokenMaterial(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func signedHeaders(
        _ fixture: Fixture,
        subject: String,
        path: String,
        jti: String,
        issuedAt: Date = Date()
    ) throws -> HTTPFields {
        let material = subject == Self.alice
            ? TokenMaterial(token: fixture.aliceToken, key: fixture.aliceKey, jwk: fixture.aliceJWK)
            : TokenMaterial(token: fixture.bobToken, key: fixture.bobKey, jwk: fixture.bobJWK)
        return try signedHeaders(
            token: material.token,
            key: material.key,
            jwk: material.jwk,
            path: path,
            nonce: fixture.runtime.dpopNonceService.issue(),
            jti: jti,
            issuedAt: issuedAt
        )
    }

    private func signedHeaders(
        token: String,
        key: P256.Signing.PrivateKey,
        jwk: OAuthJSONWebKey,
        path: String,
        nonce: String,
        jti: String,
        issuedAt: Date = Date()
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
            iat: Int64(issuedAt.timeIntervalSince1970),
            htm: "GET",
            htu: "\(Self.publicURL.absoluteString)\(path)",
            nonce: nonce,
            ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString()
        return authorizationHeaders(token: token, proof: "\(input).\(signature)")
    }

    private func authorizationHeaders(token: String, proof: String? = nil) -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token)"
        if let proof { headers[HTTPField.Name("DPoP")!] = proof }
        return headers
    }

    private func getURI(_ fixture: Fixture, collection: String, rkey: String) -> String {
        "\(Self.getPath)?space=\(percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&collection=\(collection)&rkey=\(rkey)"
    }

    private func listURI(
        _ fixture: Fixture,
        collection: String? = nil,
        limit: Int? = nil,
        cursor: String? = nil,
        reverse: Bool? = nil,
        excludeValues: Bool? = nil
    ) -> String {
        var fields = ["space=\(percentEncode(fixture.space.rawValue))", "repo=\(Self.alice)"]
        if let collection { fields.append("collection=\(collection)") }
        if let limit { fields.append("limit=\(limit)") }
        if let cursor { fields.append("cursor=\(percentEncode(cursor))") }
        if let reverse { fields.append("reverse=\(reverse ? "true" : "false")") }
        if let excludeValues { fields.append("excludeValues=\(excludeValues ? "true" : "false")") }
        return "\(Self.listPath)?\(fields.joined(separator: "&"))"
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

    private func tid(_ offset: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])")
    }

    private func close(_ fixture: Fixture) async throws {
        try await fixture.directory.close()
        try await fixture.control.close()
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

    private func assertNoStore(_ response: TestResponse, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
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
    let aliceToken: String
    let aliceKey: P256.Signing.PrivateKey
    let aliceJWK: OAuthJSONWebKey
    let bobToken: String
    let bobKey: P256.Signing.PrivateKey
    let bobJWK: OAuthJSONWebKey
    let recordURIs: [SpaceRecordURI]
}
