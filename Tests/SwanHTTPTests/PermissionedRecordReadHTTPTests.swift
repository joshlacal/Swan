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
    private static let createPath = "/xrpc/com.atproto.space.createRecord"
    private static let putPath = "/xrpc/com.atproto.space.putRecord"
    private static let deletePath = "/xrpc/com.atproto.space.deleteRecord"
    private static let applyPath = "/xrpc/com.atproto.space.applyWrites"

    func testPermissionedWriteAdmissionReturnsTemporaryUnavailableBeforeDecode() async throws {
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
                server.authenticatedSpaceRecords?.jsonWriteAdmission
                    === admission
            )
            let held = try XCTUnwrap(
                admission.reserve(maximumRequestBytes: maximum)
            )
            let app = server.buildApplication(
                logger: Logger(label: "PermissionedRecordWriteAdmissionTests")
            )
            let body = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","record":{"$type":"app.bsky.feed.post"}}"#
            try await app.test(.router) { client in
                let response = try await client.execute(
                    uri: Self.createPath,
                    method: .post,
                    headers: try writeHeaders(
                        fixture,
                        path: Self.createPath,
                        jti: "permissioned-write-admission"
                    ),
                    body: ByteBuffer(string: body)
                )
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.jsonObject(response.body)["error"] as? String,
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
            let narrowForeignAuthority = try signedHeaders(
                token: narrow.token,
                key: narrow.key,
                jwk: narrow.jwk,
                path: Self.getPath,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "narrow-foreign-authority"
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
                // The record exists in Alice's opened repository, but an
                // exact grant for Alice's space cannot be replayed against a
                // space with Bob as authority.
                try await client.execute(
                    uri: self.getURI(
                        fixture,
                        space: fixture.foreignSpace,
                        collection: Self.collection,
                        rkey: "foreign"
                    ),
                    method: .get,
                    headers: narrowForeignAuthority
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

    func testBareAndActionUnqualifiedSpaceScopesCannotBecomeDurableTokens() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let exactScope = "space:app.bsky.bookmarks?authority=\(Self.alice)&skey=record-read&action=read&collection=\(Self.collection)"
            _ = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [exactScope])

            let invalidScopes = [
                "space:app.bsky.bookmarks",
                "space:app.bsky.bookmarks?authority=\(Self.alice)&skey=record-read",
            ]
            for scope in invalidScopes {
                do {
                    _ = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [scope])
                    XCTFail("OAuth issuance accepted an unqualified space scope: \(scope)")
                } catch {
                    // The validated-session boundary rejects this before a
                    // token can be minted.
                }

                let now = Date()
                let binding = OAuthClientBinding(
                    issuer: Self.publicURL.absoluteString,
                    clientID: "https://client.example/metadata",
                    redirectURI: "https://client.example/callback",
                    scopes: [scope],
                    dpopJKT: String(repeating: "a", count: 43)
                )
                let family = OAuthTokenFamily(
                    familyID: UUID(),
                    subject: Self.alice,
                    binding: binding,
                    expiresAt: now.addingTimeInterval(3_600)
                )
                let tokens = OAuthIssuedTokenDigests(
                    familyID: family.familyID,
                    accessTokenDigest: Data(repeating: 0x01, count: 32),
                    refreshTokenDigest: Data(repeating: 0x02, count: 32),
                    accessExpiresAt: now.addingTimeInterval(300),
                    refreshExpiresAt: now.addingTimeInterval(3_000)
                )
                do {
                    try await fixture.control.issueTokenPair(family: family, tokens: tokens, now: now)
                    XCTFail("durable OAuth store accepted an unqualified space scope: \(scope)")
                } catch {
                    // SQLite validates the same tuple shape so a malformed
                    // legacy binding cannot bypass the issuance boundary.
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
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(try self.errorCode(response.body), "public_data_pending")
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

    func testAuthenticatedWriteEndpointsPersistCanonicalPrivateRecordsAndFailAtomically() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "PermissionedRecordWriteHTTPTests"))
            let rkey = "created"
            let createdURI = "\(fixture.space.rawValue)/\(Self.alice)/\(Self.collection)/\(rkey)"
            let create = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"\#(rkey)","record":{"$type":"app.bsky.feed.post","text":"created"}}"#
            let createHeaders = try writeHeaders(fixture, path: Self.createPath, jti: "create")
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: createHeaders, body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    XCTAssertEqual(body["uri"] as? String, createdURI)
                    XCTAssertNotNil(body["cid"] as? String)
                }
                let getHeaders = try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "created-read")
                try await client.execute(uri: self.getURI(fixture, collection: Self.collection, rkey: rkey), method: .get, headers: getHeaders) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try XCTUnwrap((try self.jsonObject(response.body))["value"] as? [String: Any])
                    XCTAssertEqual(value["$type"] as? String, "app.bsky.feed.post")
                    XCTAssertEqual(value["text"] as? String, "created")
                }

                let put = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"\#(rkey)","record":{"$type":"app.bsky.feed.post","text":"updated"}}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.putPath, jti: "put"), body: ByteBuffer(string: put)) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual((try self.jsonObject(response.body))["uri"] as? String, createdURI)
                }

                let apply = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","rkey":"batch","value":{"$type":"app.bsky.feed.post","text":"one"}},{"$type":"com.atproto.space.applyWrites#update","collection":"\#(Self.collection)","rkey":"batch","value":{"$type":"app.bsky.feed.post","text":"two"}}]}"#
                try await client.execute(uri: Self.applyPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.applyPath, jti: "apply"), body: ByteBuffer(string: apply)) { response in
                    XCTAssertEqual(response.status, .ok)
                    let results = try XCTUnwrap((try self.jsonObject(response.body))["results"] as? [[String: Any]])
                    XCTAssertEqual(results.count, 2)
                    XCTAssertEqual(results.map { $0["$type"] as? String }, ["com.atproto.space.applyWrites#createResult", "com.atproto.space.applyWrites#updateResult"])
                }

                let atomicFailure = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","rkey":"must-not-appear","value":{"$type":"app.bsky.feed.post","text":"no"}},{"$type":"com.atproto.space.applyWrites#update","collection":"\#(Self.collection)","rkey":"missing","value":{"$type":"app.bsky.feed.post","text":"no"}}]}"#
                try await client.execute(uri: Self.applyPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.applyPath, jti: "apply-atomic"), body: ByteBuffer(string: atomicFailure)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                try await client.execute(uri: self.getURI(fixture, collection: Self.collection, rkey: "must-not-appear"), method: .get, headers: try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "atomic-read")) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try self.errorCode(response.body), "RecordNotFound")
                }

                let missingDelete = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"missing"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.writeHeaders(fixture, path: Self.deletePath, jti: "missing-delete"), body: ByteBuffer(string: missingDelete)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                let duplicate = #"{"space":"\#(fixture.space.rawValue)","space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","record":{"$type":"app.bsky.feed.post"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "duplicate"), body: ByteBuffer(string: duplicate)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testValidateTrueMatchesPinnedSpaceWriteParityWithoutWeakeningAtomicity() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordWriteValidateTrueTests")
            )
            let schemaInvalidRecord = #"{"$type":"app.bsky.feed.post","text":7}"#
            let createdRKey = "validate-created"
            let batchRKey = "validate-batch"
            try await app.test(.router) { client in
                let create = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"\#(createdRKey)","validate":true,"record":\#(schemaInvalidRecord)}"#
                try await client.execute(
                    uri: Self.createPath,
                    method: .post,
                    headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "validate-create"),
                    body: ByteBuffer(string: create)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.jsonObject(response.body)
                    XCTAssertNil(body["validationStatus"])
                }
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: createdRKey),
                    method: .get,
                    headers: try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "validate-create-read")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try XCTUnwrap((try self.jsonObject(response.body))["value"] as? [String: Any])
                    XCTAssertEqual(value["$type"] as? String, "app.bsky.feed.post")
                    XCTAssertEqual(value["text"] as? Int, 7)
                }

                let put = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"\#(createdRKey)","validate":true,"record":{"$type":"app.bsky.feed.post","text":8}}"#
                try await client.execute(
                    uri: Self.putPath,
                    method: .post,
                    headers: try self.writeHeaders(fixture, path: Self.putPath, jti: "validate-put"),
                    body: ByteBuffer(string: put)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNil((try self.jsonObject(response.body))["validationStatus"])
                }
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: createdRKey),
                    method: .get,
                    headers: try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "validate-put-read")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(((try self.jsonObject(response.body))["value"] as? [String: Any])?["text"] as? Int, 8)
                }

                let apply = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","validate":true,"writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","rkey":"\#(batchRKey)","value":{"$type":"app.bsky.feed.post","text":9}},{"$type":"com.atproto.space.applyWrites#update","collection":"\#(Self.collection)","rkey":"\#(batchRKey)","value":{"$type":"app.bsky.feed.post","text":10}}]}"#
                try await client.execute(
                    uri: Self.applyPath,
                    method: .post,
                    headers: try self.writeHeaders(fixture, path: Self.applyPath, jti: "validate-apply"),
                    body: ByteBuffer(string: apply)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let results = try XCTUnwrap((try self.jsonObject(response.body))["results"] as? [[String: Any]])
                    XCTAssertEqual(results.map { $0["$type"] as? String }, [
                        "com.atproto.space.applyWrites#createResult",
                        "com.atproto.space.applyWrites#updateResult",
                    ])
                    XCTAssertTrue(results.allSatisfy { $0["validationStatus"] == nil })
                }
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: batchRKey),
                    method: .get,
                    headers: try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "validate-apply-read")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(((try self.jsonObject(response.body))["value"] as? [String: Any])?["text"] as? Int, 10)
                }

                let atomicFailure = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","validate":true,"writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","rkey":"validate-must-not-appear","value":\#(schemaInvalidRecord)},{"$type":"com.atproto.space.applyWrites#update","collection":"\#(Self.collection)","rkey":"validate-missing","value":\#(schemaInvalidRecord)}]}"#
                try await client.execute(
                    uri: Self.applyPath,
                    method: .post,
                    headers: try self.writeHeaders(fixture, path: Self.applyPath, jti: "validate-atomic"),
                    body: ByteBuffer(string: atomicFailure)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                try await client.execute(
                    uri: self.getURI(fixture, collection: Self.collection, rkey: "validate-must-not-appear"),
                    method: .get,
                    headers: try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "validate-atomic-read")
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try self.errorCode(response.body), "RecordNotFound")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testOmittedApplyWriteRKeysRemainUniquePastPetrelCounterRange() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "PermissionedRecordWriteTIDTests"))
            let operationCount = 1_026
            let create = #"{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","value":{"$type":"app.bsky.feed.post"}}"#
            let batch = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","writes":[\#(Array(repeating: create, count: operationCount).joined(separator: ","))]}"#
            XCTAssertLessThan(batch.utf8.count, 1 * 1024 * 1024)
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.applyPath,
                    method: .post,
                    headers: try self.writeHeaders(fixture, path: Self.applyPath, jti: "omitted-batch"),
                    body: ByteBuffer(string: batch)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let results = try XCTUnwrap((try self.jsonObject(response.body))["results"] as? [[String: Any]])
                    XCTAssertEqual(results.count, operationCount)
                    let uris = try Set(results.map { try XCTUnwrap($0["uri"] as? String) })
                    XCTAssertEqual(uris.count, operationCount)

                    let postBatchCreate = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","record":{"$type":"app.bsky.feed.post"}}"#
                    try await client.execute(
                        uri: Self.createPath,
                        method: .post,
                        headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "omitted-after-batch"),
                        body: ByteBuffer(string: postBatchCreate)
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        XCTAssertFalse(uris.contains(try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)))
                    }
                }
            }

            // Omitted rkeys are allocated before the write reaches the CAS
            // transaction. Exercise genuinely concurrent HTTP invocations,
            // then test the same allocator directly so losing CAS contenders
            // cannot mask an accidental duplicate allocation.
            let concurrentRequestCount = 32
            let concurrentRequests = try (0 ..< concurrentRequestCount).map { index -> (HTTPFields, String) in
                let body = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","record":{"$type":"app.bsky.feed.post","text":"concurrent-\#(index)"}}"#
                return (
                    try writeHeaders(fixture, path: Self.createPath, jti: "omitted-concurrent-\(index)"),
                    body
                )
            }
            try await app.test(.router) { client in
                let outcomes = await withTaskGroup(of: ConcurrentWriteOutcome.self, returning: [ConcurrentWriteOutcome].self) { group in
                    for (headers, body) in concurrentRequests {
                        group.addTask {
                            do {
                                return try await client.execute(
                                    uri: Self.createPath,
                                    method: .post,
                                    headers: headers,
                                    body: ByteBuffer(string: body)
                                ) { response in
                                    let uri: String?
                                    if response.status == .ok {
                                        let object = try JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any]
                                        uri = object?["uri"] as? String
                                    } else {
                                        uri = nil
                                    }
                                    return ConcurrentWriteOutcome(status: response.status.code, uri: uri)
                                }
                            } catch {
                                return ConcurrentWriteOutcome(status: -1, uri: nil)
                            }
                        }
                    }
                    return await group.reduce(into: []) { $0.append($1) }
                }
                XCTAssertFalse(outcomes.contains { $0.status == -1 })
                XCTAssertTrue(outcomes.allSatisfy { $0.status == 200 || $0.status == 409 })
                let successfulURIs = outcomes.compactMap(\.uri)
                XCTAssertFalse(successfulURIs.isEmpty)
                XCTAssertEqual(Set(successfulURIs).count, successfulURIs.count)
            }
            let allocator = SwanPermissionedTIDAllocator()
            let allocated = await withTaskGroup(of: String?.self, returning: [String].self) { group in
                for _ in 0 ..< concurrentRequestCount {
                    group.addTask { try? await allocator.next().toString() }
                }
                return await group.reduce(into: []) { values, value in
                    if let value { values.append(value) }
                }
            }
            XCTAssertEqual(allocated.count, concurrentRequestCount)
            XCTAssertEqual(Set(allocated).count, concurrentRequestCount)
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testPermissionedTIDAllocatorObservesDurableRevisionAfterRestart() async throws {
        let durableRevision = try TID(tidString: "7777777777777")
        let allocator = SwanPermissionedTIDAllocator()
        await allocator.observe(durableRevision)

        let next = try await allocator.next()
        XCTAssertGreaterThan(next, durableRevision)
        XCTAssertEqual(next.toString().utf8.count, 13)
    }

    func testApplyWritesCreateRejectsMalformedPresentRKeyWithoutMutationAndAcceptsOmission() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let inspectionDatabase = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: Self.alice
        )
        do {
            let loadedInitialSnapshot =
                try await inspectionDatabase.repositorySnapshot(
                    space: fixture.space,
                    author: Self.alice
                )
            let initialSnapshot = try XCTUnwrap(
                loadedInitialSnapshot
            )
            let malformedRKeys = [
                ("invalid-string", #""bad/key""#),
                ("wrong-type", "7"),
                ("null", "null"),
            ]
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordReadHTTPTests.strict-rkey")
            )

            try await app.test(.router) { client in
                for (name, rkey) in malformedRKeys {
                    let body = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","rkey":\#(rkey),"value":{"$type":"app.bsky.feed.post","text":"must-not-appear"}}]}"#
                    let response = try await client.execute(
                        uri: Self.applyPath,
                        method: .post,
                        headers: try self.writeHeaders(
                            fixture,
                            path: Self.applyPath,
                            jti: "apply-malformed-\(name)"
                        ),
                        body: ByteBuffer(string: body)
                    )

                    XCTAssertEqual(response.status, .badRequest, name)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest", name)
                    self.assertNoStore(response)
                    let snapshotAfterRejectedRequest =
                        try await inspectionDatabase.repositorySnapshot(
                            space: fixture.space,
                            author: Self.alice
                        )
                    XCTAssertEqual(
                        snapshotAfterRejectedRequest,
                        initialSnapshot,
                        name
                    )
                }

                let omitted = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(Self.collection)","value":{"$type":"app.bsky.feed.post","text":"generated-rkey"}}]}"#
                let response = try await client.execute(
                    uri: Self.applyPath,
                    method: .post,
                    headers: try self.writeHeaders(
                        fixture,
                        path: Self.applyPath,
                        jti: "apply-omitted-rkey-strict-decoder"
                    ),
                    body: ByteBuffer(string: omitted)
                )

                XCTAssertEqual(
                    response.status,
                    .ok,
                    String(decoding: response.body.readableBytesView, as: UTF8.self)
                )
                let results = try XCTUnwrap(
                    (try self.jsonObject(response.body))["results"] as? [[String: Any]]
                )
                XCTAssertEqual(results.count, 1)
                XCTAssertTrue(
                    try XCTUnwrap(results.first?["uri"] as? String)
                        .hasPrefix("\(fixture.space.rawValue)/\(Self.alice)/\(Self.collection)/")
                )
                let snapshotAfterOmittedRKey =
                    try await inspectionDatabase.repositorySnapshot(
                        space: fixture.space,
                        author: Self.alice
                    )
                XCTAssertNotEqual(snapshotAfterOmittedRKey, initialSnapshot)
            }
            try await inspectionDatabase.close()
            try await close(fixture)
        } catch {
            try? await inspectionDatabase.close()
            try? await close(fixture)
            throw error
        }
    }

    func testWriteBoundaryScopesReplayAndPrivateIsolation() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "PermissionedRecordWriteBoundaryTests"))
            let createBody = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"scoped","record":{"$type":"app.bsky.feed.post"}}"#
            let createScope = "space:app.bsky.bookmarks?authority=\(Self.alice)&skey=record-read&action=create&collection=\(Self.collection)"
            let updateScope = "space:app.bsky.bookmarks?authority=\(Self.alice)&skey=record-read&action=update&collection=\(Self.collection)"
            let deleteScope = "space:app.bsky.bookmarks?authority=\(Self.alice)&skey=record-read&action=delete&collection=\(Self.collection)"
            let createToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [createScope])
            let updateToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [updateScope])
            let deleteToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [deleteScope])
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(createToken, fixture: fixture, path: Self.createPath, jti: "create-scope"), body: ByteBuffer(string: createBody)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // A put needs both possible state-transition grants, while an
                // update and delete each need their own action grant.
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.writeHeaders(createToken, fixture: fixture, path: Self.putPath, jti: "put-needs-update"), body: ByteBuffer(string: createBody)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                let update = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","writes":[{"$type":"com.atproto.space.applyWrites#update","collection":"\#(Self.collection)","rkey":"scoped","value":{"$type":"app.bsky.feed.post","text":"updated"}}]}"#
                try await client.execute(uri: Self.applyPath, method: .post, headers: try self.writeHeaders(updateToken, fixture: fixture, path: Self.applyPath, jti: "update-scope"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let deleteCreate = createBody.replacingOccurrences(of: "scoped", with: "delete-me")
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(createToken, fixture: fixture, path: Self.createPath, jti: "delete-create"), body: ByteBuffer(string: deleteCreate)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let delete = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"delete-me"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.writeHeaders(deleteToken, fixture: fixture, path: Self.deletePath, jti: "delete-scope"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                var absentType = try self.signedHeaders(fixture, subject: Self.alice, path: Self.createPath, jti: "absent-content", method: "POST")
                try await client.execute(uri: Self.createPath, method: .post, headers: absentType, body: ByteBuffer(string: createBody)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                absentType[.contentType] = "text/plain"
                try await client.execute(uri: Self.createPath, method: .post, headers: absentType, body: ByteBuffer(string: createBody)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                let oversized = String(repeating: " ", count: 1 * 1024 * 1024 + 1)
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "oversized"), body: ByteBuffer(string: oversized)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                // Keep the authority URI unchanged.  The route must fail
                // before it can probe Bob's repository and disclose whether
                // it is open or contains this rkey.
                let foreign = createBody.replacingOccurrences(
                    of: "\"repo\":\"\(Self.alice)\"",
                    with: "\"repo\":\"\(Self.bob)\""
                )
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "foreign"), body: ByteBuffer(string: foreign)) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                let replay = try self.writeHeaders(fixture, path: Self.createPath, jti: "replay")
                let replayBody = createBody.replacingOccurrences(of: "scoped", with: "replay")
                try await client.execute(uri: Self.createPath, method: .post, headers: replay, body: ByteBuffer(string: replayBody)) { response in XCTAssertEqual(response.status, .ok) }
                try await client.execute(uri: Self.createPath, method: .post, headers: replay, body: ByteBuffer(string: replayBody)) { response in XCTAssertEqual(response.status, .unauthorized) }
                let wrongTarget = try self.signedHeaders(fixture, subject: Self.alice, path: Self.getPath, jti: "wrong-target", method: "POST")
                var wrongTargetJSON = wrongTarget; wrongTargetJSON[.contentType] = "application/json"
                try await client.execute(uri: Self.createPath, method: .post, headers: wrongTargetJSON, body: ByteBuffer(string: createBody.replacingOccurrences(of: "scoped", with: "wrong-target"))) { response in XCTAssertEqual(response.status, .unauthorized) }
                try await client.execute(uri: "/xrpc/com.atproto.repo.getRecord?repo=\(Self.alice)&collection=\(Self.collection)&rkey=scoped", method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(try self.errorCode(response.body), "public_data_pending")
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("scoped"))
                }
            }

            // These direct reads inspect only durable postconditions of the
            // HTTP writes: each successful request advanced the oplog and
            // atomically inserted an opaque, pending notification intent.
            let database = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: Self.alice)
            let facts = try await database.spaceOplog(space: fixture.space, author: Self.alice, since: 3)
            guard case let .incremental(entries) = facts else {
                try await database.close()
                return XCTFail("recent HTTP writes unexpectedly require full recovery")
            }
            XCTAssertEqual(entries.map(\.action), [.create, .update, .create, .delete, .create])
            let outbox = try await database.pendingOutbox(limit: 20)
            XCTAssertEqual(outbox.filter { $0.revision > 3 }.count, 5)
            XCTAssertTrue(outbox.allSatisfy { !$0.payload.contains(Data("scoped".utf8)) })
            try await database.close()

            _ = try await fixture.control.transitionStatus(
                did: Self.alice,
                to: .deactivated,
                declaration: .init(),
                now: Date()
            )
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "deactivated-write"), body: ByteBuffer(string: createBody.replacingOccurrences(of: "scoped", with: "inactive"))) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
            }
            try await close(fixture)
        } catch { try? await close(fixture); throw error }
    }

    func testWriteFailsClosedWhenPreopenedDatabaseVanishes() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordWriteMissingDatabaseTests")
            )
            let accountPath = SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice)
            try FileManager.default.removeItem(at: accountPath)
            let body = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"missing-db","record":{"$type":"app.bsky.feed.post"}}"#
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.writeHeaders(fixture, path: Self.createPath, jti: "missing-db-write"), body: ByteBuffer(string: body)) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: accountPath.path))
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testConcurrentHTTPWritesExposeCASConflictsWithoutLosingCommittedFacts() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "PermissionedRecordWriteCASRaceTests")
            )
            let requestCount = 16
            let requests = try (0 ..< requestCount).map { index -> (HTTPFields, String) in
                let body = #"{"space":"\#(fixture.space.rawValue)","repo":"\#(Self.alice)","collection":"\#(Self.collection)","rkey":"race-\#(index)","record":{"$type":"app.bsky.feed.post"}}"#
                return (
                    try writeHeaders(fixture, path: Self.createPath, jti: "cas-race-\(index)"),
                    body
                )
            }
            try await app.test(.router) { client in
                let statuses = await withTaskGroup(of: Int.self, returning: [Int].self) { group in
                    for (headers, body) in requests {
                        group.addTask {
                            do {
                                return try await client.execute(
                                    uri: Self.createPath,
                                    method: .post,
                                    headers: headers,
                                    body: ByteBuffer(string: body)
                                ) { $0.status.code }
                            } catch {
                                return -1
                            }
                        }
                    }
                    return await group.reduce(into: []) { $0.append($1) }
                }
                XCTAssertFalse(statuses.contains(-1))
                XCTAssertTrue(statuses.allSatisfy { $0 == 200 || $0 == 409 })
                XCTAssertGreaterThan(statuses.filter { $0 == 200 }.count, 0)
                XCTAssertGreaterThan(statuses.filter { $0 == 409 }.count, 0)

                let database = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: Self.alice)
                let facts = try await database.spaceOplog(space: fixture.space, author: Self.alice, since: 3)
                guard case let .incremental(entries) = facts else {
                    try await database.close()
                    return XCTFail("concurrent HTTP writes unexpectedly require full recovery")
                }
                XCTAssertEqual(entries.count, statuses.filter { $0 == 200 }.count)
                XCTAssertEqual(Set(entries.map(\.wireRevision)).count, entries.count)
                try await database.close()
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedRecordReadHTTPTests-\(UUID().uuidString)")
        let space = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "record-read")
        let foreignSpace = try SpaceURI(authority: Self.bob, spaceType: "app.bsky.bookmarks", skey: "record-read")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(registration(did: Self.alice, handle: "alice.example.com"))
            _ = try await control.createAccount(registration(did: Self.bob, handle: "bob.example.com"))
            let records = try await installRecords(root: root, space: space, foreignSpace: foreignSpace)
            try await installEmptyAccountDatabase(root: root, did: Self.bob)
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xB7, count: 32))
            let repositoryScopes = repositoryScopes(for: space)
            let alice = try await issueToken(
                runtime,
                subject: Self.alice,
                scopes: repositoryScopes
            )
            let bob = try await issueToken(
                runtime,
                subject: Self.bob,
                scopes: repositoryScopes
            )
            return Fixture(
                root: root,
                space: space,
                foreignSpace: foreignSpace,
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

    private func installRecords(
        root: URL,
        space: SpaceURI,
        foreignSpace: SpaceURI
    ) async throws -> [SpaceRecordURI] {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: Self.alice)
        do {
            let repository = try DurableSpaceRepository(database: database, space: space, author: Self.alice)
            let records = [
                try SpaceRecordURI(space: space, author: Self.alice, collection: Self.collection, rkey: "first"),
                try SpaceRecordURI(space: space, author: Self.alice, collection: Self.collection, rkey: "second"),
                try SpaceRecordURI(space: space, author: Self.alice, collection: Self.otherCollection, rkey: "third"),
            ]
            let values = ["first", "second", "third"]
            let authorization = AuthorizationContext.accountOAuth(
                subject: Self.alice,
                scopes: repositoryScopes(for: space)
            )
            for (index, record) in records.enumerated() {
                _ = try await repository.apply(
                    .put(uri: record, value: recordCBOR(values[index])),
                    expectedRevision: UInt64(index),
                    requestID: UUID(),
                    wireRevision: try tid(index),
                    authorization: authorization
                )
            }
            let foreignRepository = try DurableSpaceRepository(
                database: database,
                space: foreignSpace,
                author: Self.alice
            )
            let foreignRecord = try SpaceRecordURI(
                space: foreignSpace,
                author: Self.alice,
                collection: Self.collection,
                rkey: "foreign"
            )
            _ = try await foreignRepository.apply(
                .put(uri: foreignRecord, value: recordCBOR("foreign")),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try tid(0),
                authorization: .accountOAuth(
                    subject: Self.alice,
                    scopes: repositoryScopes(for: foreignSpace)
                )
            )
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

    private func repositoryScopes(for space: SpaceURI) -> Set<String> {
        let base = "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)"
        return [
            "\(base)&action=read",
            "\(base)&action=create&collection=\(Self.collection)",
            "\(base)&action=create&collection=\(Self.otherCollection)",
            "\(base)&action=update&collection=\(Self.collection)",
            "\(base)&action=update&collection=\(Self.otherCollection)",
            "\(base)&action=delete&collection=\(Self.collection)",
            "\(base)&action=delete&collection=\(Self.otherCollection)",
        ]
    }

    private func installEmptyAccountDatabase(root: URL, did: String) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        try await database.close()
    }

    private func makeServer(
        _ fixture: Fixture,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil
    ) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-30.json")
        )
        let resolvedWriteAdmission = try jsonWriteAdmission
            ?? PublicRepositoryJSONWriteAdmission(
                maximumConcurrentWrites: 64,
                maximumReservedRequestBytes: 64 * 1_024 * 1_024
            )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control,
            jsonWriteAdmission: resolvedWriteAdmission
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
        method: String = "GET",
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
            method: method,
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
        method: String = "GET",
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
            htm: method,
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

    private func writeHeaders(_ fixture: Fixture, path: String, jti: String) throws -> HTTPFields {
        var headers = try signedHeaders(fixture, subject: Self.alice, path: path, jti: jti, method: "POST")
        headers[.contentType] = "application/json"
        return headers
    }

    private func writeHeaders(_ token: TokenMaterial, fixture: Fixture, path: String, jti: String) throws -> HTTPFields {
        var headers = try signedHeaders(token: token.token, key: token.key, jwk: token.jwk, path: path, nonce: fixture.runtime.dpopNonceService.issue(), jti: jti, method: "POST")
        headers[.contentType] = "application/json"
        return headers
    }

    private func getURI(
        _ fixture: Fixture,
        space: SpaceURI? = nil,
        collection: String,
        rkey: String
    ) -> String {
        "\(Self.getPath)?space=\(percentEncode((space ?? fixture.space).rawValue))&repo=\(Self.alice)&collection=\(collection)&rkey=\(rkey)"
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

private struct ConcurrentWriteOutcome: Sendable {
    let status: Int
    let uri: String?
}

private struct Fixture: Sendable {
    let root: URL
    let space: SpaceURI
    let foreignSpace: SpaceURI
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
