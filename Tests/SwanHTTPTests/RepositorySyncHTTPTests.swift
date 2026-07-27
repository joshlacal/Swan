import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import XCTest
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
@testable import swan
import SwanSQLite
import SwanSpaces
import SwanStorage

final class RepositorySyncHTTPTests: XCTestCase, @unchecked Sendable {
    static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let latestPath = "/xrpc/com.atproto.space.getLatestCommit"
    private static let oplogPath = "/xrpc/com.atproto.space.listRepoOps"
    private static let repoPath = "/xrpc/com.atproto.space.getRepo"
    private static let blobPath = "/xrpc/com.atproto.space.getBlob"

    func testExchangeAndSyncOnlyCredentialCompositionLeavesRecordAndBlobOAuthOnly() async throws {
        let fixture = try await Fixture.make()
        defer { try? await fixture.close() }

        let server = try makeExchangeAndSyncOnlyServer(fixture)

        XCTAssertNotNil(server.authenticatedSpaceCredentialExchange)
        XCTAssertNotNil(server.authenticatedSpaceRepositorySync?.credentialAuthorizer)
        XCTAssertNil(server.authenticatedSpaceRecords?.credentialAuthorizer)
        XCTAssertNil(server.authenticatedSpaceBlobs?.credentialAuthorizer)
    }

    func testActualLocalServeRuntimeMountsKeysForDelegationExchangeAndSyncOnly() async throws {
        let fixture = try await Fixture.make()
        defer { try? await fixture.close() }
        let mountedKEK = fixture.root.appending(path: "mounted-space-kek")
        try Data(repeating: 0x45, count: 32).base64URLEncodedString().data(using: .utf8)!
            .write(to: mountedKEK)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: mountedKEK.path)

        let local = try await ServeLocalSpaceRuntime.make(
            keyDirectory: fixture.root.appending(path: "keys"),
            kekFile: mountedKEK,
            kekID: "sync-kek",
            controlStore: fixture.control
        )
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        let server = SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control,
            spaceCredentialExchangeConfiguration: local.credentialExchangeConfiguration,
            spaceDelegationConfiguration: local.delegationConfiguration,
            spaceRepositorySyncConfiguration: local.repositorySyncConfiguration,
            spaceRepositoryCredentialConfiguration: local.repositoryCredentialConfiguration
        )
        let closed = SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control
        )
        let exactScope = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read"
        let oauth = try await issueToken(runtime: fixture.runtime, subject: Self.bob, scopes: [exactScope])
        let delegationPath = "/xrpc/com.atproto.space.getDelegationToken"
        let credentialPath = "/xrpc/com.atproto.space.getSpaceCredential"

        let app = server.buildApplication(logger: Logger(label: "RepositorySyncHTTPTests.localRuntime"))
        try await app.test(.router) { client in
            let delegationHeaders = try self.dpopHeaders(
                token: oauth.token,
                key: oauth.key,
                jwk: oauth.jwk,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "local-runtime-delegation",
                path: delegationPath
            )
            let delegationURI = "\(delegationPath)?space=\(self.percentEncode(fixture.space.rawValue))"
            var delegationToken = ""
            try await client.execute(uri: delegationURI, method: .get, headers: delegationHeaders) { response in
                XCTAssertEqual(response.status, .ok)
                delegationToken = try XCTUnwrap(self.jsonObject(response.body)["token"] as? String)
            }
            var exchangeHeaders = HTTPFields()
            exchangeHeaders[.authorization] = "Bearer \(delegationToken)"
            exchangeHeaders[.contentType] = "application/json"
            let exchangeBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")
            var credential = ""
            try await client.execute(uri: credentialPath, method: .post, headers: exchangeHeaders, body: exchangeBody) { response in
                XCTAssertEqual(response.status, .ok)
                credential = try XCTUnwrap(self.jsonObject(response.body)["credential"] as? String)
            }
            try await client.execute(uri: credentialPath, method: .post, headers: exchangeHeaders, body: exchangeBody) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
            let bearer = self.bearerHeaders(credential)
            try await client.execute(uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get, headers: bearer) { XCTAssertEqual($0.status, .ok) }
            try await client.execute(uri: self.oplogURI(space: fixture.space, repo: Self.alice), method: .get, headers: bearer) { XCTAssertEqual($0.status, .ok) }
            try await client.execute(uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: bearer) { XCTAssertEqual($0.status, .ok) }
            try await client.execute(uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID), method: .get, headers: bearer) { XCTAssertEqual($0.status, .unauthorized) }
        }
        let closedApp = closed.buildApplication(logger: Logger(label: "RepositorySyncHTTPTests.localRuntimeClosed"))
        try await closedApp.test(.router) { client in
            try await client.execute(uri: credentialPath, method: .post) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
            }
        }
    }

    func testGetBlobStreamsPrivateCASForOAuthAndSpaceCredential() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.getBlob")
            )
            let oauth = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.alice,
                scopes: ["atproto"]
            )
            let credential = try await fixture.credential(for: fixture.space)
            try await app.test(.router) { client in
                let oauthHeaders = try self.dpopHeaders(
                    token: oauth.token,
                    key: oauth.key,
                    jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "blob-oauth-success",
                    path: Self.blobPath
                )
                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get,
                    headers: oauthHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(Data(buffer: response.body), fixture.blobPayload)
                    self.assertBlobHeaders(response, cid: fixture.blobCID, length: fixture.blobPayload.count)
                }

                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get,
                    headers: self.bearerHeaders(credential, dpop: "ignored-for-credential")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(Data(buffer: response.body), fixture.blobPayload)
                    self.assertBlobHeaders(response, cid: fixture.blobCID, length: fixture.blobPayload.count)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testGetBlobRejectsMalformedForeignCollectionScopedAndReplayRequests() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.getBlobBoundaries")
            )
            let alice = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: ["atproto"])
            let bob = try await issueToken(runtime: fixture.runtime, subject: Self.bob, scopes: ["atproto"])
            let narrowScope = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read&collection=app.bsky.feed.post"
            let narrow = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: [narrowScope])
            try await app.test(.router) { client in
                for uri in [
                    Self.blobPath,
                    "\(Self.blobPath)?space=at%3A%2F%2Fbad&space=at%3A%2F%2Fbad&repo=\(Self.alice)&cid=bad",
                    "\(Self.blobPath)?space=\(self.percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&cid=sha256%3Abad",
                    "\(Self.blobPath)?space=\(self.percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&cid=\(fixture.blobCID)&extra=x",
                ] {
                    try await client.execute(uri: uri, method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                }

                let foreignHeaders = try self.dpopHeaders(
                    token: bob.token, key: bob.key, jwk: bob.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "blob-foreign", path: Self.blobPath
                )
                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get, headers: foreignHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains(fixture.blobCID))
                }

                let narrowHeaders = try self.dpopHeaders(
                    token: narrow.token, key: narrow.key, jwk: narrow.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "blob-narrow", path: Self.blobPath
                )
                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get, headers: narrowHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }

                let replayHeaders = try self.dpopHeaders(
                    token: alice.token, key: alice.key, jwk: alice.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "blob-replay", path: Self.blobPath
                )
                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get, headers: replayHeaders
                ) { XCTAssertEqual($0.status, .ok) }
                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get, headers: replayHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }

                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .post
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testGetRepoStreamsFreshTwoRootCARForOAuthSelfAndCredentialCrossRepository() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.getRepo")
            )
            let oauth = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.alice,
                scopes: ["atproto"]
            )
            let credential = try await fixture.credential(for: fixture.space)
            let firstIKM = DataBox()
            try await app.test(.router) { client in
                let firstHeaders = try self.dpopHeaders(
                    token: oauth.token,
                    key: oauth.key,
                    jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "repo-oauth-first",
                    path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice),
                    method: .get,
                    headers: firstHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertCARNoStore(response)
                    XCTAssertNil(response.headers[.contentLength])
                    let car = Data(buffer: response.body)
                    let verified = try self.assertRecoveryCAR(
                        car,
                        fixture: fixture,
                        author: Self.alice
                    )
                    await firstIKM.set(try self.commitIKM(in: car))
                    let blockCIDs = try self.carBlockCIDs(car)
                    XCTAssertEqual(blockCIDs.count, verified.count + 2)
                    XCTAssertEqual(
                        Array(blockCIDs.dropFirst(2)),
                        [
                            CID.fromDAGCBOR(try XCTUnwrap(verified["app.bsky.feed.post/first"])),
                            CID.fromDAGCBOR(try XCTUnwrap(verified["app.bsky.feed.post/fourth"])),
                            CID.fromDAGCBOR(try XCTUnwrap(verified["app.bsky.feed.post/third"])),
                        ]
                    )
                }

                let secondHeaders = try self.dpopHeaders(
                    token: oauth.token,
                    key: oauth.key,
                    jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "repo-oauth-second",
                    path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice),
                    method: .get,
                    headers: secondHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertCARNoStore(response)
                    let initialIKM = await firstIKM.value
                    let secondIKM = try self.commitIKM(in: Data(buffer: response.body))
                    XCTAssertNotEqual(secondIKM, initialIKM)
                }

                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.bob),
                    method: .get,
                    headers: self.bearerHeaders(credential, dpop: "not-a-dpop-proof")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertCARNoStore(response)
                    _ = try self.assertRecoveryCAR(
                        Data(buffer: response.body),
                        fixture: fixture,
                        author: Self.bob
                    )
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testOAuthSelfAndCredentialCrossRepositoryReturnFreshVerifiableCommitsAndReferencePages() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.success")
            )
            let oauth = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.alice,
                scopes: ["atproto"]
            )
            let credential = try await fixture.credential(for: fixture.space)
            try await app.test(.router) { client in
                var firstCommitIKM: Data?
                let latestHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "latest-success", path: Self.latestPath
                )
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice),
                    method: .get,
                    headers: latestHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let commit = try XCTUnwrap((try self.jsonObject(response.body))["commit"] as? [String: Any])
                    try self.assertCommit(commit, fixture: fixture, author: Self.alice)
                    firstCommitIKM = try self.bytes("ikm", in: commit)
                }

                let freshLatestHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "latest-fresh-success", path: Self.latestPath
                )
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice),
                    method: .get,
                    headers: freshLatestHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let commit = try XCTUnwrap((try self.jsonObject(response.body))["commit"] as? [String: Any])
                    try self.assertCommit(commit, fixture: fixture, author: Self.alice)
                    XCTAssertNotEqual(try self.bytes("ikm", in: commit), firstCommitIKM)
                }

                // A Bearer space credential is intentionally not routed
                // through DPoP and may read a different member repository.
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.bob),
                    method: .get,
                    headers: self.bearerHeaders(credential, dpop: "not-a-dpop-proof")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let commit = try XCTUnwrap((try self.jsonObject(response.body))["commit"] as? [String: Any])
                    try self.assertCommit(commit, fixture: fixture, author: Self.bob)
                }

                let pageHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "oplog-first-page", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(space: fixture.space, repo: Self.alice, limit: 1),
                    method: .get,
                    headers: pageHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.jsonObject(response.body)
                    let entries = try XCTUnwrap(body["ops"] as? [[String: Any]])
                    XCTAssertEqual(entries.count, 1)
                    XCTAssertTrue(entries[0]["prev"] is NSNull)
                    XCTAssertNil(body["commit"])
                }

                let fullHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "oplog-full-page", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(space: fixture.space, repo: Self.alice, since: fixture.tids[0]),
                    method: .get,
                    headers: fullHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    let entries = try XCTUnwrap(body["ops"] as? [[String: Any]])
                    XCTAssertEqual(
                        entries.map { $0["rev"] as? String },
                        Array(fixture.tids.dropFirst()) + [fixture.tids[4]]
                    )
                    XCTAssertEqual(entries.count, 5)
                    // The update is still live and therefore carries a
                    // current value; the later delete makes the create stale.
                    XCTAssertNotNil(entries[0]["value"])
                    XCTAssertNil(entries[1]["value"])
                    XCTAssertNil(entries[2]["value"])
                    XCTAssertTrue(entries[1]["prev"] is NSNull)
                    XCTAssertTrue(entries[2]["cid"] is NSNull)
                    XCTAssertNotNil(entries[2]["prev"])
                    XCTAssertEqual(entries[3]["rev"] as? String, fixture.tids[4])
                    XCTAssertEqual(entries[4]["rev"] as? String, fixture.tids[4])
                    XCTAssertEqual(entries[3]["rkey"] as? String, "third")
                    XCTAssertEqual(entries[4]["rkey"] as? String, "fourth")
                    XCTAssertNotNil(entries[3]["value"])
                    XCTAssertNotNil(entries[4]["value"])
                    try self.assertCommit(
                        try XCTUnwrap(body["commit"] as? [String: Any]),
                        fixture: fixture,
                        author: Self.alice
                    )
                }

                // `since` is a TID, not a `(TID, operation-index)` cursor.
                // A limit boundary through the two-operation atomic batch at
                // tids[4] must include both rows; otherwise a consumer that
                // advances `since` to tids[4] could never retrieve the
                // omitted sibling. The next empty page is where the existing
                // reference caught-up rule supplies the head commit.
                let boundaryHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "oplog-shared-tid-boundary", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(
                        space: fixture.space,
                        repo: Self.alice,
                        since: fixture.tids[0],
                        limit: 4
                    ),
                    method: .get,
                    headers: boundaryHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.jsonObject(response.body)
                    let entries = try XCTUnwrap(body["ops"] as? [[String: Any]])
                    XCTAssertEqual(entries.count, 5)
                    XCTAssertEqual(
                        entries.map { $0["rev"] as? String },
                        Array(fixture.tids.dropFirst()) + [fixture.tids[4]]
                    )
                    XCTAssertEqual(entries.suffix(2).map { $0["rkey"] as? String }, ["third", "fourth"])
                    XCTAssertNil(body["commit"])
                }

                let afterBatchHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "oplog-after-shared-tid", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(
                        space: fixture.space,
                        repo: Self.alice,
                        since: fixture.tids[4],
                        limit: 4
                    ),
                    method: .get,
                    headers: afterBatchHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.jsonObject(response.body)
                    XCTAssertEqual((try XCTUnwrap(body["ops"] as? [[String: Any]])).count, 0)
                    try self.assertCommit(
                        try XCTUnwrap(body["commit"] as? [String: Any]),
                        fixture: fixture,
                        author: Self.alice
                    )
                }

                let excludedHeaders = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "oplog-excluded", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(space: fixture.space, repo: Self.alice, excludeValues: true),
                    method: .get,
                    headers: excludedHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let ops = try XCTUnwrap((try self.jsonObject(response.body))["ops"] as? [[String: Any]])
                    XCTAssertTrue(ops.allSatisfy { $0["value"] == nil })
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testSyncAuthorizationQueryAndDPoPFailuresRemainOpaqueAndClosed() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.boundary")
            )
            let alice = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: ["atproto"])
            let bob = try await issueToken(runtime: fixture.runtime, subject: Self.bob, scopes: ["atproto"])
            let narrowScope = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read&collection=app.bsky.feed.post"
            let narrow = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: [narrowScope])
            let sibling = try SpaceURI(authority: Self.alice, spaceType: fixture.space.spaceType, skey: "other")
            let wrongCredential = try await fixture.credential(for: sibling)
            try await app.test(.router) { client in
                for uri in [
                    Self.latestPath,
                    Self.repoPath,
                    "\(Self.latestPath)?space=at%3A%2F%2Fbad&space=at%3A%2F%2Fbad&repo=\(Self.alice)",
                    "\(Self.repoPath)?space=\(self.percentEncode(fixture.space.rawValue))&space=\(self.percentEncode(fixture.space.rawValue))&repo=\(Self.alice)",
                    "\(Self.oplogPath)?space=\(self.percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&limit=0",
                    "\(Self.oplogPath)?space=\(self.percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&since=not-a-tid",
                    "\(Self.oplogPath)?space=\(self.percentEncode(fixture.space.rawValue))&repo=\(Self.alice)&extra=x",
                ] {
                    try await client.execute(uri: uri, method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                }

                var nonceChallengeHeaders = HTTPFields()
                nonceChallengeHeaders[.authorization] = "DPoP \(alice.token)"
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get,
                    headers: nonceChallengeHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertNotNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                }

                let foreignHeaders = try self.dpopHeaders(
                    token: bob.token, key: bob.key, jwk: bob.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "foreign-repo", path: Self.latestPath
                )
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get, headers: foreignHeaders
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }

                let foreignCARHeaders = try self.dpopHeaders(
                    token: bob.token, key: bob.key, jwk: bob.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "foreign-repo-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: foreignCARHeaders
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }

                let narrowHeaders = try self.dpopHeaders(
                    token: narrow.token, key: narrow.key, jwk: narrow.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "narrow-sync", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(space: fixture.space, repo: Self.alice), method: .get, headers: narrowHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }

                let narrowCARHeaders = try self.dpopHeaders(
                    token: narrow.token, key: narrow.key, jwk: narrow.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "narrow-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: narrowCARHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }

                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.bob), method: .get,
                    headers: self.bearerHeaders(wrongCredential)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                }

                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.bob), method: .get,
                    headers: self.bearerHeaders(wrongCredential)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                }

                let replayHeaders = try self.dpopHeaders(
                    token: alice.token, key: alice.key, jwk: alice.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "sync-replay", path: Self.latestPath
                )
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get, headers: replayHeaders
                ) { XCTAssertEqual($0.status, .ok) }
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get, headers: replayHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }

                var missingProof = HTTPFields()
                missingProof[.authorization] = "DPoP \(alice.token)"
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: missingProof
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertNotNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                }

                let carReplayHeaders = try self.dpopHeaders(
                    token: alice.token, key: alice.key, jwk: alice.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "repo-car-replay", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: carReplayHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertCARNoStore(response)
                }
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: carReplayHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }

                try await client.execute(
                    uri: Self.latestPath, method: .post
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
                try await client.execute(
                    uri: Self.repoPath, method: .post
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
            }

            _ = try await fixture.control.transitionStatus(
                did: Self.alice, to: .deactivated, declaration: .init(), now: Date()
            )
            let inactiveHeaders = try dpopHeaders(
                token: alice.token, key: alice.key, jwk: alice.jwk,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "inactive", path: Self.latestPath
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get, headers: inactiveHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }
                let inactiveCARHeaders = try self.dpopHeaders(
                    token: alice.token, key: alice.key, jwk: alice.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "inactive-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: inactiveCARHeaders
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testRetentionGapCorruptionAndMissingPreopenedDatabaseFailWithoutValues() async throws {
        let fixture = try await Fixture.make(retention: 2)
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.recovery")
            )
            let access = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: ["atproto"])
            try await app.test(.router) { client in
                let gapHeaders = try self.dpopHeaders(
                    token: access.token, key: access.key, jwk: access.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "retention-gap", path: Self.oplogPath
                )
                try await client.execute(
                    uri: self.oplogURI(space: fixture.space, repo: Self.alice, since: fixture.tids[0]),
                    method: .get, headers: gapHeaders
                ) { response in
                    XCTAssertEqual(response.status, .conflict)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "full_repo_recovery_required")
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("value"))
                }
            }
            let accountPath = SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice)
            try FileManager.default.removeItem(at: accountPath)
            let missingHeaders = try dpopHeaders(
                token: access.token, key: access.key, jwk: access.jwk,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "missing-preopened", path: Self.latestPath
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice), method: .get, headers: missingHeaders
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
                let missingCARHeaders = try self.dpopHeaders(
                    token: access.token, key: access.key, jwk: access.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "missing-preopened-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: missingCARHeaders
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testCorruptProjectionAndDefaultRouteCloseWithoutRenderingRecords() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let corrupt = CorruptSyncDirectory(space: fixture.space, author: Self.alice)
            let server = try makeServer(
                fixture,
                enabled: true,
                directory: corrupt
            ).buildApplication(logger: Logger(label: "RepositorySyncHTTPTests.corrupt"))
            let access = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: ["atproto"])
            let headers = try dpopHeaders(
                token: access.token, key: access.key, jwk: access.jwk,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "corrupt-oplog", path: Self.oplogPath
            )
            try await server.test(.router) { client in
                try await client.execute(
                    uri: self.oplogURI(space: fixture.space, repo: Self.alice), method: .get, headers: headers
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("secret"))
                }
                let carHeaders = try self.dpopHeaders(
                    token: access.token, key: access.key, jwk: access.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "corrupt-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: carHeaders
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("secret"))
                }
            }

            let closed = try makeServer(fixture, enabled: false).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.default-closed")
            )
            try await closed.test(.router) { client in
                try await client.execute(uri: Self.latestPath, method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
                try await client.execute(uri: Self.repoPath, method: .get) { response in
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

    private func makeServer(
        _ fixture: Fixture,
        enabled: Bool,
        directory: (any AuthorizedSimpleSpaceDirectory)? = nil
    ) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        let selectedDirectory = directory ?? fixture.directory
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: selectedDirectory,
            accountControlStore: fixture.control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: LocalAccountSpaceCredentialSigningKeyResolver(
                    accounts: fixture.accounts, keyStore: fixture.keyStore
                ),
                delegationPublicKeys: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: fixture.accounts, publicKeyStore: fixture.keyStore
                ),
                credentialPublicKeys: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts, publicKeyStore: fixture.keyStore
                )
            ),
            spaceRepositorySyncConfiguration: enabled ? .init(
                commitSigner: LocalAccountSpaceRepositoryCommitSigner(
                    accounts: fixture.accounts, keyStore: fixture.keyStore
                )
            ) : nil
        )
    }

    /// Mirrors Task 27's local serve composition: exchange and sync receive
    /// their narrow credential dependencies, while record/blob credential
    /// reads stay unavailable unless a caller explicitly asks for the broad
    /// legacy credential configuration.
    private func makeExchangeAndSyncOnlyServer(_ fixture: Fixture) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        let credentials = SwanSpaceCredentialHTTPConfiguration(
            authoritySigningKeys: LocalAccountSpaceCredentialSigningKeyResolver(
                accounts: fixture.accounts, keyStore: fixture.keyStore
            ),
            delegationPublicKeys: LocalAccountSpaceDelegationPublicKeyResolver(
                accounts: fixture.accounts, publicKeyStore: fixture.keyStore
            ),
            credentialPublicKeys: LocalAccountSpaceCredentialPublicKeyResolver(
                accounts: fixture.accounts, publicKeyStore: fixture.keyStore
            )
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control,
            spaceCredentialExchangeConfiguration: credentials,
            spaceRepositorySyncConfiguration: .init(
                commitSigner: LocalAccountSpaceRepositoryCommitSigner(
                    accounts: fixture.accounts, keyStore: fixture.keyStore
                )
            ),
            spaceRepositoryCredentialConfiguration: .init(
                credentialPublicKeys: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts, publicKeyStore: fixture.keyStore
                )
            )
        )
    }

    private func latestURI(space: SpaceURI, repo: String) -> String {
        "\(Self.latestPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)"
    }

    private func repoURI(space: SpaceURI, repo: String) -> String {
        "\(Self.repoPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)"
    }

    private func blobURI(space: SpaceURI, repo: String, cid: String) -> String {
        "\(Self.blobPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)&cid=\(cid)"
    }

    private func oplogURI(
        space: SpaceURI,
        repo: String,
        since: String? = nil,
        limit: Int? = nil,
        excludeValues: Bool? = nil
    ) -> String {
        var values = ["space=\(percentEncode(space.rawValue))", "repo=\(repo)"]
        if let since { values.append("since=\(since)") }
        if let limit { values.append("limit=\(limit)") }
        if let excludeValues { values.append("excludeValues=\(excludeValues ? "true" : "false")") }
        return "\(Self.oplogPath)?\(values.joined(separator: "&"))"
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
                jwtID: "sync-issue-\(UUID().uuidString)",
                issuedAt: now
            ),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(subject: subject, session: session, now: now)
        return .init(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func dpopHeaders(
        token: String,
        key: P256.Signing.PrivateKey,
        jwk: OAuthJSONWebKey,
        nonce: String,
        jti: String,
        path: String
    ) throws -> HTTPFields {
        struct Header: Encodable { let alg = "ES256"; let typ = OAuthDPoPProofValidator.proofType; let jwk: OAuthJSONWebKey }
        struct Claims: Encodable { let jti: String; let iat: Int64; let htm: String; let htu: String; let nonce: String; let ath: String }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            jti: jti, iat: Int64(Date().timeIntervalSince1970), htm: "GET",
            htu: "\(Self.publicURL.absoluteString)\(path)", nonce: nonce,
            ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString()
        var fields = HTTPFields()
        fields[.authorization] = "DPoP \(token)"
        fields[HTTPField.Name("DPoP")!] = "\(input).\(signature)"
        return fields
    }

    private func bearerHeaders(_ credential: String, dpop: String? = nil) -> HTTPFields {
        var fields = HTTPFields()
        fields[.authorization] = "Bearer \(credential)"
        if let dpop { fields[HTTPField.Name("DPoP")!] = dpop }
        return fields
    }

    private func assertCommit(
        _ object: [String: Any],
        fixture: Fixture,
        author: String
    ) throws {
        let hash = try bytes("hash", in: object)
        let ikm = try bytes("ikm", in: object)
        let sig = try bytes("sig", in: object)
        let mac = try bytes("mac", in: object)
        let revision = try XCTUnwrap(object["rev"] as? String)
        XCTAssertEqual(hash.count, 32)
        let envelope = try SpaceCommitEnvelope(
            context: .init(space: fixture.space, author: author, rev: revision, ikm: ikm),
            contextSignature: sig,
            contentBinding: mac,
            commitment: hash
        )
        let encodedPublicKey = try XCTUnwrap(fixture.publicKeys[author])
        let publicKey = try P256.Signing.PublicKey(x963Representation: encodedPublicKey)
        XCTAssertTrue(try SpaceCommitCodec.verifyContextSignature(envelope, publicKey: publicKey))
        XCTAssertTrue(SpaceCommitCodec.verifyContentBinding(envelope))
    }

    private func bytes(_ name: String, in object: [String: Any]) throws -> Data {
        let wrapped = try XCTUnwrap(object[name] as? [String: Any])
        return try XCTUnwrap((wrapped["$bytes"] as? String).flatMap { Data(base64Encoded: $0) })
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

    private func assertNoStore(_ response: TestResponse, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
    }

    private func assertCARNoStore(_ response: TestResponse, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(response.headers[.contentType], "application/vnd.ipld.car", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
    }

    private func assertBlobHeaders(
        _ response: TestResponse,
        cid: String,
        length: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(response.headers[.contentType], "application/octet-stream", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
        XCTAssertEqual(response.headers[.contentLength], String(length), file: file, line: line)
        XCTAssertEqual(response.headers[HTTPField.Name("X-Content-Type-Options")!], "nosniff", file: file, line: line)
        XCTAssertEqual(response.headers[HTTPField.Name("Content-Disposition")!], "attachment; filename=\"\(cid)\"", file: file, line: line)
        XCTAssertEqual(response.headers[HTTPField.Name("Content-Security-Policy")!], "default-src 'none'; sandbox", file: file, line: line)
    }

    private func assertRecoveryCAR(
        _ data: Data,
        fixture: Fixture,
        author: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> [String: Data] {
        let reader = try CARReader(data: data)
        XCTAssertEqual(reader.roots.count, 2, file: file, line: line)
        let publicKey = try P256.Signing.PublicKey(
            x963Representation: try XCTUnwrap(fixture.publicKeys[author])
        )
        return try SpaceCARCodec.verify(
            data,
            space: fixture.space,
            author: author,
            publicKey: publicKey
        )
    }

    private func commitIKM(in car: Data) throws -> Data {
        let reader = try CARReader(data: car)
        let commitCID = try XCTUnwrap(reader.roots.first)
        let commit = try XCTUnwrap(
            try reader.decodeBlock(for: CARReader.cidHex(from: commitCID)) as? [String: Any]
        )
        return try XCTUnwrap(commit["ikm"] as? Data)
    }

    /// CARReader deliberately indexes by CID, so this small test-only parser
    /// preserves physical block order for the proposal's lexical record-block
    /// assertion. Swan's CIDs are all the fixed one-byte-varint SHA-256 CIDv1
    /// form used by the pinned profile.
    private func carBlockCIDs(_ car: Data) throws -> [CID] {
        var offset = 0
        let headerLength = try carVarint(car, offset: &offset)
        guard headerLength >= 0, offset + headerLength <= car.count else {
            throw SwanError.malformed("invalid CAR header")
        }
        offset += headerLength
        var cids: [CID] = []
        while offset < car.count {
            let blockLength = try carVarint(car, offset: &offset)
            guard blockLength >= 4, offset + blockLength <= car.count,
                  car[offset] == 0x01
            else { throw SwanError.malformed("invalid CAR block") }
            let digestLength = Int(car[offset + 3])
            let cidLength = 4 + digestLength
            guard cidLength <= blockLength else {
                throw SwanError.malformed("invalid CAR CID")
            }
            cids.append(try CID(bytes: Data(car[offset ..< offset + cidLength])))
            offset += blockLength
        }
        return cids
    }

    private func carVarint(_ data: Data, offset: inout Int) throws -> Int {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        while offset < data.count {
            let byte = data[offset]
            offset += 1
            value |= UInt64(byte & 0x7f) << shift
            if byte & 0x80 == 0, value <= UInt64(Int.max) {
                return Int(value)
            }
            shift += 7
            if shift > 63 { break }
        }
        throw SwanError.malformed("invalid CAR varint")
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

private actor DataBox {
    private(set) var value: Data?

    func set(_ value: Data) {
        self.value = value
    }
}

private struct Fixture: Sendable {
    let root: URL
    let space: SpaceURI
    let control: SQLiteControlDatabase
    let keyStore: FileAccountKeyStore
    let accounts: DurableAccountDirectory
    let directory: SQLitePreMigratedAccountDirectory
    let runtime: SwanOAuthRuntime
    let references: [String: AccountKeyReference]
    let publicKeys: [String: Data]
    let tids: [String]
    let blobCID: String
    let blobPayload: Data

    static func make(retention: Int = 10_000) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "RepositorySyncHTTPTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let keyStore = try FileAccountKeyStore(
                root: root.appending(path: "keys"),
                configuration: try .init(activeKeyID: "sync-kek", activeKey: Data(repeating: 0x45, count: 32))
            )
            let provisioner = AccountKeyProvisioner(keyStore: keyStore)
            let aliceKeys = try await provisioner.provisionInitial(accountDID: RepositorySyncHTTPTests.alice)
            let bobKeys = try await provisioner.provisionInitial(accountDID: RepositorySyncHTTPTests.bob)
            guard let alicePublicKey = try await keyStore.publicKey(for: aliceKeys.signingReference),
                  let bobPublicKey = try await keyStore.publicKey(for: bobKeys.signingReference) else {
                throw SwanError.unavailable("test signing public key is unavailable")
            }
            for (did, handle, keys) in [
                (RepositorySyncHTTPTests.alice, "alice.example.com", aliceKeys),
                (RepositorySyncHTTPTests.bob, "bob.example.com", bobKeys),
            ] {
                _ = try await control.createAccount(try registration(did: did, handle: handle, keys: keys))
            }
            let space = try SpaceURI(
                authority: RepositorySyncHTTPTests.alice,
                spaceType: "app.bsky.bookmarks",
                skey: "sync"
            )
            let tids = try [0, 1, 2, 3, 4].map(tid)
            let authorization: AuthorizationContext = .accountOAuth(
                subject: RepositorySyncHTTPTests.alice,
                scopes: ["atproto"]
            )
            let aliceDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: RepositorySyncHTTPTests.alice, oplogRetention: retention)
            _ = try await aliceDatabase.createSimpleSpace(
                space: space,
                owner: RepositorySyncHTTPTests.alice,
                configuration: .init(policy: .public, appAccess: .open),
                authorization: authorization
            )
            let aliceRepository = try DurableSpaceRepository(database: aliceDatabase, space: space, author: RepositorySyncHTTPTests.alice)
            let first = try SpaceRecordURI(space: space, author: RepositorySyncHTTPTests.alice, collection: "app.bsky.feed.post", rkey: "first")
            let second = try SpaceRecordURI(space: space, author: RepositorySyncHTTPTests.alice, collection: "app.bsky.feed.post", rkey: "second")
            _ = try await aliceRepository.apply(.put(uri: first, value: recordCBOR("one")), expectedRevision: 0, requestID: UUID(), wireRevision: try TID(tidString: tids[0]), authorization: authorization)
            _ = try await aliceRepository.apply(.put(uri: first, value: recordCBOR("two")), expectedRevision: 1, requestID: UUID(), wireRevision: try TID(tidString: tids[1]), authorization: authorization)
            _ = try await aliceRepository.apply(.put(uri: second, value: recordCBOR("three")), expectedRevision: 2, requestID: UUID(), wireRevision: try TID(tidString: tids[2]), authorization: authorization)
            _ = try await aliceRepository.apply(.delete(uri: second), expectedRevision: 3, requestID: UUID(), wireRevision: try TID(tidString: tids[3]), authorization: authorization)
            let third = try SpaceRecordURI(space: space, author: RepositorySyncHTTPTests.alice, collection: "app.bsky.feed.post", rkey: "third")
            let fourth = try SpaceRecordURI(space: space, author: RepositorySyncHTTPTests.alice, collection: "app.bsky.feed.post", rkey: "fourth")
            _ = try await aliceRepository.applyAtomically(
                [.put(uri: third, value: recordCBOR("four")), .put(uri: fourth, value: recordCBOR("five"))],
                expectedRevision: 4,
                requestID: UUID(),
                wireRevision: try TID(tidString: tids[4]),
                authorization: authorization
            )
            let blobPayload = Data("permissioned blob payload".utf8)
            let blob = try await aliceDatabase.putBlob(
                blobPayload,
                namespace: .space(space)
            )
            try await aliceDatabase.close()

            let bobDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: RepositorySyncHTTPTests.bob, oplogRetention: retention)
            let bobRepository = try DurableSpaceRepository(database: bobDatabase, space: space, author: RepositorySyncHTTPTests.bob)
            let bobRecord = try SpaceRecordURI(space: space, author: RepositorySyncHTTPTests.bob, collection: "app.bsky.feed.post", rkey: "bob")
            _ = try await bobRepository.apply(.put(uri: bobRecord, value: recordCBOR("bob")), expectedRevision: 0, requestID: UUID(), wireRevision: try TID(tidString: tids[0]), authorization: .accountOAuth(subject: RepositorySyncHTTPTests.bob, scopes: ["atproto"]))
            try await bobDatabase.close()

            let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let accounts = DurableAccountDirectory(
                store: control,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher, maximumConcurrentVerifications: 1, maximumQueuedVerifications: 1)
            )
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(dataDirectory: root, controlStore: control, oplogRetention: retention)
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0x92, count: 32))
            return Fixture(
                root: root, space: space, control: control, keyStore: keyStore,
                accounts: accounts, directory: directory, runtime: runtime,
                references: [RepositorySyncHTTPTests.alice: aliceKeys.signingReference, RepositorySyncHTTPTests.bob: bobKeys.signingReference],
                publicKeys: [RepositorySyncHTTPTests.alice: alicePublicKey, RepositorySyncHTTPTests.bob: bobPublicKey],
                tids: tids,
                blobCID: blob.cid,
                blobPayload: blobPayload
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func credential(for space: SpaceURI) async throws -> String {
        let reference = try signingReference(for: RepositorySyncHTTPTests.alice)
        let scalar = try await keyStore.key(for: reference)
        return try PermissionedDataJWT.createSpaceCredential(
            issuer: RepositorySyncHTTPTests.alice,
            space: space,
            key: try P256.Signing.PrivateKey(rawRepresentation: scalar)
        )
    }

    func signingReference(for did: String) throws -> AccountKeyReference {
        try XCTUnwrap(references[did])
    }

    func close() async throws {
        try await directory.close()
        try await control.close()
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }

    private static func registration(
        did: String,
        handle: String,
        keys: ProvisionedAccountKeys
    ) throws -> AccountControlRegistration {
        try .init(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(purpose: .signing, generation: keys.signingReference.generation),
            rotationKey: .init(purpose: .rotation, generation: keys.rotationReference.generation),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private static func tid(_ offset: Int) throws -> String {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return "222222222222\(alphabet[offset])"
    }

    private static func recordCBOR(_ text: String) -> Data {
        Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, UInt8(0x60 + text.utf8.count)]) + Data(text.utf8)
    }
}

private actor CorruptSyncDirectory: AuthorizedSimpleSpaceDirectory, AuthorizedSpaceRepositoryDirectory {
    let space: SpaceURI
    let author: String

    init(space: SpaceURI, author: String) {
        self.space = space
        self.author = author
    }

    func space(_ space: SpaceURI, authorization _: AuthorizationContext) async throws -> AuthenticatedSimpleSpaceDescription? { nil }
    func close() async throws {}
    func record(_ uri: SpaceRecordURI, authorization _: AuthorizationContext) async throws -> SpaceRecord? { nil }
    func records(space _: SpaceURI, author _: String, collection _: String?, limit _: Int, cursor _: String?, reverse _: Bool, authorization _: AuthorizationContext) async throws -> [SpaceRecord] { [] }
    func repositoryCommitState(space: SpaceURI, author: String, authorization _: AuthorizationContext) async throws -> AuthorizedSpaceRepositoryCommitState {
        .init(space: space, author: author, wireRevision: "2222222222222", commitment: Data(repeating: 0x01, count: 32))
    }
    func repositoryOplog(space: SpaceURI, author: String, since _: String?, limit _: Int, includeValues _: Bool, authorization _: AuthorizationContext) async throws -> AuthorizedSpaceRepositoryOplogRead {
        .incremental(
            state: .init(space: space, author: author, wireRevision: "2222222222222", commitment: Data(repeating: 0x01, count: 32)),
            entries: [.init(wireRevision: "2222222222222", collection: "app.bsky.feed.post", rkey: "secret", cid: "not-a-cid", previousCID: nil, value: Data("secret".utf8))]
        )
    }
    func repositoryCARSnapshot(space _: SpaceURI, author _: String, authorization _: AuthorizationContext) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        throw SwanError.unavailable("corrupt repository projection")
    }
    func apply(space _: SpaceURI, author _: String, writes _: [AuthorizedSpaceRepositoryWrite], requestID _: UUID, wireRevision _: String, authorization _: AuthorizationContext) async throws -> [AuthorizedSpaceRepositoryWriteResult] { [] }
}
