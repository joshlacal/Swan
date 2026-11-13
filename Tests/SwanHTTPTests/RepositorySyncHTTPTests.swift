import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import PetrelCrypto
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
@testable import swan
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

private actor RuntimeTokenCapture {
    private var delegation = ""
    private var credential = ""

    func setDelegation(_ value: String) { delegation = value }
    func setCredential(_ value: String) { credential = value }
    func tokens() -> (delegation: String, credential: String) { (delegation, credential) }
}

final class RepositorySyncHTTPTests: XCTestCase, @unchecked Sendable {
    static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let latestPath = "/xrpc/com.atproto.space.getLatestCommit"
    private static let oplogPath = "/xrpc/com.atproto.space.listRepoOps"
    private static let repoPath = "/xrpc/com.atproto.space.getRepo"
    private static let blobPath = "/xrpc/com.atproto.space.getBlob"
    fileprivate static let runtimeVerifierSentinel =
        "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuvw$TASK27VERIFIERSECRETMUSTNOTLEAKABCDEFGHIJKLMNO"

    func testExchangeAndSyncOnlyCredentialCompositionLeavesRecordAndBlobOAuthOnly() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let server = try makeExchangeAndSyncOnlyServer(fixture)

        XCTAssertNotNil(server.authenticatedSpaceCredentialExchange)
        XCTAssertNotNil(server.authenticatedSpaceRepositorySync?.credentialAuthorizer)
        XCTAssertNil(server.authenticatedSpaceRecords?.credentialAuthorizer)
        XCTAssertNil(server.authenticatedSpaceBlobs?.credentialAuthorizer)
    }

    func testListRepoOpsUsesSharedJSONAdmissionBeforeReadingRepository() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let admission = try PublicRepositoryJSONReadAdmission(
                maximumConcurrentReads: 1,
                maximumReservedResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumListRecordsResponseBytes
            )
            let held = try XCTUnwrap(admission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumListRecordsResponseBytes
            ))
            let app = try makeServer(
                fixture,
                enabled: true,
                jsonReadAdmission: admission
            ).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.admission")
            )
            let oauth = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.alice,
                scopes: [wholeSpaceReadScope(for: fixture.space)]
            )
            let headers = try self.dpopHeaders(
                token: oauth.token,
                key: oauth.key,
                jwk: oauth.jwk,
                nonce: fixture.runtime.dpopNonceService.issue(),
                jti: "oplog-admission-blocked",
                path: Self.oplogPath
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.oplogURI(
                        space: fixture.space,
                        repo: Self.alice,
                        limit: 1
                    ),
                    method: .get,
                    headers: headers
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "temporarily_unavailable"
                    )
                }
            }
            held.release()
            XCTAssertEqual(admission.snapshot.activeLeases, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testActualLocalServeRuntimeMountsKeysForDelegationExchangeAndSyncOnly() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }
        let mountedKEK = fixture.root.appending(path: "mounted-space-kek")
        let mountedKEKText = Data(repeating: 0x45, count: 32).base64URLEncodedString()
        try mountedKEKText.data(using: .utf8)!
            .write(to: mountedKEK)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: mountedKEK.path)

        let local = try await ServeLocalSpaceRuntime.make(
            keyDirectory: fixture.root.appending(path: "keys"),
            kekFile: mountedKEK,
            kekID: "sync-kek",
            controlStore: fixture.control
        )
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-10-29.json")
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
        let credentialPath = "/xrpc/com.atproto.space.authorizeSpaceSync"

        let app = server.buildApplication(logger: Logger(label: "RepositorySyncHTTPTests.localRuntime"))
        let observedTokens = RuntimeTokenCapture()
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
            try await client.execute(uri: delegationURI, method: .get, headers: delegationHeaders) { response in
                XCTAssertEqual(response.status, .ok)
                await observedTokens.setDelegation(
                    try XCTUnwrap(self.jsonObject(response.body)["token"] as? String)
                )
            }
            let delegation = await observedTokens.tokens().delegation
            let exchangeHeaders = SpaceCredentialSignatureTestSupport.exchangeHeaders()
            let exchangeBody = ByteBuffer(data: try JSONSerialization.data(withJSONObject: [
                "space": fixture.space.rawValue,
                "credentialKey": try SpaceCredentialSignatureTestSupport.keyID,
                "delegationToken": delegation,
            ]))
            try await client.execute(uri: credentialPath, method: .post, headers: exchangeHeaders, body: exchangeBody) { response in
                XCTAssertEqual(response.status, .ok)
                await observedTokens.setCredential(
                    try XCTUnwrap(self.jsonObject(response.body)["credential"] as? String)
                )
            }
            let credential = await observedTokens.tokens().credential
            // Reusing a body-bound delegation exercises durable replay protection.
            try await client.execute(uri: credentialPath, method: .post, headers: SpaceCredentialSignatureTestSupport.exchangeHeaders(), body: exchangeBody) { response in
                XCTAssertEqual(response.status, .badRequest)
                self.assertRuntimeSecretsAbsent(
                    response.body,
                    mountedKEK: mountedKEKText,
                    mountedPath: mountedKEK.path,
                    delegation: delegation,
                    credential: credential
                )
            }
            for uri in [self.latestURI(space: fixture.space, repo: Self.alice),
                        self.oplogURI(space: fixture.space, repo: Self.alice)] {
                let headers = try self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
                try await client.execute(uri: uri, method: .get, headers: headers) { response in
                    XCTAssertEqual(response.status, .ok)
                    let commit = try XCTUnwrap(self.jsonObject(response.body)["commit"] as? [String: Any])
                    try self.assertCommit(commit, fixture: fixture, author: Self.alice,
                                          requestHeaders: headers, responseHeaders: response.headers)
                }
            }
            let archiveHeaders = try self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
            try await client.execute(uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: archiveHeaders) { response in
                XCTAssertEqual(response.status, .ok)
                self.assertSTARNoStore(response)
                _ = try self.assertRecoverySTAR(
                    Data(buffer: response.body), fixture: fixture, author: Self.alice,
                    requestHeaders: archiveHeaders, responseHeaders: response.headers
                )
            }
            try await client.execute(uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID), method: .get, headers: self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)) { response in
                XCTAssertEqual(response.status, .unauthorized)
                self.assertRuntimeSecretsAbsent(
                    response.body,
                    mountedKEK: mountedKEKText,
                    mountedPath: mountedKEK.path,
                    delegation: delegation,
                    credential: credential
                )
            }
        }
        let tokens = await observedTokens.tokens()
        let closedApp = closed.buildApplication(logger: Logger(label: "RepositorySyncHTTPTests.localRuntimeClosed"))
        try await closedApp.test(.router) { client in
            try await client.execute(uri: credentialPath, method: .post) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                self.assertRuntimeSecretsAbsent(
                    response.body,
                    mountedKEK: mountedKEKText,
                    mountedPath: mountedKEK.path,
                    delegation: tokens.delegation,
                    credential: tokens.credential
                )
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
                scopes: [wholeSpaceReadScope(for: fixture.space)]
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
                    headers: self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
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
            let alice = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: [wholeSpaceReadScope(for: fixture.space)])
            let bob = try await issueToken(runtime: fixture.runtime, subject: Self.bob, scopes: [wholeSpaceReadScope(for: fixture.space)])
            let narrowScope = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read_self&collection=app.bsky.feed.post"
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

                // Erratum 03: a collection-qualified read grant FETCHES a
                // single blob — the aggregate classification that refused it
                // protected nothing once the same grant could exchange for a
                // whole-space credential reading the identical bytes. The
                // foreign-subject refusal above is the boundary that remains.
                let narrowHeaders = try self.dpopHeaders(
                    token: narrow.token, key: narrow.key, jwk: narrow.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "blob-narrow", path: Self.blobPath
                )
                try await client.execute(
                    uri: self.blobURI(space: fixture.space, repo: Self.alice, cid: fixture.blobCID),
                    method: .get, headers: narrowHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.contentType], "application/octet-stream")
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

    func testGetRepoStreamsStableSTARWithFreshCredentialMACsAndStrictRecordOrder() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.getRepo")
            )
            let oauth = try await issueToken(runtime: fixture.runtime, subject: Self.alice,
                                             scopes: [wholeSpaceReadScope(for: fixture.space)])
            let credential = try await fixture.credential(for: fixture.space)
            let firstArchive = DataBox()
            let firstMemberArchive = DataBox()
            let firstMemberMAC = DataBox()
            try await app.test(.router) { client in
                for index in 0 ..< 2 {
                    let headers = try self.dpopHeaders(
                        token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                        nonce: fixture.runtime.dpopNonceService.issue(),
                        jti: "repo-oauth-\(index)", path: Self.repoPath
                    )
                    try await client.execute(uri: self.repoURI(space: fixture.space, repo: Self.alice),
                                             method: .get, headers: headers) { response in
                        XCTAssertEqual(response.status, .ok)
                        self.assertSTARNoStore(response)
                        XCTAssertNil(response.headers[.contentLength])
                        let archive = Data(buffer: response.body)
                        let verified = try self.assertRecoverySTAR(
                            archive, fixture: fixture, author: Self.alice,
                            requestHeaders: headers, responseHeaders: response.headers
                        )
                        XCTAssertEqual(verified.records.map { $0.uri.rkey }, ["first", "fourth", "third"])
                        if index == 0 { await firstArchive.set(archive) }
                        else {
                            let initial = await firstArchive.value
                            XCTAssertEqual(archive, initial)
                        }
                    }
                }

                let firstHeaders = try self.credentialHeaders(credential, audience: Self.bob, fixture: fixture)
                let secondHeaders = try self.credentialHeaders(credential, audience: Self.bob, fixture: fixture)
                XCTAssertNotEqual(firstHeaders[HTTPField.Name(SpaceMACHeaders.requestHeader)!],
                                  secondHeaders[HTTPField.Name(SpaceMACHeaders.requestHeader)!])
                for (index, headers) in [firstHeaders, secondHeaders].enumerated() {
                    try await client.execute(uri: self.repoURI(space: fixture.space, repo: Self.bob),
                                             method: .get, headers: headers) { response in
                        XCTAssertEqual(response.status, .ok)
                        self.assertSTARNoStore(response)
                        let archive = Data(buffer: response.body)
                        let verified = try self.assertRecoverySTAR(
                            archive, fixture: fixture, author: Self.bob,
                            requestHeaders: headers, responseHeaders: response.headers
                        )
                        XCTAssertEqual(verified.records.map { $0.uri.rkey }, ["bob"])
                        let signature = try XCTUnwrap(response.headers[
                            HTTPField.Name(SpaceMACHeaders.signatureHeader)!
                        ])
                        if index == 0 {
                            await firstMemberArchive.set(archive)
                            await firstMemberMAC.set(Data(signature.utf8))
                        } else {
                            let initialArchive = await firstMemberArchive.value
                            let initialMAC = await firstMemberMAC.value
                            XCTAssertEqual(archive, initialArchive)
                            XCTAssertNotEqual(Data(signature.utf8), initialMAC)
                        }
                    }
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testOAuthSelfAndCredentialCrossRepositoryReturnNativeCommitsAndReferencePages() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.success")
            )
            let oauth = try await issueToken(
                runtime: fixture.runtime,
                subject: Self.alice,
                scopes: [wholeSpaceReadScope(for: fixture.space)]
            )
            let credential = try await fixture.credential(for: fixture.space)
            try await app.test(.router) { client in
                var firstCommit: SpaceRepositoryCommit?
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
                    firstCommit = try self.assertCommit(commit, fixture: fixture, author: Self.alice,
                                                        requestHeaders: latestHeaders, responseHeaders: response.headers)
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
                    let current = try self.assertCommit(commit, fixture: fixture, author: Self.alice,
                                                        requestHeaders: freshLatestHeaders, responseHeaders: response.headers)
                    XCTAssertEqual(current, firstCommit)
                }

                // A key-bound space credential may read a different member
                // repository when its request signature matches the credential
                // and names that member as its audience.
                let memberHeaders = try self.credentialHeaders(credential, audience: Self.bob, fixture: fixture)
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.bob),
                    method: .get,
                    headers: memberHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let commit = try XCTUnwrap((try self.jsonObject(response.body))["commit"] as? [String: Any])
                    try self.assertCommit(commit, fixture: fixture, author: Self.bob,
                                          requestHeaders: memberHeaders, responseHeaders: response.headers)
                }

                // The pre-rename `getRepoState` alias answers identically to
                // the canonical name: clients built on the atproto-crates
                // lineage (bulleted.app) know only the alias.
                let aliasURI = self.latestURI(space: fixture.space, repo: Self.bob)
                    .replacingOccurrences(
                        of: "com.atproto.space.getLatestCommit",
                        with: "com.atproto.space.getRepoState"
                    )
                // atproto#5569 signatures bind the credential and its
                // audience, not the URL, so the same signed headers serve
                // both names; what they cannot do is read another audience.
                try await client.execute(
                    uri: aliasURI, method: .get,
                    headers: self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "BadSpaceAudience")
                }
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.bob), method: .get,
                    headers: self.credentialHeaders(credential, audience: Self.bob, fixture: fixture)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let aliasHeaders = try self.credentialHeaders(credential, audience: Self.bob, fixture: fixture)
                try await client.execute(
                    uri: aliasURI, method: .get, headers: aliasHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let commit = try XCTUnwrap((try self.jsonObject(response.body))["commit"] as? [String: Any])
                    try self.assertCommit(commit, fixture: fixture, author: Self.bob,
                                          requestHeaders: aliasHeaders, responseHeaders: response.headers)
                }

                // And the service description lists the alias here, where its
                // route is live.
                try await client.execute(
                    uri: "/xrpc/community.lexicon.service.describe", method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let object = try XCTUnwrap(
                        try self.jsonObject(response.body) as? [String: Any])
                    let values = try XCTUnwrap(object["methods"] as? [[String: Any]])
                        .compactMap { $0["value"] as? String }
                    XCTAssertTrue(values.contains("com.atproto.space.getRepoState"))
                    XCTAssertTrue(values.contains("com.atproto.space.getLatestCommit"))
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
                    XCTAssertNotNil(body["cursor"])
                    try self.assertCommit(
                        try XCTUnwrap(body["commit"] as? [String: Any]),
                        fixture: fixture,
                        author: Self.alice,
                        requestHeaders: pageHeaders,
                        responseHeaders: response.headers
                    )
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
                        author: Self.alice,
                        responseHeaders: response.headers
                    )
                }

                // Swan keeps same-revision operations atomic. A boundary may
                // therefore overflow the requested limit; it is still a full
                // page and carries a cursor. The current commit is present on
                // every page.
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
                    XCTAssertEqual(body["cursor"] as? String, "\(fixture.tids[4])/1")
                    try self.assertCommit(
                        try XCTUnwrap(body["commit"] as? [String: Any]),
                        fixture: fixture,
                        author: Self.alice,
                        requestHeaders: boundaryHeaders,
                        responseHeaders: response.headers
                    )
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
                        author: Self.alice,
                        responseHeaders: response.headers
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

    func testCredentialSyncRequiresOneValidRepositoryMACExchangeAndOwnerMayOptIn() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.macAdmission")
            )
            let credential = try await fixture.credential(for: fixture.space)
            let oauth = try await issueToken(runtime: fixture.runtime, subject: Self.alice,
                                             scopes: [wholeSpaceReadScope(for: fixture.space)])
            let requestName = HTTPField.Name(SpaceMACHeaders.requestHeader)!
            let signatureName = HTTPField.Name(SpaceMACHeaders.signatureHeader)!
            try await app.test(.router) { client in
                for uri in [self.latestURI(space: fixture.space, repo: Self.alice),
                            self.oplogURI(space: fixture.space, repo: Self.alice, limit: 1),
                            self.repoURI(space: fixture.space, repo: Self.alice)] {
                    for failure in [
                        "missing", "wrong-tag", "invalid-key", "duplicate",
                        "malformed", "unsupported", "wrong-component", "wrong-alg",
                    ] {
                        var headers = try self.credentialHeaders(
                            credential,
                            audience: Self.alice,
                            fixture: fixture
                        )
                        let valid = try XCTUnwrap(headers[requestName])
                        let parsed = try XCTUnwrap(
                            SpaceMACHeaders.parseRequest(valid, profile: .commit)
                        )
                        switch failure {
                        case "missing":
                            headers[requestName] = nil
                        case "wrong-tag":
                            headers[requestName] = try SpaceMACHeaders.makeRequest(
                                keyID: parsed.keyID,
                                profile: .record
                            ).headerValue
                        case "invalid-key":
                            headers[requestName] =
                                #"mac=("atproto-space-commit";sf);keyid="did:key:invalid";tag="atproto-space-commit""#
                        case "duplicate":
                            headers[requestName] =
                                valid + ", second=" + parsed.signatureParameters
                        case "malformed":
                            headers[requestName] = "not a structured field"
                        case "unsupported":
                            headers[requestName] = valid + ";created=1"
                        case "wrong-component":
                            headers[requestName] =
                                #"mac=("atproto-space-record";sf);keyid="\#(parsed.keyID)";tag="atproto-space-commit""#
                        default:
                            headers[requestName] = valid + #";alg="sha-256""#
                        }
                        try await client.execute(
                            uri: uri,
                            method: .get,
                            headers: headers
                        ) { response in
                            XCTAssertEqual(response.status, .badRequest, failure)
                            XCTAssertEqual(
                                try self.errorCode(response.body),
                                "InvalidSpaceMac",
                                failure
                            )
                            XCTAssertNil(response.headers[signatureName])
                        }
                    }
                }
                var headers = try self.dpopHeaders(
                    token: oauth.token, key: oauth.key, jwk: oauth.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "owner-mac-opt-in", path: Self.latestPath
                )
                let credentialRequest = try XCTUnwrap(
                    self.credentialHeaders(
                        credential,
                        audience: Self.alice,
                        fixture: fixture
                    )[requestName]
                )
                let keyID = try XCTUnwrap(
                    SpaceMACHeaders.parseRequest(
                        credentialRequest,
                        profile: .commit
                    )
                ).keyID
                let ignored = try SpaceMACHeaders.makeRequest(
                    keyID: keyID,
                    profile: .record,
                    label: "other"
                ).headerValue
                headers[requestName] = ignored + ", " + credentialRequest
                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.alice),
                    method: .get,
                    headers: headers
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let commit = try XCTUnwrap(
                        self.jsonObject(response.body)["commit"]
                            as? [String: Any]
                    )
                    try self.assertCommit(
                        commit,
                        fixture: fixture,
                        author: Self.alice,
                        requestHeaders: headers,
                        responseHeaders: response.headers
                    )
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testGetRepoIncludesAllRecordsAndRejectsRetiredExcludeValuesParameter() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.getRepoAllRecords")
            )
            let credential = try await fixture.credential(for: fixture.space)
            try await app.test(.router) { client in
                let headers = try self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
                try await client.execute(uri: self.repoURI(space: fixture.space, repo: Self.alice),
                                         method: .get, headers: headers) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertSTARNoStore(response)
                    let archive = try self.assertRecoverySTAR(Data(buffer: response.body), fixture: fixture,
                        author: Self.alice, requestHeaders: headers, responseHeaders: response.headers)
                    XCTAssertEqual(archive.records.count, 3)
                }
                for value in ["true", "false", "yes"] {
                    try await client.execute(
                        uri: self.repoURI(space: fixture.space, repo: Self.alice) + "&excludeValues=\(value)",
                        method: .get,
                        headers: self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest, value)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest", value)
                    }
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// SWAN-08: `listRepoOps` accepts the reference `${rev}/${idx}` cursor
    /// (preferred over `since`), emits one on each full page, and returns the
    /// current commit on every page. Following cursors yields every operation once.
    func testListRepoOpsCursorPagesEveryOperationOnceAndRejectsMalformedCursor() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture, enabled: true).buildApplication(
                logger: Logger(label: "RepositorySyncHTTPTests.oplogCursor")
            )
            let credential = try await fixture.credential(for: fixture.space)
            try await app.test(.router) { client in
                var collected: [String] = []
                var cursor: String?
                var cursors: [String] = []
                var caughtUp = false
                var previousKeyID: String?
                for _ in 0 ..< 10 {
                    let headers = try self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
                    let keyID = try XCTUnwrap(SpaceMACHeaders.parseRequest(
                        headers[HTTPField.Name(SpaceMACHeaders.requestHeader)!],
                        profile: .commit
                    )).keyID
                    XCTAssertNotEqual(keyID, previousKeyID)
                    previousKeyID = keyID
                    try await client.execute(
                        uri: self.oplogURI(
                            space: fixture.space,
                            repo: Self.alice,
                            // A stale `since` must lose to the cursor.
                            since: cursor == nil ? nil : fixture.tids[0],
                            limit: 2,
                            cursor: cursor
                        ),
                        method: .get,
                        headers: headers
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        let body = try self.jsonObject(response.body)
                        let ops = try XCTUnwrap(body["ops"] as? [[String: Any]])
                        collected += ops.map {
                            "\($0["rev"] as? String ?? "")/\($0["rkey"] as? String ?? "")"
                        }
                        let next = body["cursor"] as? String
                        try self.assertCommit(
                            try XCTUnwrap(body["commit"] as? [String: Any]),
                            fixture: fixture,
                            author: Self.alice,
                            requestHeaders: headers,
                            responseHeaders: response.headers
                        )
                        caughtUp = next == nil
                        cursor = next
                        if let next { cursors.append(next) }
                    }
                    if caughtUp { break }
                }
                XCTAssertTrue(caughtUp)
                XCTAssertEqual(collected.count, 6)
                XCTAssertEqual(Set(collected).count, 6)
                XCTAssertEqual(
                    collected.map { String($0.split(separator: "/")[0]) },
                    fixture.tids + [fixture.tids[4]]
                )
                XCTAssertEqual(
                    cursors,
                    ["\(fixture.tids[1])/0", "\(fixture.tids[3])/0", "\(fixture.tids[4])/1"]
                )

                for malformed in ["not-a-cursor", "\(fixture.tids[1])/x", "\(fixture.tids[1])/", "garbage/1", "\(fixture.tids[1])/0/1"] {
                    try await client.execute(
                        uri: self.oplogURI(
                            space: fixture.space,
                            repo: Self.alice,
                            cursor: malformed
                        ),
                        method: .get,
                        headers: self.credentialHeaders(credential, audience: Self.alice, fixture: fixture)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest, malformed)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidCursor", malformed)
                    }
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
            let alice = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: [wholeSpaceReadScope(for: fixture.space)])
            let bob = try await issueToken(runtime: fixture.runtime, subject: Self.bob, scopes: [wholeSpaceReadScope(for: fixture.space)])
            let narrowScope = "space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read_self&collection=app.bsky.feed.post"
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

                let foreignSTARHeaders = try self.dpopHeaders(
                    token: bob.token, key: bob.key, jwk: bob.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "foreign-repo-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: foreignSTARHeaders
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
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    XCTAssertNotNil((try self.jsonObject(response.body))["ops"])
                }

                let narrowSTARHeaders = try self.dpopHeaders(
                    token: narrow.token, key: narrow.key, jwk: narrow.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "narrow-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: narrowSTARHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertSTARNoStore(response)
                    XCTAssertFalse(response.body.readableBytesView.isEmpty)
                }

                try await client.execute(
                    uri: self.latestURI(space: fixture.space, repo: Self.bob), method: .get,
                    headers: self.credentialHeaders(wrongCredential, audience: Self.bob, fixture: fixture)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                }

                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.bob), method: .get,
                    headers: self.credentialHeaders(wrongCredential, audience: Self.bob, fixture: fixture)
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

                let starReplayHeaders = try self.dpopHeaders(
                    token: alice.token, key: alice.key, jwk: alice.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "repo-car-replay", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: starReplayHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertSTARNoStore(response)
                }
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: starReplayHeaders
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
                let inactiveSTARHeaders = try self.dpopHeaders(
                    token: alice.token, key: alice.key, jwk: alice.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "inactive-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: inactiveSTARHeaders
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
            let access = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: [wholeSpaceReadScope(for: fixture.space)])
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
                let missingSTARHeaders = try self.dpopHeaders(
                    token: access.token, key: access.key, jwk: access.jwk,
                    nonce: fixture.runtime.dpopNonceService.issue(),
                    jti: "missing-preopened-car", path: Self.repoPath
                )
                try await client.execute(
                    uri: self.repoURI(space: fixture.space, repo: Self.alice), method: .get, headers: missingSTARHeaders
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
            let access = try await issueToken(runtime: fixture.runtime, subject: Self.alice, scopes: [wholeSpaceReadScope(for: fixture.space)])
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
        directory: (any AuthorizedSimpleSpaceDirectory)? = nil,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission? = nil
    ) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-10-29.json")
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
            ) : nil,
            jsonReadAdmission: jsonReadAdmission
        )
    }

    /// Mirrors Task 27's local serve composition: exchange and sync receive
    /// their narrow credential dependencies, while record/blob credential
    /// reads stay unavailable unless a caller explicitly asks for the broad
    /// legacy credential configuration.
    private func makeExchangeAndSyncOnlyServer(_ fixture: Fixture) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-10-29.json")
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

    private func repoURI(space: SpaceURI, repo: String, excludeValues: Bool? = nil) -> String {
        var uri = "\(Self.repoPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)"
        if let excludeValues { uri += "&excludeValues=\(excludeValues ? "true" : "false")" }
        return uri
    }

    private func wholeSpaceReadScope(for space: SpaceURI) -> String {
        "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&action=read"
    }

    private func blobURI(space: SpaceURI, repo: String, cid: String) -> String {
        "\(Self.blobPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)&cid=\(cid)"
    }

    private func oplogURI(
        space: SpaceURI,
        repo: String,
        since: String? = nil,
        limit: Int? = nil,
        cursor: String? = nil,
        excludeValues: Bool? = nil
    ) -> String {
        var values = ["space=\(percentEncode(space.rawValue))", "repo=\(repo)"]
        if let since { values.append("since=\(since)") }
        if let limit { values.append("limit=\(limit)") }
        if let cursor { values.append("cursor=\(percentEncode(cursor))") }
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

    private func credentialHeaders(
        _ credential: String, audience: String, fixture: Fixture
    ) throws -> HTTPFields {
        var headers = try SpaceCredentialSignatureTestSupport.headers(token: credential, audience: audience)
        let key = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: XCTUnwrap(fixture.kemPrivateKeys[audience])
        )
        let exchange = try SpaceMACKeyAgreement.send(
            authorKeyID: AccountKEMKeyProvider.didKey(key.publicKey)
        )
        headers[HTTPField.Name(SpaceMACHeaders.requestHeader)!] =
            try SpaceMACHeaders.makeRequest(
                keyID: exchange.keyID,
                profile: .commit
            ).headerValue
        return headers
    }

    @discardableResult
    private func assertCommit(
        _ object: [String: Any],
        fixture: Fixture,
        author: String,
        requestHeaders: HTTPFields? = nil,
        responseHeaders: HTTPFields
    ) throws -> SpaceRepositoryCommit {
        XCTAssertEqual(Set(object.keys), Set(["ver", "repo", "space", "rev", "data"]))
        let commit = try JSONDecoder().decode(
            SpaceRepositoryCommit.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
        XCTAssertEqual(commit.repo, author)
        XCTAssertEqual(commit.space, fixture.space)
        XCTAssertEqual(commit.rev, author == Self.alice ? fixture.tids[4] : fixture.tids[0])
        XCTAssertEqual(commit.data, try fixture.expectedCommitment(author: author))
        try assertResponseMAC(commit, fixture: fixture, requestHeaders: requestHeaders, responseHeaders: responseHeaders)
        return commit
    }

    private func assertResponseMAC(
        _ commit: SpaceRepositoryCommit,
        fixture: Fixture,
        requestHeaders: HTTPFields?,
        responseHeaders: HTTPFields?
    ) throws {
        let signature = responseHeaders?[
            HTTPField.Name(SpaceMACHeaders.signatureHeader)!
        ]
        guard let requestValues = requestHeaders?[
            values: HTTPField.Name(SpaceMACHeaders.requestHeader)!
        ], !requestValues.isEmpty else {
            XCTAssertNil(
                signature,
                "Owner OAuth without a MAC exchange returns no response MAC"
            )
            return
        }
        let request = try XCTUnwrap(
            SpaceMACHeaders.parseRequest(requestValues, profile: .commit)
        )
        let key = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: XCTUnwrap(fixture.kemPrivateKeys[commit.repo])
        )
        let secret = try SpaceMACKeyAgreement.receive(
            authorPrivateKey: key,
            keyID: request.keyID
        )
        try SpaceMACHeaders.verifyCommit(
            commit,
            request: request,
            sharedSecret: secret,
            coveredHeader: responseHeaders?[
                HTTPField.Name(SpaceMACHeaders.commitHeader)!
            ],
            signatureInput: responseHeaders?[
                HTTPField.Name(SpaceMACHeaders.signatureInputHeader)!
            ],
            signature: signature
        )
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

    private func assertRuntimeSecretsAbsent(
        _ body: ByteBuffer,
        mountedKEK: String,
        mountedPath: String,
        delegation: String,
        credential: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let text = String(decoding: body.readableBytesView, as: UTF8.self)
        for secret in [
            mountedKEK, mountedPath, Self.runtimeVerifierSentinel,
            delegation, credential,
        ] {
            XCTAssertFalse(text.contains(secret), file: file, line: line)
        }
    }

    private func assertSTARNoStore(_ response: TestResponse, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(response.headers[.contentType], SpaceSTARCodec.mediaType, file: file, line: line)
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

    private func assertRecoverySTAR(
        _ data: Data,
        fixture: Fixture,
        author: String,
        requestHeaders: HTTPFields? = nil,
        responseHeaders: HTTPFields
    ) throws -> VerifiedSpaceSTARRecovery {
        try SpaceSTARCodec.decode(data, space: fixture.space, author: author) { commit in
            XCTAssertEqual(commit.repo, author)
            XCTAssertEqual(commit.space, fixture.space)
            XCTAssertEqual(commit.data, try fixture.expectedCommitment(author: author))
            try self.assertResponseMAC(commit, fixture: fixture,
                                       requestHeaders: requestHeaders, responseHeaders: responseHeaders)
            // OAuth transport authenticates the owner-only request when no
            // response MAC is requested. Credential paths always pass headers.
            return true
        }
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
    let kemPrivateKeys: [String: Data]
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
            let aliceKEM = try await provisioner.provisionKEM(accountDID: RepositorySyncHTTPTests.alice)
            let bobKEM = try await provisioner.provisionKEM(accountDID: RepositorySyncHTTPTests.bob)
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
            let scopeBase = "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)"
            let authorization: AuthorizationContext = .accountOAuthForTesting(
                subject: RepositorySyncHTTPTests.alice,
                scopes: [
                    "atproto",
                    "\(scopeBase)&action=create&collection=app.bsky.feed.post",
                    "\(scopeBase)&action=update&collection=app.bsky.feed.post",
                    "\(scopeBase)&action=delete&collection=app.bsky.feed.post",
                ]
            )
            let aliceDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: RepositorySyncHTTPTests.alice, oplogRetention: retention)
            _ = try await aliceDatabase.createSimpleSpace(
                space: space,
                owner: RepositorySyncHTTPTests.alice,
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open),
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
            _ = try await bobRepository.apply(.put(uri: bobRecord, value: recordCBOR("bob")), expectedRevision: 0, requestID: UUID(), wireRevision: try TID(tidString: tids[0]), authorization: .accountOAuthForTesting(subject: RepositorySyncHTTPTests.bob, scopes: ["\(scopeBase)&action=create&collection=app.bsky.feed.post"]))
            try await bobDatabase.close()

            let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let accounts = DurableAccountDirectory(
                store: control,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher, maximumConcurrentVerifications: 1, maximumQueuedVerifications: 1)
            )
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                oplogRetention: retention,
                publicIdentityVerifier: nil
            )
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0x92, count: 32))
            return Fixture(
                root: root, space: space, control: control, keyStore: keyStore,
                accounts: accounts, directory: directory, runtime: runtime,
                references: [RepositorySyncHTTPTests.alice: aliceKeys.signingReference, RepositorySyncHTTPTests.bob: bobKeys.signingReference],
                kemPrivateKeys: [RepositorySyncHTTPTests.alice: aliceKEM.rawRepresentation, RepositorySyncHTTPTests.bob: bobKEM.rawRepresentation],
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

    func expectedCommitment(author: String) throws -> Data {
        let records: [(String, String)] = author == RepositorySyncHTTPTests.alice
            ? [("first", "two"), ("third", "four"), ("fourth", "five")]
            : [("bob", "bob")]
        var hash = LtHash()
        for (rkey, text) in records {
            let cid = CID.fromDAGCBOR(Self.recordCBOR(text))
            hash.add(element: "app.bsky.feed.post/\(rkey)/\(cid.string)")
        }
        return hash.commitment
    }

    func credential(for space: SpaceURI) async throws -> String {
        let reference = try signingReference(for: RepositorySyncHTTPTests.alice)
        let scalar = try await keyStore.key(for: reference)
        return try PermissionedDataJWT.createSpaceCredential(
            issuer: RepositorySyncHTTPTests.alice,
            space: space,
            key: try P256.Signing.PrivateKey(rawRepresentation: scalar),
            confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
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
            passwordVerifier: RepositorySyncHTTPTests.runtimeVerifierSentinel,
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

    func repositoryBlobCIDs(space _: SpaceURI, author _: String, since _: String?, limit _: Int, cursor _: String?, authorization _: AuthorizationContext) async throws -> [String] { [] }
    func repositoryCommitState(space: SpaceURI, author: String, authorization _: AuthorizationContext) async throws -> AuthorizedSpaceRepositoryCommitState {
        .init(space: space, author: author, wireRevision: "2222222222222", commitment: Data(repeating: 0x01, count: 32))
    }
    func repositoryOplog(space: SpaceURI, author: String, since _: String?, limit _: Int, includeValues _: Bool, maximumAggregateValueBytes _: Int, authorization _: AuthorizationContext) async throws -> AuthorizedSpaceRepositoryOplogRead {
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
