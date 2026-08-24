import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import SwanAccounts
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import PetrelRepo
import SwanSQLite
import SwanStorage
import XCTest

final class PublicRepositoryReadHTTPTests: XCTestCase, @unchecked Sendable {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.example.com"

    func testJSONReadRoutesResolveDIDAndHandleAndIgnoreAuthorizationHeaders() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        var mutableHeaders = HTTPFields()
        mutableHeaders[.authorization] = "Bearer private-space-credential"
        mutableHeaders[HTTPField.Name("DPoP")!] = "private-proof"
        let headers = mutableHeaders

        let app = fixture.server.buildApplication(logger: Logger(label: "PublicRepositoryReadHTTPTests"))
        try await app.test(.router) { client in
            for selector in [did, handle] {
                try await client.execute(
                    uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(selector)",
                    method: .get,
                    headers: headers
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.object(response.body)
                    XCTAssertEqual(body["did"] as? String, self.did)
                    XCTAssertEqual(body["handle"] as? String, self.handle)
                    XCTAssertEqual(body["collections"] as? [String], [])
                    let didDoc = try XCTUnwrap(body["didDoc"] as? [String: Any])
                    XCTAssertEqual(didDoc["id"] as? String, self.did)
                    XCTAssertEqual(didDoc["alsoKnownAs"] as? [String], ["at://\(self.handle)"])
                    let methods = try XCTUnwrap(
                        didDoc["verificationMethod"] as? [[String: Any]]
                    )
                    XCTAssertEqual(methods.first?["id"] as? String, "#atproto")
                    XCTAssertEqual(
                        methods.first?["type"] as? String,
                        "EcdsaSecp256r1VerificationKey2019"
                    )
                    XCTAssertEqual(
                        methods.first?["publicKeyMultibase"] as? String,
                        "zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF"
                    )
                    XCTAssertEqual(body["handleIsCorrect"] as? Bool, true)
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("private"))
                }
            }

            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getLatestCommit?did=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try self.object(response.body)
                XCTAssertEqual(body["cid"] as? String, fixture.state.commitCID.string)
                XCTAssertEqual(body["rev"] as? String, fixture.state.revision)
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getRepoStatus?did=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try self.object(response.body)
                XCTAssertEqual(body["did"] as? String, self.did)
                XCTAssertEqual(body["active"] as? Bool, true)
                XCTAssertEqual(body["rev"] as? String, fixture.state.revision)
            }
        }
        try await fixture.control.close()
    }

    func testDescribeRepoReportsAliasMismatchAndRejectsServiceOriginMismatch() async throws {
        let aliasFixture = try await makeFixture(
            identityHandle: "old.example.com",
            handleIsCorrect: false
        )
        defer { try? FileManager.default.removeItem(at: aliasFixture.root) }
        let aliasApp = aliasFixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.alias")
        )
        try await aliasApp.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try self.object(response.body)
                XCTAssertEqual(body["handle"] as? String, self.handle)
                XCTAssertEqual(body["handleIsCorrect"] as? Bool, false)
                XCTAssertEqual(
                    ((body["didDoc"] as? [String: Any])?["alsoKnownAs"] as? [String]),
                    ["at://old.example.com"]
                )
            }
        }
        try await aliasFixture.control.close()

        let serviceFixture = try await makeFixture(
            identityOrigin: "https://other.example"
        )
        defer { try? FileManager.default.removeItem(at: serviceFixture.root) }
        let serviceApp = serviceFixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.origin")
        )
        try await serviceApp.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }
        try await serviceFixture.control.close()
    }

    // Production mutation caught: `describeRepo` hard-codes the P-256
    // verification-method type even when admission authenticated the pinned
    // TypeScript PDS's canonical secp256k1 did:key.
    func testDescribeRepoReportsSecp256k1VerificationMethodType() async throws {
        let signingDIDKey =
            "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc"
        let fixture = try await makeFixture(
            identitySigningDIDKey: signingDIDKey
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.secp256k1")
        )

        try await app.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try self.object(response.body)
                let didDoc = try XCTUnwrap(body["didDoc"] as? [String: Any])
                let methods = try XCTUnwrap(
                    didDoc["verificationMethod"] as? [[String: Any]]
                )
                XCTAssertEqual(
                    methods.first?["type"] as? String,
                    "EcdsaSecp256k1VerificationKey2019"
                )
                XCTAssertEqual(
                    methods.first?["publicKeyMultibase"] as? String,
                    String(signingDIDKey.dropFirst("did:key:".count))
                )
            }
        }
        try await fixture.control.close()
    }

    func testGetRecordExactCIDListPaginationAndMalformedInput() async throws {
        let fixture = try await makeFixture(nonEmpty: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let record = try XCTUnwrap(fixture.records.first)
        let app = fixture.server.buildApplication(logger: Logger(label: "PublicRepositoryReadHTTPTests.records"))

        try await app.test(.router) { client in
            let base = "/xrpc/com.atproto.repo.getRecord?repo=\(handle)&collection=\(record.path.collection)&rkey=\(record.path.recordKey)"
            try await client.execute(uri: base + "&cid=\(record.cid.string)", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try self.object(response.body)
                XCTAssertEqual(body["cid"] as? String, record.cid.string)
                XCTAssertEqual((body["value"] as? [String: Any])?["text"] as? String, "one")
            }
            let wrong = CID.fromDAGCBOR(Data("wrong".utf8))
            try await client.execute(uri: base + "&cid=\(wrong.string)", method: .get) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.object(response.body)["error"] as? String, "RecordNotFound")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=app.bsky.feed.post&limit=1",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try self.object(response.body)
                XCTAssertEqual((body["records"] as? [[String: Any]])?.count, 1)
                XCTAssertNotNil(body["cursor"] as? String)
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=app.bsky.feed.post&limit=101",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        try await fixture.control.close()
    }

    func testDeferredAndWrongMethodRoutesRemainFinite() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let app = fixture.server.buildApplication(logger: Logger(label: "PublicRepositoryReadHTTPTests.deferred"))
        try await app.test(.router) { client in
            for (path, method): (String, HTTPRequest.Method) in [
                ("/xrpc/com.atproto.repo.createRecord", .post),
                ("/xrpc/com.atproto.repo.uploadBlob", .post),
            ] {
                try await client.execute(uri: path, method: method) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
            }
            // `getBlob` is no longer deferred on a read-enabled server: it is
            // a read, and it is installed by the read directory rather than by
            // the mutation capability. A live route answers the request it was
            // given — here, one with no `did` or `cid` at all.
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlob",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(
                    try self.object(response.body)["error"] as? String,
                    "InvalidRequest"
                )
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(did)",
                method: .post
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
        try await fixture.control.close()
    }

    func testMalformedPublicReadSelectorsAndParametersAreBadRequests() async throws {
        let fixture = try await makeFixture(nonEmpty: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.malformed")
        )
        let malformedPaths = [
            "/xrpc/com.atproto.repo.describeRepo?repo=not%20an%20identifier",
            "/xrpc/com.atproto.repo.getRecord?repo=not%20an%20identifier&collection=app.bsky.feed.post&rkey=one",
            "/xrpc/com.atproto.repo.getRecord?repo=\(did)&collection=not-a-collection&rkey=one",
            "/xrpc/com.atproto.repo.getRecord?repo=\(did)&collection=app.bsky.feed.post&rkey=%20",
            "/xrpc/com.atproto.repo.getRecord?repo=\(did)&collection=app.bsky.feed.post&rkey=one&cid=not-a-cid",
            "/xrpc/com.atproto.repo.listRecords?repo=not%20an%20identifier&collection=app.bsky.feed.post",
            "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=not-a-collection",
            "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=app.bsky.feed.post&limit=-1",
            "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=app.bsky.feed.post&reverse=1",
            "/xrpc/com.atproto.sync.getLatestCommit?did=\(handle)",
            "/xrpc/com.atproto.sync.getRepoStatus?did=not-a-did",
            "/xrpc/com.atproto.sync.getRepo?did=\(handle)",
            "/xrpc/com.atproto.sync.getRepo?did=\(did)&since=3jzfcijpj2z2a",
        ]
        try await app.test(.router) { client in
            for path in malformedPaths {
                try await client.execute(uri: path, method: .get) { response in
                    XCTAssertEqual(response.status, .badRequest, path)
                    XCTAssertEqual(
                        try self.object(response.body)["error"] as? String,
                        "InvalidRequest",
                        path
                    )
                }
            }
        }
        try await fixture.control.close()
    }

    func testRepoStatusKnownLifecycleValuesAndGetRepoNeverPrepareInactiveSpool() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = fixture.server.publicRepositoryReadDirectory
            as! TestPublicRepositoryReadDirectory
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.lifecycle")
        )
        try await app.test(.router) { client in
            for status: AccountControlStatus in [
                .deactivated, .deleted, .takendown, .suspended,
                .desynchronized, .throttled,
            ] {
                await directory.setStatus(status)
                try await client.execute(
                    uri: "/xrpc/com.atproto.sync.getRepoStatus?did=\(did)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try self.object(response.body)
                    XCTAssertEqual(body["active"] as? Bool, false)
                    XCTAssertEqual(body["status"] as? String, status.rawValue)
                    XCTAssertNil(body["rev"])
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.sync.getRepo?did=\(did)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
            }
            await directory.setStatus(.unknown("future"))
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getRepoStatus?did=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }
        let carRequestCount = await directory.carRequestCount
        XCTAssertEqual(carRequestCount, 0)
        try await fixture.control.close()
    }

    func testListRecordsRejectsForgedOutOfOrderDirectoryProjection() async throws {
        let fixture = try await makeFixture(nonEmpty: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = fixture.server.publicRepositoryReadDirectory
            as! TestPublicRepositoryReadDirectory
        await directory.setForgeOutOfOrderPage(true)
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.forged-page")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=app.bsky.feed.post&limit=2",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.object(response.body)["error"] as? String,
                    "temporarily_unavailable"
                )
            }
        }
        try await fixture.control.close()
    }

    func testGetRepoStreamsPinnedNonEmptyCARThroughStrictImporter() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = fixture.server.publicRepositoryReadDirectory
            as! TestPublicRepositoryReadDirectory
        let vectorURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(
                path: "fixtures/permissioned-data-0016-2026-07-03/public-repository-nonempty-car.json"
            )
        let vector = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: try Data(contentsOf: vectorURL)
            ) as? [String: Any]
        )
        let carBytes = try XCTUnwrap(
            Data(base64Encoded: try XCTUnwrap(vector["carBase64"] as? String))
        )
        let signingKey = try SwanAccounts.P256DIDKey(
            try XCTUnwrap(vector["signingKeyDID"] as? String)
        ).publicKey
        let expectedCommitCID = try XCTUnwrap(vector["commitCID"] as? String)
        await directory.setCARBytes(carBytes)
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.get-repo")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getRepo?did=\(did)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(
                    response.headers[.contentType],
                    "application/vnd.ipld.car"
                )
                let imported = try await PublicRepositoryCAR.importRepository(
                    from: HTTPPublicCARSource(Data(buffer: response.body)),
                    verifier: P256PublicRepositoryCommitVerifier(
                        publicKey: signingKey
                    )
                )
                XCTAssertEqual(imported.repository.leaves.count, 1)
                XCTAssertEqual(
                    imported.state.commitCID.string,
                    expectedCommitCID
                )
            }
        }
        let requestCount = await directory.carRequestCount
        XCTAssertEqual(requestCount, 1)
        try await fixture.control.close()
    }

    // Production mutation caught: anonymous JSON reads enter the database and
    // decode record bodies without first reserving a process-wide response
    // budget, so concurrent list/get requests can multiply the maximum page
    // allocation without bound.
    func testAnonymousListAndGetShareBoundedProcessAdmission() async throws {
        let barrier = PublicJSONReadBarrier()
        let admission = try PublicRepositoryJSONReadAdmission(
            maximumConcurrentReads: 1,
            maximumReservedResponseBytes:
                PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes
        )
        let fixture = try await makeFixture(
            nonEmpty: true,
            jsonReadBarrier: barrier,
            jsonReadAdmission: admission
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = fixture.server.publicRepositoryReadDirectory
            as! TestPublicRepositoryReadDirectory
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.json-admission")
        )
        let record = try XCTUnwrap(fixture.records.first)
        let listURI =
            "/xrpc/com.atproto.repo.listRecords?repo=\(did)&collection=app.bsky.feed.post&limit=2"
        let getURI =
            "/xrpc/com.atproto.repo.getRecord?repo=\(did)&collection=\(record.path.collection)&rkey=\(record.path.recordKey)"

        try await app.test(.router) { client in
            try await withThrowingTaskGroup(of: Int.self) { group in
                group.addTask {
                    try await client.execute(
                        uri: listURI,
                        method: .get
                    ) { Int($0.status.code) }
                }
                await barrier.waitUntilEntered()

                do {
                    try await client.execute(uri: getURI, method: .get) {
                        response in
                        XCTAssertEqual(response.status, .serviceUnavailable)
                        XCTAssertEqual(
                            try self.object(response.body)["error"] as? String,
                            "temporarily_unavailable"
                        )
                    }
                    try await client.execute(
                        uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(did)",
                        method: .get
                    ) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable)
                        XCTAssertEqual(
                            try self.object(response.body)["error"] as? String,
                            "temporarily_unavailable"
                        )
                    }
                } catch {
                    await barrier.release()
                    throw error
                }
                let outcomeRequestCount =
                    await directory.jsonOutcomeRequestCount
                XCTAssertEqual(outcomeRequestCount, 1)
                XCTAssertEqual(admission.snapshot.activeLeases, 1)

                await barrier.release()
                let completedStatus = try await group.next()
                XCTAssertEqual(try XCTUnwrap(completedStatus), 200)
            }
        }
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        XCTAssertEqual(admission.snapshot.reservedResponseBytes, 0)
        try await fixture.control.close()
    }

    // Production mutation caught: `getLatestCommit` and `getRepoStatus` reach
    // the account directory — and through it a full public-read admission,
    // including a paginated walk of the whole record index — without reserving
    // the process-wide response budget their JSON siblings reserve. Both are
    // anonymous, and `getRepoStatus` is one of the three methods a relay calls
    // against a PDS.
    func testSyncReadRoutesShareBoundedProcessAdmission() async throws {
        let admission = try PublicRepositoryJSONReadAdmission(
            maximumConcurrentReads: 1,
            maximumReservedResponseBytes:
                PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes
        )
        let fixture = try await makeFixture(
            nonEmpty: true,
            jsonReadAdmission: admission
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = fixture.server.publicRepositoryReadDirectory
            as! TestPublicRepositoryReadDirectory
        let app = fixture.server.buildApplication(
            logger: Logger(
                label: "PublicRepositoryReadHTTPTests.sync-admission"
            )
        )
        let held = try XCTUnwrap(admission.reserve(
            maximumResponseBytes:
                PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes
        ))
        let latestCommitURI =
            "/xrpc/com.atproto.sync.getLatestCommit?did=\(did)"
        let repoStatusURI = "/xrpc/com.atproto.sync.getRepoStatus?did=\(did)"

        try await app.test(.router) { client in
            for uri in [latestCommitURI, repoStatusURI] {
                do {
                    try await client.execute(uri: uri, method: .get) {
                        response in
                        XCTAssertEqual(response.status, .serviceUnavailable)
                        XCTAssertEqual(
                            try self.object(response.body)["error"] as? String,
                            "temporarily_unavailable"
                        )
                    }
                } catch {
                    held.release()
                    throw error
                }
            }
            let entered = await directory.syncOutcomeRequestCount
            XCTAssertEqual(
                entered,
                0,
                "a sync read refused by admission must not reach the directory"
            )

            // The refusal is admission pressure, not a permanent state: once
            // the budget frees both routes serve exactly as before.
            held.release()
            try await client.execute(uri: repoStatusURI, method: .get) {
                response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(
                    try self.object(response.body)["did"] as? String,
                    self.did
                )
            }
            try await client.execute(uri: latestCommitURI, method: .get) {
                response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(
                    try self.object(response.body)["rev"] as? String,
                    fixture.state.revision
                )
            }
            let served = await directory.syncOutcomeRequestCount
            XCTAssertEqual(served, 2)
        }
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        XCTAssertEqual(admission.snapshot.reservedResponseBytes, 0)
        try await fixture.control.close()
    }

    // Production mutation caught: the route releases admission with a handler
    // scope `defer`, before Hummingbird drains the returned response body.
    func testJSONAdmissionLeaseIsHeldUntilResponseBodyDrain() async throws {
        let admission = try PublicRepositoryJSONReadAdmission(
            maximumConcurrentReads: 1,
            maximumReservedResponseBytes:
                PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes
        )
        let lease = try XCTUnwrap(admission.reserve(
            maximumResponseBytes:
                PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes
        ))
        let response = publicReadJSON(
            .ok,
            ["ok": true],
            maximumBytes:
                PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes,
            lease: lease
        )

        XCTAssertEqual(admission.snapshot.activeLeases, 1)
        XCTAssertNil(admission.reserve(
            maximumResponseBytes:
                PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes
        ))

        try await response.body.write(DiscardingPublicResponseBodyWriter())

        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        XCTAssertEqual(admission.snapshot.reservedResponseBytes, 0)

        let failingLease = try XCTUnwrap(admission.reserve(
            maximumResponseBytes:
                PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes
        ))
        let failingResponse = publicReadJSON(
            .ok,
            ["ok": true],
            maximumBytes:
                PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes,
            lease: failingLease
        )
        do {
            try await failingResponse.body.write(
                FailingPublicResponseBodyWriter()
            )
            XCTFail("expected the response writer to fail")
        } catch PublicResponseBodyWriterFailure.expected {
            // Expected: the body closure's defer must still release admission.
        }
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        XCTAssertEqual(admission.snapshot.reservedResponseBytes, 0)
    }

    // Production mutation caught: a forged/non-SQLite directory can return a
    // syntactically valid page whose aggregate canonical bodies exceed the
    // anonymous JSON budget.
    func testPublicReadPageRejectsAggregateCanonicalBodyBudgetOverflow() throws {
        let collection = "app.bsky.feed.post"
        let sourcePath = try PublicRepositoryPath(
            collection: collection,
            recordKey: "source"
        )
        let prepared = try PublicRepositoryRecordCodec.prepare(
            [
                "$type": .string(collection),
                "text": .string(
                    String(
                        repeating: "x",
                        count: PublicRepositoryLimits.standard
                            .maximumRecordBlockBytes - 1_024
                    )
                ),
            ],
            for: sourcePath
        )
        XCTAssertLessThanOrEqual(
            prepared.bytes.count,
            PublicRepositoryLimits.standard.maximumRecordBlockBytes
        )
        let recordCount =
            PublicRepositoryJSONReadLimits.maximumAggregateRecordBlockBytes
                / prepared.bytes.count + 1
        let records = try (0..<recordCount).map { index in
            try PublicRepositoryReadRecord(
                path: PublicRepositoryPath(
                    collection: collection,
                    recordKey: "record-\(index)"
                ),
                cid: prepared.cid,
                canonicalBytes: prepared.bytes
            )
        }

        XCTAssertThrowsError(
            try PublicRepositoryReadPage(records: records, cursor: nil)
        ) {
            XCTAssertEqual(
                ($0 as? PublicRepositoryReadError)?.unavailableReason,
                .malformedProjectionValue
            )
        }
    }

    func testPublicDescriptionRejectsOversizedCollectionProjection() throws {
        let state = try PublicRepositoryState(
            did: did,
            revision: "3jzfcijpj2z2a",
            commitCID: CID.fromDAGCBOR(Data("commit".utf8)),
            dataCID: CID.fromDAGCBOR(Data("mst".utf8))
        )
        let identity = try PublicRepositoryReadIdentity(
            canonicalHandle: handle,
            pdsOrigin: "https://swan.example",
            signingDIDKey:
                "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF",
            handleIsCorrect: true,
            preparationRequestID: "description-budget",
            genesisOperationCID: state.commitCID.string
        )
        XCTAssertThrowsError(
            try PublicRepositoryReadDescription(
                did: did,
                canonicalHandle: handle,
                status: .active,
                state: state,
                collections: Array(
                    repeating: "app.bsky.feed.post",
                    count: PublicRepositoryReadLimits
                        .maximumDescribeRepoCollections + 1
                ),
                identity: identity
            )
        ) {
            XCTAssertEqual($0 as? PublicRepositoryReadError, .resourceLimitExceeded)
        }
    }

    // Production mutation caught: every 503 on these anonymous routes wrote a
    // `.warning`, so one persistently unavailable account let any caller set
    // the service journal's growth rate — a disk-fill path with no ceiling.
    func testPublicReadDiagnosticThrottleReportsRepeatsOncePerWindow() {
        let throttle = PublicReadDiagnosticThrottle(window: .seconds(1))
        let start = ContinuousClock.now

        XCTAssertEqual(
            throttle.admit(method: "m", reason: "r", now: start),
            0,
            "the first refusal of a distinct pair is always journalled"
        )
        for offset in 1 ... 5 {
            XCTAssertNil(
                throttle.admit(
                    method: "m",
                    reason: "r",
                    now: start.advanced(by: .milliseconds(offset * 100))
                ),
                "an identical refusal inside the window is counted, not logged"
            )
        }

        // A different failure is never delayed or hidden by an ongoing one:
        // the bound is per distinct failure, not global.
        XCTAssertEqual(
            throttle.admit(
                method: "m",
                reason: "other",
                now: start.advanced(by: .milliseconds(100))
            ),
            0
        )
        XCTAssertEqual(
            throttle.admit(
                method: "other",
                reason: "r",
                now: start.advanced(by: .milliseconds(100))
            ),
            0
        )

        // Past the window the repeats are reported once, with their count,
        // and the count is not carried forward a second time.
        XCTAssertEqual(
            throttle.admit(
                method: "m", reason: "r", now: start.advanced(by: .seconds(2))
            ),
            5
        )
        XCTAssertEqual(
            throttle.admit(
                method: "m", reason: "r", now: start.advanced(by: .seconds(4))
            ),
            0
        )
    }

    // Production mutation caught: the throttle above bounds nothing unless the
    // one function every public-read 503 leaves through consults it.
    func testRepeatedUnavailableReadsJournalOnceNotOncePerRequest() async throws {
        let fixture = try await makeFixture(
            identityOrigin: "https://other.example"
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryReadHTTPTests.log-volume")
        )
        publicReadDiagnosticThrottle.resetForTesting()
        let baseline = publicReadDiagnosticJournalLines.withLock { $0 }

        try await app.test(.router) { client in
            for _ in 0 ..< 12 {
                try await client.execute(
                    uri: "/xrpc/com.atproto.repo.describeRepo?repo=\(self.did)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(
                        try self.object(response.body)["error"] as? String,
                        "temporarily_unavailable",
                        "the client-visible body must not change"
                    )
                }
            }
        }

        let emitted = publicReadDiagnosticJournalLines.withLock { $0 }
            - baseline
        XCTAssertGreaterThanOrEqual(
            emitted,
            1,
            "the refusal must still be journalled — a suppressed 503 is a "
                + "silent one, which is the outage this series exists to end"
        )
        XCTAssertLessThanOrEqual(
            emitted,
            2,
            "journal volume must track distinct failures, not request rate"
        )
        try await fixture.control.close()
    }

    // Production mutation caught: the HTTP layer classified its 503 log line
    // through `unavailableReason`, which answers nil for the one admission
    // refusal that carries no reason of its own. A read refused by the
    // projection bound journalled `reason=projectionBoundExceeded` from
    // storage and `reason=unclassified` from HTTP — two lines, two names, one
    // 503, in the function whose whole purpose is that no 503 goes unnamed.
    func testPublicReadDiagnosticTokenNamesReasonlessAdmissionRefusals() {
        struct UnrelatedFailure: Error {}

        XCTAssertEqual(
            publicReadDiagnosticToken(
                PublicRepositoryReadError.resourceLimitExceeded
            ),
            PublicReadUnavailableReason.projectionBoundExceeded.rawValue,
            "the projection bound must be named identically on both sides"
        )
        XCTAssertEqual(
            publicReadDiagnosticToken(
                PublicRepositoryReadError.unavailable(
                    reason: .identityFactsMalformed
                )
            ),
            PublicReadUnavailableReason.identityFactsMalformed.rawValue
        )
        XCTAssertEqual(
            publicReadDiagnosticToken(CancellationError()),
            "requestCancelled"
        )
        XCTAssertEqual(
            publicReadDiagnosticToken(UnrelatedFailure()),
            "unclassified"
        )
    }

    private func makeFixture(
        nonEmpty: Bool = false,
        identityHandle: String? = nil,
        identityOrigin: String = "https://swan.example",
        identitySigningDIDKey: String =
            "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF",
        handleIsCorrect: Bool = true,
        jsonReadBarrier: PublicJSONReadBarrier? = nil,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission? = nil
    ) async throws -> (
        server: SwanHTTPServer,
        control: SQLiteControlDatabase,
        root: URL,
        state: PublicRepositoryState,
        records: [PublicRepositoryReadRecord]
    ) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRepositoryReadHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let state = try PublicRepositoryState(
            did: did,
            revision: "3jzfcijpj2z2a",
            commitCID: CID.fromDAGCBOR(Data("commit".utf8)),
            dataCID: CID.fromDAGCBOR(Data("mst".utf8))
        )
        let records: [PublicRepositoryReadRecord] = try nonEmpty
            ? ["one", "two"].map { recordKey in
            let path = try PublicRepositoryPath(
                collection: "app.bsky.feed.post", recordKey: recordKey
            )
            let prepared = try PublicRepositoryRecordCodec.prepare(
                ["$type": .string(path.collection), "text": .string(recordKey)],
                for: path
            )
            return try PublicRepositoryReadRecord(
                path: path,
                cid: prepared.cid,
                canonicalBytes: prepared.bytes
            )
            } : []
        let directory = TestPublicRepositoryReadDirectory(
            description: try .init(
                did: did,
                canonicalHandle: handle,
                status: .active,
                state: state,
                collections: nonEmpty ? ["app.bsky.feed.post"] : [],
                identity: try .init(
                    canonicalHandle: identityHandle ?? handle,
                    pdsOrigin: identityOrigin,
                    signingDIDKey: identitySigningDIDKey,
                    handleIsCorrect: handleIsCorrect,
                    preparationRequestID: "public-read-http",
                    genesisOperationCID: state.commitCID.string
                )
            ),
            records: records,
            jsonReadBarrier: jsonReadBarrier
        )
        let runtime = try SwanOAuthRuntime(
            controlStore: control,
            serverKey: Data(repeating: 0x41, count: 32)
        )
        let profile = try ProtocolProfile.load(
            from: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        return (
            SwanHTTPServer(
                profile: profile,
                configuration: .init(publicURL: URL(string: "https://swan.example")!),
                oauthRuntime: runtime,
                publicRepositoryReadDirectory: directory,
                jsonReadAdmission: jsonReadAdmission
            ),
            control, root, state, records
        )
    }

    private func object(_ buffer: ByteBuffer) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: buffer)) as? [String: Any])
    }
}

private actor TestPublicRepositoryReadDirectory: PublicRepositoryReadDirectory {
    let description: PublicRepositoryReadDescription
    let records: [PublicRepositoryReadRecord]
    private(set) var lifecycleStatus: AccountControlStatus
    private(set) var carRequestCount = 0
    private var forgeOutOfOrderPage = false
    private var carBytes: Data?
    private let jsonReadBarrier: PublicJSONReadBarrier?
    private(set) var jsonOutcomeRequestCount = 0
    /// Entries through the two `com.atproto.sync` JSON reads. In production
    /// both reach a full public-read admission, so a route that reaches this
    /// counter without an admission lease is the unbounded-work path
    /// `testSyncReadRoutesShareBoundedProcessAdmission` exists to forbid.
    private(set) var syncOutcomeRequestCount = 0

    init(
        description: PublicRepositoryReadDescription,
        records: [PublicRepositoryReadRecord],
        jsonReadBarrier: PublicJSONReadBarrier? = nil
    ) {
        self.description = description
        self.records = records
        self.jsonReadBarrier = jsonReadBarrier
        lifecycleStatus = description.status
    }

    func setStatus(_ status: AccountControlStatus) {
        lifecycleStatus = status
    }

    func setForgeOutOfOrderPage(_ enabled: Bool) {
        forgeOutOfOrderPage = enabled
    }

    func setCARBytes(_ bytes: Data) {
        carBytes = bytes
    }

    func publicRepositoryStatus(selector: String) async throws -> PublicRepositoryReadStatus? {
        guard [description.did, description.canonicalHandle].contains(selector) else { return nil }
        syncOutcomeRequestCount += 1
        return try .init(
            did: description.did,
            status: lifecycleStatus,
            revision: lifecycleStatus == .active ? description.state.revision : nil
        )
    }

    func describePublicRepository(selector: String) async throws -> PublicRepositoryReadDescription? {
        [description.did, description.canonicalHandle].contains(selector) ? description : nil
    }

    func publicRepositoryRecord(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadRecord? {
        records.first { $0.path == path && (expectedCID == nil || expectedCID == $0.cid) }
    }

    func listPublicRepositoryRecords(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadPage {
        if forgeOutOfOrderPage {
            return try .init(
                records: Array(records.prefix(limit)),
                cursor: records.first?.path.recordKey
            )
        }
        let ordered = reverse ? records : records.reversed()
        let afterCursor = ordered.filter { record in
            guard let cursor else { return true }
            return reverse
                ? record.path.recordKey > cursor
                : record.path.recordKey < cursor
        }
        let emitted = Array(afterCursor.prefix(limit))
        return try .init(
            records: emitted,
            cursor: emitted.last?.path.recordKey
        )
    }

    func publicRepositoryCAR(selector: String) async throws -> PublicRepositoryReadCAR? {
        carRequestCount += 1
        guard recognizes(selector) else { return nil }
        guard let carBytes else { return nil }
        let url = FileManager.default.temporaryDirectory
            .appending(path: "swan-public-read-test-\(UUID().uuidString).car")
        guard FileManager.default.createFile(
            atPath: url.path,
            contents: nil,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
        }
        let handle = try FileHandle(forUpdating: url)
        try FileManager.default.removeItem(at: url)
        try handle.write(contentsOf: carBytes)
        try handle.seek(toOffset: 0)
        let admission = try PublicRepositorySpoolAdmission()
        guard let lease = admission.reserve(
            accountDID: description.did,
            maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes
        ) else { throw PublicRepositoryReadError.unavailable(reason: .storageFailure) }
        return PublicRepositoryReadCAR(
            state: description.state,
            spool: PublicRepositoryCARSpool(fileHandle: handle, lease: lease)
        )
    }

    func publicRepositoryDescriptionOutcome(
        selector: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    {
        guard recognizes(selector) else { return .notFound }
        let status = try currentStatus()
        guard status.status == .active else { return .lifecycle(status) }
        // `describeRepo` and `getLatestCommit` share this outcome, so the
        // counter is only meaningful to a test that issues neither by any
        // other route.
        syncOutcomeRequestCount += 1
        return .active(description)
    }

    func publicRepositoryRecordOutcome(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    {
        guard recognizes(selector) else { return .notFound }
        let status = try currentStatus()
        guard status.status == .active else { return .lifecycle(status) }
        jsonOutcomeRequestCount += 1
        let record = records.first {
            $0.path == path && (expectedCID == nil || expectedCID == $0.cid)
        }
        return .active(try PublicRepositoryReadRecordResult(
            did: description.did,
            state: description.state,
            record: record
        ))
    }

    func publicRepositoryRecordsOutcome(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    {
        guard recognizes(selector) else { return .notFound }
        let status = try currentStatus()
        guard status.status == .active else { return .lifecycle(status) }
        jsonOutcomeRequestCount += 1
        if let jsonReadBarrier {
            await jsonReadBarrier.arriveAndWait()
        }
        return .active(try PublicRepositoryReadPageResult(
            did: description.did,
            state: description.state,
            page: try makePage(
                collection: collection,
                limit: limit,
                cursor: cursor,
                reverse: reverse
            )
        ))
    }

    func publicRepositoryCAROutcome(
        selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR> {
        guard recognizes(selector) else { return .notFound }
        let status = try currentStatus()
        guard status.status == .active else { return .lifecycle(status) }
        guard let car = try await publicRepositoryCAR(selector: selector) else {
            throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
        }
        return .active(car)
    }

    /// This fixture hosts records, not blobs. `getBlob` behaviour — including
    /// that it is served with public mutations disabled — is covered by
    /// `PublicBlobReadRegistrationTests` and `PublicBlobDIDBindingTests`.
    func publicRepositoryBlobOutcome(
        did: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget>
    {
        guard recognizes(did) else { return .notFound }
        let status = try currentStatus()
        guard status.status == .active else { return .lifecycle(status) }
        return .notFound
    }

    private func recognizes(_ selector: String) -> Bool {
        [description.did, description.canonicalHandle].contains(selector)
    }

    private func currentStatus() throws -> PublicRepositoryReadStatus {
        try .init(
            did: description.did,
            status: lifecycleStatus,
            revision: lifecycleStatus == .active
                ? description.state.revision
                : nil
        )
    }

    private func makePage(
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) throws -> PublicRepositoryReadPage {
        if forgeOutOfOrderPage {
            return try .init(
                records: Array(records.prefix(limit)),
                cursor: records.first?.path.recordKey
            )
        }
        let ordered = reverse ? records : records.reversed()
        let afterCursor = ordered.filter { record in
            guard let cursor else { return true }
            return reverse
                ? record.path.recordKey > cursor
                : record.path.recordKey < cursor
        }
        let emitted = Array(afterCursor.prefix(limit))
        return try .init(
            records: emitted,
            cursor: emitted.last?.path.recordKey
        )
    }
}

private actor PublicJSONReadBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func arriveAndWait() async {
        guard !released else { return }
        entered = true
        let waiters = entryWaiters
        entryWaiters.removeAll()
        waiters.forEach { $0.resume() }
        await withCheckedContinuation { continuation in
            if released {
                continuation.resume()
            } else {
                releaseWaiters.append(continuation)
            }
        }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        guard !released else { return }
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}

private actor HTTPPublicCARSource: PublicRepositoryCARByteSource {
    private let data: Data
    private var offset = 0

    init(_ data: Data) {
        self.data = data
    }

    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < data.count else { return nil }
        let end = min(data.count, offset + maximumBytes)
        defer { offset = end }
        return Data(data[offset..<end])
    }
}

private struct DiscardingPublicResponseBodyWriter: ResponseBodyWriter {
    func write(_: ByteBuffer) async throws {}
    func finish(_: HTTPFields?) async throws {}
}

private enum PublicResponseBodyWriterFailure: Error {
    case expected
}

private struct FailingPublicResponseBodyWriter: ResponseBodyWriter {
    func write(_: ByteBuffer) async throws {
        throw PublicResponseBodyWriterFailure.expected
    }

    func finish(_: HTTPFields?) async throws {}
}
