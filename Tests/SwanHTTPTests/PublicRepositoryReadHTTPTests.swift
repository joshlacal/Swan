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
import SwanPublicRepository
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
                ("/xrpc/com.atproto.sync.getBlob", .get),
            ] {
                try await client.execute(uri: path, method: method) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
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
        let signingKey = try P256DIDKey(
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

    private func makeFixture(
        nonEmpty: Bool = false,
        identityHandle: String? = nil,
        identityOrigin: String = "https://swan.example",
        handleIsCorrect: Bool = true
    ) async throws -> (
        server: SwanHTTPServer,
        control: SQLiteControlDatabase,
        root: URL,
        state: PublicRepositoryState,
        records: [PublicRepositoryReadRecord]
    ) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicRepositoryReadHTTPTests-\(UUID().uuidString)")
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
                    signingDIDKey: "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF",
                    handleIsCorrect: handleIsCorrect,
                    preparationRequestID: "public-read-http",
                    genesisOperationCID: state.commitCID.string
                )
            ),
            records: records
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
                publicRepositoryReadDirectory: directory
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

    init(description: PublicRepositoryReadDescription, records: [PublicRepositoryReadRecord]) {
        self.description = description
        self.records = records
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
        guard let carBytes else { return nil }
        let url = FileManager.default.temporaryDirectory
            .appending(path: "swan-public-read-test-\(UUID().uuidString).car")
        guard FileManager.default.createFile(
            atPath: url.path,
            contents: nil,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw PublicRepositoryReadError.unavailable
        }
        let handle = try FileHandle(forUpdating: url)
        try FileManager.default.removeItem(at: url)
        try handle.write(contentsOf: carBytes)
        try handle.seek(toOffset: 0)
        let admission = try PublicRepositorySpoolAdmission()
        guard let lease = admission.reserve(
            accountDID: description.did,
            maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes
        ) else { throw PublicRepositoryReadError.unavailable }
        return PublicRepositoryReadCAR(
            state: description.state,
            spool: PublicRepositoryCARSpool(fileHandle: handle, lease: lease)
        )
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
