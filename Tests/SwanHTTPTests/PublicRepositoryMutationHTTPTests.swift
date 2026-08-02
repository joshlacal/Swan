import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanPublicRepository
import SwanPublicWire
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class PublicRepositoryMutationHTTPTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let collection = "app.bsky.feed.post"
    private static let mutationPath = "/xrpc/com.atproto.repo.createRecord"
    private static let applyPath = "/xrpc/com.atproto.repo.applyWrites"
    private static let uploadPath = "/xrpc/com.atproto.repo.uploadBlob"

    func testJSONMutationAdmissionRejectsBeforeDecodeAndReleasesAfterFailure() async throws {
        let maximum = 1_000_000
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let fixture = try await makeFixture(jsonWriteAdmission: admission)
        XCTAssertTrue(fixture.server.jsonWriteAdmission === admission)
        XCTAssertTrue(
            fixture.server.publicRepositoryMutations?.jsonWriteAdmission
                === admission
        )
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let held = try XCTUnwrap(
            admission.reserve(maximumRequestBytes: maximum)
        )

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.json-write-admission")
        ).test(.router) { client in
            let unavailable = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "write-admission-full",
                    method: "POST",
                    path: Self.mutationPath
                ),
                body: ByteBuffer(string: "{}")
            )
            XCTAssertEqual(unavailable.status, .serviceUnavailable)
            XCTAssertEqual(
                try self.jsonObject(unavailable.body)["error"] as? String,
                "temporarily_unavailable"
            )

            held.release()
            let invalid = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "write-admission-release",
                    method: "POST",
                    path: Self.mutationPath
                ),
                body: ByteBuffer(string: "{}")
            )
            XCTAssertEqual(invalid.status, .badRequest)
        }
        XCTAssertEqual(admission.snapshot, .init(
            activeLeases: 0,
            reservedRequestBytes: 0
        ))
    }

    func testUploadBlobUsesSharedSpoolAdmissionAndReleasesLease() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.upload")
        ).test(.router) { client in
            var headers = try fixture.headers(
                jti: "upload-blob",
                method: "POST",
                path: Self.uploadPath
            )
            headers[.contentType] = "application/octet-stream"
            let response = try await client.execute(
                uri: Self.uploadPath,
                method: .post,
                headers: headers,
                body: ByteBuffer(data: Data("public-upload".utf8))
            )
            XCTAssertEqual(
                response.status,
                .ok,
                String(decoding: response.body.readableBytesView, as: UTF8.self)
            )
            let object = try self.jsonObject(response.body)
            let blob = try XCTUnwrap(object["blob"] as? [String: Any])
            XCTAssertEqual(blob["mimeType"] as? String, "application/octet-stream")
            XCTAssertEqual(blob["size"] as? Int, 13)
            XCTAssertNotNil((blob["ref"] as? [String: Any])?["$link"] as? String)
        }

        XCTAssertEqual(fixture.publicBlobSpoolAdmission.snapshot.activeLeases, 0)
        XCTAssertEqual(fixture.publicBlobSpoolAdmission.snapshot.reservedBytes, 0)
    }

    func testUploadBlobFailsClosedWithoutAdmissionBeforeCreatingSpool() async throws {
        let fixture = try await makeFixture(includePublicBlobSpoolAdmission: false)
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.upload-closed")
        ).test(.router) { client in
            var headers = try fixture.headers(
                jti: "upload-without-admission",
                method: "POST",
                path: Self.uploadPath
            )
            headers[.contentType] = "application/octet-stream"
            let response = try await client.execute(
                uri: Self.uploadPath,
                method: .post,
                headers: headers,
                body: ByteBuffer(data: Data("must-not-stage".utf8))
            )
            XCTAssertEqual(response.status, .serviceUnavailable)
            XCTAssertEqual(
                try self.jsonObject(response.body)["error"] as? String,
                "temporarily_unavailable"
            )
        }
    }

    func testPublicBlobSpoolAdmissionIsAtomicUnderConcurrentReservations() async throws {
        let maximumBytes = 256 * 1_024 * 1_024
        let admission = try PublicRepositorySpoolAdmission(
            maximumGlobalBytes: maximumBytes * 2,
            maximumPerAccountBytes: maximumBytes * 2
        )
        let barrier = UploadAdmissionBarrier(expected: 8)
        let successes = await withTaskGroup(of: Bool.self, returning: [Bool].self) {
            group in
            for _ in 0 ..< 8 {
                group.addTask {
                    let lease = admission.reserve(
                        accountDID: Self.did,
                        maximumBytes: maximumBytes
                    )
                    await barrier.arriveAndWait()
                    lease?.release()
                    return lease != nil
                }
            }
            var values: [Bool] = []
            for await value in group {
                values.append(value)
            }
            return values
        }

        XCTAssertEqual(successes.filter { $0 }.count, 2)
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        XCTAssertEqual(admission.snapshot.reservedBytes, 0)
    }

    func testExplicitRKeyPutDeleteNoOpAndSwapSemantics() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let putPath = "/xrpc/com.atproto.repo.putRecord"
        let deletePath = "/xrpc/com.atproto.repo.deleteRecord"
        let putBody = self.putBody(rkey: "alpha", text: "one")

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.put")
        ).test(.router) { client in
            let first = try await client.execute(
                uri: putPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "put-create",
                    method: "POST",
                    path: putPath
                ),
                body: ByteBuffer(string: putBody)
            )
            XCTAssertEqual(first.status, .ok, String(decoding: first.body.readableBytesView, as: UTF8.self))
            let firstObject = try self.jsonObject(first.body)
            let firstCID = try XCTUnwrap(firstObject["cid"] as? String)
            let firstCommit = try XCTUnwrap((firstObject["commit"] as? [String: Any])?["cid"] as? String)
            XCTAssertEqual(firstObject["uri"] as? String, "at://" + Self.did + "/" + Self.collection + "/alpha")

            // A same-CID put is a no-op before swap checks. The deliberately
            // wrong but structurally valid swap commit must not be consulted.
            let noOpBody = self.putBody(rkey: "alpha", text: "one", swapRecord: firstCommit)
            let noOp = try await client.execute(
                uri: putPath,
                method: .post,
                headers: try fixture.headers(jti: "put-no-op", method: "POST", path: putPath),
                body: ByteBuffer(string: noOpBody)
            )
            XCTAssertEqual(noOp.status, .ok, String(decoding: noOp.body.readableBytesView, as: UTF8.self))
            let noOpObject = try self.jsonObject(noOp.body)
            XCTAssertEqual(noOpObject["cid"] as? String, firstCID)
            XCTAssertNil(noOpObject["commit"] as? [String: Any])

            let updateBody = self.putBody(
                rkey: "alpha", text: "two", swapRecord: firstCID, swapCommit: firstCommit
            )
            let update = try await client.execute(
                uri: putPath,
                method: .post,
                headers: try fixture.headers(jti: "put-update", method: "POST", path: putPath),
                body: ByteBuffer(string: updateBody)
            )
            XCTAssertEqual(update.status, .ok, String(decoding: update.body.readableBytesView, as: UTF8.self))
            let updateObject = try self.jsonObject(update.body)
            let updateCID = try XCTUnwrap(updateObject["cid"] as? String)
            let updateCommit = try XCTUnwrap((updateObject["commit"] as? [String: Any])?["cid"] as? String)
            XCTAssertNotEqual(updateCID, firstCID)
            XCTAssertNotEqual(updateCommit, firstCommit)

            let stale = self.putBody(rkey: "alpha", text: "three", swapRecord: firstCID)
            let staleResponse = try await client.execute(
                uri: putPath,
                method: .post,
                headers: try fixture.headers(jti: "put-stale", method: "POST", path: putPath),
                body: ByteBuffer(string: stale)
            )
            XCTAssertEqual(staleResponse.status, .badRequest)
            XCTAssertEqual(try self.jsonObject(staleResponse.body)["error"] as? String, "InvalidSwap")

            let deleteBody = self.deleteBody(
                rkey: "alpha", swapRecord: updateCID, swapCommit: updateCommit
            )
            let deleted = try await client.execute(
                uri: deletePath,
                method: .post,
                headers: try fixture.headers(jti: "delete", method: "POST", path: deletePath),
                body: ByteBuffer(string: deleteBody)
            )
            XCTAssertEqual(deleted.status, .ok, String(decoding: deleted.body.readableBytesView, as: UTF8.self))
            XCTAssertNotNil((try self.jsonObject(deleted.body)["commit"] as? [String: Any])?["cid"])

            // A missing delete is a no-op before swap checks.
            let missing = try await client.execute(
                uri: deletePath,
                method: .post,
                headers: try fixture.headers(jti: "delete-missing", method: "POST", path: deletePath),
                body: ByteBuffer(string: self.deleteBody(rkey: "alpha", swapRecord: firstCID))
            )
            XCTAssertEqual(missing.status, .ok, String(decoding: missing.body.readableBytesView, as: UTF8.self))
            XCTAssertNil(try self.jsonObject(missing.body)["commit"] as? [String: Any])
        }
    }

    func testApplyWritesCreateRejectsMalformedPresentRKeyWithoutMutationAndAcceptsOmission() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let loadedInitialState =
            try await fixture.database.loadPublicRepositoryState()
        let initialState = try XCTUnwrap(loadedInitialState)
        let malformedRKeys = [
            ("invalid-string", #""bad/key""#),
            ("wrong-type", "7"),
            ("null", "null"),
        ]
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.strict-rkey")
        )

        try await app.test(.router) { client in
            for (name, rkey) in malformedRKeys {
                let body = #"{"repo":"\#(Self.did)","writes":[{"$type":"com.atproto.repo.applyWrites#create","collection":"\#(Self.collection)","rkey":\#(rkey),"value":{"$type":"app.bsky.feed.post","text":"must-not-appear","createdAt":"2026-07-30T00:00:00.000Z"}}]}"#
                let response = try await client.execute(
                    uri: Self.applyPath,
                    method: .post,
                    headers: try fixture.headers(
                        jti: "apply-malformed-\(name)",
                        method: "POST",
                        path: Self.applyPath
                    ),
                    body: ByteBuffer(string: body)
                )

                XCTAssertEqual(response.status, .badRequest, name)
                XCTAssertEqual(
                    try self.jsonObject(response.body)["error"] as? String,
                    "InvalidRequest",
                    name
                )
                XCTAssertEqual(response.headers[.cacheControl], "no-store", name)
                let stateAfterRejectedRequest =
                    try await fixture.database.loadPublicRepositoryState()
                XCTAssertEqual(
                    stateAfterRejectedRequest,
                    initialState,
                    name
                )
            }

            let omitted = #"{"repo":"\#(Self.did)","writes":[{"$type":"com.atproto.repo.applyWrites#create","collection":"\#(Self.collection)","value":{"$type":"app.bsky.feed.post","text":"generated-rkey","createdAt":"2026-07-30T00:00:00.000Z"}}]}"#
            let response = try await client.execute(
                uri: Self.applyPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "apply-omitted-rkey",
                    method: "POST",
                    path: Self.applyPath
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
                    .hasPrefix("at://\(Self.did)/\(Self.collection)/")
            )
            let stateAfterOmittedRKey =
                try await fixture.database.loadPublicRepositoryState()
            XCTAssertNotEqual(stateAfterOmittedRKey, initialState)
        }
    }

    func testPublicRecordLinksRequirePublicBlobReachability() async throws {
        let fixture = try await makeFixture()
        defer { Task { try? await fixture.database.close(); try? await fixture.control.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        let publicReference = try await fixture.database.putBlob(
            Data("public-image".utf8), namespace: .public,
            mimeType: "application/octet-stream"
        )
        let privateReference = try await fixture.database.putBlob(
            Data("private-image".utf8), namespace: .space(
                try SpaceURI(authority: Self.did, spaceType: "app.swan.private", skey: "test")
            )
        )
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests")
        )

        try await app.test(.router) { client in
            let publicHeaders = try fixture.headers(
                jti: "public-record", method: "POST", path: Self.mutationPath
            )
            let publicBody = self.recordBody(rkey: "public", cid: publicReference.cid)
            do {
                let decoded = try JSONDecoder().decode(
                    SwanPublicWire.ComAtprotoRepoCreateRecord.Input.self,
                    from: Data(publicBody.utf8)
                )
                _ = try PublicRepositoryRecordCodec.publicRecord(
                    from: decoded.record,
                    collection: Self.collection
                )
            } catch {
                XCTFail("test body does not decode: " + String(describing: error))
            }
            try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: publicHeaders,
                body: ByteBuffer(string: publicBody)
            ) { response in
                XCTAssertEqual(response.status, .ok, String(decoding: response.body.readableBytesView, as: UTF8.self))
                let object = try self.jsonObject(response.body)
                XCTAssertEqual(object["uri"] as? String, "at://" + Self.did + "/" + Self.collection + "/public")
                XCTAssertNotNil(object["cid"] as? String)
            }

            for (name, size, mimeType) in [
                ("typed-wrong-size", 11, "application/octet-stream"),
                ("typed-wrong-mime", 12, "image/png"),
            ] {
                let response = try await client.execute(
                    uri: Self.mutationPath,
                    method: .post,
                    headers: try fixture.headers(
                        jti: name, method: "POST", path: Self.mutationPath
                    ),
                    body: ByteBuffer(string: self.typedRecordBody(
                        rkey: name, cid: publicReference.cid, size: size, mimeType: mimeType
                    ))
                )
                XCTAssertEqual(response.status, .badRequest, name)
                XCTAssertEqual(
                    try self.jsonObject(response.body)["error"] as? String,
                    "InvalidRequest",
                    name
                )
            }

            let typedHeaders = try fixture.headers(
                jti: "public-typed-record", method: "POST", path: Self.mutationPath
            )
            let typedBody = self.typedRecordBody(
                rkey: "public-typed", cid: publicReference.cid, size: 12
            )
            try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: typedHeaders,
                body: ByteBuffer(string: typedBody)
            ) { response in
                XCTAssertEqual(response.status, .ok, String(decoding: response.body.readableBytesView, as: UTF8.self))
                let object = try self.jsonObject(response.body)
                XCTAssertEqual(object["uri"] as? String, "at://" + Self.did + "/" + Self.collection + "/public-typed")
                XCTAssertNotNil(object["cid"] as? String)
            }

            let privateHeaders = try fixture.headers(
                jti: "private-record", method: "POST", path: Self.mutationPath
            )
            let privateBody = self.recordBody(rkey: "private", cid: privateReference.cid)
            try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: privateHeaders,
                body: ByteBuffer(string: privateBody)
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.jsonObject(response.body)["error"] as? String, "InvalidRequest")
            }

            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlob?did=" + Self.did
                    + "&cid=" + publicReference.cid,
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), Data("public-image".utf8))
                XCTAssertEqual(response.headers[.contentLength], "12")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlob?did=" + Self.did
                    + "&cid=" + privateReference.cid,
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
    }

    private func makeFixture(
        includePublicBlobSpoolAdmission: Bool = true,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicRepositoryMutationHTTPTests-" + UUID().uuidString)
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let signingKey = P256.Signing.PrivateKey()
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: Self.did,
            revision: "3jzfcijpj2z2a",
            signingKey: signingKey
        )
        do {
            _ = try await control.createAccount(try AccountControlRegistration(
                did: Self.did,
                canonicalHandle: "alice.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
                publicGenesisCommitCID: genesis.commitCID.string,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let database = try await SQLiteAccountDatabase(dataDirectory: root, did: Self.did)
            _ = try await database.installPublicRepositoryGenesis(
                genesis,
                signingPublicKey: signingKey.publicKey,
                installedAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x41, count: 32)
            )
            let token = try await issueToken(runtime: runtime)
            let directory = TestMutationDirectory(did: Self.did, database: database)
            let publicBlobSpoolAdmission = try PublicRepositorySpoolAdmission()
            let server = try makeServer(
                runtime: runtime,
                control: control,
                directory: directory,
                signer: P256PublicRepositoryCommitSigner(privateKey: signingKey),
                publicBlobSpoolAdmission: includePublicBlobSpoolAdmission
                    ? publicBlobSpoolAdmission
                    : nil,
                jsonWriteAdmission: jsonWriteAdmission
            )
            return Fixture(
                root: root,
                control: control,
                database: database,
                server: server,
                token: token.token,
                key: token.key,
                jwk: token.jwk,
                runtime: runtime,
                publicBlobSpoolAdmission: publicBlobSpoolAdmission
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func makeServer(
        runtime: SwanOAuthRuntime,
        control: SQLiteControlDatabase,
        directory: TestMutationDirectory,
        signer: any PublicRepositoryCommitSigner,
        publicBlobSpoolAdmission: PublicRepositorySpoolAdmission?,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission?
    ) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-30.json")
        )
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(publicURL: Self.publicURL),
            oauthRuntime: runtime,
            authenticatedGetSpaceDirectory: NoopSimpleSpaceDirectory(),
            accountControlStore: control,
            publicRepositoryMutationDirectory: directory,
            publicRepositoryMutationSignerProvider: TestSignerProvider(signer: signer),
            publicBlobSpoolAdmission: publicBlobSpoolAdmission,
            jsonWriteAdmission: jsonWriteAdmission
        )
    }

    private func issueToken(runtime: SwanOAuthRuntime) async throws -> TokenMaterial {
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
                    scopes: ["atproto"],
                    dpopBoundAccessTokens: true
                ),
                keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: ["atproto"],
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: jwk.thumbprint(),
                jwtID: "issue-" + UUID().uuidString,
                issuedAt: now
            ),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(subject: Self.did, session: session, now: now)
        return TokenMaterial(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func recordBody(rkey: String, cid: String) -> String {
        "{\"repo\":\"" + Self.did + "\",\"collection\":\"" + Self.collection + "\",\"rkey\":\"" + rkey + "\",\"record\":{\"blob\":{\"$link\":\"" + cid + "\"}}}"
    }

    private func typedRecordBody(
        rkey: String,
        cid: String,
        size: Int,
        mimeType: String = "application/octet-stream"
    ) -> String {
        "{\"repo\":\"" + Self.did + "\",\"collection\":\"" + Self.collection
            + "\",\"rkey\":\"" + rkey + "\",\"record\":{\"blob\":{\"$type\":\"blob\",\"ref\":{\"$link\":\""
            + cid + "\"},\"mimeType\":\"" + mimeType + "\",\"size\":" + String(size) + "}}}"
    }

    private func putBody(
        rkey: String,
        text: String,
        swapRecord: String? = nil,
        swapCommit: String? = nil
    ) -> String {
        let swaps = [
            swapRecord.map { "\"swapRecord\":\"\($0)\"" },
            swapCommit.map { "\"swapCommit\":\"\($0)\"" },
        ].compactMap { $0 }.joined(separator: ",")
        let suffix = swaps.isEmpty ? "" : "," + swaps
        return "{\"repo\":\"" + Self.did + "\",\"collection\":\"" + Self.collection
            + "\",\"rkey\":\"" + rkey + "\",\"record\":{\"text\":\"" + text + "\"}" + suffix + "}"
    }

    private func deleteBody(
        rkey: String,
        swapRecord: String? = nil,
        swapCommit: String? = nil
    ) -> String {
        let swaps = [
            swapRecord.map { "\"swapRecord\":\"\($0)\"" },
            swapCommit.map { "\"swapCommit\":\"\($0)\"" },
        ].compactMap { $0 }.joined(separator: ",")
        let suffix = swaps.isEmpty ? "" : "," + swaps
        return "{\"repo\":\"" + Self.did + "\",\"collection\":\"" + Self.collection
            + "\",\"rkey\":\"" + rkey + "\"" + suffix + "}"
    }

    private func jsonObject(_ body: ByteBuffer) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
    }

    private func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func makeJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey {
        let representation = key.publicKey.x963Representation
        return try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
    }

    private struct TokenMaterial: Sendable {
        let token: String
        let key: P256.Signing.PrivateKey
        let jwk: OAuthJSONWebKey
    }

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let database: SQLiteAccountDatabase
        let server: SwanHTTPServer
        let token: String
        let key: P256.Signing.PrivateKey
        let jwk: OAuthJSONWebKey
        let runtime: SwanOAuthRuntime
        let publicBlobSpoolAdmission: PublicRepositorySpoolAdmission

        func headers(
            jti: String,
            method: String,
            path: String
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
            let nonce = runtime.dpopNonceService.issue()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
            let claims = try encoder.encode(Claims(
                jti: jti,
                iat: Int64(Date().timeIntervalSince1970),
                htm: method,
                htu: PublicRepositoryMutationHTTPTests.publicURL.absoluteString + path,
                nonce: nonce,
                ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
            )).base64URLEncodedString()
            let input = header + "." + claims
            let signature = try P256WireSignature.sign(
                Data(input.utf8), using: key
            ).base64URLEncodedString()
            var fields = HTTPFields()
            fields[.authorization] = "DPoP " + token
            fields[HTTPField.Name("DPoP")!] = input + "." + signature
            fields[.contentType] = "application/json"
            return fields
        }
    }
}

private actor TestMutationDirectory: PublicRepositoryMutationDirectory {
    let did: String
    let database: SQLiteAccountDatabase

    init(did: String, database: SQLiteAccountDatabase) {
        self.did = did
        self.database = database
    }

    func publicRepositoryMutationTarget(selector: String) async throws -> PublicRepositoryMutationTarget? {
        guard selector == did else { return nil }
        return try PublicRepositoryMutationTarget(
            did: did,
            status: .active,
            store: database
        )
    }
}

private actor UploadAdmissionBarrier {
    private let expected: Int
    private var arrivals = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(expected: Int) {
        self.expected = expected
    }

    func arriveAndWait() async {
        arrivals += 1
        guard arrivals < expected else {
            let pending = waiters
            waiters.removeAll()
            for waiter in pending {
                waiter.resume()
            }
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

private actor NoopSimpleSpaceDirectory: AuthorizedSimpleSpaceDirectory {
    func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? { nil }

    func close() async throws {}
}

private struct TestSignerProvider: PublicRepositoryMutationSignerProvider {
    let signer: any PublicRepositoryCommitSigner

    func signer(for did: String) async throws -> any PublicRepositoryCommitSigner {
        signer
    }
}
