import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import NIOPosix
import Petrel
import SQLiteNIO
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

    func testStaleSignerGenerationReResolvesAndStillEnqueuesFirehose() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let signingKey = P256.Signing.PrivateKey()
        let provider = SequencedGenerationSignerProvider(
            generations: [1, 2],
            signer: P256PublicRepositoryCommitSigner(privateKey: signingKey)
        )
        let store = GenerationCheckingMutationStore(
            database: fixture.database,
            activeGeneration: 2
        )
        let path = try PublicRepositoryPath(
            collection: Self.collection,
            recordKey: "stale-signer-retry"
        )

        let result = try await SwanPublicRepositoryMutationCoordinator.put(
            store: store,
            did: Self.did,
            path: path,
            record: PublicRecord([
                "$type": .string(Self.collection),
                "text": .string("fresh signer wins"),
            ]),
            swapRecord: nil,
            swapCommit: nil,
            requestID: "stale-signer-retry",
            bodyDigest: Data(repeating: 0x42, count: 32),
            signerProvider: provider,
            now: { 1_750_000_000_000_000 }
        )

        XCTAssertFalse(result.isNoOp)
        let resolutionCount = await provider.resolutionCount()
        let attemptedGenerations = await store.attemptedGenerations()
        XCTAssertEqual(resolutionCount, 2)
        XCTAssertEqual(attemptedGenerations, [1, 2])
        let pending = try await fixture.database.pendingPublicFirehoseOutbox()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.lifecycleGeneration, 2)
        XCTAssertEqual(pending.first?.kind, .commit)
    }

    func testJSONMutationAdmissionRejectsBeforeDecodeAndReleasesAfterFailure() async throws {
        let maximum = 1_000_000
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(5))
        let fixture = try await makeFixture(
            jsonWriteAdmission: admission,
            jsonWriteBodyPolicy: policy
        )
        XCTAssertTrue(fixture.server.jsonWriteAdmission === admission)
        XCTAssertTrue(fixture.server.jsonWriteBodyPolicy === policy)
        XCTAssertTrue(
            fixture.server.publicRepositoryMutations?.jsonWriteAdmission
                === admission
        )
        XCTAssertTrue(
            fixture.server.publicRepositoryMutations?.jsonWriteBodyPolicy
                === policy
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

    func testDeclaredOversizeJSONMutationRejectsBeforeAdmission() async throws {
        let maximum = 1_000_000
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let fixture = try await makeFixture(jsonWriteAdmission: admission)
        let held = try XCTUnwrap(
            admission.reserve(maximumRequestBytes: maximum)
        )

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "PublicRepositoryMutationHTTPTests.declared-oversize")
            )
            try await app.test(.live) { client in
                let response = try await self.executeRealSocketIncompleteBody(
                    port: try XCTUnwrap(client.port),
                    headers: try fixture.headers(
                        jti: "declared-oversize",
                        method: "POST",
                        path: Self.mutationPath
                    ),
                    declaredBodyBytes: maximum + 1,
                    emittedBody: "{"
                )

                XCTAssertEqual(response.statusCode, 400)
                XCTAssertEqual(
                    try self.jsonObject(response.body)["error"] as? String,
                    "InvalidRequest"
                )
                XCTAssertEqual(response.emittedBodyBytes, 1)
                XCTAssertEqual(
                    admission.snapshot,
                    .init(activeLeases: 1, reservedRequestBytes: maximum)
                )
            }
            held.release()
            try await fixture.database.close()
            try await fixture.control.close()
            try FileManager.default.removeItem(at: fixture.root)
        } catch {
            held.release()
            try? await fixture.database.close()
            try? await fixture.control.close()
            try? FileManager.default.removeItem(at: fixture.root)
            throw error
        }
    }

    func testContentLengthDeclarationPolicyRejectsBeforeAdmission() {
        let maximum = 1_000_000
        let rejected = contentLengthRejectionCases(maximum: maximum)
        for (name, values) in rejected {
            XCTAssertFalse(acceptsPublicMutationContentLength(values), name)
        }
        XCTAssertTrue(acceptsPublicMutationContentLength([]), "missing")
        XCTAssertTrue(acceptsPublicMutationContentLength(["1"]), "valid")
        XCTAssertTrue(acceptsPublicMutationContentLength([String(maximum)]), "boundary")
    }

    func testJSONMutationHoldsAdmissionThroughBlockedHandler() async throws {
        let maximum = 1_000_000
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let barrier = MutationTargetBarrier()
        let fixture = try await makeFixture(
            jsonWriteAdmission: admission,
            mutationBarrier: barrier
        )
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let firstBody = self.putBody(rkey: "lease-held", text: "blocked")

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.lease-handler")
        ).test(.router) { client in
            let first = Task {
                try await client.execute(
                    uri: Self.mutationPath,
                    method: .post,
                    headers: try fixture.headers(
                        jti: "lease-handler-first",
                        method: "POST",
                        path: Self.mutationPath
                    ),
                    body: ByteBuffer(string: firstBody)
                )
            }
            try await barrier.waitUntilEntered()
            XCTAssertEqual(
                admission.snapshot,
                .init(activeLeases: 1, reservedRequestBytes: maximum)
            )

            let competing = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "lease-handler-competing",
                    method: "POST",
                    path: Self.mutationPath
                ),
                body: ByteBuffer(data: Data(repeating: 0x20, count: maximum))
            )
            XCTAssertEqual(competing.status, .serviceUnavailable)
            XCTAssertEqual(
                try self.jsonObject(competing.body)["error"] as? String,
                "temporarily_unavailable"
            )

            await barrier.release()
            let completed = try await first.value
            XCTAssertEqual(completed.status, .ok)
        }
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    func testRealSocketAdmissionRefusalRespondsBeforeIncompleteBodyFinishes() async throws {
        let maximum = 1_000_000
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let fixture = try await makeFixture(jsonWriteAdmission: admission)
        let held = try XCTUnwrap(
            admission.reserve(maximumRequestBytes: maximum)
        )

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "PublicRepositoryMutationHTTPTests.real-socket-refusal")
            )
            try await app.test(.live) { client in
                let response = try await self.executeRealSocketIncompleteBody(
                    port: try XCTUnwrap(client.port),
                    headers: try fixture.headers(
                        jti: "real-socket-admission-refusal",
                        method: "POST",
                        path: Self.mutationPath
                    ),
                    declaredBodyBytes: 1_024,
                    emittedBody: "{"
                )

                XCTAssertEqual(response.statusCode, 503)
                XCTAssertEqual(
                    try self.jsonObject(response.body)["error"] as? String,
                    "temporarily_unavailable"
                )
                XCTAssertEqual(response.emittedBodyBytes, 1)
                XCTAssertEqual(
                    admission.snapshot,
                    .init(activeLeases: 1, reservedRequestBytes: maximum)
                )
            }
            held.release()
            try await fixture.database.close()
            try await fixture.control.close()
            try FileManager.default.removeItem(at: fixture.root)
        } catch {
            held.release()
            try? await fixture.database.close()
            try? await fixture.control.close()
            try? FileManager.default.removeItem(at: fixture.root)
            throw error
        }
    }

    func testRealSocketSlowDripReceivesSanitizedDeadlineResponseAndReleasesLease() async throws {
        let maximum = 1_000_000
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(100))
        let fixture = try await makeFixture(
            jsonWriteAdmission: admission,
            jsonWriteBodyPolicy: policy
        )
        let body = putBody(rkey: "real-socket-drip", text: "complete-valid-body")

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "PublicRepositoryMutationHTTPTests.real-socket-drip")
            )
            try await app.test(.live) { client in
                let port = try XCTUnwrap(client.port)
                for iteration in 0 ..< 12 {
                    let response = try await self.executeRealSocketSlowDrip(
                        port: port,
                        headers: try fixture.headers(
                            jti: "real-socket-drip-\(iteration)",
                            method: "POST",
                            path: Self.mutationPath
                        ),
                        body: body
                    )

                    XCTAssertEqual(response.statusCode, 503)
                    XCTAssertEqual(
                        try self.jsonObject(response.body)["error"] as? String,
                        "temporarily_unavailable"
                    )
                    XCTAssertGreaterThanOrEqual(response.emittedBodyBytes, 3)
                    XCTAssertEqual(
                        admission.snapshot,
                        .init(activeLeases: 0, reservedRequestBytes: 0)
                    )
                }
            }
            XCTAssertEqual(
                admission.snapshot,
                .init(activeLeases: 0, reservedRequestBytes: 0)
            )
            try await fixture.database.close()
            try await fixture.control.close()
            try FileManager.default.removeItem(at: fixture.root)
        } catch {
            try? await fixture.database.close()
            try? await fixture.control.close()
            try? FileManager.default.removeItem(at: fixture.root)
            throw error
        }
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

    func testUploadBlobSlowTimeoutLeavesNoCASReferenceQuotaOrSpoolSideEffects() async throws {
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(100))
        let fixture = try await makeFixture(jsonWriteBodyPolicy: policy)
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.upload-timeout")
        ).test(.live) { client in
            var headers = try fixture.headers(
                jti: "upload-timeout", method: "POST", path: Self.uploadPath
            )
            headers[.contentType] = "application/octet-stream"
            let response = try await executeRealSocketIncompleteHTTPBody(
                port: try XCTUnwrap(client.port),
                path: Self.uploadPath,
                headers: headers,
                declaredBodyBytes: 1_024,
                emittedBody: "truncated-upload"
            )
            XCTAssertEqual(response.statusCode, 503)
            XCTAssertEqual(try self.jsonObject(response.body)["error"] as? String,
                           "temporarily_unavailable")
        }

        XCTAssertEqual(fixture.publicBlobSpoolAdmission.snapshot.activeLeases, 0)
        XCTAssertEqual(fixture.publicBlobSpoolAdmission.snapshot.reservedBytes, 0)
        let connection = try await SQLiteConnection.open(storage: .file(
            path: SQLiteLayout.accountDatabase(in: fixture.root, did: Self.did).path
        ))
        for table in ["blob_payloads", "blob_namespace_references", "blob_cas_lifecycle"] {
            let rows = try await connection.query("SELECT COUNT(*) AS count FROM \(table)")
            XCTAssertEqual(rows.first?.column("count")?.integer, 0, table)
        }
        try await connection.close()
    }

    func testUploadBlobInvalidAuthIncompleteBodyTerminatesBoundedlyWithoutSideEffects() async throws {
        let fixture = try await makeFixture(
            jsonWriteBodyPolicy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(100))
        )
        defer { Task { try? await fixture.database.close(); try? await fixture.control.close(); try? FileManager.default.removeItem(at: fixture.root) } }
        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.upload-invalid-auth-drain")
        ).test(.live) { client in
            var headers: HTTPFields = [.contentType: "application/octet-stream"]
            headers[.authorization] = "Bearer invalid"
            let started = ContinuousClock().now
            let response = try await executeRealSocketIncompleteHTTPBody(
                port: try XCTUnwrap(client.port), path: Self.uploadPath,
                headers: headers, declaredBodyBytes: 1_024, emittedBody: "x"
            )
            XCTAssertEqual(response.statusCode, 503)
            XCTAssertLessThan(started.duration(to: .now), .seconds(1))
            XCTAssertEqual(try self.jsonObject(response.body)["error"] as? String, "temporarily_unavailable")
        }
        try await assertNoUploadSideEffects(fixture)
    }

    func testUploadBlobSpoolRefusalIncompleteBodyTerminatesBoundedlyWithoutSideEffects() async throws {
        let fixture = try await makeFixture(
            includePublicBlobSpoolAdmission: false,
            jsonWriteBodyPolicy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(100))
        )
        defer { Task { try? await fixture.database.close(); try? await fixture.control.close(); try? FileManager.default.removeItem(at: fixture.root) } }
        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.upload-spool-refusal-drain")
        ).test(.live) { client in
            var headers = try fixture.headers(
                jti: "upload-spool-refusal-drain", method: "POST", path: Self.uploadPath
            )
            headers[.contentType] = "application/octet-stream"
            let started = ContinuousClock().now
            let response = try await executeRealSocketIncompleteHTTPBody(
                port: try XCTUnwrap(client.port), path: Self.uploadPath,
                headers: headers, declaredBodyBytes: 1_024, emittedBody: "x"
            )
            XCTAssertEqual(response.statusCode, 503)
            XCTAssertLessThan(started.duration(to: .now), .seconds(1))
            XCTAssertEqual(try self.jsonObject(response.body)["error"] as? String, "temporarily_unavailable")
        }
        try await assertNoUploadSideEffects(fixture)
    }

    func testUploadBlobInvalidAuthCompleteBodyPreservesKeepAliveForNextRequest() async throws {
        let fixture = try await makeFixture()
        defer { Task { try? await fixture.database.close(); try? await fixture.control.close(); try? FileManager.default.removeItem(at: fixture.root) } }
        try await fixture.server.buildApplication(logger: Logger(label: "upload-invalid-auth-keepalive"))
            .test(.live) { client in
                var headers: HTTPFields = [.contentType: "application/octet-stream"]
                headers[.authorization] = "Bearer invalid"
                let responses = try await executeUploadThenHealthOnSameConnection(
                    port: try XCTUnwrap(client.port), headers: headers, body: "complete"
                )
                XCTAssertEqual(responses.first.statusCode, 401)
                XCTAssertEqual(responses.next.statusCode, 200)
                XCTAssertEqual(String(decoding: responses.next.body.readableBytesView, as: UTF8.self), "OK")
            }
        try await assertNoUploadSideEffects(fixture)
    }

    func testUploadBlobSpoolRefusalCompleteBodyPreservesKeepAliveForNextRequest() async throws {
        let fixture = try await makeFixture(includePublicBlobSpoolAdmission: false)
        defer { Task { try? await fixture.database.close(); try? await fixture.control.close(); try? FileManager.default.removeItem(at: fixture.root) } }
        try await fixture.server.buildApplication(logger: Logger(label: "upload-spool-refusal-keepalive"))
            .test(.live) { client in
                var headers = try fixture.headers(
                    jti: "upload-spool-refusal-keepalive", method: "POST", path: Self.uploadPath
                )
                headers[.contentType] = "application/octet-stream"
                let responses = try await executeUploadThenHealthOnSameConnection(
                    port: try XCTUnwrap(client.port), headers: headers, body: "complete"
                )
                XCTAssertEqual(responses.first.statusCode, 503)
                XCTAssertEqual(responses.next.statusCode, 200)
                XCTAssertEqual(String(decoding: responses.next.body.readableBytesView, as: UTF8.self), "OK")
            }
        try await assertNoUploadSideEffects(fixture)
    }

    func testUploadBlobRejectsMissingContentLengthBeforeSpoolAdmission() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        XCTAssertThrowsError(try requiredPublicBlobContentLength([:]))
        XCTAssertThrowsError(try requiredPublicBlobContentLength([
            .transferEncoding: "chunked"
        ]))
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

    func testUploadBlobReturnsTypedAccountQuotaError() async throws {
        let fixture = try await makeFixture(
            blobQuota: AccountBlobQuota(maximumUniqueBytes: 4, maximumReferences: 1)
        )
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.quota")
        ).test(.router) { client in
            var headers = try fixture.headers(
                jti: "upload-quota",
                method: "POST",
                path: Self.uploadPath
            )
            headers[.contentType] = "application/octet-stream"
            let response = try await client.execute(
                uri: Self.uploadPath,
                method: .post,
                headers: headers,
                body: ByteBuffer(data: Data(repeating: 0x51, count: 5))
            )
            XCTAssertEqual(response.status, .contentTooLarge)
            XCTAssertEqual(
                try self.jsonObject(response.body)["error"] as? String,
                "AccountBlobQuotaExceeded"
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

    // MARK: Staged upload confidentiality

    /// `com.atproto.repo.uploadBlob` carries no namespace intent, so a blob
    /// destined for a permissioned space arrives through exactly this route.
    /// Publishing it the instant it lands hands the bytes to any anonymous
    /// caller who knows or can derive the CID, before the uploader has said
    /// anything about where they belong.
    func testUploadedBlobIsNotAnonymouslyFetchableBeforeAPublicRecordReferencesIt()
        async throws
    {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.staged-upload")
        ).test(.router) { client in
            var uploadHeaders = try fixture.headers(
                jti: "staged-upload", method: "POST", path: Self.uploadPath
            )
            uploadHeaders[.contentType] = "application/octet-stream"
            let uploaded = try await client.execute(
                uri: Self.uploadPath,
                method: .post,
                headers: uploadHeaders,
                body: ByteBuffer(data: Data("permissioned-intent".utf8))
            )
            XCTAssertEqual(
                uploaded.status,
                .ok,
                String(decoding: uploaded.body.readableBytesView, as: UTF8.self)
            )
            let blob = try XCTUnwrap(
                try self.jsonObject(uploaded.body)["blob"] as? [String: Any]
            )
            let cid = try XCTUnwrap(
                (blob["ref"] as? [String: Any])?["$link"] as? String
            )

            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlob?did=" + Self.did
                    + "&cid=" + cid,
                method: .get
            ) { response in
                XCTAssertEqual(
                    response.status,
                    .notFound,
                    "an uploaded blob must not be anonymously readable before a public record references it"
                )
            }
        }
    }

    /// The apply that would have consumed the upload is rejected. The staged
    /// bytes must stay unreachable rather than becoming a permanent public
    /// edge nothing will ever clean up.
    func testAbandonedUploadNeverBecomesAnonymouslyFetchable() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.abandoned-upload")
        ).test(.router) { client in
            var uploadHeaders = try fixture.headers(
                jti: "abandoned-upload", method: "POST", path: Self.uploadPath
            )
            uploadHeaders[.contentType] = "application/octet-stream"
            let uploaded = try await client.execute(
                uri: Self.uploadPath,
                method: .post,
                headers: uploadHeaders,
                body: ByteBuffer(data: Data("abandoned-upload".utf8))
            )
            XCTAssertEqual(
                uploaded.status,
                .ok,
                String(decoding: uploaded.body.readableBytesView, as: UTF8.self)
            )
            let blob = try XCTUnwrap(
                try self.jsonObject(uploaded.body)["blob"] as? [String: Any]
            )
            let cid = try XCTUnwrap(
                (blob["ref"] as? [String: Any])?["$link"] as? String
            )

            // A declared size that does not match the stored payload is
            // rejected by typed blob validation, so the record never commits.
            let rejected = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "abandoned-apply", method: "POST", path: Self.mutationPath
                ),
                body: ByteBuffer(string: self.typedRecordBody(
                    rkey: "abandoned", cid: cid, size: 3
                ))
            )
            XCTAssertEqual(rejected.status, .badRequest)

            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlob?did=" + Self.did
                    + "&cid=" + cid,
                method: .get
            ) { response in
                XCTAssertEqual(
                    response.status,
                    .notFound,
                    "a rejected apply must not leave a durable public edge"
                )
            }
        }
    }

    /// Content-addressed storage is shared by CID, so re-uploading identical
    /// bytes is an ordinary client retry. It must not resurrect anonymous
    /// reachability for a payload that a permissioned record already owns.
    func testSameCIDReuploadAfterPermissionedPromotionStaysPrivate() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let payload = Data("permissioned-payload".utf8)
        let space = try SpaceURI(
            authority: Self.did, spaceType: "app.bsky.bookmarks", skey: "self"
        )
        let record = try SpaceRecordURI(
            space: space,
            author: Self.did,
            collection: Self.collection,
            rkey: "permissioned-blob"
        )

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.reupload")
        ).test(.router) { client in
            func upload(jti: String) async throws -> String {
                var headers = try fixture.headers(
                    jti: jti, method: "POST", path: Self.uploadPath
                )
                headers[.contentType] = "application/octet-stream"
                let response = try await client.execute(
                    uri: Self.uploadPath,
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(data: payload)
                )
                XCTAssertEqual(
                    response.status,
                    .ok,
                    String(decoding: response.body.readableBytesView, as: UTF8.self)
                )
                let blob = try XCTUnwrap(
                    try self.jsonObject(response.body)["blob"] as? [String: Any]
                )
                return try XCTUnwrap(
                    (blob["ref"] as? [String: Any])?["$link"] as? String
                )
            }

            func assertNotAnonymouslyReadable(
                _ cid: String,
                _ message: String
            ) async throws {
                try await client.execute(
                    uri: "/xrpc/com.atproto.sync.getBlob?did=" + Self.did
                        + "&cid=" + cid,
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .notFound, message)
                }
            }

            let cid = try await upload(jti: "reupload-first")
            try await assertNotAnonymouslyReadable(
                cid, "a staged upload is never anonymously readable"
            )

            let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "$type", value: Self.collection),
                (key: "blob", value: OrderedCBORMap(entries: [
                    (key: "$type", value: "blob"),
                    (key: "ref", value: ATProtoLink(cid: try CID.parse(cid))),
                    (key: "mimeType", value: "application/octet-stream"),
                    (key: "size", value: payload.count),
                ])),
            ]))
            _ = try await fixture.database.apply(
                space: space,
                author: Self.did,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.create(uri: record, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            try await assertNotAnonymouslyReadable(
                cid, "a promoted permissioned blob is not anonymously readable"
            )

            let second = try await upload(jti: "reupload-second")
            XCTAssertEqual(second, cid)
            try await assertNotAnonymouslyReadable(
                second,
                "re-uploading identical bytes must not restore anonymous reachability"
            )
        }
    }

    /// The regression guard on the fix itself: a blob a validated public
    /// record does reference is part of the federated protocol surface and
    /// must remain anonymously fetchable.
    func testUploadedBlobIsAnonymouslyFetchableOnceAPublicRecordReferencesIt()
        async throws
    {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? await fixture.control.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let payload = Data("published-image".utf8)

        try await fixture.server.buildApplication(
            logger: Logger(label: "PublicRepositoryMutationHTTPTests.published-upload")
        ).test(.router) { client in
            var uploadHeaders = try fixture.headers(
                jti: "published-upload", method: "POST", path: Self.uploadPath
            )
            uploadHeaders[.contentType] = "application/octet-stream"
            let uploaded = try await client.execute(
                uri: Self.uploadPath,
                method: .post,
                headers: uploadHeaders,
                body: ByteBuffer(data: payload)
            )
            XCTAssertEqual(
                uploaded.status,
                .ok,
                String(decoding: uploaded.body.readableBytesView, as: UTF8.self)
            )
            let blob = try XCTUnwrap(
                try self.jsonObject(uploaded.body)["blob"] as? [String: Any]
            )
            let cid = try XCTUnwrap(
                (blob["ref"] as? [String: Any])?["$link"] as? String
            )

            let committed = try await client.execute(
                uri: Self.mutationPath,
                method: .post,
                headers: try fixture.headers(
                    jti: "published-apply", method: "POST", path: Self.mutationPath
                ),
                body: ByteBuffer(string: self.typedRecordBody(
                    rkey: "published", cid: cid, size: payload.count
                ))
            )
            XCTAssertEqual(
                committed.status,
                .ok,
                String(decoding: committed.body.readableBytesView, as: UTF8.self)
            )

            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlob?did=" + Self.did
                    + "&cid=" + cid,
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), payload)
                XCTAssertEqual(
                    response.headers[.contentLength],
                    String(payload.count)
                )
            }
        }
    }

    private func makeFixture(
        includePublicBlobSpoolAdmission: Bool = true,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy? = nil,
        mutationBarrier: MutationTargetBarrier? = nil,
        blobQuota: AccountBlobQuota = .conservative
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
            let database = try await SQLiteAccountDatabase(
                dataDirectory: root, did: Self.did, blobQuota: blobQuota
            )
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
            let directory = TestMutationDirectory(
                did: Self.did,
                database: database,
                barrier: mutationBarrier
            )
            let publicBlobSpoolAdmission = try PublicRepositorySpoolAdmission()
            let server = try makeServer(
                runtime: runtime,
                control: control,
                directory: directory,
                signer: P256PublicRepositoryCommitSigner(privateKey: signingKey),
                publicBlobSpoolAdmission: includePublicBlobSpoolAdmission
                    ? publicBlobSpoolAdmission
                    : nil,
                jsonWriteAdmission: jsonWriteAdmission,
                jsonWriteBodyPolicy: jsonWriteBodyPolicy
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

    private func assertNoUploadSideEffects(_ fixture: Fixture) async throws {
        XCTAssertEqual(fixture.publicBlobSpoolAdmission.snapshot.activeLeases, 0)
        XCTAssertEqual(fixture.publicBlobSpoolAdmission.snapshot.reservedBytes, 0)
        let connection = try await SQLiteConnection.open(storage: .file(
            path: SQLiteLayout.accountDatabase(in: fixture.root, did: Self.did).path
        ))
        for table in ["blob_payloads", "blob_namespace_references", "blob_cas_lifecycle"] {
            let rows = try await connection.query("SELECT COUNT(*) AS count FROM \(table)")
            XCTAssertEqual(rows.first?.column("count")?.integer, 0, table)
        }
        try await connection.close()
    }

    private func makeServer(
        runtime: SwanOAuthRuntime,
        control: SQLiteControlDatabase,
        directory: TestMutationDirectory,
        signer: any PublicRepositoryCommitSigner,
        publicBlobSpoolAdmission: PublicRepositorySpoolAdmission?,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission?,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy?
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
            publicRepositoryReadDirectory: directory,
            publicRepositoryMutationDirectory: directory,
            publicRepositoryMutationSignerProvider: TestSignerProvider(signer: signer),
            publicBlobSpoolAdmission: publicBlobSpoolAdmission,
            jsonWriteAdmission: jsonWriteAdmission,
            jsonWriteBodyPolicy: jsonWriteBodyPolicy
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

    private func executeRealSocketSlowDrip(
        port: Int,
        headers: HTTPFields,
        body: String
    ) async throws -> RealSocketDripResponse {
        let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connectTimeout(.seconds(2))
            .connect(host: "localhost", port: port)
            .get()
        let asyncChannel = try await channel.eventLoop.submit {
            try NIOAsyncChannel<ByteBuffer, ByteBuffer>(
                wrappingChannelSynchronously: channel
            )
        }.get()
        let state = RealSocketDripState()
        let boundedClose = Task {
            try await Task.sleep(for: .seconds(2))
            await state.markTimedOut()
            channel.close(mode: .all, promise: nil)
        }

        do {
            let response = try await asyncChannel.executeThenClose { inbound, outbound in
                var requestHead = "POST \(Self.mutationPath) HTTP/1.1\r\n"
                for field in headers {
                    requestHead += "\(field.name.canonicalName): \(field.value)\r\n"
                }
                let bodyBytes = Array(body.utf8)
                requestHead += "host: 127.0.0.1:\(port)\r\n"
                requestHead += "content-length: \(bodyBytes.count)\r\n"
                requestHead += "\r\n"
                try await outbound.write(ByteBuffer(string: requestHead))

                let producer = Task {
                    for byte in bodyBytes {
                        try Task.checkCancellation()
                        try await outbound.write(ByteBuffer(bytes: [byte]))
                        await state.recordBodyByte()
                        try await Task.sleep(for: .milliseconds(10))
                    }
                }

                do {
                    var iterator = inbound.makeAsyncIterator()
                    var responseBytes = ByteBuffer()
                    while var chunk = try await iterator.next() {
                        responseBytes.writeBuffer(&chunk)
                        if let response = try realSocketDripResponse(
                            from: responseBytes,
                            emittedBodyBytes: await state.emittedBodyBytes
                        ) {
                            producer.cancel()
                            _ = await producer.result
                            return response
                        }
                    }
                    producer.cancel()
                    _ = await producer.result
                    throw RealSocketDripFailure.incompleteResponse
                } catch {
                    producer.cancel()
                    _ = await producer.result
                    throw error
                }
            }
            boundedClose.cancel()
            _ = await boundedClose.result
            guard !(await state.timedOut) else {
                throw RealSocketDripFailure.timeout
            }
            return response
        } catch {
            boundedClose.cancel()
            _ = await boundedClose.result
            if await state.timedOut {
                throw RealSocketDripFailure.timeout
            }
            throw error
        }
    }

    private func executeRealSocketIncompleteBody(
        port: Int,
        headers: HTTPFields,
        declaredBodyBytes: Int,
        emittedBody: String
    ) async throws -> RealSocketDripResponse {
        let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .connectTimeout(.seconds(2))
            .connect(host: "localhost", port: port)
            .get()
        let asyncChannel = try await channel.eventLoop.submit {
            try NIOAsyncChannel<ByteBuffer, ByteBuffer>(
                wrappingChannelSynchronously: channel
            )
        }.get()
        let state = RealSocketDripState()
        let boundedClose = Task {
            try await Task.sleep(for: .seconds(2))
            await state.markTimedOut()
            channel.close(mode: .all, promise: nil)
        }

        do {
            let response = try await asyncChannel.executeThenClose { inbound, outbound in
                var requestHead = "POST \(Self.mutationPath) HTTP/1.1\r\n"
                for field in headers {
                    requestHead += "\(field.name.canonicalName): \(field.value)\r\n"
                }
                requestHead += "host: 127.0.0.1:\(port)\r\n"
                requestHead += "content-length: \(declaredBodyBytes)\r\n\r\n"
                try await outbound.write(ByteBuffer(string: requestHead + emittedBody))
                await state.recordBodyByte()

                var iterator = inbound.makeAsyncIterator()
                var responseBytes = ByteBuffer()
                var completeResponse: RealSocketDripResponse?
                while var chunk = try await iterator.next() {
                    responseBytes.writeBuffer(&chunk)
                    if completeResponse == nil,
                       let response = try realSocketDripResponse(
                        from: responseBytes,
                        emittedBodyBytes: emittedBody.utf8.count
                    ) {
                        completeResponse = response
                    }
                }
                return try XCTUnwrap(
                    completeResponse,
                    "server closed before emitting the rejection response"
                )
            }
            boundedClose.cancel()
            _ = await boundedClose.result
            guard !(await state.timedOut) else {
                throw RealSocketDripFailure.timeout
            }
            return response
        } catch {
            boundedClose.cancel()
            _ = await boundedClose.result
            if await state.timedOut {
                throw RealSocketDripFailure.timeout
            }
            throw error
        }
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

func contentLengthRejectionCases(maximum: Int) -> [(String, [String])] {
    [
        ("empty", [""]),
        ("malformed", ["abc"]),
        ("signed-positive", ["+1"]),
        ("signed-negative", ["-1"]),
        ("negative-zero", ["-0"]),
        ("leading-zero", ["01"]),
        ("zero-empty-body", ["0"]),
        ("leading-whitespace", [" 1"]),
        ("trailing-whitespace", ["1 "]),
        ("overflow", ["999999999999999999999999999999999999"]),
        ("duplicate", ["1", "1"]),
        ("comma-combined", ["1, 1"]),
        ("oversized", [String(maximum + 1)]),
    ]
}

/// Backs both public surfaces. `getBlob` is served from the *read* surface
/// now, so a fixture that uploads a blob and then reads it back has to supply
/// a read directory as well as a mutation one.
private actor TestMutationDirectory:
    PublicRepositoryMutationDirectory, PublicRepositoryReadDirectory
{
    let did: String
    let database: SQLiteAccountDatabase
    let barrier: MutationTargetBarrier?

    init(
        did: String,
        database: SQLiteAccountDatabase,
        barrier: MutationTargetBarrier? = nil
    ) {
        self.did = did
        self.database = database
        self.barrier = barrier
    }

    func publicRepositoryMutationTarget(selector: String) async throws -> PublicRepositoryMutationTarget? {
        guard selector == did else { return nil }
        if let barrier {
            try await barrier.arriveAndWait()
        }
        return try PublicRepositoryMutationTarget(
            did: did,
            status: .active,
            store: database
        )
    }

    // MARK: - PublicRepositoryReadDirectory

    /// Deliberately does not arrive at `barrier`: the barrier synchronizes
    /// concurrent *mutations*, and a blob read consuming an arrival would
    /// change what the concurrency tests are measuring.
    func publicRepositoryBlobOutcome(
        did selector: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget>
    {
        guard selector == did else { return .notFound }
        return .active(
            try PublicRepositoryReadBlobTarget(
                did: did, status: .active, store: database
            )
        )
    }

    func publicRepositoryStatus(
        selector _: String
    ) async throws -> PublicRepositoryReadStatus? { nil }

    func describePublicRepository(
        selector _: String
    ) async throws -> PublicRepositoryReadDescription? { nil }

    func publicRepositoryRecord(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadRecord? { nil }

    func listPublicRepositoryRecords(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadPage {
        try .init(records: [], cursor: nil)
    }

    func publicRepositoryCAR(
        selector _: String
    ) async throws -> PublicRepositoryReadCAR? { nil }

    func publicRepositoryDescriptionOutcome(
        selector _: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    { .notFound }

    func publicRepositoryRecordOutcome(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    { .notFound }

    func publicRepositoryRecordsOutcome(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    { .notFound }

    func publicRepositoryCAROutcome(
        selector _: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR>
    { .notFound }
}

struct RealSocketDripResponse: Sendable {
    let statusCode: Int
    let body: ByteBuffer
    let emittedBodyBytes: Int
}

func realSocketDripResponse(
    from bytes: ByteBuffer,
    emittedBodyBytes: Int
) throws -> RealSocketDripResponse? {
    let response = String(decoding: bytes.readableBytesView, as: UTF8.self)
    guard let separator = response.range(of: "\r\n\r\n") else { return nil }
    let head = response[..<separator.lowerBound]
    let body = response[separator.upperBound...]
    let headLines = String(head).components(separatedBy: "\r\n")
    let statusComponents = headLines[0].split(separator: " ")
    guard statusComponents.count >= 2,
          let statusCode = Int(statusComponents[1]) else {
        throw RealSocketDripFailure.incompleteResponse
    }
    let contentLength = headLines.lazy.compactMap { line -> Int? in
        let components = line.split(separator: ":", maxSplits: 1)
        guard components.count == 2,
              components[0].lowercased() == "content-length" else { return nil }
        return Int(components[1].trimmingCharacters(in: .whitespaces))
    }.first
    guard let contentLength else { return nil }
    guard body.utf8.count >= contentLength else { return nil }
    let completeBody = String(body.prefix(contentLength))
    return RealSocketDripResponse(
        statusCode: statusCode,
        body: ByteBuffer(string: completeBody),
        emittedBodyBytes: emittedBodyBytes
    )
}

enum RealSocketDripFailure: Error {
    case timeout
    case incompleteResponse
}

actor RealSocketDripState {
    private(set) var emittedBodyBytes = 0
    private(set) var timedOut = false

    func recordBodyByte() {
        emittedBodyBytes += 1
    }

    func markTimedOut() {
        timedOut = true
    }
}

func executeRealSocketIncompleteHTTPBody(
    port: Int,
    path: String,
    headers: HTTPFields,
    declaredBodyBytes: Int,
    emittedBody: String
) async throws -> RealSocketDripResponse {
    let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
        .connectTimeout(.seconds(2))
        .connect(host: "localhost", port: port)
        .get()
    let asyncChannel = try await channel.eventLoop.submit {
        try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
    }.get()
    let state = RealSocketDripState()
    let boundedClose = Task {
        try await Task.sleep(for: .seconds(2))
        await state.markTimedOut()
        channel.close(mode: .all, promise: nil)
    }
    do {
        let response = try await asyncChannel.executeThenClose { inbound, outbound in
            var head = "POST \(path) HTTP/1.1\r\n"
            for field in headers {
                head += "\(field.name.canonicalName): \(field.value)\r\n"
            }
            head += "host: 127.0.0.1:\(port)\r\n"
            head += "content-length: \(declaredBodyBytes)\r\n\r\n"
            try await outbound.write(ByteBuffer(string: head + emittedBody))
            await state.recordBodyByte()

            var iterator = inbound.makeAsyncIterator()
            var responseBytes = ByteBuffer()
            var completeResponse: RealSocketDripResponse?
            while var chunk = try await iterator.next() {
                responseBytes.writeBuffer(&chunk)
                if completeResponse == nil,
                   let parsed = try realSocketDripResponse(
                    from: responseBytes,
                    emittedBodyBytes: emittedBody.utf8.count
                   ) {
                    completeResponse = parsed
                }
            }
            return try XCTUnwrap(
                completeResponse,
                "server closed before emitting the rejection response"
            )
        }
        boundedClose.cancel()
        _ = await boundedClose.result
        guard !(await state.timedOut) else { throw RealSocketDripFailure.timeout }
        return response
    } catch {
        boundedClose.cancel()
        _ = await boundedClose.result
        if await state.timedOut { throw RealSocketDripFailure.timeout }
        throw error
    }
}

func executeUploadThenHealthOnSameConnection(
    port: Int,
    headers: HTTPFields,
    body: String
) async throws -> (first: RealSocketDripResponse, next: RealSocketDripResponse) {
    let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
        .connectTimeout(.seconds(2)).connect(host: "localhost", port: port).get()
    let asyncChannel = try await channel.eventLoop.submit {
        try NIOAsyncChannel<ByteBuffer, ByteBuffer>(wrappingChannelSynchronously: channel)
    }.get()
    return try await asyncChannel.executeThenClose { inbound, outbound in
        var head = "POST /xrpc/com.atproto.repo.uploadBlob HTTP/1.1\r\n"
        for field in headers { head += "\(field.name.canonicalName): \(field.value)\r\n" }
        head += "host: 127.0.0.1:\(port)\r\ncontent-length: \(body.utf8.count)\r\n\r\n"
        try await outbound.write(ByteBuffer(string: head + body))
        var iterator = inbound.makeAsyncIterator()
        var bytes = ByteBuffer()
        var first: RealSocketDripResponse?
        while first == nil, var chunk = try await iterator.next() {
            bytes.writeBuffer(&chunk)
            first = try realSocketDripResponse(from: bytes, emittedBodyBytes: body.utf8.count)
        }
        try await outbound.write(ByteBuffer(string:
            "GET /health HTTP/1.1\r\nhost: 127.0.0.1:\(port)\r\nconnection: close\r\n\r\n"
        ))
        bytes.clear()
        var next: RealSocketDripResponse?
        while next == nil, var chunk = try await iterator.next() {
            bytes.writeBuffer(&chunk)
            next = try realSocketDripResponse(from: bytes, emittedBodyBytes: 0)
        }
        return (try XCTUnwrap(first), try XCTUnwrap(next))
    }
}

func oauthDPoPReplayCount(in root: URL) async throws -> Int {
    let connection = try await SQLiteConnection.open(
        storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
    )
    defer { Task { try? await connection.close() } }
    let rows = try await connection.query(
        "SELECT COUNT(*) AS row_count FROM oauth_control_dpop_replays"
    )
    return try XCTUnwrap(rows.first?.column("row_count")?.integer)
}

private actor MutationTargetBarrier {
    private var entered = false
    private var released = false

    func arriveAndWait() async throws {
        entered = true
        while !released {
            try Task.checkCancellation()
            try await Task.sleep(for: .milliseconds(2))
        }
    }

    func waitUntilEntered() async throws {
        let deadline = ContinuousClock().now.advanced(by: .seconds(5))
        while !entered {
            guard ContinuousClock().now < deadline else {
                throw MutationTargetBarrierTimeout()
            }
            try await Task.sleep(for: .milliseconds(2))
        }
    }

    func release() {
        released = true
    }
}

private struct MutationTargetBarrierTimeout: Error {}

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

    func signer(for did: String) async throws -> PublicRepositoryMutationSigner {
        .init(generation: 1, signer: signer)
    }
}

private actor SequencedGenerationSignerProvider:
    PublicRepositoryMutationSignerProvider
{
    private var generations: [UInt64]
    private let signerValue: any PublicRepositoryCommitSigner
    private var resolutions = 0

    init(
        generations: [UInt64],
        signer: any PublicRepositoryCommitSigner
    ) {
        self.generations = generations
        signerValue = signer
    }

    func signer(for _: String) async throws -> PublicRepositoryMutationSigner {
        guard generations.isEmpty == false else {
            throw SwanError.unavailable("no fresh signer generation")
        }
        resolutions += 1
        return .init(generation: generations.removeFirst(), signer: signerValue)
    }

    func resolutionCount() -> Int { resolutions }
}

private actor GenerationCheckingMutationStore: PublicRepositoryMutationStore {
    private let database: SQLiteAccountDatabase
    private let activeGeneration: UInt64
    private var generations: [UInt64] = []

    init(database: SQLiteAccountDatabase, activeGeneration: UInt64) {
        self.database = database
        self.activeGeneration = activeGeneration
    }

    func loadPublicRepositoryState() async throws -> PublicRepositoryState? {
        try await database.loadPublicRepositoryState()
    }

    func verifyPublicRepositoryProjection() async throws {
        try await database.verifyPublicRepositoryProjection()
    }

    func block(for cid: CID) async throws -> Data? {
        try await database.block(for: cid)
    }

    func publicRepositoryRecordCID(
        for path: PublicRepositoryPath
    ) async throws -> CID? {
        try await database.publicRepositoryRecordCID(for: path)
    }

    func reservePublicRepositoryRevision(
        _ request: PublicRepositoryMutationRequest,
        wallClockMicroseconds: UInt64
    ) async throws -> PublicRepositoryMutationReservationOutcome {
        try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: wallClockMicroseconds
        )
    }

    func applyPublicRepositoryMutation(
        reservation: PublicRepositoryMutationReservation,
        prepared: PreparedPublicRepositoryMutation
    ) async throws -> CommittedPublicRepositoryMutation {
        generations.append(prepared.signingGeneration)
        guard prepared.signingGeneration == activeGeneration else {
            throw PublicRepositoryMutationPublicationError.staleSigningGeneration
        }
        return try await database.applyPublicRepositoryMutation(
            reservation: reservation,
            prepared: prepared,
            firehose: .init(lifecycleGeneration: Int64(activeGeneration))
        )
    }

    func abandonPublicRepositoryReservation(
        _ reservation: PublicRepositoryMutationReservation
    ) async throws {
        try await database.abandonPublicRepositoryReservation(reservation)
    }

    func attemptedGenerations() -> [UInt64] { generations }
}
