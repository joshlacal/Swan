import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import PetrelCrypto
import PetrelRepo
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanStorage
import XCTest

/// Unauthenticated `com.atproto.sync.getRecord`.
///
/// Every proof here is checked the way a consumer checks it: handed to
/// `Repository.verifyRecordProof` with the account's signing key, never
/// compared against bytes the fixture produced. A response that merely looks
/// like a CAR proves nothing; one the verifier accepts for the requested DID,
/// collection, and key proves the route serves what the reference PDS does.
final class PublicRecordProofHTTPTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let handle = "alice.example.com"
    private static let collection = "blue.catbird.mlsChat.device"
    private static let proofPath = "/xrpc/com.atproto.sync.getRecord"

    private static func uri(
        did: String = PublicRecordProofHTTPTests.did,
        collection: String = PublicRecordProofHTTPTests.collection,
        rkey: String
    ) -> String {
        "\(proofPath)?did=\(did)&collection=\(collection)&rkey=\(rkey)"
    }

    func testExistingRecordReturnsACARProofTheVerifierAccepts() async throws {
        try await withFixture { fixture, client in
            // Anonymous by contract: credentials on the request are ignored,
            // exactly as they are on the JSON repo reads.
            var headers = HTTPFields()
            headers[.authorization] = "Bearer private-space-credential"
            headers[HTTPField.Name("DPoP")!] = "private-proof"
            try await client.execute(
                uri: Self.uri(rkey: "r07"), method: .get, headers: headers
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(
                    response.headers[.contentType], "application/vnd.ipld.car"
                )
                XCTAssertEqual(response.headers[.cacheControl], "no-store")
                let car = Data(buffer: response.body)
                XCTAssertEqual(
                    response.headers[.contentLength], String(car.count)
                )
                let verified = try await Repository.verifyRecordProof(
                    car: car,
                    did: Self.did,
                    collection: Self.collection,
                    recordKey: "r07",
                    verification: fixture.verification
                )
                XCTAssertEqual(verified.commit.cid, fixture.state.commitCID)
                XCTAssertTrue(verified.commit.isSignatureVerified)
                let record = try XCTUnwrap(verified.record)
                XCTAssertEqual(record.path.mstKey, "\(Self.collection)/r07")
                let text = try record.record().fields["text"]
                XCTAssertEqual(text, .string("device-r07"))
                // The search path for one key, not the repository.
                XCTAssertNil(car.range(of: Data("device-r08".utf8)))
            }

            // The reference lexicon still declares the deprecated `commit`
            // parameter. It is accepted and has no effect on the answer.
            try await client.execute(
                uri: Self.uri(rkey: "r07")
                    + "&commit=\(CID.fromDAGCBOR(Data("stale".utf8)).string)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                let verified = try await Repository.verifyRecordProof(
                    car: Data(buffer: response.body),
                    did: Self.did,
                    collection: Self.collection,
                    recordKey: "r07",
                    verification: fixture.verification
                )
                XCTAssertEqual(verified.commit.cid, fixture.state.commitCID)
                XCTAssertNotNil(verified.record)
            }
        }
    }

    // Production mutation caught: an absent key answers `RecordNotFound`. The
    // reference PDS answers 200 with the path blocks, and a verifier needs
    // them to tell "not declared" from "withheld".
    func testAbsentRecordReturnsAProofOfAbsence() async throws {
        try await withFixture { fixture, client in
            for (collection, rkey) in [
                (Self.collection, "absent"),
                (Self.collection, "r07a"),
                ("app.bsky.feed.post", "self"),
            ] {
                try await client.execute(
                    uri: Self.uri(collection: collection, rkey: rkey),
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok, rkey)
                    XCTAssertEqual(
                        response.headers[.contentType],
                        "application/vnd.ipld.car"
                    )
                    let verified = try await Repository.verifyRecordProof(
                        car: Data(buffer: response.body),
                        did: Self.did,
                        collection: collection,
                        recordKey: rkey,
                        verification: fixture.verification
                    )
                    XCTAssertEqual(
                        verified.commit.cid, fixture.state.commitCID, rkey
                    )
                    XCTAssertNil(verified.record, rkey)
                }
            }
        }
    }

    func testUnknownDIDAnswersExactlyAsGetLatestCommitDoes() async throws {
        try await withFixture { fixture, client in
            let unknown = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz"
            let reference = try await self.outcome(
                client,
                "/xrpc/com.atproto.sync.getLatestCommit?did=\(unknown)"
            )
            XCTAssertEqual(reference.status, .badRequest)
            XCTAssertEqual(reference.body, #"{"error":"RepoNotFound"}"#)
            let proof = try await self.outcome(
                client, Self.uri(did: unknown, rkey: "r07")
            )
            XCTAssertEqual(proof.status, reference.status)
            XCTAssertEqual(proof.body, reference.body)
            let built = await fixture.directory.proofRequestCount
            XCTAssertEqual(built, 0)
        }
    }

    func testNonActiveAccountsUseTheGetRepoLifecycleMapping() async throws {
        try await withFixture { fixture, client in
            for status: AccountControlStatus in [
                .deactivated, .suspended, .takendown, .deleting, .deleted,
                .desynchronized, .throttled,
            ] {
                await fixture.directory.setStatus(status)
                let reference = try await self.outcome(
                    client, "/xrpc/com.atproto.sync.getRepo?did=\(Self.did)"
                )
                XCTAssertEqual(reference.status, .badRequest, "\(status)")
                let proof = try await self.outcome(
                    client, Self.uri(rkey: "r07")
                )
                XCTAssertEqual(proof.status, reference.status, "\(status)")
                XCTAssertEqual(proof.body, reference.body, "\(status)")
            }
            let deactivated: AccountControlStatus = .deactivated
            await fixture.directory.setStatus(deactivated)
            let named = try await self.outcome(client, Self.uri(rkey: "r07"))
            XCTAssertEqual(named.body, #"{"error":"RepoDeactivated"}"#)
            // No proof was ever built for an account that is not active.
            let built = await fixture.directory.proofRequestCount
            XCTAssertEqual(built, 0)
        }
    }

    func testWrongHTTPMethodsAnswerThePublicReadGuard() async throws {
        try await withFixture { fixture, client in
            for method: HTTPRequest.Method in [
                .post, .put, .patch, .delete, .options,
            ] {
                try await client.execute(
                    uri: Self.uri(rkey: "r07"), method: method
                ) { response in
                    XCTAssertEqual(response.status, .notFound, "\(method)")
                    XCTAssertEqual(
                        String(buffer: response.body),
                        #"{"error":"public_endpoint_unavailable"}"#,
                        "\(method)"
                    )
                }
            }
            let built = await fixture.directory.proofRequestCount
            XCTAssertEqual(built, 0)
        }
    }

    func testMalformedParametersAreInvalidRequestBeforeStorageIsConsulted() async throws {
        try await withFixture { fixture, client in
            let longKey = String(repeating: "k", count: 513)
            for uri in [
                Self.proofPath,
                "\(Self.proofPath)?did=\(Self.did)",
                "\(Self.proofPath)?did=\(Self.did)&collection=\(Self.collection)",
                "\(Self.proofPath)?collection=\(Self.collection)&rkey=r07",
                // The lexicon's parameter is `did`: a handle is not one, even
                // though `com.atproto.repo.getRecord` accepts either.
                Self.uri(did: Self.handle, rkey: "r07"),
                Self.uri(did: "not-a-did", rkey: "r07"),
                Self.uri(did: "did:plc:", rkey: "r07"),
                Self.uri(collection: "not-a-collection", rkey: "r07"),
                Self.uri(collection: "blue.catbird", rkey: "r07"),
                Self.uri(rkey: "%20"),
                Self.uri(rkey: "."),
                Self.uri(rkey: ".."),
                Self.uri(rkey: "a%2Fb"),
                Self.uri(rkey: longKey),
                Self.uri(rkey: "r07") + "&commit=not-a-cid",
                Self.uri(rkey: "r07") + "&cid=bafyreib",
                Self.uri(rkey: "r07") + "&repo=\(Self.did)",
                Self.uri(rkey: "r07") + "&rkey=r08",
            ] {
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .badRequest, uri)
                    XCTAssertEqual(
                        String(buffer: response.body),
                        #"{"error":"InvalidRequest"}"#,
                        uri
                    )
                }
            }
            let built = await fixture.directory.proofRequestCount
            XCTAssertEqual(built, 0)
        }
    }

    /// The route must exist under whichever public profile an operator
    /// selects — production included — because no public profile artifact can
    /// declare it: the attested wire manifests pin the descriptor registry.
    func testEveryRegisteredPublicProfileServesTheRoute() async throws {
        XCTAssertTrue(
            SwanPublicRouteSurface.outOfProfilePublicMethods
                .contains("com.atproto.sync.getRecord")
        )
        var surfaces: [SwanPublicRouteSurface?] = [nil]
        for profileID in SwanPublicRouteSurface.registeredProfileIDs.sorted() {
            surfaces.append(
                try XCTUnwrap(SwanPublicRouteSurface(profileID: profileID))
            )
        }
        for surface in surfaces {
            let label = surface?.profileID ?? "default"
            try await withFixture(surface: surface) { fixture, client in
                try await client.execute(
                    uri: Self.uri(rkey: "r07"), method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok, label)
                    let verified = try await Repository.verifyRecordProof(
                        car: Data(buffer: response.body),
                        did: Self.did,
                        collection: Self.collection,
                        recordKey: "r07",
                        verification: fixture.verification
                    )
                    XCTAssertNotNil(verified.record, label)
                }
                // Opening this one method opens nothing beside it.
                for closed in [
                    "/xrpc/com.atproto.sync.getBlocks?did=\(Self.did)",
                    "/xrpc/com.atproto.sync.listRepos",
                    "/xrpc/com.atproto.sync.listBlobs?did=\(Self.did)",
                    "/xrpc/com.atproto.sync.getRecords?did=\(Self.did)",
                    "/xrpc/com.atproto.sync.getRecordx?did=\(Self.did)",
                ] {
                    try await client.execute(
                        uri: closed, method: .get
                    ) { response in
                        XCTAssertEqual(
                            response.status, .notFound, "\(label) \(closed)"
                        )
                        XCTAssertEqual(
                            String(buffer: response.body),
                            #"{"error":"public_endpoint_unavailable"}"#,
                            "\(label) \(closed)"
                        )
                    }
                }
            }
        }
    }

    // Production mutation caught: the route reaches the directory without a
    // lease — one anonymous GET buys a generation admission and an MST walk
    // outside the bound every other public read is held to — or keeps the
    // lease after the response is written.
    func testProofReadsShareTheBoundedReadAdmission() async throws {
        let admission = try PublicRepositoryJSONReadAdmission(
            maximumConcurrentReads: 1,
            maximumReservedResponseBytes:
                PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes
        )
        try await withFixture(admission: admission) { fixture, client in
            let held = try XCTUnwrap(admission.reserve(
                maximumResponseBytes:
                    PublicRepositoryRecordProofLimits.maximumProofCARBytes
            ))
            let refused = try await self.outcome(
                client, Self.uri(rkey: "r07")
            )
            XCTAssertEqual(refused.status, .serviceUnavailable)
            XCTAssertEqual(
                refused.body, #"{"error":"temporarily_unavailable"}"#
            )
            var built = await fixture.directory.proofRequestCount
            XCTAssertEqual(built, 0, "a refused admission must not reach storage")

            held.release()
            for rkey in ["r07", "absent", "r08"] {
                let served = try await self.outcome(
                    client, Self.uri(rkey: rkey)
                )
                XCTAssertEqual(served.status, .ok, rkey)
                XCTAssertEqual(
                    admission.snapshot.activeLeases, 0,
                    "the lease must be returned once the body is written"
                )
            }
            built = await fixture.directory.proofRequestCount
            XCTAssertEqual(built, 3)

            // Every early exit returns its lease too.
            let unknown = try await self.outcome(
                client,
                Self.uri(did: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz", rkey: "r07")
            )
            XCTAssertEqual(unknown.status, .badRequest)
            XCTAssertEqual(admission.snapshot.activeLeases, 0)
            let deactivated: AccountControlStatus = .deactivated
            await fixture.directory.setStatus(deactivated)
            let inactive = try await self.outcome(
                client, Self.uri(rkey: "r07")
            )
            XCTAssertEqual(inactive.status, .badRequest)
            XCTAssertEqual(admission.snapshot.activeLeases, 0)
            XCTAssertEqual(admission.snapshot.reservedResponseBytes, 0)
        }
    }

    func testStorageRefusalIsTheNamedPublicRead503() async throws {
        let admission = try PublicRepositoryJSONReadAdmission()
        try await withFixture(admission: admission) { fixture, client in
            await fixture.directory.setRefusal(
                .unavailable(reason: .generationPinStale)
            )
            publicReadDiagnosticThrottle.resetForTesting()
            let baseline = publicReadDiagnosticJournalLines.withLock { $0 }
            let refused = try await self.outcome(
                client, Self.uri(rkey: "r07")
            )
            XCTAssertEqual(refused.status, .serviceUnavailable)
            XCTAssertEqual(
                refused.body, #"{"error":"temporarily_unavailable"}"#
            )
            XCTAssertEqual(admission.snapshot.activeLeases, 0)
            XCTAssertEqual(
                publicReadDiagnosticJournalLines.withLock { $0 } - baseline,
                1,
                "a proof 503 is journalled like every other public-read 503"
            )
        }
    }

    // Production mutation caught: the route trusts whichever account the
    // directory answered with, so a directory fault serves one account's
    // signed commit under another account's DID.
    func testProofForADifferentAccountIsNotServed() async throws {
        try await withFixture { fixture, client in
            await fixture.directory.setAnsweringDID(
                "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz"
            )
            let mismatched = try await self.outcome(
                client, Self.uri(rkey: "r07")
            )
            XCTAssertEqual(mismatched.status, .badRequest)
            XCTAssertEqual(mismatched.body, #"{"error":"RepoNotFound"}"#)
        }
    }

    // Production mutation caught: a conformer hands the route an unbounded
    // archive and the response budget is whatever the directory returned.
    func testProofValueRefusesAnArchiveOverTheResponseBudget() throws {
        let state = try PublicRepositoryState(
            did: Self.did,
            revision: "3jzfcijpj2z2a",
            commitCID: CID.fromDAGCBOR(Data("commit".utf8)),
            dataCID: CID.fromDAGCBOR(Data("mst".utf8))
        )
        XCTAssertThrowsError(try PublicRepositoryReadRecordProof(
            did: Self.did,
            state: state,
            recordCID: nil,
            car: Data(
                count: PublicRepositoryRecordProofLimits
                    .maximumProofCARBytes + 1
            )
        )) {
            XCTAssertEqual(
                $0 as? PublicRepositoryReadError, .resourceLimitExceeded
            )
        }
        XCTAssertThrowsError(try PublicRepositoryReadRecordProof(
            did: Self.did, state: state, recordCID: nil, car: Data()
        )) {
            XCTAssertEqual(
                ($0 as? PublicRepositoryReadError)?.unavailableReason,
                .malformedProjectionValue
            )
        }
        XCTAssertThrowsError(try PublicRepositoryReadRecordProof(
            did: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz",
            state: state,
            recordCID: nil,
            car: Data([0x01])
        )) {
            XCTAssertEqual(
                ($0 as? PublicRepositoryReadError)?.unavailableReason,
                .malformedProjectionValue
            )
        }
        XCTAssertLessThanOrEqual(
            PublicRepositoryRecordProofLimits.maximumProofCARBytes,
            PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes,
            "a proof lease must fit the smallest admission the router accepts"
        )
    }

    // MARK: - Fixture

    private struct Fixture: Sendable {
        let directory: RecordProofReadDirectory
        let state: PublicRepositoryState
        let verification: RepositoryCommitVerification
    }

    private func outcome(
        _ client: any TestClientProtocol,
        _ uri: String
    ) async throws -> (status: HTTPResponse.Status, body: String) {
        try await client.execute(uri: uri, method: .get) { response in
            (response.status, String(buffer: response.body))
        }
    }

    private func withFixture(
        surface: SwanPublicRouteSurface? = nil,
        admission: PublicRepositoryJSONReadAdmission? = nil,
        _ body: @escaping @Sendable (
            Fixture, any TestClientProtocol
        ) async throws -> Void
    ) async throws {
        let keypair = P256Keypair.generate()
        var repository = try await Repository.create(
            did: Self.did, signer: keypair
        )
        // Enough keys that the MST has more than one layer, so a proof is a
        // real root-to-leaf path and not a single node.
        let writes: [PublicRepositoryWrite] = try (0 ..< 48).map { index in
            let rkey = String(format: "r%02d", index)
            return .create(
                path: try PublicRepositoryPath(
                    collection: Self.collection, recordKey: rkey
                ),
                record: [
                    "$type": .string(Self.collection),
                    "text": .string("device-\(rkey)"),
                ]
            )
        }
        repository = try await repository.commit(writes, signer: keypair)
            .repository
        let state = try PublicRepositoryState(
            did: Self.did,
            revision: repository.commit.revision.value,
            commitCID: repository.commit.cid,
            dataCID: repository.commit.dataCID
        )
        let directory = RecordProofReadDirectory(
            repository: repository,
            description: try PublicRepositoryReadDescription(
                did: Self.did,
                canonicalHandle: Self.handle,
                status: .active,
                state: state,
                collections: [Self.collection],
                identity: try PublicRepositoryReadIdentity(
                    canonicalHandle: Self.handle,
                    pdsOrigin: "https://swan.example",
                    signingDIDKey: keypair.didKey,
                    handleIsCorrect: true,
                    preparationRequestID: "public-record-proof-http",
                    genesisOperationCID: state.commitCID.string
                )
            )
        )
        let fixture = Fixture(
            directory: directory,
            state: state,
            verification: .signingKey(keypair.publicKey)
        )

        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRecordProofHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x47, count: 32)
            )
            // The permissioned profile production runs. The public route
            // surface is selected separately, by `surface`.
            let profile = try ProtocolProfile.load(
                from: URL(fileURLWithPath: #filePath)
                    .deletingLastPathComponent()
                    .deletingLastPathComponent()
                    .deletingLastPathComponent()
                    .appending(
                        path: "Profiles/permissioned-data-0016-2026-11-12.json"
                    )
            )
            let publicURL = URL(string: "https://swan.example")!
            let configuration = surface.map {
                SwanHTTPConfiguration(
                    publicURL: publicURL, publicRouteSurface: $0
                )
            } ?? SwanHTTPConfiguration(publicURL: publicURL)
            let server = SwanHTTPServer(
                profile: profile,
                configuration: configuration,
                oauthRuntime: runtime,
                publicRepositoryReadDirectory: directory,
                jsonReadAdmission: admission
            )
            let app = server.buildApplication(
                logger: Logger(label: "PublicRecordProofHTTPTests")
            )
            try await app.test(.router) { client in
                try await body(fixture, client)
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }
}

/// A read directory over one real, signed, in-memory repository.
///
/// Proofs come from `Repository.recordProof`, so what the route serves here is
/// a proof by Petrel's own definition and the tests can verify it against the
/// signing key. Only the outcomes the proof tests compare against are live;
/// the rest of the protocol is unreachable from this suite.
private actor RecordProofReadDirectory: PublicRepositoryReadDirectory {
    private enum Unreachable: Error { case unused }

    private let repository: Repository
    private let description: PublicRepositoryReadDescription
    private var status: AccountControlStatus = .active
    private var refusal: PublicRepositoryReadError?
    private var answeringDID: String?
    private(set) var proofRequestCount = 0

    init(
        repository: Repository,
        description: PublicRepositoryReadDescription
    ) {
        self.repository = repository
        self.description = description
    }

    func setStatus(_ status: AccountControlStatus) { self.status = status }
    func setRefusal(_ refusal: PublicRepositoryReadError) {
        self.refusal = refusal
    }

    func setAnsweringDID(_ did: String) { answeringDID = did }

    private func lifecycle<Value>(
        _ selector: String,
        _ active: () async throws -> Value
    ) async throws -> PublicRepositoryReadOutcome<Value> {
        guard selector == description.did else { return .notFound }
        guard status == .active else {
            return .lifecycle(try PublicRepositoryReadStatus(
                did: description.did, status: status, revision: nil
            ))
        }
        return .active(try await active())
    }

    func publicRepositoryRecordProofOutcome(
        did: String,
        path: PublicRepositoryPath
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordProof>
    {
        try await lifecycle(did) {
            if let refusal { throw refusal }
            proofRequestCount += 1
            let proof = try await repository.recordProof(
                collection: path.collection, recordKey: path.recordKey
            )
            let answering = answeringDID ?? description.did
            return try PublicRepositoryReadRecordProof(
                did: answering,
                state: try PublicRepositoryState(
                    did: answering,
                    revision: description.state.revision,
                    commitCID: description.state.commitCID,
                    dataCID: description.state.dataCID
                ),
                recordCID: proof.recordCID,
                car: try await proof.car()
            )
        }
    }

    func publicRepositoryDescriptionOutcome(
        selector: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    {
        try await lifecycle(selector) { description }
    }

    func publicRepositoryCAROutcome(
        selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR> {
        try await lifecycle(selector) { throw Unreachable.unused }
    }

    func publicRepositoryStatus(
        selector _: String
    ) async throws -> PublicRepositoryReadStatus? { throw Unreachable.unused }

    func describePublicRepository(
        selector _: String
    ) async throws -> PublicRepositoryReadDescription? {
        throw Unreachable.unused
    }

    func publicRepositoryRecord(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadRecord? { throw Unreachable.unused }

    func listPublicRepositoryRecords(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadPage { throw Unreachable.unused }

    func publicRepositoryCAR(
        selector _: String
    ) async throws -> PublicRepositoryReadCAR? { throw Unreachable.unused }

    func publicRepositoryRecordOutcome(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    { throw Unreachable.unused }

    func publicRepositoryRecordsOutcome(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    { throw Unreachable.unused }

    func publicRepositoryBlobOutcome(
        did _: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget>
    { throw Unreachable.unused }
}
