import Crypto
import Foundation
import Petrel
@testable import SwanInterop
import SwanOAuth
import SwanSpaces
import SwanStorage
import XCTest

final class PermissionedRemoteReplicaIncrementalHTTPOrchestratorTests:
    XCTestCase
{
    func testFetchesAuthenticatesLatestHeadAndAppliesVerifiedBatch() async throws {
        let fixture = try HTTPIncrementalFixture()
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try fixture.listBody(),
            latestBody: try fixture.latestBody(commit: fixture.commit)
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        let outcome = try await orchestrator.synchronize(
            target: fixture.target,
            requestID: "incremental-1",
            requestSequence: 1,
            appliedAt: 1_750_000_000_000_000
        )
        guard case let .applied(result) = outcome else {
            return XCTFail("expected applied, got \(outcome)")
        }
        XCTAssertEqual(result.head.wireRevision, fixture.revision)
        let capturedBatch = await store.capturedBatch()
        let batch = try XCTUnwrap(capturedBatch)
        XCTAssertEqual(batch.operations.count, 1)
        XCTAssertEqual(batch.operations[0].value, fixture.valueBytes)
        XCTAssertEqual(batch.requestSequence, 1)
        let paths = await transport.paths()
        XCTAssertEqual(paths, [
            "/xrpc/com.atproto.space.listRepoOps",
            "/xrpc/com.atproto.space.getLatestCommit",
        ])
        let requestedURLs = await transport.urls()
        let listItems = try XCTUnwrap(
            URLComponents(url: requestedURLs[0], resolvingAgainstBaseURL: false)?
                .queryItems
        )
        XCTAssertEqual(
            listItems.first(where: { $0.name == "limit" })?.value,
            "1000"
        )
    }

    func testMixedLatestHeadFailsBeforeDurableApply() async throws {
        let fixture = try HTTPIncrementalFixture()
        let later = try fixture.signedCommit(
            revision: try TID(tidString: "222222222222c")
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try fixture.listBody(),
            latestBody: try fixture.latestBody(commit: later)
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        do {
            _ = try await orchestrator.synchronize(
                target: fixture.target,
                requestID: "mixed-head",
                requestSequence: 1,
                appliedAt: 1
            )
            XCTFail("mixed head was accepted")
        } catch let error as PermissionedRemoteReplicaIncrementalVerificationError {
            XCTAssertEqual(error, .mixedHead)
        }
        let capturedBatch = await store.capturedBatch()
        XCTAssertNil(capturedBatch)
    }

    func testRetentionGapSelectsFullCARWithoutLatestOrApply() async throws {
        let fixture = try HTTPIncrementalFixture()
        let transport = IncrementalTransport(
            listStatus: 409,
            listBody: Data(
                "{\"error\":\"full_repo_recovery_required\"}".utf8
            ),
            latestBody: Data()
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        let outcome = try await orchestrator.synchronize(
            target: fixture.target,
            requestID: "gap",
            requestSequence: 1,
            appliedAt: 1
        )
        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let capturedBatch = await store.capturedBatch()
        XCTAssertNil(capturedBatch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, ["/xrpc/com.atproto.space.listRepoOps"])
    }

    func testUnrelatedConflictCannotForceFullCARRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        let transport = IncrementalTransport(
            listStatus: 409,
            listBody: Data("{\"error\":\"conflicting_replay\"}".utf8),
            latestBody: Data()
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        do {
            _ = try await orchestrator.synchronize(
                target: fixture.target,
                requestID: "unrelated-conflict",
                requestSequence: 1,
                appliedAt: 1
            )
            XCTFail("unrelated conflict selected full CAR recovery")
        } catch let error as InteropHTTPError {
            XCTAssertEqual(error, .unexpectedStatus(409))
        }
        let capturedBatch = await store.capturedBatch()
        XCTAssertNil(capturedBatch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, ["/xrpc/com.atproto.space.listRepoOps"])
    }

    func testFullCommitlessPageSelectsFullCARWithoutSkippingAtomicRevision() async throws {
        let fixture = try HTTPIncrementalFixture()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let fullPage = try encoder.encode(
            ComAtprotoSpaceListRepoOps.Output(
                ops: Array(repeating: fixture.operation, count: 1_000),
                commit: nil,
                cursor: nil
            )
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: fullPage,
            latestBody: Data()
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        let outcome = try await orchestrator.synchronize(
            target: fixture.target,
            requestID: "split-atomic-revision",
            requestSequence: 1,
            appliedAt: 1
        )

        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let capturedBatch = await store.capturedBatch()
        XCTAssertNil(capturedBatch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, ["/xrpc/com.atproto.space.listRepoOps"])
    }

    func testValidIncrementalPageBeyondJSONClientLimitSelectsFullCARRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        let largeValue: ATProtocolValueContainer = .object([
            "text": .string(String(repeating: "v", count: 2_100)),
        ])
        let operation = ComAtprotoSpaceListRepoOps.OpEntry(
            rev: fixture.operation.rev,
            collection: fixture.operation.collection,
            rkey: fixture.operation.rkey,
            cid: fixture.operation.cid,
            prev: fixture.operation.prev,
            value: largeValue
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let fullPage = try encoder.encode(
            ComAtprotoSpaceListRepoOps.Output(
                ops: Array(repeating: operation, count: 1_000),
                commit: nil,
                cursor: nil
            )
        )
        XCTAssertGreaterThan(fullPage.count, 2 * 1_024 * 1_024)

        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: fullPage,
            latestBody: Data()
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        let outcome = try await orchestrator.synchronize(
            target: fixture.target,
            requestID: "oversized-incremental-page",
            requestSequence: 1,
            appliedAt: 1
        )

        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let capturedBatch = await store.capturedBatch()
        let paths = await transport.paths()
        XCTAssertNil(capturedBatch)
        XCTAssertEqual(paths, ["/xrpc/com.atproto.space.listRepoOps"])
    }

    func testSupersededValueLessMutationSelectsFullCARWithoutApply() async throws {
        let fixture = try HTTPIncrementalFixture()
        let valueLess = ComAtprotoSpaceListRepoOps.OpEntry(
            rev: fixture.operation.rev,
            collection: fixture.operation.collection,
            rkey: fixture.operation.rkey,
            cid: fixture.operation.cid,
            prev: fixture.operation.prev,
            value: nil
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let body = try encoder.encode(
            ComAtprotoSpaceListRepoOps.Output(
                ops: [valueLess],
                commit: fixture.commit,
                cursor: nil
            )
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: body,
            latestBody: Data()
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(
            transport: transport,
            store: store
        )

        let outcome = try await orchestrator.synchronize(
            target: fixture.target,
            requestID: "superseded-value",
            requestSequence: 1,
            appliedAt: 1
        )

        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let capturedBatch = await store.capturedBatch()
        XCTAssertNil(capturedBatch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, ["/xrpc/com.atproto.space.listRepoOps"])
    }

    func testPublicationAuthorizationFailurePreventsDurableApply() async throws {
        let fixture = try HTTPIncrementalFixture()
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try fixture.listBody(),
            latestBody: try fixture.latestBody(commit: fixture.commit)
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let base = try fixture.orchestrator(
            transport: transport,
            store: store
        )
        let orchestrator = PermissionedRemoteReplicaIncrementalHTTPOrchestrator(
            source: base.source,
            store: store,
            publicationAuthorization: { _ in
                throw IncrementalPublicationTestError.accountInactive
            }
        )

        do {
            _ = try await orchestrator.synchronize(
                target: fixture.target,
                requestID: "inactive-before-publish",
                requestSequence: 1,
                appliedAt: 1
            )
            XCTFail("inactive account published an incremental batch")
        } catch let error as IncrementalPublicationTestError {
            XCTAssertEqual(error, .accountInactive)
        }
        let capturedBatch = await store.capturedBatch()
        XCTAssertNil(capturedBatch)
    }
}

private enum IncrementalPublicationTestError: Error, Equatable {
    case accountInactive
}

private struct HTTPIncrementalFixture {
    let target: PermissionedRemoteReplicaTarget
    let base: PermissionedRemoteReplicaIncrementalBaseState
    let operation: ComAtprotoSpaceListRepoOps.OpEntry
    let commit: ComAtprotoSpaceDefs.SignedCommit
    let key: P256.Signing.PrivateKey
    let revision: TID
    let valueBytes: Data
    private let finalHash: LtHash

    init() throws {
        let receiver = "did:plc:receiverabcdefghijkl"
        let repository = "did:plc:repositoryabcdefghij"
        let space = try SpaceURI(
            authority: repository,
            spaceType: "app.bsky.bookmarks",
            skey: "http-sync"
        )
        target = try .init(
            receiverDID: receiver,
            space: space,
            repositoryDID: repository
        )
        let initial = try TID(tidString: "222222222222a")
        revision = try TID(tidString: "222222222222b")
        let empty = LtHash()
        base = try .init(
            head: try .init(
                target: target,
                generation: 1,
                wireRevision: initial,
                historyFloorWireRevision: initial,
                ltHash: empty.serialized,
                commitment: empty.commitment,
                stateMarker: Data(repeating: 0x22, count: 32)
            ),
            recordCount: 0
        )
        let value: ATProtocolValueContainer = .object([
            "text": .string("network-value"),
        ])
        valueBytes = try DAGCBOR.encodeValue(value.toCBORValue())
        let cid = CID.fromDAGCBOR(valueBytes)
        operation = .init(
            rev: revision,
            collection: try NSID(nsidString: "app.bsky.feed.post"),
            rkey: try RecordKey(keyString: "one"),
            cid: cid,
            prev: nil,
            value: value
        )
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/one/\(cid.string)")
        finalHash = hash
        key = P256.Signing.PrivateKey()
        commit = try Self.wireCommit(
            try SpaceCommitCodec.sign(
                context: try .init(
                    space: space,
                    author: repository,
                    rev: revision.toString(),
                    ikm: Data(repeating: 0x44, count: 32)
                ),
                commitment: hash.commitment,
                key: key
            )
        )
    }

    func signedCommit(revision: TID) throws -> ComAtprotoSpaceDefs.SignedCommit {
        try Self.wireCommit(SpaceCommitCodec.sign(
            context: try .init(
                space: target.space,
                author: target.repositoryDID,
                rev: revision.toString(),
                ikm: Data(repeating: 0x55, count: 32)
            ),
            commitment: finalHash.commitment,
            key: key
        ))
    }

    func listBody() throws -> Data {
        try encoder.encode(ComAtprotoSpaceListRepoOps.Output(
            ops: [operation], commit: commit, cursor: nil
        ))
    }

    func latestBody(
        commit: ComAtprotoSpaceDefs.SignedCommit
    ) throws -> Data {
        try encoder.encode(ComAtprotoSpaceGetLatestCommit.Output(commit: commit))
    }

    func orchestrator(
        transport: IncrementalTransport,
        store: CapturingIncrementalStore
    ) throws -> PermissionedRemoteReplicaIncrementalHTTPOrchestrator {
        let http = try InteropHTTPClient(
            baseURL: URL(string: "https://source.test")!,
            timeout: 1,
            executeHandler: { method, url, headers, body, limit in
                try await transport.execute(
                    method: method,
                    url: url,
                    headers: headers,
                    body: body,
                    limit: limit
                )
            }
        )
        return .init(
            source: LiveInteropHost(
                label: "source",
                client: .init(http: http),
                authorization: .bearer(token: "test-only"),
                permissionedCommitVerificationKey: .p256(key.publicKey)
            ),
            store: store
        )
    }

    private var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func wireCommit(
        _ envelope: SpaceCommitEnvelope
    ) throws -> ComAtprotoSpaceDefs.SignedCommit {
        .init(
            ver: envelope.ver,
            hash: Bytes(data: envelope.commitment),
            ikm: Bytes(data: envelope.context.ikm),
            sig: Bytes(data: envelope.contextSignature),
            mac: Bytes(data: envelope.contentBinding),
            rev: try TID(tidString: envelope.context.rev)
        )
    }
}

private actor CapturingIncrementalStore:
    PermissionedRemoteReplicaIncrementalStore
{
    let base: PermissionedRemoteReplicaIncrementalBaseState?
    private var batch: PermissionedRemoteReplicaIncrementalBatch?

    init(base: PermissionedRemoteReplicaIncrementalBaseState?) {
        self.base = base
    }

    func permissionedRemoteReplicaIncrementalBaseState(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaIncrementalBaseState? {
        guard base?.head.target == target else { return nil }
        return base
    }

    func applyVerifiedPermissionedRemoteReplicaBatch(
        _ batch: PermissionedRemoteReplicaIncrementalBatch,
        appliedAt: Int64
    ) async throws -> PermissionedRemoteReplicaIncrementalApplyOutcome {
        self.batch = batch
        let head = try PermissionedRemoteReplicaHead(
            target: batch.target,
            generation: batch.expectedHead.generation,
            wireRevision: batch.terminalHead.wireRevision,
            historyFloorWireRevision:
                batch.expectedHead.historyFloorWireRevision,
            ltHash: batch.terminalHead.ltHash,
            commitment: batch.terminalHead.commitment,
            stateMarker: Data(repeating: 0x77, count: 32)
        )
        return .applied(.init(
            requestID: batch.requestID,
            requestSequence: batch.requestSequence,
            requestDigest: batch.requestDigest,
            head: head,
            recordCount: batch.terminalHead.recordCount,
            appliedAt: appliedAt
        ))
    }

    func capturedBatch() -> PermissionedRemoteReplicaIncrementalBatch? { batch }
}

private actor IncrementalTransport {
    let listStatus: Int
    let listBody: Data
    let latestBody: Data
    private var requestedPaths: [String] = []
    private var requestedURLs: [URL] = []

    init(listStatus: Int, listBody: Data, latestBody: Data) {
        self.listStatus = listStatus
        self.listBody = listBody
        self.latestBody = latestBody
    }

    func execute(
        method: InteropHTTPMethod,
        url: URL,
        headers _: [String: String],
        body _: Data?,
        limit: Int
    ) throws -> InteropHTTPResponse {
        guard method == .get else {
            throw InteropHTTPError.unexpectedStatus(405)
        }
        requestedPaths.append(url.path)
        requestedURLs.append(url)
        let status: Int
        let body: Data
        switch url.path {
        case "/xrpc/com.atproto.space.listRepoOps":
            status = listStatus
            body = listBody
        case "/xrpc/com.atproto.space.getLatestCommit":
            status = 200
            body = latestBody
        default:
            throw InteropHTTPError.unexpectedStatus(404)
        }
        guard body.count <= limit else { throw InteropHTTPError.responseTooLarge }
        return .init(
            status: status,
            headers: ["content-type": "application/json"],
            body: body,
            finalURL: url,
            redirectCount: 0
        )
    }

    func paths() -> [String] { requestedPaths }
    func urls() -> [URL] { requestedURLs }
}
