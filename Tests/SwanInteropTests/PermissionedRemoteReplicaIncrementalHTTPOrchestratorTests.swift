import Crypto
import Foundation
import Petrel
import PetrelCrypto
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

    func testEachPageUsesFreshAuthenticatedCommit() async throws {
        let fixture = try HTTPIncrementalFixture()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let first = try encoder.encode(
            ComAtprotoSpaceListRepoOps.Output(
                ops: [fixture.operation],
                commit: fixture.commit,
                cursor: "\(fixture.revision.toString())/0"
            )
        )
        let terminal = try encoder.encode(
            ComAtprotoSpaceListRepoOps.Output(
                ops: [],
                commit: fixture.commit,
                cursor: nil
            )
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBodies: [first, terminal],
            latestBody: try fixture.latestBody(commit: fixture.commit)
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let outcome = try await fixture.orchestrator(
            transport: transport,
            store: store
        ).synchronize(
            target: fixture.target,
            requestID: "paged",
            requestSequence: 1,
            appliedAt: 1
        )
        guard case .applied = outcome else {
            return XCTFail("expected paged apply, got \(outcome)")
        }
        let paths = await transport.paths()
        XCTAssertEqual(paths, [
            "/xrpc/com.atproto.space.listRepoOps",
            "/xrpc/com.atproto.space.listRepoOps",
            "/xrpc/com.atproto.space.getLatestCommit",
        ])
        let keyIDs = await transport.keyIDs()
        XCTAssertEqual(Set(keyIDs).count, 3)
    }

    func testExtendedAuthenticatedPageSelectsFullRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        let output = ComAtprotoSpaceListRepoOps.Output(
            ops: Array(repeating: fixture.operation, count: 1_500),
            commit: fixture.commit,
            cursor: "\(fixture.revision.toString())/1499"
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try JSONEncoder().encode(output),
            latestBody: Data()
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let result = try await fixture.orchestrator(
            transport: transport,
            store: store
        ).synchronize(
            target: fixture.target,
            requestID: "extended-page",
            requestSequence: 1,
            appliedAt: 1
        )
        XCTAssertEqual(result, .fullCARRecoveryRequired)
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
    }

    func testAuthenticatedIntervalOverAggregateValueBudgetSelectsFullRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        var hash = LtHash()
        let operations = try ["a", "b"].map { suffix in
            let value = ATProtocolValueContainer.object(["text": .string(String(repeating: suffix, count: 600 * 1_024))])
            let cid = try CID.fromDAGCBOR(DAGCBOR.encodeValue(value.toCBORValue()))
            let rkey = "large-\(suffix)"
            hash.add(element: "app.bsky.feed.post/\(rkey)/\(cid.string)")
            return ComAtprotoSpaceListRepoOps.OpEntry(rev: fixture.revision, collection: fixture.operation.collection,
                rkey: try RecordKey(keyString: rkey), cid: cid, prev: nil, value: value)
        }
        let commit = ComAtprotoSpaceDefs.Commit(ver: 1, repo: fixture.commit.repo, space: fixture.commit.space,
            rev: fixture.revision, data: Bytes(data: hash.commitment))
        let body = try JSONEncoder().encode(ComAtprotoSpaceListRepoOps.Output(ops: operations, commit: commit, cursor: nil))
        XCTAssertGreaterThan(body.count, 1_024 * 1_024)
        XCTAssertLessThan(body.count, 2 * 1_024 * 1_024)
        let transport = IncrementalTransport(listStatus: 200, listBody: body, latestBody: try fixture.latestBody(commit: commit))
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(transport: transport, store: store)
        let result = try await orchestrator.synchronize(target: fixture.target, requestID: "large-verified-interval", requestSequence: 1, appliedAt: 1)
        XCTAssertEqual(result, .fullCARRecoveryRequired)
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, ["/xrpc/com.atproto.space.listRepoOps", "/xrpc/com.atproto.space.getLatestCommit"])
    }

    func testMalformedContinuationAndTerminalCursorFailBeforePublication() async throws {
        let fixture = try HTTPIncrementalFixture()
        for (cursor, terminal) in [("malformed", false), ("\(fixture.revision.toString())/-1", false), ("222222222222a/999", false), ("\(fixture.revision.toString())/0", true)] {
            let output = ComAtprotoSpaceListRepoOps.Output(
                ops: Array(repeating: fixture.operation, count: terminal ? 1 : 1_000),
                commit: fixture.commit, cursor: cursor
            )
            let transport = IncrementalTransport(listStatus: 200, listBody: try JSONEncoder().encode(output), latestBody: Data())
            let store = CapturingIncrementalStore(base: fixture.base)
            let orchestrator = try fixture.orchestrator(transport: transport, store: store)
            do {
                _ = try await orchestrator.synchronize(target: fixture.target, requestID: "bad-cursor", requestSequence: 1, appliedAt: 1)
                XCTFail("invalid cursor accepted")
            } catch {
                XCTAssertEqual(
                    error as? PermissionedRemoteReplicaIncrementalVerificationError,
                    .invalidOperation
                )
            }
            let batch = await store.capturedBatch()
            XCTAssertNil(batch)
        }
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
                commit: fixture.commit,
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

    // MARK: - Truncated oplog (clearRecords / importRepo)

    func testEmptyPageAtCheckpointHeadIsUnchanged() async throws {
        let fixture = try HTTPIncrementalFixture()
        let head = try fixture.commit(
            revision: fixture.base.head.wireRevision,
            commitment: fixture.base.head.commitment
        )
        let (outcome, store, transport) = try await fixture.synchronizeEmpty(
            page: head, latest: head
        )
        XCTAssertEqual(outcome, .unchanged(fixture.base.head))
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, [
            "/xrpc/com.atproto.space.listRepoOps",
            "/xrpc/com.atproto.space.getLatestCommit",
        ])
    }

    /// Upstream `clearRecords` truncates the oplog, changes the data digest
    /// and advances the rev, so `listRepoOps` returns no ops under a newer
    /// authenticated head.
    func testClearedRepositoryWithNoOpsSelectsFullRecoveryWithoutApply() async throws {
        let fixture = try HTTPIncrementalFixture()
        let cleared = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.otherCommitment
        )
        XCTAssertNotEqual(cleared.data.data, fixture.base.head.commitment)
        let (outcome, store, transport) = try await fixture.synchronizeEmpty(
            page: cleared, latest: cleared
        )
        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
        let paths = await transport.paths()
        XCTAssertEqual(paths, [
            "/xrpc/com.atproto.space.listRepoOps",
            "/xrpc/com.atproto.space.getLatestCommit",
        ])
    }

    /// Upstream `importRepo` truncates the oplog and advances the rev over
    /// unchanged data. The durable batch requires operations, so the safe
    /// choice is full recovery rather than an in-place head advance.
    func testRevisionOnlyAdvanceWithNoOpsSelectsFullRecoveryWithoutApply() async throws {
        let fixture = try HTTPIncrementalFixture()
        let imported = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.base.head.commitment
        )
        let (outcome, store, _) = try await fixture.synchronizeEmpty(
            page: imported, latest: imported
        )
        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
    }

    func testEmptyPageWithOlderOrEqualRevisionAndDifferentDataStillThrows() async throws {
        let fixture = try HTTPIncrementalFixture()
        let older = try TID(tidString: "2222222222227")
        XCTAssertLessThan(older, fixture.base.head.wireRevision)
        for revision in [older, fixture.base.head.wireRevision] {
            for commitment in [fixture.otherCommitment, fixture.base.head.commitment]
                where !(revision == fixture.base.head.wireRevision
                    && commitment == fixture.base.head.commitment) {
                let stale = try fixture.commit(
                    revision: revision, commitment: commitment
                )
                do {
                    let (outcome, _, _) = try await fixture.synchronizeEmpty(
                        page: stale, latest: stale
                    )
                    XCTFail("stale head accepted: \(outcome)")
                } catch let error
                    as PermissionedRemoteReplicaIncrementalVerificationError {
                    XCTAssertEqual(error, .mixedHead)
                }
            }
        }
    }

    func testEmptyNewerPageWithMixedLatestHeadStillThrows() async throws {
        let fixture = try HTTPIncrementalFixture()
        let cleared = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.otherCommitment
        )
        let later = try fixture.commit(
            revision: try TID(tidString: "222222222222c"),
            commitment: fixture.otherCommitment
        )
        do {
            let (outcome, _, _) = try await fixture.synchronizeEmpty(
                page: cleared, latest: later
            )
            XCTFail("mixed head accepted: \(outcome)")
        } catch let error as PermissionedRemoteReplicaIncrementalVerificationError {
            XCTAssertEqual(error, .mixedHead)
        }
    }

    func testTamperedMACOnEmptyNewerPageCannotForceFullRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        let cleared = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.otherCommitment
        )
        do {
            let (outcome, _, _) = try await fixture.synchronizeEmpty(
                page: cleared, latest: cleared, tamperListMAC: true
            )
            XCTFail("tampered MAC accepted: \(outcome)")
        } catch is PermissionedRemoteReplicaIncrementalVerificationError {
            XCTFail("tampered MAC reached the verifier")
        } catch {
            // Rejected by the MAC transport before any head is trusted.
        }
    }

    /// Writes after a clear reach the oplog but the bridging deletes do not,
    /// so the replayed LtHash cannot match the authenticated digest.
    func testAuthenticatedNonEmptyPageWithLtHashMismatchSelectsFullRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        let terminal = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.otherCommitment
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try fixture.listBody(ops: [fixture.operation], commit: terminal),
            latestBody: try fixture.latestBody(commit: terminal)
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(transport: transport, store: store)
        let outcome = try await orchestrator.synchronize(
            target: fixture.target, requestID: "post-clear-writes",
            requestSequence: 1, appliedAt: 1
        )
        XCTAssertEqual(outcome, .fullCARRecoveryRequired)
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
    }

    func testLtHashMismatchWithMixedLatestHeadStillThrows() async throws {
        let fixture = try HTTPIncrementalFixture()
        let terminal = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.otherCommitment
        )
        let later = try fixture.commit(
            revision: try TID(tidString: "222222222222c"),
            commitment: fixture.otherCommitment
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try fixture.listBody(ops: [fixture.operation], commit: terminal),
            latestBody: try fixture.latestBody(commit: later)
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(transport: transport, store: store)
        do {
            _ = try await orchestrator.synchronize(
                target: fixture.target, requestID: "post-clear-mixed",
                requestSequence: 1, appliedAt: 1
            )
            XCTFail("mixed head selected recovery")
        } catch let error as PermissionedRemoteReplicaIncrementalVerificationError {
            XCTAssertEqual(error, .mixedHead)
        }
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
    }

    func testTamperedMACOnLtHashMismatchPageCannotForceFullRecovery() async throws {
        let fixture = try HTTPIncrementalFixture()
        let terminal = try fixture.commit(
            revision: fixture.revision,
            commitment: fixture.otherCommitment
        )
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try fixture.listBody(ops: [fixture.operation], commit: terminal),
            latestBody: try fixture.latestBody(commit: terminal),
            tamperListMAC: true
        )
        let store = CapturingIncrementalStore(base: fixture.base)
        let orchestrator = try fixture.orchestrator(transport: transport, store: store)
        do {
            let outcome = try await orchestrator.synchronize(
                target: fixture.target, requestID: "post-clear-tampered",
                requestSequence: 1, appliedAt: 1
            )
            XCTFail("tampered MAC accepted: \(outcome)")
        } catch is PermissionedRemoteReplicaIncrementalVerificationError {
            XCTFail("tampered MAC reached the verifier")
        } catch {
            // Rejected by the MAC transport before any head is trusted.
        }
        let batch = await store.capturedBatch()
        XCTAssertNil(batch)
        let paths = await transport.paths()
        XCTAssertFalse(paths.contains("/xrpc/com.atproto.space.getLatestCommit"))
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
    let commit: ComAtprotoSpaceDefs.Commit
    let key: P256.KeyAgreement.PrivateKey
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
        key = try Self.kemKey()
        commit = .init(
            ver: 1, repo: try DID(didString: repository), space: try SpaceRef(uriString: space.rawValue),
            rev: revision, data: Bytes(data: hash.commitment)
        )
    }

    static func kemKey() throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
    }

    func signedCommit(revision: TID) throws -> ComAtprotoSpaceDefs.Commit {
        .init(ver: 1, repo: try DID(didString: target.repositoryDID),
              space: try SpaceRef(uriString: target.space.rawValue), rev: revision, data: Bytes(data: finalHash.commitment))
    }

    func listBody() throws -> Data {
        try listBody(ops: [operation], commit: commit)
    }

    func listBody(
        ops: [ComAtprotoSpaceListRepoOps.OpEntry],
        commit: ComAtprotoSpaceDefs.Commit
    ) throws -> Data {
        try encoder.encode(ComAtprotoSpaceListRepoOps.Output(
            ops: ops, commit: commit, cursor: nil
        ))
    }

    /// A digest that neither the empty checkpoint nor the fixture interval
    /// produces.
    var otherCommitment: Data {
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/unrelated/bafyunrelated")
        return hash.commitment
    }

    func commit(revision: TID, commitment: Data) throws -> ComAtprotoSpaceDefs.Commit {
        .init(ver: 1, repo: try DID(didString: target.repositoryDID),
              space: try SpaceRef(uriString: target.space.rawValue), rev: revision, data: Bytes(data: commitment))
    }

    func synchronizeEmpty(
        page: ComAtprotoSpaceDefs.Commit,
        latest: ComAtprotoSpaceDefs.Commit,
        tamperListMAC: Bool = false
    ) async throws -> (
        PermissionedRemoteReplicaIncrementalSyncOutcome,
        CapturingIncrementalStore,
        IncrementalTransport
    ) {
        let transport = IncrementalTransport(
            listStatus: 200,
            listBody: try listBody(ops: [], commit: page),
            latestBody: try latestBody(commit: latest),
            tamperListMAC: tamperListMAC
        )
        let store = CapturingIncrementalStore(base: base)
        let outcome = try await orchestrator(transport: transport, store: store)
            .synchronize(target: target, requestID: "empty-page", requestSequence: 1, appliedAt: 1)
        return (outcome, store, transport)
    }

    func latestBody(
        commit: ComAtprotoSpaceDefs.Commit
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
                permissionedKEMKey: try P256DIDKey(publicKey: P256.Signing.PublicKey(compressedRepresentation: key.publicKey.compressedRepresentation)).value
            ),
            store: store
        )
    }

    private var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
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
    let listBodies: [Data]
    let latestBody: Data
    let tamperListMAC: Bool
    private var listIndex = 0
    private var requestedPaths: [String] = []
    private var requestedURLs: [URL] = []
    private var requestedKeyIDs: [String] = []

    init(
        listStatus: Int,
        listBody: Data,
        latestBody: Data,
        tamperListMAC: Bool = false
    ) {
        self.listStatus = listStatus
        listBodies = [listBody]
        self.latestBody = latestBody
        self.tamperListMAC = tamperListMAC
    }

    init(
        listStatus: Int,
        listBodies: [Data],
        latestBody: Data,
        tamperListMAC: Bool = false
    ) {
        self.listStatus = listStatus
        self.listBodies = listBodies
        self.latestBody = latestBody
        self.tamperListMAC = tamperListMAC
    }

    func execute(
        method: InteropHTTPMethod,
        url: URL,
        headers: [String: String],
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
            guard !listBodies.isEmpty else {
                throw InteropHTTPError.transportFailure
            }
            body = listBodies[min(listIndex, listBodies.count - 1)]
            listIndex += 1
        case "/xrpc/com.atproto.space.getLatestCommit":
            status = 200
            body = latestBody
        default:
            throw InteropHTTPError.unexpectedStatus(404)
        }
        guard body.count <= limit else {
            throw InteropHTTPError.responseTooLarge
        }
        guard let request = try SpaceMACHeaders.parseRequest(
            headers[SpaceMACHeaders.requestHeader],
            profile: .commit
        ) else {
            throw SpaceMACHeaders.HeaderError.invalidSpaceMAC
        }
        requestedKeyIDs.append(request.keyID)
        var responseHeaders = ["content-type": "application/json"]
        if status == 200 {
            let commit: ComAtprotoSpaceDefs.Commit
            if url.path.hasSuffix("getLatestCommit") {
                commit = try JSONDecoder().decode(
                    ComAtprotoSpaceGetLatestCommit.Output.self,
                    from: body
                ).commit
            } else {
                commit = try JSONDecoder().decode(
                    ComAtprotoSpaceListRepoOps.Output.self,
                    from: body
                ).commit
            }
            let secret = try SpaceMACKeyAgreement.receive(
                authorPrivateKey: HTTPIncrementalFixture.kemKey(),
                keyID: request.keyID
            )
            let value = try SpaceRepositoryCommit(
                ver: commit.ver,
                repo: commit.repo.didString(),
                space: SpaceURI(commit.space.uriString()),
                rev: commit.rev.toString(),
                data: commit.data.data
            )
            let mac = try SpaceMACHeaders.commitResponse(
                value,
                request: request,
                sharedSecret: tamperListMAC
                    && url.path.hasSuffix("listRepoOps")
                    ? Data(repeating: 0, count: 32)
                    : secret
            )
            responseHeaders[mac.coveredHeaderName] = mac.coveredHeaderValue
            responseHeaders[SpaceMACHeaders.signatureInputHeader] =
                mac.signatureInput
            responseHeaders[SpaceMACHeaders.signatureHeader] = mac.signature
        }
        return .init(
            status: status,
            headers: responseHeaders,
            body: body,
            finalURL: url,
            redirectCount: 0
        )
    }

    func paths() -> [String] { requestedPaths }
    func urls() -> [URL] { requestedURLs }
    func keyIDs() -> [String] { requestedKeyIDs }
}
