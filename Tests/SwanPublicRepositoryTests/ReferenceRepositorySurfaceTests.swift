import Foundation
import XCTest
import Petrel
@testable import SwanPublicRepository

final class ReferenceRepositorySurfaceTests: XCTestCase {
    func testSyncEnumerationIsBoundedAndCursorStable() async throws {
        let blocks = try makeBlocks(count: 3)
        let surface = try PublicRepositoryReferenceSurface(
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            revision: "3jzfc6r5bqg2a",
            blocks: blocks,
            records: [
                .init(path: try .init(collection: "app.bsky.feed.post", recordKey: "a"), cid: blocks[0].cid),
                .init(path: try .init(collection: "app.bsky.feed.post", recordKey: "b"), cid: blocks[1].cid)
            ],
            repositories: [
                try .init(did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", head: blocks[0].cid, rev: "3jzfc6r5bqg2a"),
                try .init(did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", head: blocks[1].cid, rev: "3jzfc6r5bqg2a")
            ],
            maximumPageSize: 2
        )

        let first = try await surface.listRepos(limit: 1)
        XCTAssertEqual(first.repos.count, 1)
        XCTAssertNotNil(first.cursor)
        let second = try await surface.listRepos(limit: 1, cursor: try XCTUnwrap(first.cursor))
        XCTAssertEqual(second.repos.map(\.did), ["did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"])

        let blockPage = try await surface.getBlocks([blocks[0].cid, blocks[1].cid, blocks[2].cid], limit: 2)
        XCTAssertEqual(blockPage.blocks.count, 2)
        XCTAssertNotNil(blockPage.cursor)
        XCTAssertEqual(blockPage.missing, [])

        let records = try await surface.listRecords(collection: "app.bsky.feed.post", limit: 1, reverse: true)
        XCTAssertEqual(records.records.count, 1)
        XCTAssertNotNil(records.cursor)
    }

    func testListBlobsHonorsSinceRevisionAndUsesCIDKeysetCursor() async throws {
        let blocks = try makeBlocks(count: 3)
        let surface = try PublicRepositoryReferenceSurface(
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", revision: "3jzfc6r5bqg2a",
            blocks: blocks, records: [], blobs: blocks.map(\.cid),
            blobRevisions: [blocks[0].cid: "3jzfc6r5bqg2b", blocks[1].cid: "3jzfc6r5bqg2c", blocks[2].cid: "3jzfc6r5bqg2d"], maximumPageSize: 2
        )
        let page = try await surface.listBlobs(limit: 2, since: "3jzfc6r5bqg2a")
        XCTAssertEqual(page.blobs.count, 2)
        let next = try await surface.listBlobs(limit: 2, since: "3jzfc6r5bqg2a", cursor: try XCTUnwrap(page.cursor))
        XCTAssertEqual(next.blobs.count, 0)
    }

    func testMissingBlobListingIsPaginatedAndDoesNotMaterializeUnboundedInput() async throws {
        let cid = CID.fromDAGCBOR(Data([0xa0]))
        let surface = try PublicRepositoryReferenceSurface(
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            revision: "3jzfc6r5bqg2a",
            blocks: [], records: [], maximumPageSize: 2
        )
        let page = try await surface.listMissingBlobs([cid, cid], limit: 1)
        XCTAssertEqual(page.missing, [cid])
        XCTAssertNil(page.cursor)
    }

    func testImportVerifiesRootAndSignatureBeforeTransactionalCommit() async throws {
        let bytes = Data([0xa0])
        let root = CID.fromDAGCBOR(bytes)
        let committer = RecordingImportCommitter()
        let verifier = try PublicRepositoryReferenceImportVerifier(maximumBlocks: 2, maximumBytes: 32)
        let envelope = try PublicRepositoryImportEnvelope(
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            rootCID: root,
            blocks: [.init(cid: root, bytes: bytes)],
            signature: Data([1]), requestID: "import-1", requestDigest: Data(repeating: 7, count: 32)
        )
        _ = try await verifier.verifyAndCommit(envelope, committer: committer, existingBlobResolver: nil) { did, cid, signature in
            did == "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" && cid == root && signature == Data([1])
        }
        let committed = await committer.states
        XCTAssertEqual(committed.count, 1)
        XCTAssertEqual(committed[0].rootCID, root)
    }

    func testImportSupportsBoundedReferencedBlobPayloadAndIdempotentRetry() async throws {
        let rootBytes = Data([0xa0])
        let blobBytes = Data([0xa1, 0x61, 0x78, 0x01])
        let root = CID.fromDAGCBOR(rootBytes)
        let blob = CID.fromDAGCBOR(blobBytes)
        let committer = RecordingImportCommitter()
        let verifier = try PublicRepositoryReferenceImportVerifier(maximumBlocks: 3, maximumBytes: 64)
        let envelope = try PublicRepositoryImportEnvelope(did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", rootCID: root, blocks: [.init(cid: root, bytes: rootBytes)], referencedBlobs: [blob], blobPayloads: [.init(cid: blob, bytes: blobBytes)], signature: Data([1]), requestID: "import-2", requestDigest: Data(repeating: 8, count: 32))
        _ = try await verifier.verifyAndCommit(envelope, committer: committer) { _, _, _ in true }
        _ = try await verifier.verifyAndCommit(envelope, committer: committer) { _, _, _ in true }
        let states = await committer.states
        XCTAssertEqual(states.count, 1)
    }

    func testImportRejectsInvalidSignatureWithoutCallingCommitter() async throws {
        let bytes = Data([0xa0])
        let root = CID.fromDAGCBOR(bytes)
        let committer = RecordingImportCommitter()
        let verifier = try PublicRepositoryReferenceImportVerifier(maximumBlocks: 2, maximumBytes: 32)
        let envelope = PublicRepositoryImportEnvelope(
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
            rootCID: root,
            blocks: [.init(cid: root, bytes: bytes)],
            signature: Data([9]), requestID: "import-invalid", requestDigest: Data(repeating: 9, count: 32)
        )
        do {
            _ = try await verifier.verifyAndCommit(envelope, committer: committer) { _, _, _ in false }
            XCTFail("invalid signature unexpectedly committed")
        } catch let error as PublicRepositoryReferenceImportError {
            XCTAssertEqual(error, .invalidSignature)
        }
        let states = await committer.states
        XCTAssertEqual(states.count, 0)
    }

    func testImportRejectsUnassembledCommitterBeforeMutation() async throws {
        let bytes = Data([0xa0])
        let root = CID.fromDAGCBOR(bytes)
        let committer = RecordingImportCommitter(durable: false)
        let verifier = try PublicRepositoryReferenceImportVerifier(maximumBlocks: 2, maximumBytes: 32)
        let envelope = try PublicRepositoryImportEnvelope(did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", rootCID: root, blocks: [.init(cid: root, bytes: bytes)], signature: Data([1]), requestID: "unassembled", requestDigest: Data(repeating: 3, count: 32))
        do {
            _ = try await verifier.verifyAndCommit(envelope, committer: committer) { _, _, _ in true }
            XCTFail("unassembled committer unexpectedly accepted import")
        } catch let error as PublicRepositoryReferenceImportError {
            XCTAssertEqual(error, .unassembled)
        }
    }

    private func makeBlocks(count: Int) throws -> [PublicRepositoryBlock] {
        try (0..<count).map { index in
            let data = Data([0xa1, 0x61, 0x69, UInt8(index)])
            let cid = CID.fromDAGCBOR(data)
            return PublicRepositoryBlock(cid: cid, bytes: data)
        }
    }
}

private actor RecordingImportCommitter: PublicRepositoryImportCommitter {
    let isDurableTransactional: Bool
    init(durable: Bool = true) { isDurableTransactional = durable }
    var states: [PublicRepositoryImportedState] = []
    private var requests: [String: Data] = [:]
    func commit(_ state: PublicRepositoryImportedState, requestID: String, requestDigest: Data, expectedRootCID: CID?) async throws -> PublicRepositoryImportedState {
        if let existing = requests[requestID] {
            guard existing == requestDigest else { throw PublicRepositoryReferenceImportError.conflictingRequestReuse }
            return states[0]
        }
        requests[requestID] = requestDigest
        states.append(state)
        return state
    }
}
