import Crypto
import Foundation
import Petrel
import XCTest
@testable import SwanSpaces

final class StreamingSpaceCARRecoveryRecordSinkTests: XCTestCase {
    func testVerifiedRecordIsDeliveredInBoundedChunksAndCompletesOnce()
        async throws
    {
        let author = "did:plc:remote-writer"
        let space = try SpaceURI(
            authority: "did:plc:space-authority",
            spaceType: "app.swan.private",
            skey: "sink-test"
        )
        let collection = "app.bsky.feed.post"
        let rkey = "large"
        let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "payload", value: Data(repeating: 0x61, count: 96 * 1_024)),
        ]))
        let cid = CID.fromDAGCBOR(value)
        let record = SpaceRecord(
            uri: try SpaceRecordURI(
                space: space,
                author: author,
                collection: collection,
                rkey: rkey
            ),
            value: value,
            cid: cid.string,
            revision: 1
        )
        var ltHash = LtHash()
        ltHash.add(element: "\(collection)/\(rkey)/\(cid.string)")
        let signingKey = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: author,
                rev: "222222222222a",
                ikm: Data(repeating: 0x41, count: 32)
            ),
            commitment: ltHash.commitment,
            key: signingKey
        )
        let car = try SpaceCARCodec.encode(
            commit: commit,
            records: [record]
        )
        let sink = RecordingRecoverySink()
        let summary = try await SpaceCARCodec.verifyStreamingRecovery(
            from: RecoveryDataSource(car.data),
            space: space,
            author: author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature(
                    $0,
                    publicKey: signingKey.publicKey
                )
            },
            index: RecoveryIndex(),
            recordSink: sink,
            limits: try SpaceCARRecoveryLimits(
                maximumCARBytes: car.data.count
            )
        )

        let observation = await sink.observation
        XCTAssertEqual(observation.commitRoot, summary.commitRootCID)
        XCTAssertEqual(observation.indexRoot, summary.indexRootCID)
        XCTAssertEqual(observation.completedCIDs, [cid])
        XCTAssertEqual(observation.bodyBytes, value.count)
        XCTAssertEqual(
            observation.chunkIndices,
            Array(observation.chunkSizes.indices)
        )
        XCTAssertEqual(observation.completedChunkCount, observation.chunkSizes.count)
        XCTAssertTrue(observation.chunkSizes.allSatisfy {
            $0 > 0 && $0 <= SpaceCARRecoveryLimits.maximumChunkBytes
        })
        XCTAssertEqual(observation.chunkSizes.reduce(0, +), value.count)
        XCTAssertEqual(summary.uniqueBlockCount, 1)
        XCTAssertEqual(summary.receivedByteCount, car.data.count)
    }
}

private actor RecoveryDataSource: SpaceCARRecoveryByteSource {
    private let data: Data
    private var offset = 0

    init(_ data: Data) {
        self.data = data
    }

    func read(maximumBytes: Int) -> Data? {
        guard offset < data.count else { return nil }
        let end = min(data.count, offset + min(maximumBytes, 7 * 1_024))
        defer { offset = end }
        return Data(data[offset ..< end])
    }
}

private actor RecoveryIndex: SpaceCARRecoveryIndex {
    private var entries: [SpaceCARRecoveryIndexEntry] = []
    private var consumed = Set<String>()

    func insert(_ entry: SpaceCARRecoveryIndexEntry) throws {
        guard !entries.contains(where: { $0.path == entry.path }) else {
            throw SpaceCARStreamingError.duplicateIndexEntry
        }
        entries.append(entry)
    }

    func nextUnconsumedCanonicalEntry()
        -> SpaceCARRecoveryIndexEntry?
    {
        entries
            .filter { !consumed.contains($0.path) }
            .sorted { SpaceCARCodec.canonicalRecordPathPrecedes($0.path, $1.path) }
            .first
    }

    func hasConsumedCID(_ cid: CID) -> Bool {
        entries.contains { $0.cid == cid && consumed.contains($0.path) }
    }

    func consumeEntry(_ entry: SpaceCARRecoveryIndexEntry) throws {
        guard nextUnconsumedCanonicalEntry() == entry,
              consumed.insert(entry.path).inserted else {
            throw SpaceCARStreamingError.invalidRecordOrder
        }
    }

}

private actor RecordingRecoverySink: SpaceCARRecoveryRecordSink {
    struct Observation: Sendable {
        var commitRoot: CID?
        var indexRoot: CID?
        var chunkSizes: [Int] = []
        var chunkIndices: [Int] = []
        var completedCIDs: [CID] = []
        var completedChunkCount = 0
        var bodyBytes = 0
    }

    private var state = Observation()

    var observation: Observation { state }

    func receiveRoots(commit: CID, index: CID) {
        state.commitRoot = commit
        state.indexRoot = index
    }

    func receiveCommit(cid: CID, body: Data) {}

    func beginRecord(cid: CID, byteCount: Int) {
        state.bodyBytes = byteCount
    }

    func appendRecordChunk(
        cid: CID,
        chunkIndex: Int,
        bytes: Data
    ) {
        state.chunkIndices.append(chunkIndex)
        state.chunkSizes.append(bytes.count)
    }

    func completeRecord(
        cid: CID,
        byteCount: Int,
        chunkCount: Int
    ) {
        state.bodyBytes = byteCount
        state.completedChunkCount = chunkCount
        state.completedCIDs.append(cid)
    }
}
