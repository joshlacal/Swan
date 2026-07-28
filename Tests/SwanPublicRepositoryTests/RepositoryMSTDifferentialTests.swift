import Foundation
import Petrel
@testable import SwanPublicRepository
import XCTest

final class RepositoryMSTDifferentialTests: XCTestCase {
    func testSeededOperationsMatchIndependentSlowRebuildAfterEveryMutation() async throws {
        var random = SeededGenerator(seed: 0x5A17_2026_0728)
        let paths = try (0 ..< 48).map {
            try PublicRepositoryPath(
                collection: $0.isMultiple(of: 3) ? "app.bsky.feed.like" : "app.bsky.feed.post",
                recordKey: "seed-\($0)"
            )
        }
        var records: [PublicRepositoryPath: PreparedPublicRecord] = [:]
        var recordBlocks: [CID: Data] = [:]
        for path in paths {
            let prepared = try makeRecord(path: path, version: 0)
            records[path] = prepared
            recordBlocks[prepared.cid] = prepared.bytes
        }

        var expected: [PublicRepositoryPath: CID] = [:]
        var incremental = try RepositoryMST.empty()
        for step in 0 ..< 120 {
            let path = paths[Int(random.next() % UInt64(paths.count))]
            if expected[path] == nil {
                let prepared = records[path]!
                expected[path] = prepared.cid
                incremental = try await incremental.adding(path: path, recordCID: prepared.cid)
            } else if random.next().isMultiple(of: 3) {
                expected.removeValue(forKey: path)
                incremental = try await incremental.deleting(path: path)
            } else {
                let prepared = try makeRecord(path: path, version: step + 1)
                records[path] = prepared
                recordBlocks[prepared.cid] = prepared.bytes
                expected[path] = prepared.cid
                incremental = try await incremental.updating(path: path, recordCID: prepared.cid)
            }
            try await assertEquivalent(
                incremental: incremental,
                expected: expected,
                recordBlocks: recordBlocks,
                step: step
            )
        }
    }

    func testInsertionPermutationsConvergeToIdenticalRootAndReachableBytes() async throws {
        let paths = try [
            "3jqfcqzm3fo2j", "3jqfcqzm3fp2j", "3jqfcqzm3fr2j",
            "3jqfcqzm3fs2j", "3jqfcqzm3ft2j", "3jqfcqzm3fx2j",
            "3jqfcqzm3fz2j", "3jqfcqzm4fc2j", "3jqfcqzm4fd2j",
        ].map { try PublicRepositoryPath(collection: "com.example.record", recordKey: $0) }
        let recordCID = try CID.parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454")
        let permutations = [
            paths,
            Array(paths.reversed()),
            [paths[5], paths[0], paths[8], paths[2], paths[7], paths[1], paths[6], paths[4], paths[3]],
        ]
        var projections: [(CID, [CID: Data])] = []
        for order in permutations {
            var tree = try RepositoryMST.empty()
            for path in order {
                tree = try await tree.adding(path: path, recordCID: recordCID)
            }
            let materialized = try await tree.materialized()
            projections.append((materialized.rootCID, materialized.newBlocks.dictionary))
        }

        for projection in projections.dropFirst() {
            XCTAssertEqual(projection.0, projections[0].0)
            XCTAssertEqual(projection.1, projections[0].1)
        }
    }

    private func assertEquivalent(
        incremental: RepositoryMST,
        expected: [PublicRepositoryPath: CID],
        recordBlocks: [CID: Data],
        step: Int
    ) async throws {
        let oracle = try SlowMSTRebuild.build(expected)
        let materialized = try await incremental.materialized()
        var incrementalBlocks = materialized.newBlocks.dictionary
        if expected.isEmpty {
            incrementalBlocks[PublicRepositoryGenesisCodec.emptyCID] =
                PublicRepositoryGenesisCodec.canonicalEmptyMST
        }
        XCTAssertEqual(materialized.rootCID, oracle.rootCID, "root at step \(step)")
        XCTAssertEqual(incrementalBlocks, oracle.blocks, "blocks at step \(step)")

        let listed = try await incremental.listed()
        let expectedLeaves = expected.map { RepositoryMSTLeaf(path: $0.key, recordCID: $0.value) }
            .sorted { $0.path.mstKey < $1.path.mstKey }
        XCTAssertEqual(listed, expectedLeaves, "listing at step \(step)")

        let source = DictionaryBlockSource(
            oracle.blocks.merging(recordBlocks) { left, _ in left }
        )
        let validated = try await RepositoryMSTValidation.validate(
            rootCID: oracle.rootCID,
            blocks: source
        )
        let validatedProjection = validated.leaves.map { ($0.path, $0.recordCID) }
        let expectedProjection = expectedLeaves.map { ($0.path, $0.recordCID) }
        XCTAssertEqual(
            validatedProjection.map(\.0),
            expectedProjection.map(\.0),
            "strict paths at step \(step)"
        )
        XCTAssertEqual(
            validatedProjection.map(\.1),
            expectedProjection.map(\.1),
            "strict values at step \(step)"
        )
    }

    private func makeRecord(path: PublicRepositoryPath, version: Int) throws -> PreparedPublicRecord {
        try PublicRepositoryRecordCodec.prepare(
            PublicRecord([
                "$type": .string(path.collection),
                "version": .integer(version),
            ]),
            for: path
        )
    }
}

/// Deliberately does not call RepositoryMST mutations. It reconstructs the
/// canonical tree from sorted leaves by partitioning each exact hash layer.
private enum SlowMSTRebuild {
    struct Result {
        let rootCID: CID
        let blocks: [CID: Data]
    }

    static func build(_ records: [PublicRepositoryPath: CID]) throws -> Result {
        let leaves = records.map { RepositoryMSTLeaf(path: $0.key, recordCID: $0.value) }
            .sorted { $0.path.mstKey < $1.path.mstKey }
        guard let maximumLayer = leaves.map({ RepositoryMSTCodec.keyDepth(for: $0.path) }).max() else {
            return Result(
                rootCID: PublicRepositoryGenesisCodec.emptyCID,
                blocks: [
                    PublicRepositoryGenesisCodec.emptyCID:
                        PublicRepositoryGenesisCodec.canonicalEmptyMST,
                ]
            )
        }
        var blocks: [CID: Data] = [:]
        let root = try buildNode(leaves, at: maximumLayer, blocks: &blocks)
        return Result(rootCID: root, blocks: blocks)
    }

    private static func buildNode(
        _ leaves: [RepositoryMSTLeaf],
        at layer: Int,
        blocks: inout [CID: Data]
    ) throws -> CID {
        precondition(!leaves.isEmpty)
        precondition(layer >= 0)
        let directIndices = leaves.indices.filter {
            RepositoryMSTCodec.keyDepth(for: leaves[$0].path) == layer
        }
        let node: RepositoryMSTNode
        if directIndices.isEmpty {
            precondition(layer > 0)
            let child = try buildNode(leaves, at: layer - 1, blocks: &blocks)
            node = RepositoryMSTNode(leftTreeCID: child, entries: [])
        } else {
            let firstDirect = directIndices[0]
            let left = firstDirect == 0
                ? nil
                : try buildNode(Array(leaves[..<firstDirect]), at: layer - 1, blocks: &blocks)
            var nodeLeaves: [RepositoryMSTLeaf] = []
            for (offset, index) in directIndices.enumerated() {
                let next = offset + 1 < directIndices.count ? directIndices[offset + 1] : leaves.endIndex
                let right = index + 1 == next
                    ? nil
                    : try buildNode(Array(leaves[(index + 1)..<next]), at: layer - 1, blocks: &blocks)
                nodeLeaves.append(.init(
                    path: leaves[index].path,
                    recordCID: leaves[index].recordCID,
                    rightTreeCID: right
                ))
            }
            node = try RepositoryMSTCodec.node(leaves: nodeLeaves, leftTreeCID: left)
        }
        let bytes = try RepositoryMSTCodec.encode(node)
        let cid = CID.fromDAGCBOR(bytes)
        blocks[cid] = bytes
        return cid
    }
}

private struct DictionaryBlockSource: PublicRepositoryBlockSource {
    let storage: [CID: Data]

    init(_ storage: [CID: Data]) {
        self.storage = storage
    }

    func block(for cid: CID) async throws -> Data? {
        storage[cid]
    }
}

private struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}

private extension PublicRepositoryGenesisCodec {
    static var emptyCID: CID {
        CID.fromDAGCBOR(canonicalEmptyMST)
    }
}

private extension PublicRepositoryBlockMap {
    var dictionary: [CID: Data] {
        Dictionary(uniqueKeysWithValues: cids.compactMap { cid in
            block(for: cid).map { (cid, $0) }
        })
    }
}
