// The topology invariants in this file are based on
// bluesky-social/atproto@3f6c96d5d2d25438bd40fa89d6ecc37865f8e354
// packages/repo/src/mst/{mst,util}.ts, used under the repository's
// MIT OR Apache-2.0 notice policy recorded in THIRD_PARTY_NOTICES.md.
// The hostile-input checks are Swan-specific hardening.

import Foundation
import Petrel

public enum RepositoryMSTValidationError: Error, Sendable, Equatable {
    case unsupportedCID
    case missingBlock
    case blockCIDMismatch
    case invalidNodeSchema
    case invalidEntrySchema
    case nonCanonicalNode
    case invalidCIDLink
    case invalidPrefixCompression
    case keysNotStrictlyIncreasing
    case invalidPath
    case leafLayerMismatch
    case subtreeOutOfRange
    case invalidLayer
    case invalidEmptyTopology
    case repeatedNode
    case missingRecordBlock
    case recordBlockCIDMismatch
    case recordBlockTooLarge
    case invalidRecordBlock
    case nodeLimitExceeded
    case entryLimitExceeded
    case cborDepthLimitExceeded
    case invalidReachableRepositoryByteBudget
    case reachableRepositoryByteLimitExceeded
}

public struct ValidatedPublicRepositoryMST: Sendable, Equatable {
    public let rootCID: CID
    public let rootLayer: Int
    public let leaves: [RepositoryMSTLeaf]
    public let reachableMSTBlocks: [CID: Data]
    public let reachableRecordCIDs: Set<CID>
    public let reachableRepositoryByteCount: Int
}

public enum PublicRepositoryReachableBlockKind: String, Sendable, Equatable {
    case mst
    case record
}

/// Durable import validators use this sink to externalize the verified
/// projection. Calls carry identifiers only; block bodies remain in the
/// supplied block source and are released after each validation step.
public protocol PublicRepositoryReachableProjectionSink: Sendable {
    func recordReachableBlock(
        cid: CID,
        kind: PublicRepositoryReachableBlockKind
    ) async throws
    func recordRepositoryIndex(path: PublicRepositoryPath, recordCID: CID) async throws
}

public struct ValidatedPublicRepositoryProjection: Sendable, Equatable {
    public let rootCID: CID
    public let rootLayer: Int
    public let mstBlockCount: Int
    public let recordBlockCount: Int
    public let recordCount: Int
    public let reachableRepositoryByteCount: Int
}

public enum RepositoryMSTValidation {
    /// Applies the same canonical AT data-model and path `$type` validation
    /// used for every reachable MST record to a single public read result.
    public static func validateRecordBlock(
        _ bytes: Data,
        for path: PublicRepositoryPath,
        limits: PublicRepositoryLimits = .standard
    ) throws {
        guard bytes.count <= limits.maximumRecordBlockBytes else {
            throw RepositoryMSTValidationError.recordBlockTooLarge
        }
        _ = try RepositoryRecordBlockValidator.decode(
            bytes,
            expectedType: path.collection,
            maximumDepth: limits.maximumCBORNestingDepth
        )
    }

    /// Converts canonical repository DAG-CBOR directly into the AT data-model
    /// container used by generated XRPC outputs. The repository validator is
    /// the decoder, so no JSON bridge can stringify integers or rewrite
    /// links/bytes.
    public static func decodeRecordBlock(
        _ bytes: Data,
        for path: PublicRepositoryPath,
        limits: PublicRepositoryLimits = .standard
    ) throws -> ATProtocolValueContainer {
        guard bytes.count <= limits.maximumRecordBlockBytes else {
            throw RepositoryMSTValidationError.recordBlockTooLarge
        }
        return try RepositoryRecordBlockValidator.decode(
            bytes,
            expectedType: path.collection,
            maximumDepth: limits.maximumCBORNestingDepth
        )
    }

    public static func validate(
        rootCID: CID,
        blocks: any PublicRepositoryBlockSource,
        limits: PublicRepositoryLimits = .standard,
        maximumReachableRepositoryBytes: Int? = nil
    ) async throws -> ValidatedPublicRepositoryMST {
        try await validate(
            rootCID: rootCID,
            blocks: blocks,
            limits: limits,
            maximumReachableRepositoryBytes: maximumReachableRepositoryBytes,
            maximumMSTNodesOverride: nil,
            maximumMSTEntriesPerNodeOverride: nil
        )
    }

    /// Internal overrides let boundary tests prove zero/exact budgets without
    /// weakening the externally constructible production policy.
    static func validate(
        rootCID: CID,
        blocks: any PublicRepositoryBlockSource,
        limits: PublicRepositoryLimits,
        maximumReachableRepositoryBytes: Int? = nil,
        maximumMSTNodesOverride: Int? = nil,
        maximumMSTEntriesPerNodeOverride: Int? = nil
    ) async throws -> ValidatedPublicRepositoryMST {
        do {
            try PublicRepositoryCID.validate(rootCID)
        } catch {
            throw RepositoryMSTValidationError.unsupportedCID
        }
        guard limits.maximumCBORNestingDepth >= 3 else {
            throw RepositoryMSTValidationError.cborDepthLimitExceeded
        }

        let maximumNodes = maximumMSTNodesOverride ?? limits.maximumMSTNodes
        let maximumEntries = maximumMSTEntriesPerNodeOverride ?? limits.maximumMSTEntriesPerNode
        let maximumReachableBytes = maximumReachableRepositoryBytes ?? limits.maximumCARBytes
        guard maximumReachableBytes >= 0, maximumReachableBytes <= limits.maximumCARBytes else {
            throw RepositoryMSTValidationError.invalidReachableRepositoryByteBudget
        }

        struct WorkItem {
            let cid: CID
            let lowerBound: Data?
            let upperBound: Data?
            let expectedLayer: Int?
            let isRoot: Bool
        }

        var work = [WorkItem(
            cid: rootCID,
            lowerBound: nil,
            upperBound: nil,
            expectedLayer: nil,
            isRoot: true
        )]
        var referencedNodes: Set<CID> = [rootCID]
        var seenNodes = Set<CID>()
        var mstBlocks: [CID: Data] = [:]
        var leaves: [RepositoryMSTLeaf] = []
        var recordCIDs = Set<CID>()
        var reachableBytes = 0
        var rootLayer: Int?

        while let item = work.popLast() {
            guard seenNodes.insert(item.cid).inserted else {
                throw RepositoryMSTValidationError.repeatedNode
            }
            guard seenNodes.count <= maximumNodes else {
                throw RepositoryMSTValidationError.nodeLimitExceeded
            }
            let bytes = try await requiredBlock(item.cid, from: blocks)
            do {
                try PublicRepositoryCID.validate(item.cid, blockBytes: bytes)
            } catch PublicRepositoryDomainError.unsupportedCID {
                throw RepositoryMSTValidationError.unsupportedCID
            } catch {
                throw RepositoryMSTValidationError.blockCIDMismatch
            }
            reachableBytes = try adding(bytes.count, to: reachableBytes, maximum: maximumReachableBytes)

            let node = try RepositoryMSTCodec.decode(bytes)
            guard node.entries.count <= maximumEntries else {
                throw RepositoryMSTValidationError.entryLimitExceeded
            }
            let nodeLeaves = try RepositoryMSTCodec.reconstructedLeaves(from: node)
            let layer: Int

            if let first = nodeLeaves.first {
                layer = RepositoryMSTCodec.keyDepth(for: first.path)
                guard (0 ... 128).contains(layer) else {
                    throw RepositoryMSTValidationError.invalidLayer
                }
                if let expected = item.expectedLayer, layer != expected {
                    throw RepositoryMSTValidationError.invalidLayer
                }
                for leaf in nodeLeaves where RepositoryMSTCodec.keyDepth(for: leaf.path) != layer {
                    throw RepositoryMSTValidationError.leafLayerMismatch
                }
            } else if item.isRoot {
                guard node.leftTreeCID == nil,
                      bytes == PublicRepositoryGenesisCodec.canonicalEmptyMST else {
                    throw RepositoryMSTValidationError.invalidEmptyTopology
                }
                layer = 0
            } else {
                guard let expected = item.expectedLayer,
                      expected > 0,
                      node.leftTreeCID != nil else {
                    throw RepositoryMSTValidationError.invalidEmptyTopology
                }
                layer = expected
            }

            if item.isRoot {
                rootLayer = layer
            }
            mstBlocks[item.cid] = bytes

            if nodeLeaves.isEmpty {
                if let left = node.leftTreeCID {
                    guard referencedNodes.insert(left).inserted else {
                        throw RepositoryMSTValidationError.repeatedNode
                    }
                    work.append(.init(
                        cid: left,
                        lowerBound: item.lowerBound,
                        upperBound: item.upperBound,
                        expectedLayer: layer - 1,
                        isRoot: false
                    ))
                }
                continue
            }

            for leaf in nodeLeaves {
                let key = Data(leaf.path.mstKey.utf8)
                guard isInside(key, lower: item.lowerBound, upper: item.upperBound) else {
                    throw RepositoryMSTValidationError.subtreeOutOfRange
                }
                leaves.append(leaf)
                recordCIDs.insert(leaf.recordCID)
            }

            guard layer > 0 || (node.leftTreeCID == nil && nodeLeaves.allSatisfy { $0.rightTreeCID == nil }) else {
                throw RepositoryMSTValidationError.invalidLayer
            }
            if let left = node.leftTreeCID {
                guard referencedNodes.insert(left).inserted else {
                    throw RepositoryMSTValidationError.repeatedNode
                }
                work.append(.init(
                    cid: left,
                    lowerBound: item.lowerBound,
                    upperBound: Data(nodeLeaves[0].path.mstKey.utf8),
                    expectedLayer: layer - 1,
                    isRoot: false
                ))
            }
            for index in nodeLeaves.indices {
                guard let right = nodeLeaves[index].rightTreeCID else { continue }
                guard referencedNodes.insert(right).inserted else {
                    throw RepositoryMSTValidationError.repeatedNode
                }
                let lower = Data(nodeLeaves[index].path.mstKey.utf8)
                let upper = index + 1 < nodeLeaves.count
                    ? Data(nodeLeaves[index + 1].path.mstKey.utf8)
                    : item.upperBound
                work.append(.init(
                    cid: right,
                    lowerBound: lower,
                    upperBound: upper,
                    expectedLayer: layer - 1,
                    isRoot: false
                ))
            }
        }

        var expectedCollectionsByRecordCID: [CID: Set<String>] = [:]
        for leaf in leaves {
            expectedCollectionsByRecordCID[leaf.recordCID, default: []].insert(leaf.path.collection)
        }
        for cid in recordCIDs {
            guard let bytes = try await blocks.block(for: cid) else {
                throw RepositoryMSTValidationError.missingRecordBlock
            }
            do {
                try PublicRepositoryCID.validate(cid, blockBytes: bytes)
            } catch PublicRepositoryDomainError.unsupportedCID {
                throw RepositoryMSTValidationError.unsupportedCID
            } catch {
                throw RepositoryMSTValidationError.recordBlockCIDMismatch
            }
            guard bytes.count <= limits.maximumRecordBlockBytes else {
                throw RepositoryMSTValidationError.recordBlockTooLarge
            }
            reachableBytes = try adding(bytes.count, to: reachableBytes, maximum: maximumReachableBytes)
            guard let expectedCollections = expectedCollectionsByRecordCID[cid] else {
                throw RepositoryMSTValidationError.missingRecordBlock
            }
            for expectedCollection in expectedCollections {
                do {
                    try RepositoryRecordBlockValidator.validate(
                        bytes,
                        expectedType: expectedCollection,
                        maximumDepth: limits.maximumCBORNestingDepth
                    )
                } catch {
                    throw RepositoryMSTValidationError.invalidRecordBlock
                }
            }
        }

        leaves.sort { Data($0.path.mstKey.utf8).lexicographicallyPrecedes(Data($1.path.mstKey.utf8)) }
        for pair in zip(leaves, leaves.dropFirst()) {
            guard pair.0.path.mstKey < pair.1.path.mstKey else {
                throw RepositoryMSTValidationError.keysNotStrictlyIncreasing
            }
        }
        guard let rootLayer else {
            throw RepositoryMSTValidationError.missingBlock
        }
        return ValidatedPublicRepositoryMST(
            rootCID: rootCID,
            rootLayer: rootLayer,
            leaves: leaves,
            reachableMSTBlocks: mstBlocks,
            reachableRecordCIDs: recordCIDs,
            reachableRepositoryByteCount: reachableBytes
        )
    }

    /// Performs the same strict validation as `validate`, but externalizes the
    /// reachable projection instead of retaining every MST block body. The
    /// in-memory working set is one fetched block plus topology metadata.
    public static func validateProjection(
        rootCID: CID,
        blocks: any PublicRepositoryBlockSource,
        projection: any PublicRepositoryReachableProjectionSink,
        limits: PublicRepositoryLimits = .standard,
        maximumReachableRepositoryBytes: Int? = nil
    ) async throws -> ValidatedPublicRepositoryProjection {
        do {
            try PublicRepositoryCID.validate(rootCID)
        } catch {
            throw RepositoryMSTValidationError.unsupportedCID
        }
        guard limits.maximumCBORNestingDepth >= 3 else {
            throw RepositoryMSTValidationError.cborDepthLimitExceeded
        }
        let maximumReachableBytes = maximumReachableRepositoryBytes ?? limits.maximumCARBytes
        guard maximumReachableBytes >= 0, maximumReachableBytes <= limits.maximumCARBytes else {
            throw RepositoryMSTValidationError.invalidReachableRepositoryByteBudget
        }

        struct WorkItem {
            let cid: CID
            let lowerBound: Data?
            let upperBound: Data?
            let expectedLayer: Int?
            let isRoot: Bool
        }
        var work = [WorkItem(
            cid: rootCID, lowerBound: nil, upperBound: nil,
            expectedLayer: nil, isRoot: true
        )]
        var referencedNodes: Set<CID> = [rootCID]
        var seenNodes = Set<CID>()
        var leaves: [RepositoryMSTLeaf] = []
        var recordCIDs = Set<CID>()
        var reachableBytes = 0
        var rootLayer: Int?

        while let item = work.popLast() {
            try Task.checkCancellation()
            guard seenNodes.insert(item.cid).inserted else {
                throw RepositoryMSTValidationError.repeatedNode
            }
            guard seenNodes.count <= limits.maximumMSTNodes else {
                throw RepositoryMSTValidationError.nodeLimitExceeded
            }
            let bytes = try await requiredBlock(item.cid, from: blocks)
            do {
                try PublicRepositoryCID.validate(item.cid, blockBytes: bytes)
            } catch PublicRepositoryDomainError.unsupportedCID {
                throw RepositoryMSTValidationError.unsupportedCID
            } catch {
                throw RepositoryMSTValidationError.blockCIDMismatch
            }
            reachableBytes = try adding(bytes.count, to: reachableBytes, maximum: maximumReachableBytes)
            let node = try RepositoryMSTCodec.decode(bytes)
            guard node.entries.count <= limits.maximumMSTEntriesPerNode else {
                throw RepositoryMSTValidationError.entryLimitExceeded
            }
            let nodeLeaves = try RepositoryMSTCodec.reconstructedLeaves(from: node)
            let layer: Int
            if let first = nodeLeaves.first {
                layer = RepositoryMSTCodec.keyDepth(for: first.path)
                guard (0 ... 128).contains(layer) else {
                    throw RepositoryMSTValidationError.invalidLayer
                }
                if let expected = item.expectedLayer, layer != expected {
                    throw RepositoryMSTValidationError.invalidLayer
                }
                guard nodeLeaves.allSatisfy({
                    RepositoryMSTCodec.keyDepth(for: $0.path) == layer
                }) else {
                    throw RepositoryMSTValidationError.leafLayerMismatch
                }
            } else if item.isRoot {
                guard node.leftTreeCID == nil,
                      bytes == PublicRepositoryGenesisCodec.canonicalEmptyMST else {
                    throw RepositoryMSTValidationError.invalidEmptyTopology
                }
                layer = 0
            } else {
                guard let expected = item.expectedLayer,
                      expected > 0, node.leftTreeCID != nil else {
                    throw RepositoryMSTValidationError.invalidEmptyTopology
                }
                layer = expected
            }
            if item.isRoot { rootLayer = layer }
            try await projection.recordReachableBlock(cid: item.cid, kind: .mst)

            if nodeLeaves.isEmpty {
                if let left = node.leftTreeCID {
                    guard referencedNodes.insert(left).inserted else {
                        throw RepositoryMSTValidationError.repeatedNode
                    }
                    work.append(.init(
                        cid: left, lowerBound: item.lowerBound,
                        upperBound: item.upperBound, expectedLayer: layer - 1,
                        isRoot: false
                    ))
                }
                continue
            }
            for leaf in nodeLeaves {
                let key = Data(leaf.path.mstKey.utf8)
                guard isInside(key, lower: item.lowerBound, upper: item.upperBound) else {
                    throw RepositoryMSTValidationError.subtreeOutOfRange
                }
                leaves.append(leaf)
                recordCIDs.insert(leaf.recordCID)
            }
            guard layer > 0 ||
                    (node.leftTreeCID == nil && nodeLeaves.allSatisfy { $0.rightTreeCID == nil })
            else {
                throw RepositoryMSTValidationError.invalidLayer
            }
            if let left = node.leftTreeCID {
                guard referencedNodes.insert(left).inserted else {
                    throw RepositoryMSTValidationError.repeatedNode
                }
                work.append(.init(
                    cid: left, lowerBound: item.lowerBound,
                    upperBound: Data(nodeLeaves[0].path.mstKey.utf8),
                    expectedLayer: layer - 1, isRoot: false
                ))
            }
            for index in nodeLeaves.indices {
                guard let right = nodeLeaves[index].rightTreeCID else { continue }
                guard referencedNodes.insert(right).inserted else {
                    throw RepositoryMSTValidationError.repeatedNode
                }
                work.append(.init(
                    cid: right,
                    lowerBound: Data(nodeLeaves[index].path.mstKey.utf8),
                    upperBound: index + 1 < nodeLeaves.count
                        ? Data(nodeLeaves[index + 1].path.mstKey.utf8)
                        : item.upperBound,
                    expectedLayer: layer - 1,
                    isRoot: false
                ))
            }
        }

        var expectedCollectionsByRecordCID: [CID: Set<String>] = [:]
        for leaf in leaves {
            expectedCollectionsByRecordCID[leaf.recordCID, default: []].insert(leaf.path.collection)
        }
        for cid in recordCIDs {
            try Task.checkCancellation()
            guard let bytes = try await blocks.block(for: cid) else {
                throw RepositoryMSTValidationError.missingRecordBlock
            }
            do {
                try PublicRepositoryCID.validate(cid, blockBytes: bytes)
            } catch PublicRepositoryDomainError.unsupportedCID {
                throw RepositoryMSTValidationError.unsupportedCID
            } catch {
                throw RepositoryMSTValidationError.recordBlockCIDMismatch
            }
            guard bytes.count <= limits.maximumRecordBlockBytes else {
                throw RepositoryMSTValidationError.recordBlockTooLarge
            }
            reachableBytes = try adding(bytes.count, to: reachableBytes, maximum: maximumReachableBytes)
            guard let expectedCollections = expectedCollectionsByRecordCID[cid] else {
                throw RepositoryMSTValidationError.missingRecordBlock
            }
            for collection in expectedCollections {
                do {
                    try RepositoryRecordBlockValidator.validate(
                        bytes, expectedType: collection,
                        maximumDepth: limits.maximumCBORNestingDepth
                    )
                } catch {
                    throw RepositoryMSTValidationError.invalidRecordBlock
                }
            }
            try await projection.recordReachableBlock(cid: cid, kind: .record)
        }
        leaves.sort {
            Data($0.path.mstKey.utf8).lexicographicallyPrecedes(Data($1.path.mstKey.utf8))
        }
        for pair in zip(leaves, leaves.dropFirst()) {
            guard pair.0.path.mstKey < pair.1.path.mstKey else {
                throw RepositoryMSTValidationError.keysNotStrictlyIncreasing
            }
        }
        for leaf in leaves {
            try await projection.recordRepositoryIndex(
                path: leaf.path, recordCID: leaf.recordCID
            )
        }
        guard let rootLayer else {
            throw RepositoryMSTValidationError.missingBlock
        }
        return .init(
            rootCID: rootCID,
            rootLayer: rootLayer,
            mstBlockCount: seenNodes.count,
            recordBlockCount: recordCIDs.count,
            recordCount: leaves.count,
            reachableRepositoryByteCount: reachableBytes
        )
    }

    private static func requiredBlock(
        _ cid: CID,
        from blocks: any PublicRepositoryBlockSource
    ) async throws -> Data {
        guard let bytes = try await blocks.block(for: cid) else {
            throw RepositoryMSTValidationError.missingBlock
        }
        return bytes
    }

    private static func isInside(_ key: Data, lower: Data?, upper: Data?) -> Bool {
        if let lower, !lower.lexicographicallyPrecedes(key) { return false }
        if let upper, !key.lexicographicallyPrecedes(upper) { return false }
        return true
    }

    private static func adding(_ count: Int, to total: Int, maximum: Int) throws -> Int {
        let (result, overflow) = total.addingReportingOverflow(count)
        guard !overflow, count >= 0, result <= maximum else {
            throw RepositoryMSTValidationError.reachableRepositoryByteLimitExceeded
        }
        return result
    }
}

/// Strict, allocation-bounded validation of the AT data-model subset used by
/// record blocks. MST validation cannot stop at CID integrity: the leaf path's
/// collection and the record's top-level `$type` are one repository invariant.
private struct RepositoryRecordBlockValidator {
    private let bytes: [UInt8]
    private var offset = 0
    private var topLevelType: String?

    static func validate(
        _ data: Data,
        expectedType: String,
        maximumDepth: Int
    ) throws {
        _ = try decode(
            data,
            expectedType: expectedType,
            maximumDepth: maximumDepth
        )
    }

    static func decode(
        _ data: Data,
        expectedType: String,
        maximumDepth: Int
    ) throws -> ATProtocolValueContainer {
        var parser = Self(bytes: Array(data))
        let value = try parser.readMap(
            depth: 1,
            maximumDepth: maximumDepth,
            captureType: true
        )
        guard parser.offset == parser.bytes.count, parser.topLevelType == expectedType else {
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
        return .object(value)
    }

    private mutating func readValue(
        depth: Int,
        maximumDepth: Int
    ) throws -> ATProtocolValueContainer {
        guard offset < bytes.count else { throw RepositoryMSTValidationError.invalidRecordBlock }
        switch bytes[offset] >> 5 {
        case 0:
            let value = try readArgument(major: 0)
            guard value <= UInt64(PublicRepositoryRecordCodec.maximumSafeInteger) else {
                throw RepositoryMSTValidationError.invalidRecordBlock
            }
            return .number(Int(value))
        case 1:
            let value = try readArgument(major: 1)
            guard value < UInt64(-PublicRepositoryRecordCodec.minimumSafeInteger) else {
                throw RepositoryMSTValidationError.invalidRecordBlock
            }
            return .number(-1 - Int(value))
        case 2:
            return .bytes(Bytes(data: try readData(major: 2)))
        case 3:
            return .string(try readText())
        case 4:
            guard depth < maximumDepth else { throw RepositoryMSTValidationError.invalidRecordBlock }
            let count = try readLength(major: 4)
            var values: [ATProtocolValueContainer] = []
            values.reserveCapacity(count)
            for _ in 0 ..< count {
                values.append(try readValue(
                    depth: depth + 1,
                    maximumDepth: maximumDepth
                ))
            }
            return .array(values)
        case 5:
            guard depth < maximumDepth else { throw RepositoryMSTValidationError.invalidRecordBlock }
            return .object(try readMap(
                depth: depth + 1,
                maximumDepth: maximumDepth,
                captureType: false
            ))
        case 6:
            guard try readArgument(major: 6) == 42 else {
                throw RepositoryMSTValidationError.invalidRecordBlock
            }
            let payload = try readData(major: 2)
            guard payload.count == 37, payload.first == 0 else {
                throw RepositoryMSTValidationError.invalidRecordBlock
            }
            let cid = try CID(bytes: Data(payload.dropFirst()))
            let cidBytes = cid.bytes
            guard cidBytes.count == 36,
                  cidBytes[cidBytes.startIndex] == 0x01,
                  cidBytes[cidBytes.startIndex + 1] == cid.codec.rawValue,
                  cid.codec == .raw || cid.codec == .dagCBOR,
                  cid.multihash.algorithm == Multihash.sha256Code,
                  cid.multihash.length == Multihash.sha256Length,
                  cid.multihash.digest.count == 32 else {
                throw RepositoryMSTValidationError.invalidRecordBlock
            }
            return .link(ATProtoLink(cid: cid))
        case 7:
            let byte = bytes[offset]
            guard byte == 0xf4 || byte == 0xf5 || byte == 0xf6 else {
                throw RepositoryMSTValidationError.invalidRecordBlock
            }
            offset += 1
            switch byte {
            case 0xf4: return .bool(false)
            case 0xf5: return .bool(true)
            default: return .null
            }
        default:
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
    }

    private mutating func readMap(
        depth: Int,
        maximumDepth: Int,
        captureType: Bool
    ) throws -> [String: ATProtocolValueContainer] {
        let count = try readLength(major: 5)
        var previousKey: Data?
        var sawType = false
        var values: [String: ATProtocolValueContainer] = [:]
        values.reserveCapacity(count)
        for _ in 0 ..< count {
            let key = try readText()
            let keyBytes = Data(key.utf8)
            if let previousKey {
                guard canonicalKeyPrecedes(previousKey, keyBytes) else {
                    throw RepositoryMSTValidationError.invalidRecordBlock
                }
            }
            previousKey = keyBytes
            if captureType, key == "$type" {
                guard !sawType else { throw RepositoryMSTValidationError.invalidRecordBlock }
                topLevelType = try readText()
                values[key] = .string(topLevelType!)
                sawType = true
            } else {
                values[key] = try readValue(
                    depth: depth,
                    maximumDepth: maximumDepth
                )
            }
        }
        if captureType, !sawType {
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
        return values
    }

    private func canonicalKeyPrecedes(_ lhs: Data, _ rhs: Data) -> Bool {
        lhs.count == rhs.count ? lhs.lexicographicallyPrecedes(rhs) : lhs.count < rhs.count
    }

    private mutating func readText() throws -> String {
        let data = try readData(major: 3)
        guard let value = String(data: data, encoding: .utf8) else {
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
        return value
    }

    private mutating func readData(major: UInt8) throws -> Data {
        let count = try readLength(major: major)
        guard count <= bytes.count - offset else {
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
        let value = Data(bytes[offset ..< offset + count])
        offset += count
        return value
    }

    private mutating func readLength(major: UInt8) throws -> Int {
        let value = try readArgument(major: major)
        guard value <= UInt64(Int.max) else {
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
        return Int(value)
    }

    private mutating func readArgument(major: UInt8) throws -> UInt64 {
        guard offset < bytes.count else { throw RepositoryMSTValidationError.invalidRecordBlock }
        let initial = bytes[offset]
        offset += 1
        guard initial >> 5 == major else { throw RepositoryMSTValidationError.invalidRecordBlock }
        switch initial & 0x1f {
        case 0 ... 23:
            return UInt64(initial & 0x1f)
        case 24:
            let value = try readFixed(1)
            guard value >= 24 else { throw RepositoryMSTValidationError.invalidRecordBlock }
            return value
        case 25:
            let value = try readFixed(2)
            guard value > UInt8.max else { throw RepositoryMSTValidationError.invalidRecordBlock }
            return value
        case 26:
            let value = try readFixed(4)
            guard value > UInt16.max else { throw RepositoryMSTValidationError.invalidRecordBlock }
            return value
        case 27:
            let value = try readFixed(8)
            guard value > UInt32.max else { throw RepositoryMSTValidationError.invalidRecordBlock }
            return value
        default:
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
    }

    private mutating func readFixed(_ count: Int) throws -> UInt64 {
        guard count <= bytes.count - offset else {
            throw RepositoryMSTValidationError.invalidRecordBlock
        }
        var result: UInt64 = 0
        for byte in bytes[offset ..< offset + count] {
            result = (result << 8) | UInt64(byte)
        }
        offset += count
        return result
    }
}
