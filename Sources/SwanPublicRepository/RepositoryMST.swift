// This file adapts the immutable/lazy MST mutation algorithm from
// bluesky-social/atproto@3f6c96d5d2d25438bd40fa89d6ecc37865f8e354
// packages/repo/src/mst/{mst,util}.ts, used under the repository's
// MIT OR Apache-2.0 notice policy recorded in THIRD_PARTY_NOTICES.md.

import Foundation
import Petrel

public enum RepositoryMSTMutationError: Error, Sendable, Equatable {
    case duplicateKey
    case missingKey
    case missingBlock
    case blockCIDMismatch
    case invalidNode
    case invalidLayer
    case nodeLimitExceeded
    case entryLimitExceeded
    case relevantBlockBudgetExceeded
}

public struct MaterializedRepositoryMST: Sendable, Equatable {
    public let rootCID: CID
    public let newBlocks: PublicRepositoryBlockMap
}

/// An immutable repository MST. Loaded nodes retain only their CID and block
/// source until an operation reaches them; mutations replace just the nodes on
/// the affected search path.
public struct RepositoryMST: Sendable {
    private indirect enum Entry: Sendable {
        case leaf(RepositoryMSTLeaf)
        case tree(RepositoryMST)
    }

    private let blocks: any PublicRepositoryBlockSource
    private let pointer: CID?
    private let knownEntries: [Entry]?
    private let knownLayer: Int?
    private let limits: PublicRepositoryLimits

    private init(
        blocks: any PublicRepositoryBlockSource,
        pointer: CID?,
        entries: [Entry]?,
        layer: Int?,
        limits: PublicRepositoryLimits
    ) {
        self.blocks = blocks
        self.pointer = pointer
        knownEntries = entries
        knownLayer = layer
        self.limits = limits
    }

    public static func load(
        rootCID: CID,
        blocks: any PublicRepositoryBlockSource,
        limits: PublicRepositoryLimits = .standard
    ) throws -> Self {
        do {
            try PublicRepositoryCID.validate(rootCID)
        } catch {
            throw RepositoryMSTMutationError.blockCIDMismatch
        }
        return Self(
            blocks: blocks,
            pointer: rootCID,
            entries: nil,
            layer: nil,
            limits: limits
        )
    }

    public static func empty(limits: PublicRepositoryLimits = .standard) throws -> Self {
        let bytes = PublicRepositoryGenesisCodec.canonicalEmptyMST
        let cid = CID.fromDAGCBOR(bytes)
        let source = try PublicRepositoryBlockMap(
            blocks: [.init(cid: cid, bytes: bytes)],
            maximumRelevantBytes: limits.maximumRelevantBlockBytes
        )
        return Self(
            blocks: source,
            pointer: cid,
            entries: [],
            layer: 0,
            limits: limits
        )
    }

    public func get(_ path: PublicRepositoryPath) async throws -> CID? {
        let entries = try await entries()
        let index = firstLeafIndex(notLessThan: path, in: entries)
        if case let .leaf(leaf)? = entry(at: index, in: entries), leaf.path == path {
            return leaf.recordCID
        }
        if case let .tree(subtree)? = entry(at: index - 1, in: entries) {
            return try await subtree.get(path)
        }
        return nil
    }

    public func adding(path: PublicRepositoryPath, recordCID: CID) async throws -> Self {
        try validateRecordCID(recordCID)
        return try await add(path: path, recordCID: recordCID, knownDepth: nil)
    }

    public func updating(path: PublicRepositoryPath, recordCID: CID) async throws -> Self {
        try validateRecordCID(recordCID)
        let entries = try await entries()
        let index = firstLeafIndex(notLessThan: path, in: entries)
        if case let .leaf(found)? = entry(at: index, in: entries), found.path == path {
            return try replacing(
                entryAt: index,
                with: .leaf(.init(path: path, recordCID: recordCID)),
                in: entries
            )
        }
        if case let .tree(subtree)? = entry(at: index - 1, in: entries) {
            let updated = try await subtree.updating(path: path, recordCID: recordCID)
            return try replacing(entryAt: index - 1, with: .tree(updated), in: entries)
        }
        throw RepositoryMSTMutationError.missingKey
    }

    public func deleting(path: PublicRepositoryPath) async throws -> Self {
        try await deleteRecursively(path: path).trimmingTop()
    }

    public func listed() async throws -> [RepositoryMSTLeaf] {
        var result: [RepositoryMSTLeaf] = []
        try await appendLeaves(to: &result)
        return result
    }

    public func materialized() async throws -> MaterializedRepositoryMST {
        var collector = NewBlockCollector(limits: limits)
        let root = try await collectNewBlocks(into: &collector)
        let map: PublicRepositoryBlockMap
        do {
            map = try PublicRepositoryBlockMap(
                blocks: collector.blocks,
                maximumRelevantBytes: limits.maximumRelevantBlockBytes
            )
        } catch PublicRepositoryDomainError.relevantBlockBudgetExceeded {
            throw RepositoryMSTMutationError.relevantBlockBudgetExceeded
        } catch {
            throw error
        }
        return MaterializedRepositoryMST(rootCID: root, newBlocks: map)
    }

    // MARK: Mutation

    private func add(
        path: PublicRepositoryPath,
        recordCID: CID,
        knownDepth: Int?
    ) async throws -> Self {
        let keyDepth = knownDepth ?? RepositoryMSTCodec.keyDepth(for: path)
        let layer = try await layer()
        let entries = try await entries()
        let leaf = Entry.leaf(.init(path: path, recordCID: recordCID))

        if keyDepth == layer {
            let index = firstLeafIndex(notLessThan: path, in: entries)
            if case let .leaf(found)? = entry(at: index, in: entries), found.path == path {
                throw RepositoryMSTMutationError.duplicateKey
            }
            if case let .tree(subtree)? = entry(at: index - 1, in: entries) {
                let split = try await subtree.split(around: path)
                var replacement: [Entry] = []
                if let left = split.left { replacement.append(.tree(left)) }
                replacement.append(leaf)
                if let right = split.right { replacement.append(.tree(right)) }
                var updated = Array(entries[..<(index - 1)])
                updated.append(contentsOf: replacement)
                updated.append(contentsOf: entries[index...])
                return try newTree(updated)
            }
            var updated = entries
            updated.insert(leaf, at: index)
            return try newTree(updated)
        }

        if keyDepth < layer {
            let index = firstLeafIndex(notLessThan: path, in: entries)
            if case let .tree(subtree)? = entry(at: index - 1, in: entries) {
                let updated = try await subtree.add(
                    path: path,
                    recordCID: recordCID,
                    knownDepth: keyDepth
                )
                return try replacing(entryAt: index - 1, with: .tree(updated), in: entries)
            }
            let child = Self(
                blocks: blocks,
                pointer: nil,
                entries: [],
                layer: layer - 1,
                limits: limits
            )
            let updatedChild = try await child.add(
                path: path,
                recordCID: recordCID,
                knownDepth: keyDepth
            )
            var updated = entries
            updated.insert(.tree(updatedChild), at: index)
            return try newTree(updated)
        }

        let split = try await split(around: path)
        var left = split.left
        var right = split.right
        let extraLayers = keyDepth - layer
        if extraLayers > 1 {
            for _ in 1 ..< extraLayers {
                if let current = left { left = try current.parent() }
                if let current = right { right = try current.parent() }
            }
        }
        var rootEntries: [Entry] = []
        if let left { rootEntries.append(.tree(left)) }
        rootEntries.append(leaf)
        if let right { rootEntries.append(.tree(right)) }
        return try Self(
            blocks: blocks,
            pointer: nil,
            entries: rootEntries,
            layer: keyDepth,
            limits: limits
        ).checked()
    }

    private func deleteRecursively(path: PublicRepositoryPath) async throws -> Self {
        let entries = try await entries()
        let index = firstLeafIndex(notLessThan: path, in: entries)
        if case let .leaf(found)? = entry(at: index, in: entries), found.path == path {
            if case let .tree(left)? = entry(at: index - 1, in: entries),
               case let .tree(right)? = entry(at: index + 1, in: entries) {
                let merged = try await left.appendingMerge(right)
                var updated = Array(entries[..<(index - 1)])
                updated.append(.tree(merged))
                if index + 2 < entries.count {
                    updated.append(contentsOf: entries[(index + 2)...])
                }
                return try newTree(updated)
            }
            var updated = entries
            updated.remove(at: index)
            return try newTree(updated)
        }

        if case let .tree(subtree)? = entry(at: index - 1, in: entries) {
            let updatedSubtree = try await subtree.deleteRecursively(path: path)
            let childEntries = try await updatedSubtree.entries()
            if childEntries.isEmpty {
                var updated = entries
                updated.remove(at: index - 1)
                return try newTree(updated)
            }
            return try replacing(entryAt: index - 1, with: .tree(updatedSubtree), in: entries)
        }
        throw RepositoryMSTMutationError.missingKey
    }

    private func split(around path: PublicRepositoryPath) async throws -> (left: Self?, right: Self?) {
        let entries = try await entries()
        let currentLayer = try await layer()
        let index = firstLeafIndex(notLessThan: path, in: entries)
        var leftEntries = Array(entries[..<index])
        var rightEntries = Array(entries[index...])

        if case let .tree(boundary)? = leftEntries.last {
            leftEntries.removeLast()
            let splitBoundary = try await boundary.split(around: path)
            if let left = splitBoundary.left { leftEntries.append(.tree(left)) }
            if let right = splitBoundary.right { rightEntries.insert(.tree(right), at: 0) }
        }

        let left = leftEntries.isEmpty ? nil : try newTree(leftEntries, layer: currentLayer)
        let right = rightEntries.isEmpty ? nil : try newTree(rightEntries, layer: currentLayer)
        return (left, right)
    }

    private func appendingMerge(_ other: Self) async throws -> Self {
        guard try await layer() == other.layer() else {
            throw RepositoryMSTMutationError.invalidLayer
        }
        var leftEntries = try await entries()
        var rightEntries = try await other.entries()
        if case let .tree(leftBoundary)? = leftEntries.last,
           case let .tree(rightBoundary)? = rightEntries.first {
            leftEntries.removeLast()
            rightEntries.removeFirst()
            let merged = try await leftBoundary.appendingMerge(rightBoundary)
            return try newTree(leftEntries + [.tree(merged)] + rightEntries)
        }
        return try newTree(leftEntries + rightEntries)
    }

    private func trimmingTop() async throws -> Self {
        let entries = try await entries()
        if entries.count == 1, case let .tree(child) = entries[0] {
            return try await child.trimmingTop()
        }
        return self
    }

    private func parent() throws -> Self {
        guard let layer = knownLayer, layer < 128 else {
            throw RepositoryMSTMutationError.invalidLayer
        }
        return try Self(
            blocks: blocks,
            pointer: nil,
            entries: [.tree(self)],
            layer: layer + 1,
            limits: limits
        ).checked()
    }

    // MARK: Loading and encoding

    private func entries() async throws -> [Entry] {
        if let knownEntries { return knownEntries }
        guard let pointer, let bytes = try await blocks.block(for: pointer) else {
            throw RepositoryMSTMutationError.missingBlock
        }
        do {
            try PublicRepositoryCID.validate(pointer, blockBytes: bytes)
        } catch {
            throw RepositoryMSTMutationError.blockCIDMismatch
        }
        let node: RepositoryMSTNode
        do {
            node = try RepositoryMSTCodec.decode(bytes)
        } catch {
            throw RepositoryMSTMutationError.invalidNode
        }
        let leaves: [RepositoryMSTLeaf]
        do {
            leaves = try RepositoryMSTCodec.reconstructedLeaves(from: node)
        } catch {
            throw RepositoryMSTMutationError.invalidNode
        }
        let inferredLayer = leaves.first.map { RepositoryMSTCodec.keyDepth(for: $0.path) }
        let childLayer = knownLayer.map { $0 - 1 } ?? inferredLayer.map { $0 - 1 }
        var result: [Entry] = []
        if let left = node.leftTreeCID {
            result.append(.tree(Self(
                blocks: blocks,
                pointer: left,
                entries: nil,
                layer: childLayer,
                limits: limits
            )))
        }
        for leaf in leaves {
            result.append(.leaf(.init(path: leaf.path, recordCID: leaf.recordCID)))
            if let right = leaf.rightTreeCID {
                result.append(.tree(Self(
                    blocks: blocks,
                    pointer: right,
                    entries: nil,
                    layer: childLayer,
                    limits: limits
                )))
            }
        }
        guard result.count <= limits.maximumMSTEntriesPerNode * 2 + 1 else {
            throw RepositoryMSTMutationError.entryLimitExceeded
        }
        return result
    }

    private func layer() async throws -> Int {
        if let knownLayer {
            guard (0 ... 128).contains(knownLayer) else {
                throw RepositoryMSTMutationError.invalidLayer
            }
            return knownLayer
        }
        let entries = try await entries()
        for entry in entries {
            if case let .leaf(leaf) = entry {
                return RepositoryMSTCodec.keyDepth(for: leaf.path)
            }
        }
        for entry in entries {
            if case let .tree(child) = entry {
                let childLayer = try await child.layer()
                guard childLayer < 128 else { throw RepositoryMSTMutationError.invalidLayer }
                return childLayer + 1
            }
        }
        return 0
    }

    private func encoded() async throws -> (cid: CID, bytes: Data) {
        let entries = try await entries()
        var leaves: [RepositoryMSTLeaf] = []
        var leftTreeCID: CID?
        var index = 0
        if case let .tree(left)? = entries.first {
            leftTreeCID = try await left.rootCID()
            index = 1
        }
        while index < entries.count {
            guard case let .leaf(leaf) = entries[index] else {
                throw RepositoryMSTMutationError.invalidNode
            }
            var rightTreeCID: CID?
            if index + 1 < entries.count, case let .tree(right) = entries[index + 1] {
                rightTreeCID = try await right.rootCID()
                index += 1
            }
            leaves.append(.init(path: leaf.path, recordCID: leaf.recordCID, rightTreeCID: rightTreeCID))
            index += 1
        }
        guard leaves.count <= limits.maximumMSTEntriesPerNode else {
            throw RepositoryMSTMutationError.entryLimitExceeded
        }
        let node: RepositoryMSTNode
        do {
            node = try RepositoryMSTCodec.node(leaves: leaves, leftTreeCID: leftTreeCID)
            let bytes = try RepositoryMSTCodec.encode(node)
            return (CID.fromDAGCBOR(bytes), bytes)
        } catch {
            throw RepositoryMSTMutationError.invalidNode
        }
    }

    private func rootCID() async throws -> CID {
        if let pointer, knownEntries == nil { return pointer }
        return try await encoded().cid
    }

    private func collectNewBlocks(into collector: inout NewBlockCollector) async throws -> CID {
        let encoded = try await encoded()
        if let existing = try await blocks.block(for: encoded.cid) {
            guard existing == encoded.bytes else {
                throw RepositoryMSTMutationError.blockCIDMismatch
            }
            return encoded.cid
        }
        try collector.add(cid: encoded.cid, bytes: encoded.bytes)
        for entry in try await entries() {
            if case let .tree(child) = entry {
                _ = try await child.collectNewBlocks(into: &collector)
            }
        }
        return encoded.cid
    }

    private func appendLeaves(to result: inout [RepositoryMSTLeaf]) async throws {
        for entry in try await entries() {
            switch entry {
            case let .leaf(leaf):
                result.append(leaf)
            case let .tree(child):
                try await child.appendLeaves(to: &result)
            }
        }
    }

    private func newTree(_ entries: [Entry], layer: Int? = nil) throws -> Self {
        try Self(
            blocks: blocks,
            pointer: nil,
            entries: entries,
            layer: layer ?? knownLayer,
            limits: limits
        ).checked()
    }

    private func checked() throws -> Self {
        guard let entries = knownEntries else { return self }
        let leafCount = entries.reduce(into: 0) { count, entry in
            if case .leaf = entry { count += 1 }
        }
        guard leafCount <= limits.maximumMSTEntriesPerNode else {
            throw RepositoryMSTMutationError.entryLimitExceeded
        }
        var previousWasTree = false
        for entry in entries {
            let isTree: Bool
            if case .tree = entry { isTree = true } else { isTree = false }
            guard !(previousWasTree && isTree) else {
                throw RepositoryMSTMutationError.invalidNode
            }
            previousWasTree = isTree
        }
        return self
    }

    private func replacing(entryAt index: Int, with entry: Entry, in entries: [Entry]) throws -> Self {
        var updated = entries
        updated[index] = entry
        return try newTree(updated)
    }

    private func firstLeafIndex(notLessThan path: PublicRepositoryPath, in entries: [Entry]) -> Int {
        entries.firstIndex {
            if case let .leaf(leaf) = $0 {
                return leaf.path.mstKey >= path.mstKey
            }
            return false
        } ?? entries.count
    }

    private func entry(at index: Int, in entries: [Entry]) -> Entry? {
        entries.indices.contains(index) ? entries[index] : nil
    }

    private func validateRecordCID(_ cid: CID) throws {
        do {
            try PublicRepositoryCID.validate(cid)
        } catch {
            throw RepositoryMSTMutationError.blockCIDMismatch
        }
    }
}

private struct NewBlockCollector {
    let limits: PublicRepositoryLimits
    var blocks: [PublicRepositoryBlock] = []
    var cids = Set<CID>()
    var byteCount = 0

    mutating func add(cid: CID, bytes: Data) throws {
        guard cids.insert(cid).inserted else { return }
        guard blocks.count < limits.maximumMSTNodes else {
            throw RepositoryMSTMutationError.nodeLimitExceeded
        }
        let (next, overflow) = byteCount.addingReportingOverflow(bytes.count)
        guard !overflow, next <= limits.maximumRelevantBlockBytes else {
            throw RepositoryMSTMutationError.relevantBlockBudgetExceeded
        }
        blocks.append(.init(cid: cid, bytes: bytes))
        byteCount = next
    }
}
