import Crypto
import Foundation
import Petrel
import SwanPublicFirehose
import SwanPublicRepository

public struct RelayVerifiedFullRepository: Sendable, Equatable {
  public let snapshot: RelayRepositorySnapshot
  public let records: [String: CID]

  public var head: RelayRepositoryHead { snapshot.head }

  fileprivate init(snapshot: RelayRepositorySnapshot) {
    self.snapshot = snapshot
    records = snapshot.records
  }
}

public enum RelayFullRepositoryVerifier {
  /// Structurally inspects a self-contained CAR so a live runner can bind the
  /// expected head before the authenticated verifier independently checks it.
  /// This makes no signature claim and must never be used as acceptance by
  /// itself.
  public static func inspect(car: Data) async throws -> RelayRepositorySnapshot {
    guard car.count <= PublicRepositoryLimits.standard.maximumCARBytes else {
      throw RelayVerifierError.repositoryCARTooLarge
    }
    let sink = RelayCARCollector()
    let parsed: PublicRepositoryCARParseResult
    do {
      parsed = try await PublicRepositoryCAR.parseIncrementally(
        from: RelayCARDataSource(car),
        to: sink
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    let blocks = await sink.blocks
    guard let commitBytes = blocks[parsed.rootCID] else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    let commit: StructurallyValidatedPublicRepositorySignedCommit
    do {
      commit = try PublicRepositoryCommitCodec.structurallyValidate(
        signedCommitBytes: commitBytes,
        expectedCommitCID: parsed.rootCID
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    let repository: ValidatedPublicRepositoryMST
    do {
      repository = try await RepositoryMSTValidation.validate(
        rootCID: commit.descriptor.dataCID,
        blocks: RelayDictionaryBlockSource(storage: blocks)
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    let required = Set(repository.reachableMSTBlocks.keys)
      .union(repository.reachableRecordCIDs)
      .union([parsed.rootCID])
    guard required.isSubset(of: Set(blocks.keys)) else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    var records: [String: CID] = [:]
    for leaf in repository.leaves {
      guard records.updateValue(leaf.recordCID, forKey: leaf.path.mstKey) == nil else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
    }
    return RelayRepositorySnapshot(
      did: commit.descriptor.did,
      revision: commit.descriptor.revision.value,
      commitCID: parsed.rootCID,
      dataCID: commit.descriptor.dataCID,
      records: records,
      mstDigest: RelayRepositoryVerificationState.mstDigest(
        repository.reachableMSTBlocks
      )
    )
  }

  public static func verify(
    car: Data,
    expected: RelayRepositoryHead,
    verifier: any PublicRepositoryCommitVerifier,
    maximumCARBytes: Int = PublicRepositoryLimits.standard.maximumCARBytes
  ) async throws -> RelayVerifiedFullRepository {
    let state = try await RelayRepositoryVerificationState.fullSnapshot(
      car: car,
      expected: expected,
      verifier: verifier,
      maximumCARBytes: maximumCARBytes
    )
    return .init(snapshot: state.snapshot)
  }
}

/// Authenticated repository state retained only while an ephemeral relay
/// capture is being checked. Raw blocks are private and are never Codable or
/// included in the aggregate result.
public struct RelayRepositoryVerificationState: Sendable {
  public let snapshot: RelayRepositorySnapshot
  public let payloadKind: RelayRepositoryPayloadKind
  private let reachableBlocks: [CID: Data]
  private let subtreeMSTBlocks: [CID: Set<CID>]

  private init(
    snapshot: RelayRepositorySnapshot,
    payloadKind: RelayRepositoryPayloadKind,
    reachableBlocks: [CID: Data],
    subtreeMSTBlocks: [CID: Set<CID>]
  ) {
    self.snapshot = snapshot
    self.payloadKind = payloadKind
    self.reachableBlocks = reachableBlocks
    self.subtreeMSTBlocks = subtreeMSTBlocks
  }

  public static func fullSnapshot(
    car: Data,
    expected: RelayRepositoryHead,
    verifier: any PublicRepositoryCommitVerifier,
    maximumCARBytes: Int = PublicRepositoryLimits.standard.maximumCARBytes
  ) async throws -> Self {
    let verified = try await verifyCAR(
      car,
      expectedRoot: expected.commitCID,
      previousBlocks: [:],
      requireSelfContainedRepository: true,
      verifier: verifier,
      maximumCARBytes: maximumCARBytes
    )
    try verifyHead(verified.snapshot.head, expected: expected)
    return .init(
      snapshot: verified.snapshot,
      payloadKind: .fullSnapshot,
      reachableBlocks: verified.reachableBlocks,
      subtreeMSTBlocks: verified.subtreeMSTBlocks
    )
  }

  public static func activationSync(
    _ event: RelaySyncEvent,
    verifier: any PublicRepositoryCommitVerifier
  ) async throws -> Self {
    let verified = try await verifyCommitAnnouncement(event, verifier: verifier)
    guard verified.commit.descriptor.did == event.did else {
      throw RelayVerifierError.repositoryDIDMismatch
    }
    guard verified.commit.descriptor.revision.value == event.rev else {
      throw RelayVerifierError.commitRevisionMismatch
    }
    let emptyCID: CID
    do {
      emptyCID = try CID.parse(PublicRepositoryGenesisCodec.canonicalEmptyMSTCID)
    } catch {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    guard verified.commit.descriptor.dataCID == emptyCID else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    let mstBlocks = [emptyCID: PublicRepositoryGenesisCodec.canonicalEmptyMST]
    let snapshot = RelayRepositorySnapshot(
      did: event.did,
      revision: event.rev,
      commitCID: verified.commit.commitCID,
      dataCID: emptyCID,
      records: [:],
      mstDigest: mstDigest(mstBlocks)
    )
    return .init(
      snapshot: snapshot,
      payloadKind: .commitAnnouncement,
      reachableBlocks: [
        verified.commit.commitCID: verified.commit.signedCommitBytes,
        emptyCID: PublicRepositoryGenesisCodec.canonicalEmptyMST,
      ],
      subtreeMSTBlocks: [emptyCID: Set([emptyCID])]
    )
  }
  public func synchronizing(
    _ event: RelaySyncEvent,
    verifier: any PublicRepositoryCommitVerifier
  ) async throws -> Self {
    let verified = try await Self.verifyCommitAnnouncement(event, verifier: verifier)
    guard verified.commit.descriptor.did == event.did,
          event.did == snapshot.did else {
      throw RelayVerifierError.repositoryDIDMismatch
    }
    guard verified.commit.descriptor.revision.value == event.rev,
          event.rev == snapshot.revision else {
      throw RelayVerifierError.commitRevisionMismatch
    }
    guard verified.commit.commitCID == snapshot.commitCID else {
      throw RelayVerifierError.commitCIDMismatch
    }
    guard verified.commit.descriptor.dataCID == snapshot.dataCID else {
      throw RelayVerifierError.finalDataCIDMismatch
    }
    return .init(
      snapshot: snapshot,
      payloadKind: .commitAnnouncement,
      reachableBlocks: reachableBlocks,
      subtreeMSTBlocks: subtreeMSTBlocks
    )
  }
  public func applying(
    commit event: RelayCommitEvent,
    verifier: any PublicRepositoryCommitVerifier
  ) async throws -> Self {
    try Task.checkCancellation()
    guard event.blocks.count <= FirehoseFrameLimits.maximumCommitBlocksBytes else {
      throw RelayVerifierError.commitBlocksTooLarge
    }
    let sink = RelayCARCollector()
    let parsed: PublicRepositoryCARParseResult
    do {
      parsed = try await PublicRepositoryCAR.parseIncrementally(
        from: RelayCARDataSource(event.blocks),
        to: sink
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    guard parsed.rootCID == event.commitCID else {
      throw RelayVerifierError.commitCIDMismatch
    }
    let root = parsed.rootCID
    let diffBlocks = await sink.blocks
    guard let commitBytes = diffBlocks[root] else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    var merged = reachableBlocks
    for (cid, bytes) in diffBlocks {
      if let existing = merged[cid], existing != bytes {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      do {
        try PublicRepositoryCID.validate(cid, blockBytes: bytes)
      } catch {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      merged[cid] = bytes
    }
    let commit: VerifiedPublicRepositorySignedCommit
    do {
      commit = try await PublicRepositoryCommitCodec.verify(
        signedCommitBytes: commitBytes,
        expectedCommitCID: root,
        verifier: verifier
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    guard commit.descriptor.did == snapshot.did, event.repo == snapshot.did else {
      throw RelayVerifierError.repositoryDIDMismatch
    }
    guard commit.descriptor.revision.value == event.rev else {
      throw RelayVerifierError.commitRevisionMismatch
    }
    guard event.commitCID == root else {
      throw RelayVerifierError.commitCIDMismatch
    }
    guard event.since == snapshot.revision else {
      throw RelayVerifierError.sinceRevisionMismatch
    }
    guard event.prevDataCID == snapshot.dataCID else {
      throw RelayVerifierError.previousDataCIDMismatch
    }

    var newRecords = snapshot.records
    var touchedPaths: [PublicRepositoryPath] = []
    for op in event.ops {
      try Task.checkCancellation()
      let path = try validateRepositoryPath(op.path)
      touchedPaths.append(path)
      switch op.action {
      case .create:
        guard let recordCID = op.cid, op.prev == nil else {
          throw RelayVerifierError.invalidRepositoryOperation
        }
        guard newRecords[op.path] == nil else {
          throw RelayVerifierError.repositoryDeltaMismatch
        }
        guard let recordBytes = merged[recordCID] else {
          throw RelayVerifierError.invalidRepositoryCAR
        }
        do {
          try RepositoryMSTValidation.validateRecordBlock(recordBytes, for: path)
        } catch {
          throw RelayVerifierError.invalidRepositoryCAR
        }
        newRecords[op.path] = recordCID

      case .update:
        guard let recordCID = op.cid, let prev = op.prev else {
          throw RelayVerifierError.invalidRepositoryOperation
        }
        guard newRecords[op.path] == prev else {
          throw RelayVerifierError.repositoryDeltaMismatch
        }
        guard let recordBytes = merged[recordCID] else {
          throw RelayVerifierError.invalidRepositoryCAR
        }
        do {
          try RepositoryMSTValidation.validateRecordBlock(recordBytes, for: path)
        } catch {
          throw RelayVerifierError.invalidRepositoryCAR
        }
        newRecords[op.path] = recordCID

      case .delete:
        guard op.cid == nil, let prev = op.prev else {
          throw RelayVerifierError.invalidRepositoryOperation
        }
        guard newRecords[op.path] == prev else {
          throw RelayVerifierError.repositoryDeltaMismatch
        }
        newRecords.removeValue(forKey: op.path)
      }
    }
    guard newRecords.count <= PublicRepositoryLimits.standard.maximumRepositoryRecords else {
      throw RelayVerifierError.invalidRepositoryCAR
    }

    var tree: RepositoryMST
    do {
      tree = try RepositoryMST.load(
        rootCID: snapshot.dataCID,
        blocks: RelayDictionaryBlockSource(storage: merged)
      )
    } catch {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    for op in event.ops {
      try Task.checkCancellation()
      let path = try validateRepositoryPath(op.path)
      do {
        switch op.action {
        case .create:
          tree = try await tree.adding(path: path, recordCID: op.cid!)
        case .update:
          tree = try await tree.updating(path: path, recordCID: op.cid!)
        case .delete:
          tree = try await tree.deleting(path: path)
        }
      } catch {
        throw RelayVerifierError.invalidRepositoryCAR
      }
    }
    let materialized: MaterializedRepositoryMST
    do {
      materialized = try await tree.materialized()
    } catch {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    guard materialized.rootCID == commit.descriptor.dataCID else {
      throw RelayVerifierError.finalDataCIDMismatch
    }

    var updatedSubtreeMSTBlocks = subtreeMSTBlocks
    func resolveSubtree(_ cid: CID) throws -> Set<CID> {
      try Task.checkCancellation()
      if let existing = updatedSubtreeMSTBlocks[cid] {
        return existing
      }
      guard let bytes = merged[cid] else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      let node: RepositoryMSTNode
      do {
        node = try RepositoryMSTCodec.decode(bytes)
      } catch {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      var set: Set<CID> = [cid]
      if let left = node.leftTreeCID {
        set.formUnion(try resolveSubtree(left))
      }
      for entry in node.entries {
        if let right = entry.rightTreeCID {
          set.formUnion(try resolveSubtree(right))
        }
      }
      updatedSubtreeMSTBlocks[cid] = set
      return set
    }

    let reachableMSTCIDs = try resolveSubtree(materialized.rootCID)

    var newMSTBlocks: [CID: Data] = [:]
    var mstByteCount = 0
    for cid in reachableMSTCIDs {
      guard let bytes = merged[cid] else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      newMSTBlocks[cid] = bytes
      mstByteCount += bytes.count
    }

    let newRecordCIDs = Set(newRecords.values)
    var recordByteCount = 0
    for cid in newRecordCIDs {
      guard let bytes = merged[cid] else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      recordByteCount += bytes.count
    }

    guard newMSTBlocks.count <= PublicRepositoryLimits.standard.maximumMSTNodes else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    guard (mstByteCount + recordByteCount) <= PublicRepositoryLimits.standard.maximumCARBytes else {
      throw RelayVerifierError.invalidRepositoryCAR
    }

    var reachable: [CID: Data] = [root: commitBytes]
    for (cid, bytes) in newMSTBlocks {
      reachable[cid] = bytes
    }
    for cid in newRecordCIDs {
      guard let bytes = merged[cid] else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      reachable[cid] = bytes
    }

    let newSnapshot = RelayRepositorySnapshot(
      did: commit.descriptor.did,
      revision: commit.descriptor.revision.value,
      commitCID: root,
      dataCID: commit.descriptor.dataCID,
      records: newRecords,
      mstDigest: Self.mstDigest(newMSTBlocks)
    )
    try RelayCommitSemanticVerifier.verify(
      event: event,
      previous: snapshot,
      current: newSnapshot
    )
    return .init(
      snapshot: newSnapshot,
      payloadKind: .commitDiff,
      reachableBlocks: reachable,
      subtreeMSTBlocks: updatedSubtreeMSTBlocks
    )
  }

  private static func findOldSpineCIDs(
    rootCID: CID,
    paths: [PublicRepositoryPath],
    blocks: [CID: Data]
  ) throws -> Set<CID> {
    var spine = Set<CID>()
    for path in paths {
      try Task.checkCancellation()
      var currentCID = rootCID
      while true {
        guard spine.insert(currentCID).inserted else { break }
        guard let bytes = blocks[currentCID] else { break }
        let node: RepositoryMSTNode
        do {
          node = try RepositoryMSTCodec.decode(bytes)
        } catch {
          break
        }
        let nodeLeaves: [RepositoryMSTLeaf]
        do {
          nodeLeaves = try RepositoryMSTCodec.reconstructedLeaves(from: node)
        } catch {
          break
        }
        if nodeLeaves.isEmpty {
          if let left = node.leftTreeCID {
            currentCID = left
          } else {
            break
          }
        } else {
          let index = nodeLeaves.firstIndex {
            !RepositoryMSTCodec.lexicographicallyPrecedes($0.path.mstKeyBytes, path.mstKeyBytes)
          } ?? nodeLeaves.count
          if index < nodeLeaves.count, nodeLeaves[index].path == path {
            break
          } else if index == 0 {
            if let left = node.leftTreeCID {
              currentCID = left
            } else {
              break
            }
          } else {
            if let right = nodeLeaves[index - 1].rightTreeCID {
              currentCID = right
            } else {
              break
            }
          }
        }
      }
    }
    return spine
  }

  private static func verifyCAR(
    _ car: Data,
    expectedRoot: CID?,
    previousBlocks: [CID: Data],
    requireSelfContainedRepository: Bool,
    verifier: any PublicRepositoryCommitVerifier,
    maximumCARBytes: Int
  ) async throws -> (snapshot: RelayRepositorySnapshot, reachableBlocks: [CID: Data], subtreeMSTBlocks: [CID: Set<CID>]) {
    guard maximumCARBytes > 0, car.count <= maximumCARBytes else {
      throw RelayVerifierError.repositoryCARTooLarge
    }
    let sink = RelayCARCollector()
    let parsed: PublicRepositoryCARParseResult
    do {
      parsed = try await PublicRepositoryCAR.parseIncrementally(
        from: RelayCARDataSource(car),
        to: sink
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    if let expectedRoot, parsed.rootCID != expectedRoot {
      throw RelayVerifierError.commitCIDMismatch
    }
    let root = parsed.rootCID
    let diffBlocks = await sink.blocks
    guard let commitBytes = diffBlocks[root] else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    var merged = previousBlocks
    for (cid, bytes) in diffBlocks {
      if let existing = merged[cid], existing != bytes {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      merged[cid] = bytes
    }
    let commit: VerifiedPublicRepositorySignedCommit
    do {
      commit = try await PublicRepositoryCommitCodec.verify(
        signedCommitBytes: commitBytes,
        expectedCommitCID: root,
        verifier: verifier
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    let blockSource = RelayDictionaryBlockSource(storage: merged)
    let repository: ValidatedPublicRepositoryMST
    do {
      repository = try await RepositoryMSTValidation.validate(
        rootCID: commit.descriptor.dataCID,
        blocks: blockSource,
        limits: .standard,
        maximumReachableRepositoryBytes: maximumCARBytes
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    guard repository.reachableMSTBlocks.count <= PublicRepositoryLimits.standard.maximumMSTNodes else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    guard repository.leaves.count <= PublicRepositoryLimits.standard.maximumRepositoryRecords else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    guard repository.reachableRepositoryByteCount <= maximumCARBytes else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    if requireSelfContainedRepository {
      let required = Set(repository.reachableMSTBlocks.keys)
        .union(repository.reachableRecordCIDs)
        .union([root])
      guard required.isSubset(of: Set(diffBlocks.keys)) else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
    }
    var records: [String: CID] = [:]
    for leaf in repository.leaves {
      guard records.updateValue(leaf.recordCID, forKey: leaf.path.mstKey) == nil else {
        throw RelayVerifierError.invalidRepositoryCAR
      }
    }
    var reachable: [CID: Data] = [root: commitBytes]
    for cid in Set(repository.reachableMSTBlocks.keys).union(repository.reachableRecordCIDs) {
      guard let bytes = merged[cid] else { throw RelayVerifierError.invalidRepositoryCAR }
      reachable[cid] = bytes
    }

    var subtreeMSTBlocks: [CID: Set<CID>] = [:]
    func computeSubtree(_ cid: CID) throws -> Set<CID> {
      try Task.checkCancellation()
      if let existing = subtreeMSTBlocks[cid] { return existing }
      guard let bytes = repository.reachableMSTBlocks[cid] else { return [] }
      let node: RepositoryMSTNode
      do {
        node = try RepositoryMSTCodec.decode(bytes)
      } catch {
        throw RelayVerifierError.invalidRepositoryCAR
      }
      var set: Set<CID> = [cid]
      if let left = node.leftTreeCID {
        set.formUnion(try computeSubtree(left))
      }
      for entry in node.entries {
        if let right = entry.rightTreeCID {
          set.formUnion(try computeSubtree(right))
        }
      }
      subtreeMSTBlocks[cid] = set
      return set
    }
    _ = try computeSubtree(commit.descriptor.dataCID)

    let snapshot = RelayRepositorySnapshot(
      did: commit.descriptor.did,
      revision: commit.descriptor.revision.value,
      commitCID: root,
      dataCID: commit.descriptor.dataCID,
      records: records,
      mstDigest: mstDigest(repository.reachableMSTBlocks)
    )
    return (snapshot, reachable, subtreeMSTBlocks)
  }

  private static func verifyCommitAnnouncement(
    _ event: RelaySyncEvent,
    verifier: any PublicRepositoryCommitVerifier
  ) async throws -> (commit: VerifiedPublicRepositorySignedCommit, bytes: Data) {
    guard event.blocks.count <= FirehoseFrameLimits.maximumSyncBlocksBytes else {
      throw RelayVerifierError.syncBlocksTooLarge
    }
    let sink = RelayCARCollector()
    let parsed: PublicRepositoryCARParseResult
    do {
      parsed = try await PublicRepositoryCAR.parseIncrementally(
        from: RelayCARDataSource(event.blocks),
        to: sink
      )
    } catch {
      throw try mapRepositoryError(error)
    }
    let blocks = await sink.blocks
    guard parsed.frameCount == 1,
          blocks.count == 1,
          let bytes = blocks[parsed.rootCID] else {
      throw RelayVerifierError.invalidRepositoryCAR
    }
    do {
      let commit = try await PublicRepositoryCommitCodec.verify(
        signedCommitBytes: bytes,
        expectedCommitCID: parsed.rootCID,
        verifier: verifier
      )
      return (commit, bytes)
    } catch {
      throw try mapRepositoryError(error)
    }
  }

  private static func verifyHead(
    _ actual: RelayRepositoryHead,
    expected: RelayRepositoryHead
  ) throws {
    guard actual.did == expected.did else { throw RelayVerifierError.repositoryDIDMismatch }
    guard actual.revision == expected.revision else {
      throw RelayVerifierError.commitRevisionMismatch
    }
    guard actual.commitCID == expected.commitCID else {
      throw RelayVerifierError.commitCIDMismatch
    }
    guard actual.dataCID == expected.dataCID else {
      throw RelayVerifierError.finalDataCIDMismatch
    }
  }

  fileprivate static func mstDigest(_ blocks: [CID: Data]) -> String {
    var hasher = SHA256()
    for cid in blocks.keys.sorted(by: { $0.string < $1.string }) {
      hasher.update(data: cid.bytes)
      hasher.update(data: blocks[cid]!)
    }
    return "sha256:\(hex(hasher.finalize()))"
  }
}

public enum RelayRepositoryDigest {
  public static func projection(_ records: [String: CID]) -> String {
    var hasher = SHA256()
    for path in records.keys.sorted() {
      hasher.update(data: Data(path.utf8))
      hasher.update(data: Data([0]))
      hasher.update(data: records[path]!.bytes)
    }
    return "sha256:\(hex(hasher.finalize()))"
  }
}

private func mapRepositoryError(_ error: Error) throws -> RelayVerifierError {
  if error is CancellationError {
    throw CancellationError()
  }
  if let error = error as? PublicRepositoryCommitError, error == .invalidSignature {
    return .invalidCommitSignature
  }
  if let error = error as? PublicRepositoryCARError {
    if case .commit(.invalidSignature) = error { return .invalidCommitSignature }
  }
  return .invalidRepositoryCAR
}
private func validateRepositoryPath(_ value: String) throws -> PublicRepositoryPath {
  guard let slash = value.firstIndex(of: "/") else {
    throw RelayVerifierError.repositoryDeltaMismatch
  }
  do {
    return try PublicRepositoryPath(
      collection: String(value[..<slash]),
      recordKey: String(value[value.index(after: slash)...])
    )
  } catch {
    throw RelayVerifierError.repositoryDeltaMismatch
  }
}

private func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
  digest.map { String(format: "%02x", $0) }.joined()
}

private actor RelayCARDataSource: PublicRepositoryCARByteSource {
  private let data: Data
  private var offset = 0

  init(_ data: Data) {
    self.data = data
  }

  func read(maximumBytes: Int) async throws -> Data? {
    guard offset < data.count else { return nil }
    let end = min(data.count, offset + maximumBytes)
    defer { offset = end }
    return Data(data[offset ..< end])
  }
}

private actor RelayCARCollector: PublicRepositoryCARFrameSink {
  private(set) var blocks: [CID: Data] = [:]
  private var root: CID?

  func receiveHeader(rootCID: CID, receivedByteCount _: Int) async throws {
    guard root == nil || root == rootCID else {
      throw PublicRepositoryCARError.malformedHeader
    }
    root = rootCID
  }

  func receiveBlock(
    _ block: PublicRepositoryBlock,
    receivedByteCount _: Int,
    frameCount _: Int
  ) async throws {
    if let existing = blocks[block.cid], existing != block.bytes {
      throw PublicRepositoryCARError.duplicateBlockConflict
    }
    blocks[block.cid] = block.bytes
  }
}

private struct RelayDictionaryBlockSource: PublicRepositoryBlockSource {
  let storage: [CID: Data]

  func block(for cid: CID) async throws -> Data? { storage[cid] }
}
