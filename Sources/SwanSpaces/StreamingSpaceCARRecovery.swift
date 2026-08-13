import Crypto
import Foundation
import Petrel
import SwanCore

/// A pull-based source for a permissioned recovery CAR. Implementations must
/// return no more than `maximumBytes`; the verifier never requests more than
/// 64 KiB and rejects sources that violate that contract.
public protocol SpaceCARRecoveryByteSource: Sendable {
    func read(maximumBytes: Int) async throws -> Data?
}

public struct SpaceCARRecoveryIndexEntry: Sendable, Equatable {
    public let path: String
    public let cid: CID

    public init(path: String, cid: CID) {
        self.path = path
        self.cid = cid
    }
}

/// Storage-neutral scratch index for a full recovery. Production callers use
/// a disposable SQLite implementation so neither the DRISL map nor its set of
/// paths/CIDs is retained in process memory.
public protocol SpaceCARRecoveryIndex: Sendable {
    func insert(_ entry: SpaceCARRecoveryIndexEntry) async throws
    func nextUnconsumedLexicographicEntry() async throws -> SpaceCARRecoveryIndexEntry?
    /// Marks every indexed path that references `cid` as satisfied by the one
    /// corresponding CAR block. The return value is the number of paths
    /// consumed, not the number of block frames.
    func consumeEntries(forCID cid: CID) async throws -> Int
}

/// A durable recovery consumer. The verifier tees at most 64 KiB at a time
/// into this sink while validating the same bytes. `completeRecord` is called
/// only after canonical validation, CID verification, and DRISL consumption.
public protocol SpaceCARRecoveryRecordSink: Sendable {
    func receiveRoots(commit: CID, index: CID) async throws
    func receiveCommit(cid: CID, body: Data) async throws
    func beginRecord(cid: CID, byteCount: Int) async throws
    func appendRecordChunk(
        cid: CID,
        chunkIndex: Int,
        bytes: Data
    ) async throws
    func completeRecord(
        cid: CID,
        byteCount: Int,
        chunkCount: Int
    ) async throws
}

public struct SpaceCARRecoveryLimits: Sendable, Equatable {
    public static let maximumChunkBytes = 64 * 1_024
    public static let absoluteMaximumCommitBytes = 64 * 1_024
    public static let absoluteMaximumRecordBytes = 1 * 1_024 * 1_024
    public static let absoluteMaximumCARBytes = 256 * 1_024 * 1_024
    public static let absoluteMaximumIndexEntries = 100_000
    public static let absoluteMaximumUniqueBlocks = 100_000
    public static let absoluteMaximumLogicalRestoredBytes = 256 * 1_024 * 1_024

    public let maximumCARBytes: Int
    public let maximumRecordBytes: Int
    public let maximumIndexEntries: Int
    public let maximumUniqueBlocks: Int
    public let maximumLogicalRestoredBytes: Int
    public static let standard = Self(
        validatedMaximumCARBytes: Self.absoluteMaximumCARBytes,
        maximumRecordBytes: Self.absoluteMaximumRecordBytes,
        maximumIndexEntries: Self.absoluteMaximumIndexEntries,
        maximumUniqueBlocks: Self.absoluteMaximumUniqueBlocks,
        maximumLogicalRestoredBytes: Self.absoluteMaximumLogicalRestoredBytes
    )

    public init(
        maximumCARBytes: Int = Self.absoluteMaximumCARBytes,
        maximumRecordBytes: Int = Self.absoluteMaximumRecordBytes,
        maximumIndexEntries: Int = Self.absoluteMaximumIndexEntries,
        maximumUniqueBlocks: Int = Self.absoluteMaximumUniqueBlocks,
        maximumLogicalRestoredBytes: Int = Self.absoluteMaximumLogicalRestoredBytes
    ) throws {
        guard (1 ... Self.absoluteMaximumCARBytes).contains(maximumCARBytes),
              (1 ... Self.absoluteMaximumRecordBytes).contains(maximumRecordBytes),
              (1 ... Self.absoluteMaximumIndexEntries).contains(maximumIndexEntries),
              (1 ... Self.absoluteMaximumUniqueBlocks).contains(maximumUniqueBlocks),
              (1 ... Self.absoluteMaximumLogicalRestoredBytes)
                .contains(maximumLogicalRestoredBytes),
              maximumUniqueBlocks <= maximumIndexEntries
        else {
            throw SpaceCARStreamingError.invalidLimits
        }
        self.maximumCARBytes = maximumCARBytes
        self.maximumRecordBytes = maximumRecordBytes
        self.maximumIndexEntries = maximumIndexEntries
        self.maximumUniqueBlocks = maximumUniqueBlocks
        self.maximumLogicalRestoredBytes = maximumLogicalRestoredBytes
    }

    private init(
        validatedMaximumCARBytes: Int,
        maximumRecordBytes: Int,
        maximumIndexEntries: Int,
        maximumUniqueBlocks: Int,
        maximumLogicalRestoredBytes: Int
    ) {
        self.maximumCARBytes = validatedMaximumCARBytes
        self.maximumRecordBytes = maximumRecordBytes
        self.maximumIndexEntries = maximumIndexEntries
        self.maximumUniqueBlocks = maximumUniqueBlocks
        self.maximumLogicalRestoredBytes = maximumLogicalRestoredBytes
    }
}

/// The bounded result of a fully verified recovery CAR. Record values and the
/// DRISL map remain outside the result so a caller cannot accidentally turn a
/// streaming verification path back into repository-wide memory retention.
public struct VerifiedStreamingSpaceCARRecovery: Sendable, Equatable {
    public let commitRootCID: CID
    public let indexRootCID: CID
    public let wireRevision: TID
    public let recordCount: Int
    public let uniqueBlockCount: Int
    public let verifiedExpectedWitnessCount: Int
    public let ltHash: Data
    public let commitment: Data
    public let commitBodyDigest: Data
    public let receivedByteCount: Int
    /// Sum of each verified record body multiplied by the number of DRISL
    /// paths that reference its CID. This is the maximum SQLite value payload
    /// the publication transaction is allowed to write.
    public let logicalRestoredByteCount: Int

    public init(
        commitRootCID: CID,
        indexRootCID: CID,
        wireRevision: TID,
        recordCount: Int,
        uniqueBlockCount: Int,
        verifiedExpectedWitnessCount: Int,
        ltHash: Data,
        commitment: Data,
        commitBodyDigest: Data,
        receivedByteCount: Int,
        logicalRestoredByteCount: Int
    ) {
        self.commitRootCID = commitRootCID
        self.indexRootCID = indexRootCID
        self.wireRevision = wireRevision
        self.recordCount = recordCount
        self.uniqueBlockCount = uniqueBlockCount
        self.verifiedExpectedWitnessCount = verifiedExpectedWitnessCount
        self.ltHash = ltHash
        self.commitment = commitment
        self.commitBodyDigest = commitBodyDigest
        self.receivedByteCount = receivedByteCount
        self.logicalRestoredByteCount = logicalRestoredByteCount
    }
}

public enum SpaceCARStreamingError: Error, Sendable, Equatable {
    case invalidLimits
    case invalidChunk
    case byteLimitExceeded
    case malformedVarint
    case nonCanonicalVarint
    case malformedHeader
    case invalidRootCount
    case unsupportedVersion
    case malformedFrame
    case invalidCID
    case blockCIDMismatch
    case commitBodyLimitExceeded
    case recordBodyLimitExceeded
    case commitDidNotVerify
    case malformedIndex
    case nonCanonicalIndex
    case duplicateIndexEntry
    case indexEntryLimitExceeded
    case uniqueBlockLimitExceeded
    case invalidRecordOrder
    case invalidRecordValue
    case unindexedBlocks
    case invalidExpectedWitness
    case expectedWitnessMismatch
    case commitmentMismatch
    case stagingUnavailable
}

extension SpaceCARCodec {
    /// Re-decodes the bounded signed-commit block during a network-free
    /// publication transaction. Signature verification remains the
    /// pre-staging verifier's job; this binds the immutable body to the
    /// stored target, wire revision, and commitment.
    public static func structurallyValidateRecoveryCommit(
        _ body: Data,
        space: SpaceURI,
        author: String
    ) throws -> SpaceCommitEnvelope {
        guard body.count <= SpaceCARRecoveryLimits.absoluteMaximumCommitBytes
        else {
            throw SpaceCARStreamingError.commitBodyLimitExceeded
        }
        let envelope: SpaceCommitEnvelope
        do {
            envelope = try decodeCommit(body, space: space, author: author)
            guard try encodeCommit(envelope) == body else {
                throw SpaceCARStreamingError.malformedFrame
            }
        } catch let error as SpaceCARStreamingError {
            throw error
        } catch {
            throw SpaceCARStreamingError.malformedFrame
        }
        return envelope
    }

    /// Validates the exact record representation accepted by permissioned CAR
    /// recovery and persistence. Storage callers must not trust a caller-
    /// supplied CID independently of the canonical DAG-CBOR bytes.
    public static func validateCanonicalRecord(
        _ value: Data,
        expectedCID: String
    ) throws {
        guard value.count <= SpaceCARRecoveryLimits.absoluteMaximumRecordBytes
        else {
            throw SpaceCARStreamingError.recordBodyLimitExceeded
        }
        let cid: CID
        do {
            cid = try CID.parse(expectedCID)
        } catch {
            throw SpaceCARStreamingError.invalidCID
        }
        guard expectedCID == cid.string,
              cid.codec == .dagCBOR,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length),
              CID.fromDAGCBOR(value) == cid else {
            throw SpaceCARStreamingError.blockCIDMismatch
        }
        try CanonicalSpaceRecordValidator.validate(value)
    }

    /// Strictly verifies a proposal-0016 two-root recovery without retaining
    /// the CAR, its DRISL index, or its record set. The first two frames must
    /// be the signed commit and DRISL roots. Each unique record CID then
    /// appears exactly once, ordered by the first lexical path that references
    /// it.
    public static func verifyStreamingRecovery(
        from source: any SpaceCARRecoveryByteSource,
        space: SpaceURI,
        author: String,
        contextSignatureVerifier: @Sendable (SpaceCommitEnvelope) throws -> Bool,
        index: any SpaceCARRecoveryIndex,
        recordSink: (any SpaceCARRecoveryRecordSink)? = nil,
        expectedEntries: [SpaceCARRecoveryIndexEntry] = [],
        limits: SpaceCARRecoveryLimits = .standard
    ) async throws -> VerifiedStreamingSpaceCARRecovery {
        let expectedWitnesses = try validatedExpectedWitnesses(expectedEntries)
        let reader = SpaceCARStreamingInput(
            source: source,
            maximumBytes: limits.maximumCARBytes
        )
        let headerLength = try await reader.readCanonicalVarint()
        guard headerLength <= UInt64(SpaceCARStreamingInput.maximumHeaderBytes) else {
            throw SpaceCARStreamingError.malformedHeader
        }
        let header = try await reader.readExactly(Int(headerLength))
        let roots = try parseStreamingRecoveryHeader(header)

        let commitFrame = try await readSmallStreamingFrame(
            from: reader,
            maximumBodyBytes: SpaceCARRecoveryLimits.absoluteMaximumCommitBytes,
            limitError: .commitBodyLimitExceeded
        )
        guard commitFrame.cid == roots.commit else {
            throw SpaceCARStreamingError.invalidRecordOrder
        }
        let envelope: SpaceCommitEnvelope
        do {
            envelope = try decodeCommit(
                commitFrame.body,
                space: space,
                author: author
            )
        } catch {
            throw SpaceCARStreamingError.malformedFrame
        }
        guard try encodeCommit(envelope) == commitFrame.body else {
            throw SpaceCARStreamingError.malformedFrame
        }
        guard try contextSignatureVerifier(envelope),
              SpaceCommitCodec.verifyContentBinding(envelope)
        else {
            throw SpaceCARStreamingError.commitDidNotVerify
        }
        let wireRevision: TID
        do {
            wireRevision = try TID(tidString: envelope.context.rev)
        } catch {
            throw SpaceCARStreamingError.malformedFrame
        }
        // Do not durably hand attacker-selected roots to staging until both
        // commit checks above have run. A failed first frame therefore leaves
        // no provisional root state for cleanup to reason about.
        //
        // Be precise about what those two checks establish, because it is
        // strictly less than "the author authorized this exact commit root":
        //
        //   * `contextSignatureVerifier` proves the author signed the tuple
        //     (space, author, rev, ikm) and nothing more. The content
        //     commitment is NOT among the signed bytes — see
        //     `SpaceCommitCodec.contextSigningBytes`, which covers only the
        //     "atproto-space-v1" domain plus those four length-prefixed
        //     fields.
        //   * `verifyContentBinding` proves only that whoever produced this
        //     envelope knew the IKM. The IKM is not a secret on this path: it
        //     ships in the clear as the `ikm` field of the wire commit block
        //     (`com.atproto.space.defs#signedCommit`). Any party that can
        //     serve, relay, or replay that block can therefore substitute a
        //     different commitment and recompute a valid MAC for it under the
        //     author's original, untouched signature.
        //
        // Exact-content integrity for permissioned repository content is
        // consequently delegated to the pinned HTTPS source origin, bounded
        // downstream by the equivocation / high-water checks in
        // `SQLitePermissionedRemoteReplicaRecovery`. That is a property of the
        // pinned upstream proposal-0016 trust model, not a Swan defect;
        // changing it requires an upstream amendment plus a coordinated
        // re-pin. `StreamingSpaceCARRecoveryTests` pins the substitution as
        // deliberate, tested behaviour so it is not "fixed" blind.
        try await recordSink?.receiveRoots(
            commit: roots.commit,
            index: roots.index
        )
        try await recordSink?.receiveCommit(
            cid: commitFrame.cid,
            body: commitFrame.body
        )

        let indexFrameLength = try await reader.readCanonicalVarint()
        guard indexFrameLength > UInt64(SpaceCARStreamingInput.cidByteCount),
              indexFrameLength <= UInt64(Int.max)
        else {
            throw SpaceCARStreamingError.malformedFrame
        }
        let indexCID = try parseStreamingCID(
            try await reader.readExactly(SpaceCARStreamingInput.cidByteCount)
        )
        guard indexCID == roots.index else {
            throw SpaceCARStreamingError.invalidRecordOrder
        }
        let indexBodyLength = Int(indexFrameLength) - SpaceCARStreamingInput.cidByteCount
        let frame = StreamingSpaceCARFrameBody(
            reader: reader,
            byteCount: indexBodyLength
        )
        var ltHash = LtHash()
        let indexSummary = try await parseStreamingDRISLIndex(
            from: frame,
            into: index,
            ltHash: &ltHash,
            expectedWitnesses: expectedWitnesses,
            maximumIndexEntries: limits.maximumIndexEntries
        )
        let indexedCount = indexSummary.indexedCount
        guard frame.remainingByteCount == 0 else {
            throw SpaceCARStreamingError.malformedIndex
        }
        let calculatedIndexCID = frame.finalizedDAGCBORCID()
        guard calculatedIndexCID == indexCID else {
            throw SpaceCARStreamingError.blockCIDMismatch
        }
        guard streamingConstantTimeEqual(
            ltHash.commitment,
            envelope.commitment
        ) else {
            throw SpaceCARStreamingError.commitmentMismatch
        }
        // Expected entries are an evidence assertion, not an authenticity
        // primitive. Authenticate the complete DRISL root and its signed
        // commitment first so a tampered/truncated response cannot forge an
        // expected-witness failure classification.
        guard !indexSummary.witnessMismatch,
              indexSummary.matchedWitnessCount == expectedWitnesses.count
        else {
            throw SpaceCARStreamingError.expectedWitnessMismatch
        }

        var consumedPathCount = 0
        var uniqueBlockCount = 0
        var logicalRestoredByteCount = 0
        while let frameLength = try await reader.readCanonicalVarintOrEOF() {
            try Task.checkCancellation()
            let (nextUniqueBlockCount, uniqueCountOverflow) =
                uniqueBlockCount.addingReportingOverflow(1)
            guard !uniqueCountOverflow,
                  nextUniqueBlockCount <= limits.maximumUniqueBlocks
            else {
                throw SpaceCARStreamingError.uniqueBlockLimitExceeded
            }
            uniqueBlockCount = nextUniqueBlockCount
            guard frameLength > UInt64(SpaceCARStreamingInput.cidByteCount),
                  frameLength <= UInt64(
                      SpaceCARStreamingInput.cidByteCount + limits.maximumRecordBytes
                  )
            else {
                throw SpaceCARStreamingError.recordBodyLimitExceeded
            }
            let cid = try parseStreamingCID(
                try await reader.readExactly(SpaceCARStreamingInput.cidByteCount)
            )
            guard let expected = try await index.nextUnconsumedLexicographicEntry(),
                  expected.cid == cid
            else {
                throw SpaceCARStreamingError.invalidRecordOrder
            }
            let bodyLength = Int(frameLength) - SpaceCARStreamingInput.cidByteCount
            try await recordSink?.beginRecord(
                cid: cid,
                byteCount: bodyLength
            )
            let recordFrame = StreamingSpaceCARFrameBody(
                reader: reader,
                byteCount: bodyLength,
                boundsError: .invalidRecordValue,
                recordCID: cid,
                recordSink: recordSink
            )
            try await StreamingCanonicalSpaceRecordValidator.validate(
                recordFrame
            )
            guard recordFrame.remainingByteCount == 0 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            guard recordFrame.finalizedDAGCBORCID() == cid else {
                throw SpaceCARStreamingError.blockCIDMismatch
            }
            let consumedForCID = try await index.consumeEntries(forCID: cid)
            let (nextCount, overflow) = consumedPathCount.addingReportingOverflow(
                consumedForCID
            )
            guard consumedForCID > 0, !overflow, nextCount <= indexedCount else {
                throw SpaceCARStreamingError.unindexedBlocks
            }
            let (logicalBytesForCID, productOverflow) =
                bodyLength.multipliedReportingOverflow(by: consumedForCID)
            let (nextLogicalRestoredByteCount, sumOverflow) =
                logicalRestoredByteCount.addingReportingOverflow(
                    logicalBytesForCID
                )
            guard !productOverflow,
                  !sumOverflow,
                  nextLogicalRestoredByteCount
                    <= limits.maximumLogicalRestoredBytes else {
                throw SpaceCARStreamingError.byteLimitExceeded
            }
            consumedPathCount = nextCount
            logicalRestoredByteCount = nextLogicalRestoredByteCount
            let chunkCount = try await recordFrame.finishRecordStaging()
            try await recordSink?.completeRecord(
                cid: cid,
                byteCount: bodyLength,
                chunkCount: chunkCount
            )
        }
        guard consumedPathCount == indexedCount,
              try await index.nextUnconsumedLexicographicEntry() == nil
        else {
            throw SpaceCARStreamingError.unindexedBlocks
        }
        return VerifiedStreamingSpaceCARRecovery(
            commitRootCID: roots.commit,
            indexRootCID: roots.index,
            wireRevision: wireRevision,
            recordCount: consumedPathCount,
            uniqueBlockCount: uniqueBlockCount,
            verifiedExpectedWitnessCount: indexSummary.matchedWitnessCount,
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment,
            commitBodyDigest: Data(SHA256.hash(data: commitFrame.body)),
            receivedByteCount: reader.receivedByteCount,
            logicalRestoredByteCount: logicalRestoredByteCount
        )
    }

    private static func validatedExpectedWitnesses(
        _ entries: [SpaceCARRecoveryIndexEntry]
    ) throws -> [String: CID] {
        // The live interop path needs one expected path/CID witness. Keep this
        // API useful for small assertions without turning it into another
        // caller-controlled repository index in process memory.
        guard entries.count <= 64 else {
            throw SpaceCARStreamingError.invalidExpectedWitness
        }
        var result: [String: CID] = [:]
        result.reserveCapacity(entries.count)
        for entry in entries {
            guard isRecordPath(entry.path),
                  entry.cid.bytes.count == SpaceCARStreamingInput.cidByteCount,
                  entry.cid.codec == .dagCBOR,
                  entry.cid.multihash.algorithm == Multihash.sha256Code,
                  entry.cid.multihash.length == Multihash.sha256Length,
                  entry.cid.multihash.digest.count
                    == Int(Multihash.sha256Length),
                  result.updateValue(entry.cid, forKey: entry.path) == nil
            else {
                throw SpaceCARStreamingError.invalidExpectedWitness
            }
        }
        return result
    }

    private static func parseStreamingRecoveryHeader(
        _ header: Data
    ) throws -> (commit: CID, index: CID) {
        // The profile permits only CIDv1/dag-cbor/sha256 roots, whose binary
        // form is exactly 36 bytes. That makes the canonical two-root header
        // one exact 99-byte schema.
        guard header.count == 99 else {
            throw SpaceCARStreamingError.invalidRootCount
        }
        guard header[0] == 0xa2,
              header[1] == 0x65,
              header[2 ..< 7] == Data("roots".utf8),
              header[7] == 0x82,
              header[8] == 0xd8,
              header[9] == 0x2a,
              header[10] == 0x58,
              header[11] == 0x25,
              header[12] == 0,
              header[49] == 0xd8,
              header[50] == 0x2a,
              header[51] == 0x58,
              header[52] == 0x25,
              header[53] == 0,
              header[90] == 0x67,
              header[91 ..< 98] == Data("version".utf8)
        else {
            throw SpaceCARStreamingError.malformedHeader
        }
        guard header[98] == 1 else {
            throw SpaceCARStreamingError.unsupportedVersion
        }
        let commit = try parseStreamingCID(Data(header[13 ..< 49]))
        let index = try parseStreamingCID(Data(header[54 ..< 90]))
        guard commit != index else {
            throw SpaceCARStreamingError.invalidRootCount
        }
        let canonical: Data
        do {
            canonical = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "roots", value: [
                    ATProtoLink(cid: commit),
                    ATProtoLink(cid: index),
                ]),
                (key: "version", value: 1),
            ]))
        } catch {
            throw SpaceCARStreamingError.malformedHeader
        }
        guard canonical == header else {
            throw SpaceCARStreamingError.malformedHeader
        }
        return (commit, index)
    }

    private static func readSmallStreamingFrame(
        from reader: SpaceCARStreamingInput,
        maximumBodyBytes: Int,
        limitError: SpaceCARStreamingError
    ) async throws -> (cid: CID, body: Data) {
        let frameLength = try await reader.readCanonicalVarint()
        guard frameLength > UInt64(SpaceCARStreamingInput.cidByteCount) else {
            throw SpaceCARStreamingError.malformedFrame
        }
        guard frameLength <= UInt64(
            SpaceCARStreamingInput.cidByteCount + maximumBodyBytes
        ) else {
            throw limitError
        }
        let cid = try parseStreamingCID(
            try await reader.readExactly(SpaceCARStreamingInput.cidByteCount)
        )
        let body = try await reader.readExactlyInChunks(
            Int(frameLength) - SpaceCARStreamingInput.cidByteCount
        )
        guard CID.fromDAGCBOR(body) == cid else {
            throw SpaceCARStreamingError.blockCIDMismatch
        }
        return (cid, body)
    }

    private static func parseStreamingDRISLIndex(
        from frame: StreamingSpaceCARFrameBody,
        into index: any SpaceCARRecoveryIndex,
        ltHash: inout LtHash,
        expectedWitnesses: [String: CID],
        maximumIndexEntries: Int
    ) async throws -> (
        indexedCount: Int,
        matchedWitnessCount: Int,
        witnessMismatch: Bool
    ) {
        let count = try await frame.readCanonicalCBORArgument(major: 5)
        guard count <= UInt64(maximumIndexEntries) else {
            throw SpaceCARStreamingError.indexEntryLimitExceeded
        }
        var previousKey: Data?
        var matchedWitnessCount = 0
        var witnessMismatch = false
        for _ in 0 ..< Int(count) {
            try Task.checkCancellation()
            let keyLength = try await frame.readCanonicalCBORArgument(major: 3)
            // The domain grammar caps this below 830 bytes. Reject before
            // allocating if a hostile index advertises anything larger.
            guard keyLength <= 1_024 else {
                throw SpaceCARStreamingError.malformedIndex
            }
            let keyBytes = try await frame.readExactly(Int(keyLength))
            guard let path = String(data: keyBytes, encoding: .utf8),
                  Data(path.utf8) == keyBytes,
                  isRecordPath(path)
            else {
                throw SpaceCARStreamingError.malformedIndex
            }
            if let previousKey {
                let isAfter = previousKey.count < keyBytes.count ||
                    (
                        previousKey.count == keyBytes.count &&
                            previousKey.lexicographicallyPrecedes(keyBytes)
                    )
                guard isAfter else {
                    throw SpaceCARStreamingError.nonCanonicalIndex
                }
            }
            previousKey = keyBytes

            guard try await frame.readExactly(2) == Data([0xd8, 0x2a]),
                  try await frame.readExactly(2) == Data([0x58, 0x25]),
                  try await frame.readExactly(1) == Data([0])
            else {
                throw SpaceCARStreamingError.malformedIndex
            }
            let cid = try parseStreamingCID(
                try await frame.readExactly(SpaceCARStreamingInput.cidByteCount)
            )
            let entry = SpaceCARRecoveryIndexEntry(path: path, cid: cid)
            try await index.insert(entry)
            ltHash.add(element: "\(path)/\(cid.string)")
            if let expectedCID = expectedWitnesses[path] {
                if expectedCID == cid {
                    matchedWitnessCount += 1
                } else {
                    witnessMismatch = true
                }
            }
        }
        return (Int(count), matchedWitnessCount, witnessMismatch)
    }

    private static func parseStreamingCID(_ bytes: Data) throws -> CID {
        guard bytes.count == SpaceCARStreamingInput.cidByteCount else {
            throw SpaceCARStreamingError.invalidCID
        }
        let cid: CID
        do {
            cid = try CID(bytes: bytes)
        } catch {
            throw SpaceCARStreamingError.invalidCID
        }
        guard cid.bytes == bytes,
              cid.codec == .dagCBOR,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length)
        else {
            throw SpaceCARStreamingError.invalidCID
        }
        return cid
    }
}

private final class SpaceCARStreamingInput {
    static let maximumHeaderBytes = 1_024
    static let cidByteCount = 36

    private let source: any SpaceCARRecoveryByteSource
    private let maximumBytes: Int
    private var buffer = Data()
    private var offset = 0
    private var receivedBytes = 0
    private var reachedEnd = false

    init(source: any SpaceCARRecoveryByteSource, maximumBytes: Int) {
        self.source = source
        self.maximumBytes = maximumBytes
    }

    var receivedByteCount: Int { receivedBytes }

    func readCanonicalVarint() async throws -> UInt64 {
        guard let value = try await readCanonicalVarintOrEOF() else {
            throw SpaceCARStreamingError.malformedVarint
        }
        return value
    }

    func readCanonicalVarintOrEOF() async throws -> UInt64? {
        guard let first = try await readByteOrEOF() else { return nil }
        var encoded = Data([first])
        var value = UInt64(first & 0x7f)
        var shift: UInt64 = 7
        var byte = first
        while byte & 0x80 != 0 {
            guard encoded.count < 10, shift < 64,
                  let next = try await readByteOrEOF()
            else {
                throw SpaceCARStreamingError.malformedVarint
            }
            byte = next
            encoded.append(byte)
            let portion = UInt64(byte & 0x7f)
            guard shift < 63 || portion <= 1 else {
                throw SpaceCARStreamingError.malformedVarint
            }
            value |= portion << shift
            shift += 7
        }
        guard Self.canonicalUnsignedVarint(value) == encoded else {
            throw SpaceCARStreamingError.nonCanonicalVarint
        }
        return value
    }

    func readExactly(_ count: Int) async throws -> Data {
        guard count >= 0 else {
            throw SpaceCARStreamingError.malformedFrame
        }
        while availableByteCount < count {
            guard try await fill(
                maximumBytes: min(
                    SpaceCARRecoveryLimits.maximumChunkBytes,
                    count - availableByteCount
                )
            ) else {
                throw SpaceCARStreamingError.malformedFrame
            }
        }
        let result = Data(buffer[offset ..< offset + count])
        offset += count
        compactIfNeeded()
        return result
    }

    func readExactlyInChunks(_ count: Int) async throws -> Data {
        guard count >= 0 else {
            throw SpaceCARStreamingError.malformedFrame
        }
        var output = Data()
        output.reserveCapacity(count)
        var remaining = count
        while remaining > 0 {
            let amount = min(
                remaining,
                SpaceCARRecoveryLimits.maximumChunkBytes
            )
            output.append(try await readExactly(amount))
            remaining -= amount
        }
        return output
    }

    private var availableByteCount: Int {
        buffer.count - offset
    }

    private func readByteOrEOF() async throws -> UInt8? {
        while availableByteCount == 0 {
            guard try await fill(maximumBytes: 1) else { return nil }
        }
        let byte = buffer[offset]
        offset += 1
        compactIfNeeded()
        return byte
    }

    private func fill(maximumBytes requested: Int) async throws -> Bool {
        try Task.checkCancellation()
        guard !reachedEnd else { return false }
        compactBeforeAppend()
        let remaining = maximumBytes - receivedBytes
        if remaining == 0 {
            guard let overflow = try await source.read(maximumBytes: 1) else {
                reachedEnd = true
                return false
            }
            guard !overflow.isEmpty, overflow.count <= 1 else {
                throw SpaceCARStreamingError.invalidChunk
            }
            throw SpaceCARStreamingError.byteLimitExceeded
        }
        let request = min(
            max(1, requested),
            min(SpaceCARRecoveryLimits.maximumChunkBytes, remaining)
        )
        guard let chunk = try await source.read(maximumBytes: request) else {
            reachedEnd = true
            return false
        }
        guard !chunk.isEmpty, chunk.count <= request else {
            throw SpaceCARStreamingError.invalidChunk
        }
        buffer.append(chunk)
        receivedBytes += chunk.count
        return true
    }

    private func compactBeforeAppend() {
        guard offset > 0 else { return }
        if offset == buffer.count {
            buffer.removeAll(keepingCapacity: true)
        } else {
            buffer = Data(buffer[offset...])
        }
        offset = 0
    }

    private func compactIfNeeded() {
        guard offset == buffer.count ||
            offset >= SpaceCARRecoveryLimits.maximumChunkBytes
        else { return }
        compactBeforeAppend()
    }

    private static func canonicalUnsignedVarint(_ value: UInt64) -> Data {
        var remaining = value
        var result = Data()
        repeat {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            result.append(byte)
        } while remaining != 0
        return result
    }
}

private final class StreamingSpaceCARFrameBody {
    private let reader: SpaceCARStreamingInput
    private let boundsError: SpaceCARStreamingError
    private var hasher = SHA256()
    private(set) var remainingByteCount: Int
    private var finalizedCID: CID?
    private let recordCID: CID?
    private let recordSink: (any SpaceCARRecoveryRecordSink)?
    private var recordChunkBuffer = Data()
    private var nextRecordChunkIndex = 0

    init(
        reader: SpaceCARStreamingInput,
        byteCount: Int,
        boundsError: SpaceCARStreamingError = .malformedIndex,
        recordCID: CID? = nil,
        recordSink: (any SpaceCARRecoveryRecordSink)? = nil
    ) {
        self.reader = reader
        self.boundsError = boundsError
        self.recordCID = recordCID
        self.recordSink = recordSink
        remainingByteCount = byteCount
        recordChunkBuffer.reserveCapacity(
            SpaceCARRecoveryLimits.maximumChunkBytes
        )
    }

    func readExactly(_ count: Int) async throws -> Data {
        guard count >= 0, count <= remainingByteCount else {
            throw boundsError
        }
        let bytes = try await reader.readExactly(count)
        hasher.update(data: bytes)
        remainingByteCount -= count
        try await stageRecordBytes(bytes)
        return bytes
    }

    func finishRecordStaging() async throws -> Int {
        guard remainingByteCount == 0 else { throw boundsError }
        if !recordChunkBuffer.isEmpty {
            try await flushRecordChunk()
        }
        return nextRecordChunkIndex
    }

    func readCanonicalCBORArgument(major: UInt8) async throws -> UInt64 {
        let first = try await readExactly(1)[0]
        guard first >> 5 == major else {
            throw SpaceCARStreamingError.malformedIndex
        }
        let additional = first & 0x1f
        switch additional {
        case 0 ... 23:
            return UInt64(additional)
        case 24:
            let value = UInt64(try await readExactly(1)[0])
            guard value >= 24 else {
                throw SpaceCARStreamingError.nonCanonicalIndex
            }
            return value
        case 25:
            let value = try await readBigEndianInteger(byteCount: 2)
            guard value > UInt64(UInt8.max) else {
                throw SpaceCARStreamingError.nonCanonicalIndex
            }
            return value
        case 26:
            let value = try await readBigEndianInteger(byteCount: 4)
            guard value > UInt64(UInt16.max) else {
                throw SpaceCARStreamingError.nonCanonicalIndex
            }
            return value
        case 27:
            let value = try await readBigEndianInteger(byteCount: 8)
            guard value > UInt64(UInt32.max) else {
                throw SpaceCARStreamingError.nonCanonicalIndex
            }
            return value
        default:
            throw SpaceCARStreamingError.malformedIndex
        }
    }

    func finalizedDAGCBORCID() -> CID {
        if let finalizedCID { return finalizedCID }
        let cid = CID(
            codec: .dagCBOR,
            multihash: .init(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: Data(hasher.finalize())
            )
        )
        finalizedCID = cid
        return cid
    }

    private func readBigEndianInteger(byteCount: Int) async throws -> UInt64 {
        let bytes = try await readExactly(byteCount)
        return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    private func stageRecordBytes(_ bytes: Data) async throws {
        guard recordSink != nil else { return }
        var offset = bytes.startIndex
        while offset < bytes.endIndex {
            let available = SpaceCARRecoveryLimits.maximumChunkBytes
                - recordChunkBuffer.count
            let remaining = bytes.distance(from: offset, to: bytes.endIndex)
            let amount = min(available, remaining)
            let end = bytes.index(offset, offsetBy: amount)
            recordChunkBuffer.append(contentsOf: bytes[offset ..< end])
            offset = end
            if recordChunkBuffer.count
                == SpaceCARRecoveryLimits.maximumChunkBytes
            {
                try await flushRecordChunk()
            }
        }
    }

    private func flushRecordChunk() async throws {
        guard let recordCID, let recordSink,
              !recordChunkBuffer.isEmpty else { return }
        let chunk = recordChunkBuffer
        recordChunkBuffer.removeAll(keepingCapacity: true)
        try await recordSink.appendRecordChunk(
            cid: recordCID,
            chunkIndex: nextRecordChunkIndex,
            bytes: chunk
        )
        nextRecordChunkIndex += 1
    }
}

private func streamingConstantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for index in lhs.indices {
        difference |= lhs[index] ^ rhs[index]
    }
    return difference == 0
}

/// Canonical DAG-CBOR validation over the record frame itself. Large byte and
/// text strings are consumed in 64 KiB chunks, so validating 100,000 distinct
/// near-limit records cannot leave one ~1 MiB allocation behind per frame.
private struct StreamingCanonicalSpaceRecordValidator {
    private static let maximumDepth = 64
    private static let maximumMapKeyBytes = 1_024
    private static let maximumSafeInteger: UInt64 = 9_007_199_254_740_991

    private let frame: StreamingSpaceCARFrameBody

    static func validate(
        _ frame: StreamingSpaceCARFrameBody
    ) async throws {
        var parser = Self(frame: frame)
        try await parser.readMap(depth: 1)
    }

    private mutating func readValue(depth: Int) async throws {
        guard depth <= Self.maximumDepth,
              frame.remainingByteCount > 0
        else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        let initial = try await frame.readExactly(1)[0]
        switch initial >> 5 {
        case 0:
            guard try await readArgument(initial: initial)
                    <= Self.maximumSafeInteger
            else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        case 1:
            guard try await readArgument(initial: initial)
                    < Self.maximumSafeInteger
            else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        case 2:
            let count = try await readLength(initial: initial)
            try await discard(byteCount: count)
        case 3:
            let count = try await readLength(initial: initial)
            try await validateUTF8(byteCount: count)
        case 4:
            let count = try await readLength(initial: initial)
            guard count <= frame.remainingByteCount else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            for _ in 0 ..< count {
                try await readValue(depth: depth + 1)
            }
        case 5:
            try await readMap(initial: initial, depth: depth + 1)
        case 6:
            guard try await readArgument(initial: initial) == 42 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let bytesInitial = try await frame.readExactly(1)[0]
            guard bytesInitial >> 5 == 2,
                  try await readLength(initial: bytesInitial) == 37
            else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let payload = try await frame.readExactly(37)
            guard payload.first == 0 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let cidBytes = Data(payload.dropFirst())
            let cid: CID
            do {
                cid = try CID(bytes: cidBytes)
            } catch {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            guard cid.bytes == cidBytes,
                  cid.codec == .raw || cid.codec == .dagCBOR,
                  cid.multihash.algorithm == Multihash.sha256Code,
                  cid.multihash.length == Multihash.sha256Length,
                  cid.multihash.digest.count == Int(Multihash.sha256Length)
            else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        case 7:
            guard initial == 0xf4 || initial == 0xf5 || initial == 0xf6 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        default:
            throw SpaceCARStreamingError.invalidRecordValue
        }
    }

    private mutating func readMap(depth: Int) async throws {
        guard depth <= Self.maximumDepth,
              frame.remainingByteCount > 0
        else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        let initial = try await frame.readExactly(1)[0]
        guard initial >> 5 == 5 else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        try await readMap(initial: initial, depth: depth)
    }

    private mutating func readMap(
        initial: UInt8,
        depth: Int
    ) async throws {
        guard depth <= Self.maximumDepth else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        let count = try await readLength(initial: initial)
        guard count <= frame.remainingByteCount / 2 else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        var previousKey: Data?
        for _ in 0 ..< count {
            let keyInitial = try await frame.readExactly(1)[0]
            guard keyInitial >> 5 == 3 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let keyLength = try await readLength(initial: keyInitial)
            guard keyLength <= Self.maximumMapKeyBytes else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let keyBytes = try await frame.readExactly(keyLength)
            guard String(data: keyBytes, encoding: .utf8) != nil else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            if let previousKey {
                let canonical = previousKey.count < keyBytes.count
                    || (
                        previousKey.count == keyBytes.count
                            && previousKey.lexicographicallyPrecedes(keyBytes)
                    )
                guard canonical else {
                    throw SpaceCARStreamingError.invalidRecordValue
                }
            }
            previousKey = keyBytes
            try await readValue(depth: depth)
        }
    }

    private mutating func readLength(initial: UInt8) async throws -> Int {
        let value = try await readArgument(initial: initial)
        guard value <= UInt64(Int.max) else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        return Int(value)
    }

    private mutating func readArgument(initial: UInt8) async throws -> UInt64 {
        switch initial & 0x1f {
        case 0 ... 23:
            return UInt64(initial & 0x1f)
        case 24:
            let value = UInt64(try await frame.readExactly(1)[0])
            guard value >= 24 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        case 25:
            let value = try await readFixed(byteCount: 2)
            guard value > UInt64(UInt8.max) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        case 26:
            let value = try await readFixed(byteCount: 4)
            guard value > UInt64(UInt16.max) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        case 27:
            let value = try await readFixed(byteCount: 8)
            guard value > UInt64(UInt32.max) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        default:
            throw SpaceCARStreamingError.invalidRecordValue
        }
    }

    private mutating func readFixed(byteCount: Int) async throws -> UInt64 {
        let bytes = try await frame.readExactly(byteCount)
        return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    private mutating func discard(byteCount: Int) async throws {
        guard byteCount <= frame.remainingByteCount else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        var remaining = byteCount
        while remaining > 0 {
            let amount = min(
                remaining,
                SpaceCARRecoveryLimits.maximumChunkBytes
            )
            _ = try await frame.readExactly(amount)
            remaining -= amount
        }
    }

    private mutating func validateUTF8(byteCount: Int) async throws {
        guard byteCount <= frame.remainingByteCount else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        var validator = StreamingUTF8Validator()
        var remaining = byteCount
        while remaining > 0 {
            let amount = min(
                remaining,
                SpaceCARRecoveryLimits.maximumChunkBytes
            )
            let bytes = try await frame.readExactly(amount)
            guard validator.consume(bytes) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            remaining -= amount
        }
        guard validator.isComplete else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
    }
}

private struct StreamingUTF8Validator {
    private var remainingContinuationBytes = 0
    private var scalar: UInt32 = 0
    private var minimumScalar: UInt32 = 0

    var isComplete: Bool { remainingContinuationBytes == 0 }

    mutating func consume(_ bytes: Data) -> Bool {
        for byte in bytes {
            if remainingContinuationBytes == 0 {
                switch byte {
                case 0x00 ... 0x7f:
                    continue
                case 0xc2 ... 0xdf:
                    remainingContinuationBytes = 1
                    scalar = UInt32(byte & 0x1f)
                    minimumScalar = 0x80
                case 0xe0 ... 0xef:
                    remainingContinuationBytes = 2
                    scalar = UInt32(byte & 0x0f)
                    minimumScalar = 0x800
                case 0xf0 ... 0xf4:
                    remainingContinuationBytes = 3
                    scalar = UInt32(byte & 0x07)
                    minimumScalar = 0x1_0000
                default:
                    return false
                }
                continue
            }
            guard byte >= 0x80, byte <= 0xbf else { return false }
            scalar = (scalar << 6) | UInt32(byte & 0x3f)
            remainingContinuationBytes -= 1
            if remainingContinuationBytes == 0 {
                guard scalar >= minimumScalar,
                      scalar <= 0x10_ffff,
                      !(0xd800 ... 0xdfff).contains(scalar)
                else {
                    return false
                }
            }
        }
        return true
    }
}

/// Direct validation avoids the JSON bridge used by the convenience Petrel
/// decoder, which can normalize integer widths or typed-object framing. It
/// accepts only the canonical AT data-model subset and a top-level map.
struct CanonicalSpaceRecordValidator {
    private static let maximumDepth = 64
    private static let maximumMapKeyBytes = 1_024
    private static let maximumSafeInteger: UInt64 = 9_007_199_254_740_991

    private let bytes: Data
    private var offset = 0

    static func validate(_ data: Data) throws {
        var parser = Self(bytes: data)
        try parser.readMap(depth: 1)
        guard parser.offset == data.count else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
    }

    private mutating func readValue(depth: Int) throws {
        guard depth <= Self.maximumDepth, offset < bytes.count else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        switch bytes[offset] >> 5 {
        case 0:
            guard try readArgument(major: 0) <= Self.maximumSafeInteger else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        case 1:
            guard try readArgument(major: 1) < Self.maximumSafeInteger else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        case 2:
            try skipData(major: 2)
        case 3:
            _ = try readText(maximumBytes: bytes.count)
        case 4:
            let count = try readLength(major: 4)
            guard count <= bytes.count - offset else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            for _ in 0 ..< count {
                try readValue(depth: depth + 1)
            }
        case 5:
            try readMap(depth: depth + 1)
        case 6:
            guard try readArgument(major: 6) == 42 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let payload = try readData(major: 2, maximumBytes: 37)
            guard payload.count == 37, payload.first == 0 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            let cid: CID
            do {
                cid = try CID(bytes: Data(payload.dropFirst()))
            } catch {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            guard cid.bytes == Data(payload.dropFirst()),
                  cid.codec == .raw || cid.codec == .dagCBOR,
                  cid.multihash.algorithm == Multihash.sha256Code,
                  cid.multihash.length == Multihash.sha256Length,
                  cid.multihash.digest.count == Int(Multihash.sha256Length)
            else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
        case 7:
            let value = bytes[offset]
            guard value == 0xf4 || value == 0xf5 || value == 0xf6 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            offset += 1
        default:
            throw SpaceCARStreamingError.invalidRecordValue
        }
    }

    private mutating func readMap(depth: Int) throws {
        guard depth <= Self.maximumDepth else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        let count = try readLength(major: 5)
        guard count <= (bytes.count - offset) / 2 else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        var previousKey: Data?
        for _ in 0 ..< count {
            let key = try readText(maximumBytes: Self.maximumMapKeyBytes)
            let keyBytes = Data(key.utf8)
            if let previousKey {
                let canonical = previousKey.count < keyBytes.count ||
                    (
                        previousKey.count == keyBytes.count &&
                            previousKey.lexicographicallyPrecedes(keyBytes)
                    )
                guard canonical else {
                    throw SpaceCARStreamingError.invalidRecordValue
                }
            }
            previousKey = keyBytes
            try readValue(depth: depth)
        }
    }

    private mutating func readText(maximumBytes: Int) throws -> String {
        let data = try readData(major: 3, maximumBytes: maximumBytes)
        guard let value = String(data: data, encoding: .utf8),
              Data(value.utf8) == data else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        return value
    }

    private mutating func skipData(major: UInt8) throws {
        let count = try readLength(major: major)
        guard count <= bytes.count - offset else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        offset += count
    }

    private mutating func readData(
        major: UInt8,
        maximumBytes: Int
    ) throws -> Data {
        let count = try readLength(major: major)
        guard count <= maximumBytes, count <= bytes.count - offset else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        let result = Data(bytes[offset ..< offset + count])
        offset += count
        return result
    }

    private mutating func readLength(major: UInt8) throws -> Int {
        let value = try readArgument(major: major)
        guard value <= UInt64(Int.max) else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        return Int(value)
    }

    private mutating func readArgument(major: UInt8) throws -> UInt64 {
        guard offset < bytes.count else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        let initial = bytes[offset]
        offset += 1
        guard initial >> 5 == major else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        switch initial & 0x1f {
        case 0 ... 23:
            return UInt64(initial & 0x1f)
        case 24:
            let value = try readFixed(byteCount: 1)
            guard value >= 24 else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        case 25:
            let value = try readFixed(byteCount: 2)
            guard value > UInt64(UInt8.max) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        case 26:
            let value = try readFixed(byteCount: 4)
            guard value > UInt64(UInt16.max) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        case 27:
            let value = try readFixed(byteCount: 8)
            guard value > UInt64(UInt32.max) else {
                throw SpaceCARStreamingError.invalidRecordValue
            }
            return value
        default:
            throw SpaceCARStreamingError.invalidRecordValue
        }
    }

    private mutating func readFixed(byteCount: Int) throws -> UInt64 {
        guard byteCount <= bytes.count - offset else {
            throw SpaceCARStreamingError.invalidRecordValue
        }
        var value: UInt64 = 0
        for byte in bytes[offset ..< offset + byteCount] {
            value = (value << 8) | UInt64(byte)
        }
        offset += byteCount
        return value
    }
}
