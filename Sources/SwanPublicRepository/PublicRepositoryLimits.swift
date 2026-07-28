/// Resource limits shared by the public repository mutation and import paths.
///
/// `maximumWrites` and `maximumRelevantBlockBytes` are frozen interoperability
/// bounds from the pinned atproto implementation. The remaining values are
/// explicit Swan hostile-input policy and may only be tightened or enlarged
/// within the documented construction bounds.
public struct PublicRepositoryLimits: Sendable, Equatable {
    /// Pinned maximum writes in one atomic repository request.
    public static let pinnedMaximumWrites = 200

    /// Pinned maximum aggregate bytes in new/relevant commit blocks.
    public static let pinnedMaximumRelevantBlockBytes = 2_000_000

    /// The acceptance suite requires a 256 MiB CAR to stream successfully.
    public static let requiredStreamingCARBytes = 256 * 1_024 * 1_024

    /// Initial Swan hostile-import policy.
    public static let standard = try! PublicRepositoryLimits(
        maximumRecordBlockBytes: 1_000_000,
        maximumCARBytes: 512 * 1_024 * 1_024,
        maximumCARBlocks: 1_000_000,
        maximumMSTNodes: 500_000,
        maximumMSTEntriesPerNode: 4_096,
        maximumCBORNestingDepth: 64
    )

    public let maximumWrites: Int
    public let maximumRelevantBlockBytes: Int
    public let maximumRecordBlockBytes: Int
    public let maximumCARBytes: Int
    public let maximumCARBlocks: Int
    public let maximumMSTNodes: Int
    public let maximumMSTEntriesPerNode: Int
    public let maximumCBORNestingDepth: Int

    /// Constructs a bounded Swan policy while preserving the pinned protocol
    /// limits. Custom policies can reduce most work budgets; the CAR byte
    /// budget cannot fall below the required 256 MiB streaming acceptance
    /// case.
    public init(
        maximumRecordBlockBytes: Int,
        maximumCARBytes: Int,
        maximumCARBlocks: Int,
        maximumMSTNodes: Int,
        maximumMSTEntriesPerNode: Int,
        maximumCBORNestingDepth: Int
    ) throws {
        guard (1...Self.maximumPermittedRecordBlockBytes).contains(maximumRecordBlockBytes) else {
            throw PublicRepositoryLimitError.maximumRecordBlockBytesOutOfRange
        }
        guard (Self.requiredStreamingCARBytes...Self.maximumPermittedCARBytes).contains(maximumCARBytes) else {
            throw PublicRepositoryLimitError.maximumCARBytesOutOfRange
        }
        guard (1...Self.maximumPermittedCARBlocks).contains(maximumCARBlocks) else {
            throw PublicRepositoryLimitError.maximumCARBlocksOutOfRange
        }
        guard (1...Self.maximumPermittedMSTNodes).contains(maximumMSTNodes) else {
            throw PublicRepositoryLimitError.maximumMSTNodesOutOfRange
        }
        guard maximumMSTNodes <= maximumCARBlocks else {
            throw PublicRepositoryLimitError.mstNodesExceedCARBlocks
        }
        guard (1...Self.maximumPermittedMSTEntriesPerNode).contains(maximumMSTEntriesPerNode) else {
            throw PublicRepositoryLimitError.maximumMSTEntriesPerNodeOutOfRange
        }
        guard (1...Self.maximumPermittedCBORNestingDepth).contains(maximumCBORNestingDepth) else {
            throw PublicRepositoryLimitError.maximumCBORNestingDepthOutOfRange
        }

        maximumWrites = Self.pinnedMaximumWrites
        maximumRelevantBlockBytes = Self.pinnedMaximumRelevantBlockBytes
        self.maximumRecordBlockBytes = maximumRecordBlockBytes
        self.maximumCARBytes = maximumCARBytes
        self.maximumCARBlocks = maximumCARBlocks
        self.maximumMSTNodes = maximumMSTNodes
        self.maximumMSTEntriesPerNode = maximumMSTEntriesPerNode
        self.maximumCBORNestingDepth = maximumCBORNestingDepth
    }

    /// A finite ceiling keeps frame-count arithmetic and operational policy
    /// reviewable even on 64-bit platforms where `Int.max` is much larger.
    public static let maximumPermittedRecordBlockBytes = 1_000_000
    public static let maximumPermittedCARBytes = 4 * 1_024 * 1_024 * 1_024
    public static let maximumPermittedCARBlocks = 1_000_000
    public static let maximumPermittedMSTNodes = 500_000
    public static let maximumPermittedMSTEntriesPerNode = 4_096
    public static let maximumPermittedCBORNestingDepth = 64
}

public enum PublicRepositoryLimitError: Error, Sendable, Equatable {
    case maximumRecordBlockBytesOutOfRange
    case maximumCARBytesOutOfRange
    case maximumCARBlocksOutOfRange
    case maximumMSTNodesOutOfRange
    case mstNodesExceedCARBlocks
    case maximumMSTEntriesPerNodeOutOfRange
    case maximumCBORNestingDepthOutOfRange
}
