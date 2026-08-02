import Foundation
import Petrel

public enum StatefulFaultMode: String, Codable, Sendable, CaseIterable {
    case normal
    case offline
    case disconnected
    case delayed
    case duplicated
    case reordered
    case corrupted
}

/// Secret-free durable replica state used by the cross-host fault matrix.
/// DIDs, space URIs, record values, credentials, and raw LtHash state are
/// intentionally excluded.
public struct StatefulReplicaHeadWitness: Encodable, Sendable, Equatable {
    public let generation: UInt64
    public let revision: String
    public let commitment: String

    public init?(generation: UInt64, revision: String, commitment: String) {
        guard generation > 0,
              generation <= UInt64(Int.max),
              (try? TID(tidString: revision)) != nil,
              let commitment = FixtureSanitizer.canonicalSHA256Hex(commitment)
        else { return nil }
        self.generation = generation
        self.revision = revision
        self.commitment = commitment
    }
}

/// One stateful cross-host fault cell. The initializer derives its verdict
/// from durable head witnesses rather than accepting a caller-provided
/// `passed` Boolean.
public struct StatefulFaultInteropCell: Encodable, Sendable, Equatable {
    public let mode: StatefulFaultMode
    public let before: StatefulReplicaHeadWitness?
    public let intended: StatefulReplicaHeadWitness
    public let afterFault: StatefulReplicaHeadWitness?
    public let afterHeal: StatefulReplicaHeadWitness?
    public let faultObserved: Bool
    public let invalidDeliveryRejected: Bool
    public let assertions: [StatefulInteropAssertion]
    public let status: String

    public init(
        mode: StatefulFaultMode,
        before: StatefulReplicaHeadWitness?,
        intended: StatefulReplicaHeadWitness,
        afterFault: StatefulReplicaHeadWitness?,
        afterHeal: StatefulReplicaHeadWitness?,
        faultObserved: Bool,
        invalidDeliveryRejected: Bool
    ) {
        self.mode = mode
        self.before = before
        self.intended = intended
        self.afterFault = afterFault
        self.afterHeal = afterHeal
        self.faultObserved = faultObserved
        self.invalidDeliveryRejected = invalidDeliveryRejected

        let preservesBefore = before == afterFault
        let reachesIntendedDuringFault = afterFault == intended
        let healsToIntended = afterHeal == intended
        let advancesIncrementally = Self.advancesIncrementally(
            from: before,
            to: afterFault
        )
        let modeAssertions: [StatefulInteropAssertion]
        switch mode {
        case .normal:
            modeAssertions = [
                .init(name: "fault-cell-reached-intended-head", passed: reachesIntendedDuringFault),
                .init(name: "fault-cell-healed-head-matches", passed: healsToIntended),
            ]
        case .delayed:
            modeAssertions = [
                .init(name: "delay-observed", passed: faultObserved),
                .init(name: "delayed-delivery-reached-intended-head", passed: reachesIntendedDuringFault),
                .init(name: "delayed-healed-head-matches", passed: healsToIntended),
            ]
        case .offline, .disconnected:
            modeAssertions = [
                .init(name: "outage-observed", passed: faultObserved),
                .init(name: "outage-had-last-good-head", passed: before != nil),
                .init(name: "outage-preserved-last-good-head", passed: preservesBefore),
                .init(name: "outage-healed-to-intended-head", passed: healsToIntended),
            ]
        case .duplicated:
            modeAssertions = [
                .init(name: "duplicate-observed", passed: faultObserved),
                .init(name: "duplicate-delivery-idempotent", passed: invalidDeliveryRejected),
                .init(name: "duplicate-had-last-good-head", passed: before != nil),
                .init(name: "duplicate-advanced-in-place", passed: advancesIncrementally),
                .init(name: "duplicate-terminal-head-matches", passed: reachesIntendedDuringFault),
                .init(name: "duplicate-healed-head-matches", passed: healsToIntended),
            ]
        case .reordered:
            modeAssertions = [
                .init(name: "reordering-observed", passed: faultObserved),
                .init(name: "stale-delivery-rejected", passed: invalidDeliveryRejected),
                .init(name: "reordering-had-last-good-head", passed: before != nil),
                .init(name: "future-delivery-preserved-last-good-head", passed: preservesBefore),
                .init(name: "reordering-healed-head-matches", passed: healsToIntended),
            ]
        case .corrupted:
            modeAssertions = [
                .init(name: "corruption-observed", passed: faultObserved),
                .init(name: "corruption-rejected", passed: invalidDeliveryRejected),
                .init(name: "corruption-had-last-good-head", passed: before != nil),
                .init(name: "corruption-preserved-last-good-head", passed: preservesBefore),
                .init(name: "corruption-healed-to-intended-head", passed: healsToIntended),
            ]
        }
        assertions = modeAssertions
        status = modeAssertions.allSatisfy(\.passed) ? "passed" : "failed"
    }

    private static func advancesIncrementally(
        from before: StatefulReplicaHeadWitness?,
        to after: StatefulReplicaHeadWitness?
    ) -> Bool {
        guard let before, let after else { return false }
        return after.generation == before.generation
            && after.revision != before.revision
            && after.commitment != before.commitment
    }
}

public struct StatefulFaultInteropMatrixArtifact:
    Encodable, Sendable, Equatable
{
    public let scenario: String
    public let profileID: String
    public let kind: String
    public let cells: [StatefulFaultInteropCell]
    public let status: String

    public init(scenario: String, cells: [StatefulFaultInteropCell]) {
        self.scenario = FixtureSanitizer.safeIdentifier(scenario)
        profileID = OfflineProtocolProfileVerifier.stableProfileID
        kind = "stateful-cross-host-fault-matrix"
        self.cells = cells
        let exactModes = Set(cells.map(\.mode)) == Set(StatefulFaultMode.allCases)
            && cells.count == StatefulFaultMode.allCases.count
        status = exactModes && cells.allSatisfy { $0.status == "passed" }
            ? "passed"
            : "failed"
    }
}
