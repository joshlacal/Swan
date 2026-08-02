import Foundation
import Petrel
import SwanSpaces

/// A named assertion in the stateful alpha evidence. The value is deliberately
/// summary-only: selectors, credentials, and record values stay in the live
/// runner and never reach the persisted result.
public struct StatefulInteropAssertion: Codable, Sendable, Equatable {
    public let name: String
    public let passed: Bool

    public init(name: String, passed: Bool) {
        self.name = FixtureSanitizer.sanitize(["assertion": name])["assertion"] ?? "<redacted>"
        self.passed = passed
    }
}

/// A real, stateful permissioned-data alpha result. It embeds the sanitized
/// live round-trip evidence and makes every required transition explicit:
/// write/read CID convergence, incremental operation revision + CID,
/// reconstructed signed commitment, and full-CAR recovery.
public struct StatefulInteropMatrixArtifact: Codable, Sendable, Equatable {
    public let scenario: String
    public let profileID: String
    public let kind: String
    public let assertions: [StatefulInteropAssertion]
    public let roundTrip: LiveInteropPermissionedRoundTripArtifact
    public let status: String

    public init(
        scenario: String,
        assertions: [StatefulInteropAssertion],
        roundTrip: LiveInteropPermissionedRoundTripArtifact
    ) {
        self.scenario = FixtureSanitizer.sanitize(["scenario": scenario])["scenario"] ?? "<redacted>"
        self.profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.kind = "stateful-permissioned-alpha"
        self.assertions = assertions
        self.roundTrip = roundTrip
        self.status = assertions.allSatisfy(\.passed) ? "passed" : "failed"
    }
}

/// Executes the live create/read path with both terminal-state verifiers
/// enabled. This is intentionally a wrapper, not a second protocol client:
/// the same credential exchange, request binding, CAR streaming, and crypto
/// verification used by the live runner remain the source of truth.
public enum StatefulInteropMatrixRunner {
    public static func execute(
        scenario: String,
        member: LiveInteropHost,
        authority: LiveInteropHost,
        broker: SpaceCredentialBroker,
        space: SpaceURI,
        createBody: Data,
        readQuery: [String: String],
        blobBody: Data? = nil,
        readHost: LiveInteropHost? = nil,
        includeIncrementalValues: Bool = true,
        clientAttestation: String? = nil,
        recorder: InteropFixtureRecorder? = nil
    ) async -> StatefulInteropMatrixArtifact {
        let roundTrip = await LiveInteropRunner.permissionedCreateAndRead(
            scenario: scenario,
            member: member,
            authority: authority,
            broker: broker,
            space: space,
            createBody: createBody,
            readQuery: readQuery,
            blobBody: blobBody,
            readHost: readHost,
            verifyIncrementalSync: true,
            includeIncrementalValues: includeIncrementalValues,
            verifyFullCAR: true,
            clientAttestation: clientAttestation,
            recorder: recorder
        )
        return evaluate(scenario: scenario, roundTrip: roundTrip)
    }

    /// Public for deterministic unit tests and for consumers that obtain a
    /// live artifact through another controlled process.
    public static func evaluate(
        scenario: String,
        roundTrip: LiveInteropPermissionedRoundTripArtifact
    ) -> StatefulInteropMatrixArtifact {
        let evidenceAssertions = [
            StatefulInteropAssertion(name: "credential-issued", passed: roundTrip.credentialIssued),
            StatefulInteropAssertion(name: "write-status-success", passed: isSuccessful(roundTrip.writeStatus)),
            StatefulInteropAssertion(name: "read-status-success", passed: isSuccessful(roundTrip.readStatus)),
            StatefulInteropAssertion(name: "error-code-absent", passed: roundTrip.errorCode == nil),
            StatefulInteropAssertion(name: "write-read-cid-match", passed: roundTrip.writeCID != nil && roundTrip.writeCID == roundTrip.readCID),
            StatefulInteropAssertion(name: "sync-status-success", passed: isSuccessful(roundTrip.syncStatus)),
            StatefulInteropAssertion(name: "sync-operation-cid-matches-write", passed: roundTrip.writeCID != nil && roundTrip.writeCID == roundTrip.syncOperationCID),
            StatefulInteropAssertion(name: "sync-operation-revision-recorded", passed: !(roundTrip.syncOperationRevision?.isEmpty ?? true)),
            StatefulInteropAssertion(name: "sync-operation-revision-is-tid", passed: roundTrip.syncOperationRevision.flatMap { try? TID(tidString: $0) } != nil),
            StatefulInteropAssertion(name: "sync-values-included", passed: roundTrip.syncValuesIncluded == true),
            StatefulInteropAssertion(name: "sync-commitment-recorded", passed: !(roundTrip.syncCommitment?.isEmpty ?? true)),
            StatefulInteropAssertion(name: "sync-commit-revision-recorded", passed: !(roundTrip.syncCommitRevision?.isEmpty ?? true)),
            StatefulInteropAssertion(name: "sync-commit-revision-is-tid", passed: roundTrip.syncCommitRevision.flatMap { try? TID(tidString: $0) } != nil),
            StatefulInteropAssertion(name: "sync-operation-and-commit-revisions-match", passed: roundTrip.syncOperationRevision != nil && roundTrip.syncOperationRevision == roundTrip.syncCommitRevision),
            StatefulInteropAssertion(name: "sync-commit-verified", passed: roundTrip.syncCommitVerified == true),
            StatefulInteropAssertion(name: "full-car-status-success", passed: isSuccessful(roundTrip.fullCARStatus)),
            StatefulInteropAssertion(name: "full-car-records-recovered", passed: (roundTrip.fullCARRecordCount ?? 0) > 0),
            StatefulInteropAssertion(name: "full-car-commitment-recorded", passed: !(roundTrip.fullCARCommitment?.isEmpty ?? true)),
            StatefulInteropAssertion(name: "full-car-revision-recorded", passed: !(roundTrip.fullCARWireRevision?.isEmpty ?? true)),
            StatefulInteropAssertion(name: "full-car-revision-is-tid", passed: roundTrip.fullCARWireRevision.flatMap { try? TID(tidString: $0) } != nil),
            StatefulInteropAssertion(name: "full-car-expected-record-verified", passed: roundTrip.fullCARExpectedRecordVerified == true),
            StatefulInteropAssertion(name: "sync-and-full-car-commitments-match", passed: roundTrip.syncCommitment != nil && roundTrip.syncCommitment == roundTrip.fullCARCommitment),
            StatefulInteropAssertion(name: "sync-and-full-car-revisions-match", passed: roundTrip.syncCommitRevision != nil && roundTrip.syncCommitRevision == roundTrip.fullCARWireRevision),
            StatefulInteropAssertion(name: "full-car-verified", passed: roundTrip.fullCARVerified == true),
            StatefulInteropAssertion(
                name: "permissioned-blob-verified",
                passed: (roundTrip.blobUploadStatus == nil
                    && roundTrip.blobCID == nil
                    && roundTrip.blobBytes == nil
                    && roundTrip.blobVerified == nil)
                    || (roundTrip.blobUploadStatus.map { (200 ... 299).contains($0) } == true
                        && roundTrip.blobDownloadStatus.map { (200 ... 299).contains($0) } == true
                        && roundTrip.blobCID != nil
                        && roundTrip.blobVerified == true
                        && (roundTrip.blobBytes ?? 0) > 0)
            ),
        ]
        let evidencePassed = evidenceAssertions.allSatisfy(\.passed)
        let normalizedConvergence = evidencePassed
            && roundTrip.converged
            && roundTrip.status == "passed"
            && roundTrip.errorCode == nil
        let normalizedRoundTrip = normalized(
            roundTrip,
            converged: normalizedConvergence
        )
        let assertions = evidenceAssertions + [
            StatefulInteropAssertion(
                name: "live-round-trip-converged",
                passed: normalizedRoundTrip.converged
            ),
            StatefulInteropAssertion(
                name: "live-round-trip-status-passed",
                passed: normalizedRoundTrip.status == "passed"
            ),
        ]
        return StatefulInteropMatrixArtifact(
            scenario: scenario,
            assertions: assertions,
            roundTrip: normalizedRoundTrip
        )
    }

    private static func isSuccessful(_ status: Int?) -> Bool {
        status.map { (200 ... 299).contains($0) } == true
    }

    /// A caller-provided artifact is evidence input, not an authority to claim
    /// convergence. Normalize its outward result so every stateful assertion
    /// and the embedded round-trip status tell the same story.
    private static func normalized(
        _ roundTrip: LiveInteropPermissionedRoundTripArtifact,
        converged: Bool
    ) -> LiveInteropPermissionedRoundTripArtifact {
        LiveInteropPermissionedRoundTripArtifact(
            scenario: roundTrip.scenario,
            member: roundTrip.member,
            authority: roundTrip.authority,
            credentialIssued: roundTrip.credentialIssued,
            writeStatus: roundTrip.writeStatus,
            readStatus: roundTrip.readStatus,
            writeCID: roundTrip.writeCID,
            readCID: roundTrip.readCID,
            writeResponseSHA256: roundTrip.writeResponseSHA256,
            readResponseSHA256: roundTrip.readResponseSHA256,
            syncStatus: roundTrip.syncStatus,
            syncOpsCount: roundTrip.syncOpsCount,
            syncOperationCID: roundTrip.syncOperationCID,
            syncOperationRevision: roundTrip.syncOperationRevision,
            syncCommitment: roundTrip.syncCommitment,
            syncCommitRevision: roundTrip.syncCommitRevision,
            syncCommitVerified: roundTrip.syncCommitVerified,
            syncValuesIncluded: roundTrip.syncValuesIncluded,
            fullCARStatus: roundTrip.fullCARStatus,
            fullCARRecordCount: roundTrip.fullCARRecordCount,
            fullCARCommitment: roundTrip.fullCARCommitment,
            fullCARWireRevision: roundTrip.fullCARWireRevision,
            fullCARExpectedRecordVerified:
                roundTrip.fullCARExpectedRecordVerified,
            fullCARVerified: roundTrip.fullCARVerified,
            blobUploadStatus: roundTrip.blobUploadStatus,
            blobDownloadStatus: roundTrip.blobDownloadStatus,
            blobCID: roundTrip.blobCID,
            blobBytes: roundTrip.blobBytes,
            blobVerified: roundTrip.blobVerified,
            converged: converged,
            status: converged ? "passed" : "failed",
            errorCode: roundTrip.errorCode,
            events: roundTrip.events
        )
    }
}
