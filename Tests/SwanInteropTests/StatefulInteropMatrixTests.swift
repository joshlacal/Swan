import XCTest
@testable import SwanInterop

final class StatefulInteropMatrixTests: XCTestCase {
    private static let recordCID =
        "bafyreidqz2dr7cr5h62etpb4hlhgkr6o6aw7y5h74sgzcjjsu4sl7w7fxe"

    func testEvaluationRequiresEveryStatefulWitness() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "stateful-alpha",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222a",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222a",
            syncCommitVerified: true,
            syncValuesIncluded: true,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "a", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "stateful-alpha",
            roundTrip: live
        )

        XCTAssertEqual(artifact.kind, "stateful-permissioned-alpha")
        XCTAssertEqual(artifact.status, "passed")
        XCTAssertTrue(artifact.assertions.allSatisfy(\.passed))
        XCTAssertEqual(artifact.roundTrip.syncOperationRevision, "222222222222a")
        XCTAssertEqual(artifact.roundTrip.syncCommitment, String(repeating: "a", count: 64))
        XCTAssertEqual(artifact.roundTrip.fullCARWireRevision, "222222222222a")
        XCTAssertTrue(artifact.roundTrip.fullCARExpectedRecordVerified == true)
    }

    func testEvaluationRejectsMetadataOnlyIncrementalSync() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "metadata-only-sync",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222a",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222a",
            syncCommitVerified: true,
            syncValuesIncluded: false,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "a", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "metadata-only-sync",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "sync-values-included" && !$0.passed
        })
    }

    func testEvaluationRejectsEndpointOnlyEvidence() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "endpoint-only",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncCommitVerified: true,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "endpoint-only",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "sync-operation-revision-recorded" && !$0.passed
        })
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "full-car-commitment-recorded" && !$0.passed
        })
        XCTAssertFalse(artifact.roundTrip.converged)
        XCTAssertEqual(artifact.roundTrip.status, "failed")
    }

    func testEvaluationRejectsDivergentTerminalCommitments() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "commitment-mismatch",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222a",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222a",
            syncCommitVerified: true,
            syncValuesIncluded: true,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "b", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "commitment-mismatch",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "sync-and-full-car-commitments-match" && !$0.passed
        })
        XCTAssertFalse(artifact.roundTrip.converged)
        XCTAssertEqual(artifact.roundTrip.status, "failed")
    }

    /// Regression for a rollback false-positive:
    ///
    /// T1 contains state A, T2 contains state B, and T3 returns to state A.
    /// T1 and T3 therefore have the same commitment, but replaying the older
    /// T1 CAR must not substantiate the terminal T3 incremental revision.
    func testEvaluationRejectsOlderFullCARWithSameTerminalCommitment() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "rollback-replay",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 3,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222c",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222c",
            syncCommitVerified: true,
            syncValuesIncluded: true,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "a", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "rollback-replay",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "sync-and-full-car-revisions-match" && !$0.passed
        })
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "sync-and-full-car-commitments-match" && $0.passed
        })
        XCTAssertFalse(artifact.roundTrip.converged)
        XCTAssertEqual(artifact.roundTrip.status, "failed")
    }

    func testEvaluationRejectsExpectedRecordWitnessMismatch() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "record-witness-mismatch",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222a",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222a",
            syncCommitVerified: true,
            syncValuesIncluded: true,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "a", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: false,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "record-witness-mismatch",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "full-car-expected-record-verified" && !$0.passed
        })
        XCTAssertFalse(artifact.roundTrip.converged)
        XCTAssertEqual(artifact.roundTrip.status, "failed")
    }

    func testEvaluationRejectsEndpointStatusAndErrorFalsePositive() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "endpoint-status-false-positive",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222a",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222a",
            syncCommitVerified: true,
            syncValuesIncluded: true,
            fullCARStatus: 500,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "a", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: "InternalServerError",
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "endpoint-status-false-positive",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "full-car-status-success" && !$0.passed
        })
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "error-code-absent" && !$0.passed
        })
        XCTAssertFalse(artifact.roundTrip.converged)
        XCTAssertEqual(artifact.roundTrip.status, "failed")
    }

    func testEvaluationRequiresPermissionedBlobRoundTripWhenRequested() {
        let live = LiveInteropPermissionedRoundTripArtifact(
            scenario: "permissioned-blob-mismatch",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "d", count: 64),
            readResponseSHA256: String(repeating: "e", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.recordCID,
            syncOperationRevision: "222222222222a",
            syncCommitment: String(repeating: "a", count: 64),
            syncCommitRevision: "222222222222a",
            syncCommitVerified: true,
            syncValuesIncluded: true,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "a", count: 64),
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true,
            fullCARVerified: true,
            // A failed upload can have no HTTP status when the transport
            // throws. It must not be mistaken for a run that did not request
            // a blob at all.
            blobUploadStatus: nil,
            blobDownloadStatus: nil,
            blobCID: nil,
            blobBytes: nil,
            blobVerified: false,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )

        let artifact = StatefulInteropMatrixRunner.evaluate(
            scenario: "permissioned-blob-mismatch",
            roundTrip: live
        )

        XCTAssertEqual(artifact.status, "failed")
        XCTAssertTrue(artifact.assertions.contains {
            $0.name == "permissioned-blob-verified" && !$0.passed
        })
        XCTAssertFalse(artifact.roundTrip.converged)
    }
}
