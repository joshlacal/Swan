import Foundation
import SwanInterop
import SwanSpaces
import SwanStorage
import XCTest

final class PermissionedRecoveryAcceptanceArtifactTests: XCTestCase {
    func testArtifactRetainsOnlyCanonicalRecoveryEvidence() throws {
        let digest = String(repeating: "a", count: 64)
        let artifact = PermissionedRecoveryAcceptanceArtifact(
            scenario: "retention-gap-corruption",
            gapStatus: 409,
            gapErrorCode: "full_repo_recovery_required",
            priorHeadPresent: false,
            validHeadGeneration: 1,
            validHeadRevision: "3lqjz7x4abc2k",
            validCommitment: digest,
            validRecordCount: 3,
            corruptionRejected: true,
            corruptErrorCode: "CARBlockCIDMismatch",
            finalHeadGeneration: 1,
            finalHeadRevision: "3lqjz7x4abc2k",
            finalCommitment: digest,
            lastValidHeadPreserved: true,
            status: "passed",
            errorCode: nil
        )

        XCTAssertEqual(artifact.profileID, "permissioned-data-0016-2026-07-30")
        XCTAssertEqual(artifact.gapErrorCode, "full_repo_recovery_required")
        XCTAssertEqual(artifact.validCommitment, digest)
        XCTAssertEqual(artifact.corruptErrorCode, "CARBlockCIDMismatch")
        XCTAssertTrue(artifact.lastValidHeadPreserved)

        let serialized = String(
            decoding: try JSONEncoder().encode(artifact),
            as: UTF8.self
        ).lowercased()
        for forbidden in [
            "receiverdid", "repositorydid", "spaceuri", "authorization",
            "access_token", "refresh_token", "password", "private_key",
            "verifieridentity", "requestdigest", "statemarker",
        ] {
            XCTAssertFalse(serialized.contains(forbidden), forbidden)
        }
    }

    func testArtifactRedactsNoncanonicalPeerEvidence() {
        let opaque =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.c2lnbmF0dXJl"
        let artifact = PermissionedRecoveryAcceptanceArtifact(
            scenario: opaque,
            gapStatus: 200,
            gapErrorCode: opaque,
            priorHeadPresent: true,
            validHeadGeneration: 0,
            validHeadRevision: opaque,
            validCommitment: opaque,
            validRecordCount: -1,
            corruptionRejected: false,
            corruptErrorCode: opaque,
            finalHeadGeneration: 0,
            finalHeadRevision: opaque,
            finalCommitment: opaque,
            lastValidHeadPreserved: false,
            status: opaque,
            errorCode: opaque
        )

        XCTAssertEqual(artifact.scenario, "<redacted>")
        XCTAssertEqual(artifact.gapErrorCode, "<redacted>")
        XCTAssertNil(artifact.validHeadGeneration)
        XCTAssertNil(artifact.validHeadRevision)
        XCTAssertNil(artifact.validCommitment)
        XCTAssertNil(artifact.validRecordCount)
        XCTAssertEqual(artifact.corruptErrorCode, "<redacted>")
        XCTAssertEqual(artifact.status, "failed")
        XCTAssertEqual(artifact.errorCode, "<redacted>")
    }

    func testRecoveryFailureCodesDoNotReflectArbitraryErrors() {
        XCTAssertEqual(
            PermissionedRecoveryFailureCode.code(
                for: PermissionedRemoteReplicaRecoveryError.corruptReplica
            ),
            "RecoveryCorruptReplica"
        )
        XCTAssertEqual(
            PermissionedRecoveryFailureCode.code(for: SecretError()),
            "RecoveryFailed"
        )
        XCTAssertTrue(
            PermissionedRecoveryFailureCode
                .isInjectedFinalByteCorruptionRejection(
                    SpaceCARStreamingError.blockCIDMismatch
                )
        )
        XCTAssertFalse(
            PermissionedRecoveryFailureCode
                .isInjectedFinalByteCorruptionRejection(
                    PermissionedRemoteReplicaRecoveryError.corruptReplica
                )
        )
        XCTAssertFalse(
            PermissionedRecoveryFailureCode
                .isInjectedFinalByteCorruptionRejection(SecretError())
        )
    }

    private struct SecretError: Error, CustomStringConvertible {
        var description: String { "access_token=must-not-leak" }
    }
}
