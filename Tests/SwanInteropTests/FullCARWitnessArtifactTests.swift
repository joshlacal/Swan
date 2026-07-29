import Foundation
import XCTest
@testable import SwanInterop

final class FullCARWitnessArtifactTests: XCTestCase {
    private static let recordCID =
        "bafyreidqz2dr7cr5h62etpb4hlhgkr6o6aw7y5h74sgzcjjsu4sl7w7fxe"

    func testArtifactRetainsOnlyCanonicalTIDAndWitnessSummary() throws {
        let artifact = makeArtifact(
            fullCARWireRevision: "222222222222a",
            fullCARExpectedRecordVerified: true
        )

        XCTAssertEqual(artifact.fullCARWireRevision, "222222222222a")
        XCTAssertTrue(artifact.fullCARExpectedRecordVerified == true)

        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: JSONEncoder().encode(artifact)
            ) as? [String: Any]
        )
        let keys = Set(object.keys.map { $0.lowercased() })
        for forbidden in [
            "collection", "rkey", "recordvalue", "token", "url",
            "privatekey", "verificationkey",
        ] {
            XCTAssertFalse(
                keys.contains(where: { $0.contains(forbidden) }),
                "full-CAR evidence leaked a forbidden field: \(forbidden)"
            )
        }
    }

    func testArtifactRejectsArbitraryRevisionText() {
        let artifact = makeArtifact(
            fullCARWireRevision: "https://private.example/record?rkey=secret",
            fullCARExpectedRecordVerified: true
        )

        XCTAssertNil(artifact.fullCARWireRevision)
    }

    func testExpectedRecordWitnessCannotDefaultToTrue() {
        let artifact = makeArtifact()

        XCTAssertNil(artifact.fullCARExpectedRecordVerified)
    }

    private func makeArtifact(
        fullCARWireRevision: String? = nil,
        fullCARExpectedRecordVerified: Bool? = nil
    ) -> LiveInteropPermissionedRoundTripArtifact {
        LiveInteropPermissionedRoundTripArtifact(
            scenario: "full-car-witness",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "a", count: 64),
            readResponseSHA256: String(repeating: "b", count: 64),
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "c", count: 64),
            fullCARWireRevision: fullCARWireRevision,
            fullCARExpectedRecordVerified:
                fullCARExpectedRecordVerified,
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )
    }
}
