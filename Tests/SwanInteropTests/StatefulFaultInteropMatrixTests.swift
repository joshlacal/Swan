import XCTest
@testable import SwanInterop

final class StatefulFaultInteropMatrixTests: XCTestCase {
    private func head(
        _ generation: UInt64,
        _ revision: String,
        _ byte: Character
    ) -> StatefulReplicaHeadWitness {
        StatefulReplicaHeadWitness(
            generation: generation,
            revision: revision,
            commitment: String(repeating: byte, count: 64)
        )!
    }

    func testOutageRequiresLastGoodPreservationAndHealedConvergence() {
        let before = head(1, "222222222222a", "a")
        let intended = head(2, "222222222222b", "b")
        let passed = StatefulFaultInteropCell(
            mode: .disconnected,
            before: before,
            intended: intended,
            afterFault: before,
            afterHeal: intended,
            faultObserved: true,
            invalidDeliveryRejected: false
        )
        XCTAssertEqual(passed.status, "passed")

        let publishedDuringOutage = StatefulFaultInteropCell(
            mode: .disconnected,
            before: before,
            intended: intended,
            afterFault: intended,
            afterHeal: intended,
            faultObserved: true,
            invalidDeliveryRejected: false
        )
        XCTAssertEqual(publishedDuringOutage.status, "failed")
        XCTAssertTrue(publishedDuringOutage.assertions.contains {
            $0.name == "outage-preserved-last-good-head" && !$0.passed
        })
    }

    func testCorruptionRequiresRejectionAndLastGoodPreservation() {
        let before = head(4, "222222222222d", "d")
        let intended = head(5, "222222222222e", "e")
        let acceptedCorruption = StatefulFaultInteropCell(
            mode: .corrupted,
            before: before,
            intended: intended,
            afterFault: intended,
            afterHeal: intended,
            faultObserved: true,
            invalidDeliveryRejected: false
        )
        XCTAssertEqual(acceptedCorruption.status, "failed")

        let rejected = StatefulFaultInteropCell(
            mode: .corrupted,
            before: before,
            intended: intended,
            afterFault: before,
            afterHeal: intended,
            faultObserved: true,
            invalidDeliveryRejected: true
        )
        XCTAssertEqual(rejected.status, "passed")
    }

    func testDuplicateRequiresOneInPlaceHeadAdvance() {
        let before = head(7, "222222222222g", "a")
        let intended = head(7, "222222222222h", "b")
        let passed = StatefulFaultInteropCell(
            mode: .duplicated,
            before: before,
            intended: intended,
            afterFault: intended,
            afterHeal: intended,
            faultObserved: true,
            invalidDeliveryRejected: true
        )
        XCTAssertEqual(passed.status, "passed")

        let skippedGeneration = head(9, "222222222222j", "b")
        let failed = StatefulFaultInteropCell(
            mode: .duplicated,
            before: before,
            intended: skippedGeneration,
            afterFault: skippedGeneration,
            afterHeal: skippedGeneration,
            faultObserved: true,
            invalidDeliveryRejected: true
        )
        XCTAssertEqual(failed.status, "failed")
    }

    func testReorderingRequiresStaleDeliveryRejection() {
        let before = head(2, "222222222222b", "a")
        let intended = head(3, "222222222222c", "b")
        let failed = StatefulFaultInteropCell(
            mode: .reordered,
            before: before,
            intended: intended,
            afterFault: before,
            afterHeal: intended,
            faultObserved: true,
            invalidDeliveryRejected: false
        )
        XCTAssertEqual(failed.status, "failed")
    }

    func testMatrixRequiresEveryModeExactlyOnce() {
        var cells: [StatefulFaultInteropCell] = []
        var generation: UInt64 = 1
        for mode in StatefulFaultMode.allCases {
            let before = head(generation, "222222222222a", "a")
            let intended = head(generation, "222222222222b", "b")
            let failureMode = mode == .offline || mode == .disconnected
                || mode == .reordered || mode == .corrupted
            cells.append(StatefulFaultInteropCell(
                mode: mode,
                before: before,
                intended: intended,
                afterFault: failureMode ? before : intended,
                afterHeal: intended,
                faultObserved: mode != .normal,
                invalidDeliveryRejected: mode == .duplicated || mode == .reordered || mode == .corrupted
            ))
            generation += 1
        }
        let artifact = StatefulFaultInteropMatrixArtifact(
            scenario: "cross-host-fault-matrix",
            cells: cells
        )
        XCTAssertEqual(artifact.status, "passed")

        let incomplete = StatefulFaultInteropMatrixArtifact(
            scenario: "incomplete",
            cells: Array(cells.dropLast())
        )
        XCTAssertEqual(incomplete.status, "failed")
    }

    func testHeadWitnessRejectsInvalidOrUnsanitizedFields() {
        XCTAssertNil(StatefulReplicaHeadWitness(
            generation: 0,
            revision: "222222222222a",
            commitment: String(repeating: "a", count: 64)
        ))
        XCTAssertNil(StatefulReplicaHeadWitness(
            generation: 1,
            revision: "not-a-tid",
            commitment: String(repeating: "a", count: 64)
        ))
        XCTAssertNil(StatefulReplicaHeadWitness(
            generation: 1,
            revision: "222222222222a",
            commitment: "secret"
        ))
    }
}
