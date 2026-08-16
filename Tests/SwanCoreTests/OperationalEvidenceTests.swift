import XCTest
@testable import SwanCore

final class OperationalEvidenceTests: XCTestCase {
    func testMetricsNeverAcceptIdentifierOrSecretLabels() throws {
        let metrics = OperationalMetrics()
        try metrics.increment(.httpError, labels: ["status": "503"])
        XCTAssertThrowsError(try metrics.increment(.auth, labels: ["did": "did:plc:secret"]))
        XCTAssertThrowsError(try metrics.increment(.signup, labels: ["token": "bearer-secret"]))
        XCTAssertEqual(metrics.snapshot()[.httpError], 1)
        XCTAssertFalse(metrics.assembled)
    }

    func testReadinessRequiresEveryDeclaredCriticalCheck() throws {
        let checks = OperationalReadiness()
        checks.set(.http, healthy: true)
        checks.set(.backup, healthy: false)
        XCTAssertFalse(checks.report().ready)
        checks.set(.backup, healthy: true)
        let report = checks.report()
        XCTAssertFalse(report.ready)
        XCTAssertFalse(report.assembled)
    }
}
