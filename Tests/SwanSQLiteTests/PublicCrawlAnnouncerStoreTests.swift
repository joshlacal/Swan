import Foundation
import SQLiteNIO
import SwanPublicFirehose
@testable import SwanSQLite
import XCTest

final class PublicCrawlAnnouncerStoreTests: XCTestCase {
    private let origin = "https://crawler-a.example"
    private let epoch = Date(timeIntervalSince1970: 1_785_844_800)

    func testMigrationInstallsAnnouncerStateSchema() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let rows = try await control.connection.query(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'public_crawl_announcer_state'
            """
        )
        XCTAssertEqual(rows.count, 1)
    }

    func testRecordSuccessOutcomeRoundTripsState() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let next = epoch.addingTimeInterval(86_400)
        try await control.recordCrawlAnnounceOutcome(
            origin: origin,
            success: true,
            now: epoch,
            nextAttemptAt: next
        )
        let states = try await control.crawlAnnouncerStates()
        XCTAssertEqual(states.count, 1)
        let state = try XCTUnwrap(states.first)
        XCTAssertEqual(state.crawlerOrigin, origin)
        XCTAssertEqual(state.attempts, 0)
        XCTAssertEqual(state.nextAttemptAt, try PublicFirehoseTime.microseconds(next))
        XCTAssertEqual(state.lastAttemptAt, try PublicFirehoseTime.microseconds(epoch))
        XCTAssertEqual(state.lastSuccessAt, try PublicFirehoseTime.microseconds(epoch))
    }

    func testFailuresIncrementAttemptsAndSuccessResetsAttempts() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let firstBackoff = epoch.addingTimeInterval(30)
        let secondBackoff = epoch.addingTimeInterval(60)
        let recovered = epoch.addingTimeInterval(90)

        try await control.recordCrawlAnnounceOutcome(
            origin: origin,
            success: false,
            now: epoch,
            nextAttemptAt: firstBackoff
        )
        let firstStates = try await control.crawlAnnouncerStates()
        var state = try XCTUnwrap(firstStates.first)
        XCTAssertEqual(state.attempts, 1)
        XCTAssertEqual(state.nextAttemptAt, try PublicFirehoseTime.microseconds(firstBackoff))
        XCTAssertNil(state.lastSuccessAt)

        try await control.recordCrawlAnnounceOutcome(
            origin: origin,
            success: false,
            now: firstBackoff,
            nextAttemptAt: secondBackoff
        )
        let secondStates = try await control.crawlAnnouncerStates()
        state = try XCTUnwrap(secondStates.first)
        XCTAssertEqual(state.attempts, 2)
        XCTAssertEqual(state.nextAttemptAt, try PublicFirehoseTime.microseconds(secondBackoff))
        XCTAssertEqual(state.lastAttemptAt, try PublicFirehoseTime.microseconds(firstBackoff))
        XCTAssertNil(state.lastSuccessAt)

        try await control.recordCrawlAnnounceOutcome(
            origin: origin,
            success: true,
            now: secondBackoff,
            nextAttemptAt: recovered
        )
        let recoveredStates = try await control.crawlAnnouncerStates()
        state = try XCTUnwrap(recoveredStates.first)
        XCTAssertEqual(state.attempts, 0, "a success must reset the consecutive-failure counter")
        XCTAssertEqual(state.nextAttemptAt, try PublicFirehoseTime.microseconds(recovered))
        XCTAssertEqual(state.lastAttemptAt, try PublicFirehoseTime.microseconds(secondBackoff))
        XCTAssertEqual(state.lastSuccessAt, try PublicFirehoseTime.microseconds(secondBackoff))
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicCrawlAnnouncerStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}
