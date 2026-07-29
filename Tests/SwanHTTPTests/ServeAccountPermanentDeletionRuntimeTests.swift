import Foundation
import SwanStorage
@testable import swan
import XCTest

final class ServeAccountPermanentDeletionRuntimeTests: XCTestCase {
    func testStartupSweepRescansFromBeginningAfterEachBoundedPage()
        async throws
    {
        let lower = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
        let first = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
        let priorCursor = "did:plc:cccccccccccccccccccccccc"
        let remaining = "did:plc:dddddddddddddddddddddddd"
        let inventory = try MutablePendingDeletionInventory(
            initialDIDs: [first, priorCursor, remaining],
            insertedDID: lower,
            insertAfterCompleting: priorCursor
        )

        try await resumePendingDeletionJobsBeforeServe(
            pageLimit: 2,
            fetch: { afterDID, limit in
                await inventory.fetch(
                    afterDID: afterDID,
                    limit: limit
                )
            },
            resume: { did, _ in
                await inventory.complete(did: did)
            },
            now: { Date(timeIntervalSince1970: 1_750_000_900) }
        )

        let completed = await inventory.completedDIDs()
        let cursors = await inventory.requestedCursors()
        XCTAssertEqual(
            completed,
            [first, priorCursor, lower, remaining]
        )
        XCTAssertEqual(cursors, [nil, nil, nil])
    }
}

private actor MutablePendingDeletionInventory {
    private var jobs: [String: AccountDeletionJob]
    private let insertedJob: AccountDeletionJob
    private let insertionTrigger: String
    private var inserted = false
    private var completed: [String] = []
    private var cursors: [String?] = []

    init(
        initialDIDs: [String],
        insertedDID: String,
        insertAfterCompleting: String
    ) throws {
        jobs = try Dictionary(
            uniqueKeysWithValues: initialDIDs.map {
                ($0, try Self.job(did: $0))
            }
        )
        insertedJob = try Self.job(did: insertedDID)
        insertionTrigger = insertAfterCompleting
    }

    func fetch(
        afterDID: String?,
        limit: Int
    ) -> [AccountDeletionJob] {
        cursors.append(afterDID)
        return jobs.values
            .filter { job in
                afterDID.map { job.did > $0 } ?? true
            }
            .sorted { $0.did < $1.did }
            .prefix(limit)
            .map { $0 }
    }

    func complete(did: String) {
        completed.append(did)
        jobs.removeValue(forKey: did)
        if did == insertionTrigger, !inserted {
            inserted = true
            jobs[insertedJob.did] = insertedJob
        }
    }

    func completedDIDs() -> [String] { completed }

    func requestedCursors() -> [String?] { cursors }

    private static func job(did: String) throws -> AccountDeletionJob {
        let now = Date(timeIntervalSince1970: 1_750_000_900)
        return try AccountDeletionJob(
            did: did,
            stage: .accountDataDestroyed,
            revision: 1,
            requestedAt: now,
            updatedAt: now,
            tombstone: try AccountTombstoneMetadata(
                declaredAt: now,
                reason: "startup-recovery-test"
            ),
            export: nil,
            rotationKey: nil,
            stagingKeyBindings: []
        )
    }
}
