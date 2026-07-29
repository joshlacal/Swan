import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest

@testable import SwanSQLite

final class PermissionedRemoteReplicaRecoverySQLiteTests: XCTestCase {
  func testAuthenticatedBootstrapAndCurrentGenerationQualifiedRead()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "authenticated-bootstrap"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let initial = try fixture.archive(
        revision: "222222222222a",
        values: ["initial value"],
        ikmByte: 0x11
      )

      XCTAssertThrowsError(
        try fixture.binding(
          archive: initial,
          expectedBase: nil,
          requestID: "missing-bootstrap-freshness",
          freshnessWitness: nil
        )
      ) {
        XCTAssertEqual(
          $0 as? PermissionedRemoteReplicaRecoveryError,
          .invalidBinding
        )
      }

      let unauthenticated = try await fixture.start(
        database: database,
        archive: initial,
        expectedBase: nil,
        requestID: "unauthenticated-bootstrap",
        freshnessWitness: fixture.witness(for: initial)
      )
      let unauthenticatedStaging =
        SQLitePermissionedRemoteReplicaRecoveryStaging(
          database: database,
          sessionID: unauthenticated.session.id,
          now: { RemoteReplicaSQLiteFixture.operationNow }
        )
      do {
        _ = try await SpaceCARCodec.verifyStreamingRecovery(
          from: RemoteReplicaCARDataSource(initial.car),
          space: fixture.space,
          author: fixture.repositoryDID,
          contextSignatureVerifier: {
            try SpaceCommitCodec.verifyContextSignature(
              $0,
              publicKey: P256.Signing.PrivateKey().publicKey
            )
          },
          index: unauthenticatedStaging,
          recordSink: unauthenticatedStaging,
          limits: initial.limits
        )
        XCTFail("an initial replica install accepted the wrong signing key")
      } catch let error as SpaceCARStreamingError {
        XCTAssertEqual(error, .commitDidNotVerify)
      }
      let unauthenticatedHead =
        try await database.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertNil(unauthenticatedHead)
      try await database.cleanupPermissionedRemoteReplicaImportSession(
        id: unauthenticated.session.id
      )

      let installedInitial = try await fixture.install(
        database: database,
        archive: initial,
        expectedBase: nil,
        requestID: "authenticated-bootstrap"
      )
      XCTAssertEqual(installedInitial.result.head.generation, 1)
      let initialRead = try await database.permissionedRemoteReplicaRecord(
        target: fixture.target,
        collection: initial.records[0].collection,
        rkey: initial.records[0].rkey
      )
      XCTAssertEqual(initialRead, initial.records[0].value)
      try await assertNoRemoteReplicaStaging(in: database)

      let replacement = try fixture.archive(
        revision: "222222222222b",
        values: ["replacement value"],
        ikmByte: 0x12
      )
      let installedReplacement = try await fixture.install(
        database: database,
        archive: replacement,
        expectedBase: installedInitial.result.head,
        requestID: "authenticated-replacement"
      )
      XCTAssertEqual(installedReplacement.result.head.generation, 2)
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 1,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await fixture.injectRetainedRecord(
        initial.records[0],
        generation: 1,
        database: database
      )

      let retainedGenerations = try await database.connection.query(
        """
        SELECT generation
        FROM permissioned_remote_replica_records
        WHERE space_uri = ? AND repository_did = ?
          AND collection = ? AND rkey = ?
        ORDER BY generation
        LIMIT 3
        """,
        [
          .text(fixture.space.rawValue),
          .text(fixture.repositoryDID),
          .text(replacement.records[0].collection),
          .text(replacement.records[0].rkey),
        ]
      )
      XCTAssertEqual(
        retainedGenerations.compactMap {
          $0.column("generation")?.integer
        },
        [1, 2]
      )
      let replacementRead =
        try await database.permissionedRemoteReplicaRecord(
          target: fixture.target,
          collection: replacement.records[0].collection,
          rkey: replacement.records[0].rkey
        )
      XCTAssertEqual(
        replacementRead,
        replacement.records[0].value,
        "the public read must join through only the current head generation"
      )
      try await assertNoRemoteReplicaStaging(in: database)
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

  func testWrongFreshnessAndTamperedStagingLeaveLastGoodReplicaUnchanged()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "freshness-and-staging"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let initial = try fixture.archive(
        revision: "222222222222a",
        values: ["last good"],
        ikmByte: 0x21
      )
      let installed = try await fixture.install(
        database: database,
        archive: initial,
        expectedBase: nil,
        requestID: "last-good"
      )
      let replacement = try fixture.archive(
        revision: "222222222222b",
        values: ["unpublished replacement"],
        ikmByte: 0x22
      )

      var wrongCommitment = replacement.commitment
      wrongCommitment[wrongCommitment.startIndex] =
        wrongCommitment[wrongCommitment.startIndex] ^ 0xff
      let wrongWitness = try PermissionedRemoteReplicaFreshnessWitness(
        wireRevision: replacement.wireRevision,
        commitment: wrongCommitment
      )
      let wrongFreshness = try await fixture.stage(
        database: database,
        archive: replacement,
        expectedBase: installed.result.head,
        requestID: "wrong-freshness",
        freshnessWitness: wrongWitness
      )
      await assertRemoteReplicaError(.freshnessMismatch) {
        try await database.markPermissionedRemoteReplicaImportVerified(
          sessionID: wrongFreshness.session.id,
          verification: wrongFreshness.verification,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      }
      let wrongFreshnessSession =
        try await database.permissionedRemoteReplicaImportSession(
          id: wrongFreshness.session.id
        )
      XCTAssertEqual(wrongFreshnessSession.status, .poisoned)
      let headAfterWrongFreshness =
        try await database.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertEqual(
        headAfterWrongFreshness,
        installed.result.head
      )
      try await database.cleanupPermissionedRemoteReplicaImportSession(
        id: wrongFreshness.session.id
      )

      let tampered = try await fixture.stage(
        database: database,
        archive: replacement,
        expectedBase: installed.result.head,
        requestID: "tampered-staging",
        freshnessWitness: fixture.witness(for: replacement)
      )
      try await database.markPermissionedRemoteReplicaImportVerified(
        sessionID: tampered.session.id,
        verification: tampered.verification,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
      let verifiedBeforeTamper =
        try await database.permissionedRemoteReplicaImportSession(
          id: tampered.session.id
        )
      XCTAssertEqual(verifiedBeforeTamper.status, .verified)
      let replacementRecord = try XCTUnwrap(replacement.records.first)
      let changed = try await database.connection.query(
        """
        UPDATE permissioned_remote_replica_import_block_chunks
        SET bytes = ?
        WHERE session_id = ? AND cid = ? AND chunk_index = 0
        RETURNING chunk_index
        """,
        [
          Data(repeating: 0x7f, count: replacementRecord.value.count)
            .sqliteData!,
          .text(tampered.session.id),
          .text(replacementRecord.cid.string),
        ]
      )
      XCTAssertEqual(changed.count, 1)
      await assertRemoteReplicaError(.corruptStaging) {
        try await database
          .publishVerifiedPermissionedRemoteReplicaRecovery(
            sessionID: tampered.session.id,
            consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
            now: RemoteReplicaSQLiteFixture.operationNow
          )
      }
      let verifiedAfterTamper =
        try await database.permissionedRemoteReplicaImportSession(
          id: tampered.session.id
        )
      XCTAssertEqual(verifiedAfterTamper, verifiedBeforeTamper)
      let headAfterTamper =
        try await database.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertEqual(
        headAfterTamper,
        installed.result.head
      )
      let readAfterTamper =
        try await database.permissionedRemoteReplicaRecord(
          target: fixture.target,
          collection: initial.records[0].collection,
          rkey: initial.records[0].rkey
        )
      XCTAssertEqual(
        readAfterTamper,
        initial.records[0].value
      )
      let recovered = try await database
        .recoverExpiredPermissionedRemoteReplicaImportSessions(
          now: RemoteReplicaSQLiteFixture.expiresAt
        )
      XCTAssertEqual(
        recovered,
        1
      )
      try await assertNoRemoteReplicaStaging(in: database)
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 2,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

  func testCorruptLiveProjectionBlocksReplacementBeforeHeadSwap()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "corrupt-live-projection"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let initial = try fixture.archive(
        revision: "222222222222a",
        values: ["installed projection"],
        ikmByte: 0x31
      )
      let installed = try await fixture.install(
        database: database,
        archive: initial,
        expectedBase: nil,
        requestID: "installed-before-corruption"
      )
      let installedRecord = try XCTUnwrap(initial.records.first)
      let corrupted = try await database.connection.query(
        """
        UPDATE permissioned_remote_replica_block_chunks
        SET bytes = ?
        WHERE space_uri = ? AND repository_did = ?
          AND generation = ? AND cid = ? AND chunk_index = 0
        RETURNING chunk_index
        """,
        [
          Data(repeating: 0x6d, count: installedRecord.value.count)
            .sqliteData!,
          .text(fixture.space.rawValue),
          .text(fixture.repositoryDID),
          .integer(Int(installed.result.head.generation)),
          .text(installedRecord.cid.string),
        ]
      )
      XCTAssertEqual(corrupted.count, 1)

      let replacement = try fixture.archive(
        revision: "222222222222b",
        values: ["must not replace corrupt live data"],
        ikmByte: 0x32
      )
      let staged = try await fixture.stage(
        database: database,
        archive: replacement,
        expectedBase: installed.result.head,
        requestID: "blocked-replacement",
        freshnessWitness: fixture.witness(for: replacement)
      )
      try await database.markPermissionedRemoteReplicaImportVerified(
        sessionID: staged.session.id,
        verification: staged.verification,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
      await assertRemoteReplicaError(.corruptReplica) {
        try await database.publishVerifiedPermissionedRemoteReplicaRecovery(
          sessionID: staged.session.id,
          consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      }

      let headAfterBlockedReplacement =
        try await database.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertEqual(
        headAfterBlockedReplacement,
        installed.result.head
      )
      let blockedSession =
        try await database.permissionedRemoteReplicaImportSession(
          id: staged.session.id
        )
      XCTAssertEqual(blockedSession.status, .verified)
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 2,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

  func testEqualTIDSameProjectionIsIdempotentAndDifferentCommitmentEquivocates()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "same-tid"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let initial = try fixture.archive(
        revision: "222222222222a",
        values: ["stable value"],
        ikmByte: 0x41
      )
      let installed = try await fixture.install(
        database: database,
        archive: initial,
        expectedBase: nil,
        requestID: "same-tid-base"
      )
      let equivalent = try fixture.archive(
        revision: "222222222222a",
        values: ["stable value"],
        ikmByte: 0x42
      )
      XCTAssertNotEqual(equivalent.commitRootCID, initial.commitRootCID)
      let idempotent = try await fixture.install(
        database: database,
        archive: equivalent,
        expectedBase: installed.result.head,
        requestID: "same-tid-equivalent"
      )
      XCTAssertEqual(idempotent.result.head, installed.result.head)
      XCTAssertEqual(idempotent.result.head.generation, 1)
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 2,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await assertNoRemoteReplicaStaging(in: database)

      let replay = try await database
        .createPermissionedRemoteReplicaImportSession(
          binding: idempotent.binding,
          createdAt: RemoteReplicaSQLiteFixture.createdAt,
          expiresAt: RemoteReplicaSQLiteFixture.expiresAt,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      guard case let .committed(replayed) = replay else {
        throw RemoteReplicaSQLiteTestError.unexpectedStartOutcome
      }
      XCTAssertEqual(replayed, idempotent.result)

      let conflicting = try fixture.archive(
        revision: "222222222222a",
        values: ["different value at the same TID"],
        ikmByte: 0x43
      )
      XCTAssertNotEqual(conflicting.commitment, installed.result.head.commitment)
      let equivocation = try await fixture.stage(
        database: database,
        archive: conflicting,
        expectedBase: installed.result.head,
        requestID: "same-tid-equivocation",
        freshnessWitness: fixture.witness(for: conflicting)
      )
      try await database.markPermissionedRemoteReplicaImportVerified(
        sessionID: equivocation.session.id,
        verification: equivocation.verification,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
      await assertRemoteReplicaError(.equivocation) {
        try await database.publishVerifiedPermissionedRemoteReplicaRecovery(
          sessionID: equivocation.session.id,
          consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      }
      let headAfterEquivocation =
        try await database.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertEqual(
        headAfterEquivocation,
        installed.result.head
      )
      let readAfterEquivocation =
        try await database.permissionedRemoteReplicaRecord(
          target: fixture.target,
          collection: initial.records[0].collection,
          rkey: initial.records[0].rkey
        )
      XCTAssertEqual(
        readAfterEquivocation,
        initial.records[0].value
      )
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 2,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

  func testEveryPublishFailpointReopensAndCleansCrashResidue()
    async throws
  {
    for failpoint in 0 ... 5 {
      let fixture = try RemoteReplicaSQLiteFixture(
        name: "publish-failpoint-\(failpoint)"
      )
      defer { try? FileManager.default.removeItem(at: fixture.root) }
      let database = try await fixture.open()
      let archive = try fixture.archive(
        revision: "222222222222a",
        values: ["failpoint \(failpoint)"],
        ikmByte: UInt8(0x50 + failpoint)
      )
      let staged = try await fixture.stage(
        database: database,
        archive: archive,
        expectedBase: nil,
        requestID: "failpoint-\(failpoint)",
        freshnessWitness: fixture.witness(for: archive)
      )
      try await database.markPermissionedRemoteReplicaImportVerified(
        sessionID: staged.session.id,
        verification: staged.verification,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
      await database.installTestingHooks(SQLiteTestingHooks(
        afterRemoteReplicaMutatingSQL: { index in
          if index == failpoint {
            throw RemoteReplicaInjectedFailure.expected
          }
        }
      ))
      do {
        _ = try await database
          .publishVerifiedPermissionedRemoteReplicaRecovery(
            sessionID: staged.session.id,
            consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
            now: RemoteReplicaSQLiteFixture.operationNow
          )
        XCTFail("publish failpoint \(failpoint) did not fire")
      } catch {
        XCTAssertEqual(
          error as? RemoteReplicaInjectedFailure,
          .expected,
          "unexpected error at publish failpoint \(failpoint)"
        )
      }
      let failedHead =
        try await database.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertNil(
        failedHead,
        "failpoint \(failpoint) published a head despite rollback"
      )
      try await database.close()

      let reopened = try await fixture.open()
      do {
        let reopenedHead =
          try await reopened.permissionedRemoteReplicaHead(
            target: fixture.target
          )
        XCTAssertNil(reopenedHead)
        try await assertNoRemoteReplicaStaging(in: reopened)
        try await assertNoRemoteReplicaLiveRows(
          in: reopened,
          target: fixture.target
        )
        let resultRows = try await reopened.connection.query(
          """
          SELECT COUNT(*) AS count
          FROM permissioned_remote_replica_import_results
          """
        )
        XCTAssertEqual(
          resultRows.first?.column("count")?.integer,
          0,
          "failpoint \(failpoint) left a committed result"
        )

        let retry = try await fixture.install(
          database: reopened,
          archive: archive,
          expectedBase: nil,
          requestID: "retry-after-failpoint-\(failpoint)"
        )
        XCTAssertEqual(retry.result.head.generation, 1)
        try await assertNoRemoteReplicaStaging(in: reopened)
        try await reopened.close()
      } catch {
        try? await reopened.close()
        throw error
      }
    }
  }

  func testExpiredPreparingCrashResidueIsCleanedOnReopenWithoutLosingLastGood()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "expired-preparing-reopen"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let initial = try fixture.archive(
      revision: "222222222222a",
      values: ["last good before crash"],
      ikmByte: 0x58
    )
    let installed = try await fixture.install(
      database: database,
      archive: initial,
      expectedBase: nil,
      requestID: "preparing-crash-base"
    )
    let replacement = try fixture.archive(
      revision: "222222222222b",
      values: ["partially prepared one", "partially prepared two"],
      ikmByte: 0x59
    )
    let staged = try await fixture.stage(
      database: database,
      archive: replacement,
      expectedBase: installed.result.head,
      requestID: "preparing-crash-candidate",
      freshnessWitness: fixture.witness(for: replacement)
    )
    try await database.markPermissionedRemoteReplicaImportVerified(
      sessionID: staged.session.id,
      verification: staged.verification,
      now: RemoteReplicaSQLiteFixture.operationNow
    )
    let claimed = try await database.connection.query(
      """
      UPDATE permissioned_remote_replica_import_sessions
      SET status = 'preparing', prepared_generation = 2,
          prepared_projection_digest = ?
      WHERE session_id = ? AND status = 'verified'
      RETURNING session_id
      """,
      [
        Data(repeating: 0x5a, count: 32).sqliteData!,
        .text(staged.session.id),
      ]
    )
    XCTAssertEqual(claimed.count, 1)
    try await fixture.injectRetainedRecord(
      replacement.records[0],
      generation: 2,
      database: database
    )
    let preparing =
      try await database.permissionedRemoteReplicaImportSession(
        id: staged.session.id
      )
    XCTAssertEqual(preparing.status, .preparing)
    try await assertRemoteReplicaGenerationRows(
      in: database,
      target: fixture.target,
      generation: 2,
      expectedRecords: 1,
      expectedBlocks: 1,
      expectedChunks: 1
    )
    try await database.close()

    let reopened = try await fixture.open()
    do {
      let reopenedHead =
        try await reopened.permissionedRemoteReplicaHead(
          target: fixture.target
        )
      XCTAssertEqual(reopenedHead, installed.result.head)
      let reopenedValue =
        try await reopened.permissionedRemoteReplicaRecord(
          target: fixture.target,
          collection: initial.records[0].collection,
          rkey: initial.records[0].rkey
        )
      XCTAssertEqual(reopenedValue, initial.records[0].value)
      try await assertNoRemoteReplicaStaging(in: reopened)
      try await assertRemoteReplicaGenerationRows(
        in: reopened,
        target: fixture.target,
        generation: 1,
        expectedRecords: 1,
        expectedBlocks: 1,
        expectedChunks: 1
      )
      try await assertRemoteReplicaGenerationRows(
        in: reopened,
        target: fixture.target,
        generation: 2,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await reopened.close()
    } catch {
      try? await reopened.close()
      throw error
    }
  }

  func testOneHundredTwentyNineRecordsPrepareAndCleanupAcrossBoundedPages()
    async throws
  {
    XCTAssertEqual(
      PermissionedRemoteReplicaRecoveryBudgets.maximumRowsPerPass,
      128
    )
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "bounded-pages"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let recordCount =
        PermissionedRemoteReplicaRecoveryBudgets.maximumRowsPerPass + 1
      let first = try fixture.archive(
        revision: "222222222222a",
        values: (0 ..< recordCount).map { "first generation \($0)" },
        ikmByte: 0x61
      )
      let firstStaged = try await fixture.stage(
        database: database,
        archive: first,
        expectedBase: nil,
        requestID: "bounded-first",
        freshnessWitness: fixture.witness(for: first)
      )
      try await database.markPermissionedRemoteReplicaImportVerified(
        sessionID: firstStaged.session.id,
        verification: firstStaged.verification,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
      try await assertRemoteReplicaStagingCardinality(
        in: database,
        expectedIndex: recordCount,
        expectedBlocks: recordCount,
        expectedChunks: recordCount
      )
      let firstProbe = RemoteReplicaMutationProbe()
      await database.installTestingHooks(SQLiteTestingHooks(
        afterRemoteReplicaMutatingSQL: { index in
          await firstProbe.record(index)
        }
      ))
      let firstResult = try await database
        .publishVerifiedPermissionedRemoteReplicaRecovery(
          sessionID: firstStaged.session.id,
          consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      XCTAssertEqual(firstResult.head.generation, 1)
      let firstCounts = await firstProbe.snapshot()
      XCTAssertEqual(firstCounts[1], 2)
      XCTAssertEqual(firstCounts[2], 2)
      XCTAssertEqual(firstCounts[3], 2)
      try await assertNoRemoteReplicaStaging(in: database)

      let second = try fixture.archive(
        revision: "222222222222b",
        values: (0 ..< recordCount).map { "second generation \($0)" },
        ikmByte: 0x62
      )
      let secondStaged = try await fixture.stage(
        database: database,
        archive: second,
        expectedBase: firstResult.head,
        requestID: "bounded-second",
        freshnessWitness: fixture.witness(for: second)
      )
      try await database.markPermissionedRemoteReplicaImportVerified(
        sessionID: secondStaged.session.id,
        verification: secondStaged.verification,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
      let secondProbe = RemoteReplicaMutationProbe()
      await database.installTestingHooks(SQLiteTestingHooks(
        afterRemoteReplicaMutatingSQL: { index in
          await secondProbe.record(index)
        }
      ))
      let secondResult = try await database
        .publishVerifiedPermissionedRemoteReplicaRecovery(
          sessionID: secondStaged.session.id,
          consumedAt: RemoteReplicaSQLiteFixture.operationNow + 2,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      XCTAssertEqual(secondResult.head.generation, 2)
      let secondCounts = await secondProbe.snapshot()
      XCTAssertEqual(secondCounts[1], 2)
      XCTAssertEqual(secondCounts[2], 2)
      XCTAssertEqual(secondCounts[3], 2)
      try await assertNoRemoteReplicaStaging(in: database)
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 1,
        expectedRecords: 0,
        expectedBlocks: 0,
        expectedChunks: 0
      )
      try await assertRemoteReplicaGenerationRows(
        in: database,
        target: fixture.target,
        generation: 2,
        expectedRecords: recordCount,
        expectedBlocks: recordCount,
        expectedChunks: recordCount
      )
      let currentValue =
        try await database.permissionedRemoteReplicaRecord(
          target: fixture.target,
          collection: second.records[0].collection,
          rkey: second.records[0].rkey
        )
      XCTAssertEqual(
        currentValue,
        second.records[0].value
      )
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }
}

private struct RemoteReplicaSQLiteFixture {
  static let createdAt: Int64 = 100
  static let operationNow: Int64 = 101
  static let expiresAt: Int64 = 200

  let root: URL
  let receiverDID = "did:plc:remote-replica-receiver"
  let repositoryDID = "did:plc:remote-replica-writer"
  let space: SpaceURI
  let target: PermissionedRemoteReplicaTarget
  let signingKey = P256.Signing.PrivateKey()

  init(name: String) throws {
    root = FileManager.default.temporaryDirectory.appending(
      path: "SwanRemoteReplica-\(name)-\(UUID().uuidString)",
      directoryHint: .isDirectory
    )
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    space = try SpaceURI(
      authority: "did:plc:remote-replica-authority",
      spaceType: "app.swan.remote-replica",
      skey: "acceptance"
    )
    target = try PermissionedRemoteReplicaTarget(
      receiverDID: receiverDID,
      space: space,
      repositoryDID: repositoryDID
    )
  }

  func open() async throws -> SQLiteAccountDatabase {
    try await SQLiteAccountDatabase(
      dataDirectory: root,
      did: receiverDID
    )
  }

  func archive(
    revision: String,
    values: [String],
    ikmByte: UInt8
  ) throws -> RemoteReplicaArchive {
    guard !values.isEmpty else {
      throw RemoteReplicaSQLiteTestError.emptyFixture
    }
    let collection = "app.bsky.feed.post"
    var testRecords: [RemoteReplicaRecord] = []
    var encodedRecords: [SpaceRecord] = []
    var ltHash = LtHash()
    for (index, text) in values.enumerated() {
      let rkey = values.count == 1
        ? "record"
        : String(format: "record-%04d", index)
      let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
        (key: "text", value: text),
      ]))
      let cid = CID.fromDAGCBOR(value)
      let uri = try SpaceRecordURI(
        space: space,
        author: repositoryDID,
        collection: collection,
        rkey: rkey
      )
      testRecords.append(RemoteReplicaRecord(
        collection: collection,
        rkey: rkey,
        value: value,
        cid: cid
      ))
      encodedRecords.append(SpaceRecord(
        uri: uri,
        value: value,
        cid: cid.string,
        revision: UInt64(index + 1)
      ))
      ltHash.add(element: "\(collection)/\(rkey)/\(cid.string)")
    }
    let wireRevision = try TID(tidString: revision)
    let commit = try SpaceCommitCodec.sign(
      context: try SpaceCommitContext(
        space: space,
        author: repositoryDID,
        rev: revision,
        ikm: Data(repeating: ikmByte, count: 32)
      ),
      commitment: ltHash.commitment,
      key: signingKey
    )
    let encoded = try SpaceCARCodec.encode(
      commit: commit,
      records: encodedRecords
    )
    return RemoteReplicaArchive(
      wireRevision: wireRevision,
      commitment: ltHash.commitment,
      commitRootCID: encoded.commitCID,
      car: encoded.data,
      records: testRecords,
      limits: try SpaceCARRecoveryLimits(
        maximumCARBytes: encoded.data.count
      )
    )
  }

  func witness(
    for archive: RemoteReplicaArchive
  ) throws -> PermissionedRemoteReplicaFreshnessWitness {
    try PermissionedRemoteReplicaFreshnessWitness(
      wireRevision: archive.wireRevision,
      commitment: archive.commitment
    )
  }

  func binding(
    archive: RemoteReplicaArchive,
    expectedBase: PermissionedRemoteReplicaHead?,
    requestID: String,
    freshnessWitness: PermissionedRemoteReplicaFreshnessWitness?
  ) throws -> PermissionedRemoteReplicaImportBinding {
    try PermissionedRemoteReplicaImportBinding(
      requestID: requestID,
      requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
      sourceOrigin: "https://writer.example",
      target: target,
      expectedBase: expectedBase,
      freshnessWitness: freshnessWitness,
      verifierIdentity: "did:key:remote-replica-test-verifier",
      profileID: "permissioned-data-0016-test",
      limits: archive.limits
    )
  }

  func start(
    database: SQLiteAccountDatabase,
    archive: RemoteReplicaArchive,
    expectedBase: PermissionedRemoteReplicaHead?,
    requestID: String,
    freshnessWitness: PermissionedRemoteReplicaFreshnessWitness
  ) async throws -> RemoteReplicaStartedImport {
    let binding = try binding(
      archive: archive,
      expectedBase: expectedBase,
      requestID: requestID,
      freshnessWitness: freshnessWitness
    )
    let outcome = try await database
      .createPermissionedRemoteReplicaImportSession(
        binding: binding,
        createdAt: Self.createdAt,
        expiresAt: Self.expiresAt,
        now: Self.operationNow
      )
    guard case let .staged(session) = outcome else {
      throw RemoteReplicaSQLiteTestError.unexpectedStartOutcome
    }
    return RemoteReplicaStartedImport(
      binding: binding,
      session: session
    )
  }

  func stage(
    database: SQLiteAccountDatabase,
    archive: RemoteReplicaArchive,
    expectedBase: PermissionedRemoteReplicaHead?,
    requestID: String,
    freshnessWitness: PermissionedRemoteReplicaFreshnessWitness
  ) async throws -> RemoteReplicaStagedImport {
    let started = try await start(
      database: database,
      archive: archive,
      expectedBase: expectedBase,
      requestID: requestID,
      freshnessWitness: freshnessWitness
    )
    let staging = SQLitePermissionedRemoteReplicaRecoveryStaging(
      database: database,
      sessionID: started.session.id,
      now: { Self.operationNow }
    )
    let verificationKey = signingKey.publicKey
    let verification = try await SpaceCARCodec.verifyStreamingRecovery(
      from: RemoteReplicaCARDataSource(archive.car),
      space: space,
      author: repositoryDID,
      contextSignatureVerifier: {
        try SpaceCommitCodec.verifyContextSignature(
          $0,
          publicKey: verificationKey
        )
      },
      index: staging,
      recordSink: staging,
      expectedEntries: archive.records.first.map {
        [
          SpaceCARRecoveryIndexEntry(
            path: "\($0.collection)/\($0.rkey)",
            cid: $0.cid
          ),
        ]
      } ?? [],
      limits: archive.limits
    )
    return RemoteReplicaStagedImport(
      binding: started.binding,
      session: started.session,
      verification: verification
    )
  }

  func install(
    database: SQLiteAccountDatabase,
    archive: RemoteReplicaArchive,
    expectedBase: PermissionedRemoteReplicaHead?,
    requestID: String
  ) async throws -> RemoteReplicaInstalledImport {
    let staged = try await stage(
      database: database,
      archive: archive,
      expectedBase: expectedBase,
      requestID: requestID,
      freshnessWitness: witness(for: archive)
    )
    try await database.markPermissionedRemoteReplicaImportVerified(
      sessionID: staged.session.id,
      verification: staged.verification,
      now: Self.operationNow
    )
    let result = try await database
      .publishVerifiedPermissionedRemoteReplicaRecovery(
        sessionID: staged.session.id,
        consumedAt: Self.operationNow + 1,
        now: Self.operationNow
      )
    return RemoteReplicaInstalledImport(
      binding: staged.binding,
      result: result
    )
  }

  func injectRetainedRecord(
    _ record: RemoteReplicaRecord,
    generation: UInt64,
    database: SQLiteAccountDatabase
  ) async throws {
    _ = try await database.connection.query(
      """
      INSERT INTO permissioned_remote_replica_blocks(
        space_uri, repository_did, cid, byte_count,
        chunk_count, generation
      ) VALUES (?, ?, ?, ?, 1, ?)
      """,
      [
        .text(space.rawValue),
        .text(repositoryDID),
        .text(record.cid.string),
        .integer(record.value.count),
        .integer(Int(generation)),
      ]
    )
    _ = try await database.connection.query(
      """
      INSERT INTO permissioned_remote_replica_block_chunks(
        space_uri, repository_did, generation,
        cid, chunk_index, bytes
      ) VALUES (?, ?, ?, ?, 0, ?)
      """,
      [
        .text(space.rawValue),
        .text(repositoryDID),
        .integer(Int(generation)),
        .text(record.cid.string),
        record.value.sqliteData!,
      ]
    )
    _ = try await database.connection.query(
      """
      INSERT INTO permissioned_remote_replica_records(
        space_uri, repository_did, collection, rkey,
        cid, generation
      ) VALUES (?, ?, ?, ?, ?, ?)
      """,
      [
        .text(space.rawValue),
        .text(repositoryDID),
        .text(record.collection),
        .text(record.rkey),
        .text(record.cid.string),
        .integer(Int(generation)),
      ]
    )
  }
}

private struct RemoteReplicaArchive {
  let wireRevision: TID
  let commitment: Data
  let commitRootCID: CID
  let car: Data
  let records: [RemoteReplicaRecord]
  let limits: SpaceCARRecoveryLimits
}

private struct RemoteReplicaRecord {
  let collection: String
  let rkey: String
  let value: Data
  let cid: CID
}

private struct RemoteReplicaStartedImport {
  let binding: PermissionedRemoteReplicaImportBinding
  let session: PermissionedRemoteReplicaImportSession
}

private struct RemoteReplicaStagedImport {
  let binding: PermissionedRemoteReplicaImportBinding
  let session: PermissionedRemoteReplicaImportSession
  let verification: VerifiedStreamingSpaceCARRecovery
}

private struct RemoteReplicaInstalledImport {
  let binding: PermissionedRemoteReplicaImportBinding
  let result: CommittedPermissionedRemoteReplicaRecovery
}

private actor RemoteReplicaCARDataSource: SpaceCARRecoveryByteSource {
  private let bytes: Data
  private var offset = 0

  init(_ bytes: Data) {
    self.bytes = bytes
  }

  func read(maximumBytes: Int) -> Data? {
    guard offset < bytes.count else { return nil }
    let end = min(
      bytes.count,
      offset + min(
        maximumBytes,
        SpaceCARRecoveryLimits.maximumChunkBytes
      )
    )
    defer { offset = end }
    return Data(bytes[offset ..< end])
  }
}

private actor RemoteReplicaMutationProbe {
  private var counts: [Int: Int] = [:]

  func record(_ index: Int) {
    counts[index, default: 0] += 1
  }

  func snapshot() -> [Int: Int] {
    counts
  }
}

private enum RemoteReplicaInjectedFailure: Error, Equatable {
  case expected
}

private enum RemoteReplicaSQLiteTestError: Error {
  case emptyFixture
  case unexpectedStartOutcome
}

private func assertRemoteReplicaError<T>(
  _ expected: PermissionedRemoteReplicaRecoveryError,
  file: StaticString = #filePath,
  line: UInt = #line,
  operation: () async throws -> T
) async {
  do {
    _ = try await operation()
    XCTFail(
      "expected remote-replica error \(expected)",
      file: file,
      line: line
    )
  } catch {
    XCTAssertEqual(
      error as? PermissionedRemoteReplicaRecoveryError,
      expected,
      file: file,
      line: line
    )
  }
}

private func assertNoRemoteReplicaStaging(
  in database: SQLiteAccountDatabase,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  let rows = try await database.connection.query(
    """
    SELECT
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_sessions) AS sessions,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_index) AS idx,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_blocks) AS blocks,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_block_chunks) AS chunks
    """
  )
  XCTAssertEqual(
    rows.first?.column("sessions")?.integer,
    0,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("idx")?.integer,
    0,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("blocks")?.integer,
    0,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("chunks")?.integer,
    0,
    file: file,
    line: line
  )
}

private func assertRemoteReplicaStagingCardinality(
  in database: SQLiteAccountDatabase,
  expectedIndex: Int,
  expectedBlocks: Int,
  expectedChunks: Int,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  let rows = try await database.connection.query(
    """
    SELECT
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_index) AS idx,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_blocks) AS blocks,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_import_block_chunks) AS chunks
    """
  )
  XCTAssertEqual(
    rows.first?.column("idx")?.integer,
    expectedIndex,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("blocks")?.integer,
    expectedBlocks,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("chunks")?.integer,
    expectedChunks,
    file: file,
    line: line
  )
}

private func assertRemoteReplicaGenerationRows(
  in database: SQLiteAccountDatabase,
  target: PermissionedRemoteReplicaTarget,
  generation: UInt64,
  expectedRecords: Int,
  expectedBlocks: Int,
  expectedChunks: Int,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  let bindings: [SQLiteData] = [
    .text(target.space.rawValue),
    .text(target.repositoryDID),
    .integer(Int(generation)),
  ]
  let rows = try await database.connection.query(
    """
    SELECT
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_records
       WHERE space_uri = ? AND repository_did = ?
         AND generation = ?) AS records,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_blocks
       WHERE space_uri = ? AND repository_did = ?
         AND generation = ?) AS blocks,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_block_chunks
       WHERE space_uri = ? AND repository_did = ?
         AND generation = ?) AS chunks
    """,
    bindings + bindings + bindings
  )
  XCTAssertEqual(
    rows.first?.column("records")?.integer,
    expectedRecords,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("blocks")?.integer,
    expectedBlocks,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("chunks")?.integer,
    expectedChunks,
    file: file,
    line: line
  )
}

private func assertNoRemoteReplicaLiveRows(
  in database: SQLiteAccountDatabase,
  target: PermissionedRemoteReplicaTarget,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  let bindings: [SQLiteData] = [
    .text(target.space.rawValue),
    .text(target.repositoryDID),
  ]
  let rows = try await database.connection.query(
    """
    SELECT
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_records
       WHERE space_uri = ? AND repository_did = ?) AS records,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_blocks
       WHERE space_uri = ? AND repository_did = ?) AS blocks,
      (SELECT COUNT(*)
       FROM permissioned_remote_replica_block_chunks
       WHERE space_uri = ? AND repository_did = ?) AS chunks
    """,
    bindings + bindings + bindings
  )
  XCTAssertEqual(
    rows.first?.column("records")?.integer,
    0,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("blocks")?.integer,
    0,
    file: file,
    line: line
  )
  XCTAssertEqual(
    rows.first?.column("chunks")?.integer,
    0,
    file: file,
    line: line
  )
}
