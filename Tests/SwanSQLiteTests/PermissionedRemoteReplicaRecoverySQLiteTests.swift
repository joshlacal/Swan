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

  func testCanonicalRecordOrderRecoveryWithSharedCID() async throws {
    let fixture = try RemoteReplicaSQLiteFixture(name: "canonical-car-order")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let archive = try fixture.archive(
        revision: "222222222222a",
        values: ["shared", "distinct", "shared"],
        ikmByte: 0x31,
        rkeys: ["aa", "b", "z"]
      )
      let installed = try await fixture.install(
        database: database, archive: archive, expectedBase: nil,
        requestID: "canonical-car-order",
        publicationAuthorization: fixture.publicationAuthorization
      )
      XCTAssertEqual(installed.result.head.generation, 1)
      for record in archive.records {
        let value = try await database.permissionedRemoteReplicaRecord(
          target: fixture.target, collection: record.collection, rkey: record.rkey
        )
        XCTAssertEqual(value, record.value)
      }
      try await assertNoRemoteReplicaStaging(in: database)
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

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
        requestID: "authenticated-bootstrap",
        publicationAuthorization: fixture.publicationAuthorization
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
        requestID: "authenticated-replacement",
        publicationAuthorization: fixture.publicationAuthorization
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

  // Regression: `permissionedRemoteReplicaRecords` must read the head through
  // the gate-free loader. Calling the gate-wrapped `permissionedRemoteReplicaHead`
  // inside its own `withConnectionGate` deadlocks the connection gate forever.
  func testRemoteReplicaRecordsEnumerationDoesNotDeadlockTheConnectionGate()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "records-enumeration-regression"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let archive = try fixture.archive(
        revision: "222222222222a",
        values: ["gate regression value"],
        ikmByte: 0x33
      )
      let installed = try await fixture.install(
        database: database,
        archive: archive,
        expectedBase: nil,
        requestID: "records-enumeration-regression",
        publicationAuthorization: fixture.publicationAuthorization
      )
      XCTAssertEqual(installed.result.head.generation, 1)
      let snapshots = try await database.permissionedRemoteReplicaRecords(
        target: fixture.target
      )
      XCTAssertEqual(snapshots.count, 1)
      XCTAssertEqual(snapshots[0].uri.collection, "app.bsky.feed.post")
      XCTAssertEqual(snapshots[0].uri.rkey, "record")
      XCTAssertEqual(snapshots[0].value, archive.records[0].value)
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

  func testDeactivatedControlAccountRejectsDirectSQLitePublication()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "deactivated-publication"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let control = try await SQLiteControlDatabase(
      dataDirectory: fixture.root
    )
    defer { Task { try? await control.close() } }
    _ = try await control.createAccount(
      AccountControlRegistration(
        did: fixture.receiverDID,
        canonicalHandle: "remote-replica-receiver.example.com",
        passwordVerifier:
          "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        signingKey: .init(purpose: .signing, generation: 1),
        rotationKey: .init(purpose: .rotation, generation: 1),
        createdAt: Date(timeIntervalSince1970: 100)
      )
    )
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    let archive = try fixture.archive(
      revision: "222222222222a",
      values: ["must remain unpublished"],
      ikmByte: 0x1a
    )
    let staged = try await fixture.stage(
      database: database,
      archive: archive,
      expectedBase: nil,
      requestID: "deactivated-direct-sqlite",
      freshnessWitness: fixture.witness(for: archive)
    )
    try await database.markPermissionedRemoteReplicaImportVerified(
      sessionID: staged.session.id,
      verification: staged.verification,
      now: RemoteReplicaSQLiteFixture.operationNow
    )
    _ = try await control.transitionStatus(
      did: fixture.receiverDID,
      to: .deactivated,
      declaration: .init(),
      now: Date(timeIntervalSince1970: 102)
    )

    do {
      _ = try await database
        .publishVerifiedPermissionedRemoteReplicaRecovery(
          sessionID: staged.session.id,
          consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
          now: RemoteReplicaSQLiteFixture.operationNow,
          publicationAuthorization: { operation in
            try await control.withActiveAccountAuthorization(
              did: fixture.receiverDID,
              operation: operation
            )
          }
        )
      XCTFail("deactivated account must not publish a remote replica")
    } catch let error as AccountControlStoreError {
      XCTAssertEqual(error, .invalidTransition)
    }

    let head = try await database.permissionedRemoteReplicaHead(
      target: fixture.target
    )
    XCTAssertNil(head)
    try await assertNoRemoteReplicaLiveRows(
      in: database,
      target: fixture.target
    )
  }

  func testFinalHeadSwapRemainsInsideActiveAccountAuthorization()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "active-publication-enclosure"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let control = try await SQLiteControlDatabase(
      dataDirectory: fixture.root
    )
    defer { Task { try? await control.close() } }
    _ = try await control.createAccount(
      AccountControlRegistration(
        did: fixture.receiverDID,
        canonicalHandle: "remote-replica-receiver.example.com",
        passwordVerifier:
          "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        signingKey: .init(purpose: .signing, generation: 1),
        rotationKey: .init(purpose: .rotation, generation: 1),
        createdAt: Date(timeIntervalSince1970: 100)
      )
    )
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    let archive = try fixture.archive(
      revision: "222222222222a",
      values: ["publication remains fenced"],
      ikmByte: 0x1b
    )
    let staged = try await fixture.stage(
      database: database,
      archive: archive,
      expectedBase: nil,
      requestID: "active-publication-enclosure",
      freshnessWitness: fixture.witness(for: archive)
    )
    try await database.markPermissionedRemoteReplicaImportVerified(
      sessionID: staged.session.id,
      verification: staged.verification,
      now: RemoteReplicaSQLiteFixture.operationNow
    )
    let publicationFence = RemoteReplicaPublicationFence()
    await database.installTestingHooks(SQLiteTestingHooks(
      afterRemoteReplicaMutatingSQL: { index in
        if index == 4 {
          try await publicationFence.requireOperationActive()
        }
      }
    ))

    let result = try await database
      .publishVerifiedPermissionedRemoteReplicaRecovery(
        sessionID: staged.session.id,
        consumedAt: RemoteReplicaSQLiteFixture.operationNow + 1,
        now: RemoteReplicaSQLiteFixture.operationNow,
        publicationAuthorization: { operation in
          try await control.withActiveAccountAuthorization(
            did: fixture.receiverDID
          ) {
            try await publicationFence.authorize(operation)
          }
        }
      )

    XCTAssertEqual(result.head.wireRevision, archive.wireRevision)
    let authorizationAttempted = await publicationFence.authorizationAttempted
    let operationActive = await publicationFence.operationActive
    XCTAssertTrue(authorizationAttempted)
    XCTAssertFalse(operationActive)
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
        requestID: "last-good",
        publicationAuthorization: fixture.publicationAuthorization
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
            now: RemoteReplicaSQLiteFixture.operationNow,
            publicationAuthorization: fixture.publicationAuthorization
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
        requestID: "installed-before-corruption",
        publicationAuthorization: fixture.publicationAuthorization
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
          now: RemoteReplicaSQLiteFixture.operationNow,
          publicationAuthorization: fixture.publicationAuthorization
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
        requestID: "same-tid-base",
        publicationAuthorization: fixture.publicationAuthorization
      )
      let equivalent = try fixture.archive(
        revision: "222222222222a",
        values: ["stable value"],
        ikmByte: 0x42
      )
      XCTAssertNotEqual(equivalent.commitRootCID, initial.commitRootCID)
      let publicationCounter = RemoteReplicaPublicationCounter()
      let idempotent = try await fixture.install(
        database: database,
        archive: equivalent,
        expectedBase: installed.result.head,
        requestID: "same-tid-equivalent",
        publicationAuthorization: { operation in
          await publicationCounter.increment()
          return try await fixture.publicationAuthorization(operation)
        }
      )
      XCTAssertEqual(idempotent.result.head, installed.result.head)
      XCTAssertEqual(idempotent.result.head.generation, 1)
      let publicationCount = await publicationCounter.value
      XCTAssertEqual(publicationCount, 1)
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

      // A request ID and caller-supplied request digest are not sufficient
      // replay authority. The durable result must bind the complete expected
      // base, not only its generation; otherwise a low-level storage caller
      // could receive a committed replay for a different CAS precondition.
      var forgedMarker = installed.result.head.stateMarker
      forgedMarker[forgedMarker.startIndex] ^= 0x01
      let forgedBase = try PermissionedRemoteReplicaHead(
        target: fixture.target,
        generation: installed.result.head.generation,
        wireRevision: installed.result.head.wireRevision,
        historyFloorWireRevision:
          installed.result.head.historyFloorWireRevision,
        ltHash: installed.result.head.ltHash,
        commitment: installed.result.head.commitment,
        stateMarker: forgedMarker
      )
      let forgedBinding = try fixture.binding(
        archive: equivalent,
        expectedBase: forgedBase,
        requestID: "same-tid-equivalent",
        freshnessWitness: fixture.witness(for: equivalent)
      )
      await assertRemoteReplicaError(.conflictingRequestReuse) {
        try await database.createPermissionedRemoteReplicaImportSession(
          binding: forgedBinding,
          createdAt: RemoteReplicaSQLiteFixture.createdAt,
          expiresAt: RemoteReplicaSQLiteFixture.expiresAt,
          now: RemoteReplicaSQLiteFixture.operationNow
        )
      }

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
          now: RemoteReplicaSQLiteFixture.operationNow,
          publicationAuthorization: fixture.publicationAuthorization
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

  func testCommittedReplayRejectsChangedLogicalRestoreLimitAfterRestart()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "logical-limit-replay")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let archive = try fixture.archive(
      revision: "222222222222a", values: ["logical limit"], ikmByte: 0x44
    )
    let installed = try await fixture.install(
      database: database, archive: archive, expectedBase: nil,
      requestID: "logical-limit-replay",
      publicationAuthorization: fixture.publicationAuthorization
    )
    try await database.close()

    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    let original = installed.binding
    let stricterLimits = try SpaceCARRecoveryLimits(
      maximumCARBytes: original.limits.maximumCARBytes,
      maximumRecordBytes: original.limits.maximumRecordBytes,
      maximumIndexEntries: original.limits.maximumIndexEntries,
      maximumUniqueBlocks: original.limits.maximumUniqueBlocks,
      maximumLogicalRestoredBytes:
        original.limits.maximumLogicalRestoredBytes - 1
    )
    let source = try PermissionedRemoteReplicaSourceIdentity(
      persistedOrigin: original.sourceOrigin,
      repositoryDID: original.target.repositoryDID,
      verifierIdentity: original.verifierIdentity
    )
    let changed = try PermissionedRemoteReplicaImportBinding(
      requestID: original.requestID,
      requestDigest: original.requestDigest,
      source: source,
      target: original.target,
      expectedBase: original.expectedBase,
      freshnessWitness: original.freshnessWitness,
      profileID: original.profileID,
      limits: stricterLimits
    )
    let beforeHead = try await reopened.permissionedRemoteReplicaHead(
      target: fixture.target
    )
    await assertRemoteReplicaError(.conflictingRequestReuse) {
      try await reopened.createPermissionedRemoteReplicaImportSession(
        binding: changed,
        createdAt: RemoteReplicaSQLiteFixture.createdAt,
        expiresAt: RemoteReplicaSQLiteFixture.expiresAt,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
    }
    let afterHead = try await reopened.permissionedRemoteReplicaHead(
      target: fixture.target
    )
    let resultCount = try await reopened.connection.query(
      "SELECT COUNT(*) AS count FROM permissioned_remote_replica_import_results"
    ).first?.column("count")?.integer
    XCTAssertEqual(afterHead, beforeHead)
    XCTAssertEqual(resultCount, 1)
  }

  func testImportSessionRestoresLogicalByteLimitAfterRestart() async throws {
    let fixture = try RemoteReplicaSQLiteFixture(name: "logical-limit-session")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let base = try fixture.archive(
      revision: "222222222222a", values: ["session limit"], ikmByte: 0x45
    )
    let logicalLimit = base.car.count + 17
    let archive = RemoteReplicaArchive(
      wireRevision: base.wireRevision,
      commitment: base.commitment,
      commitRootCID: base.commitRootCID,
      car: base.car,
      records: base.records,
      limits: try SpaceCARRecoveryLimits(
        maximumCARBytes: base.limits.maximumCARBytes,
        maximumRecordBytes: base.limits.maximumRecordBytes,
        maximumIndexEntries: base.limits.maximumIndexEntries,
        maximumUniqueBlocks: base.limits.maximumUniqueBlocks,
        maximumLogicalRestoredBytes: logicalLimit
      )
    )
    let binding = try fixture.binding(
      archive: archive, expectedBase: nil,
      requestID: "logical-limit-session",
      freshnessWitness: fixture.witness(for: archive)
    )
    let now = Int64(Date().timeIntervalSince1970)
    let outcome = try await database.createPermissionedRemoteReplicaImportSession(
      binding: binding, createdAt: now, expiresAt: now + 3_600, now: now
    )
    guard case let .staged(started) = outcome else {
      throw RemoteReplicaSQLiteTestError.unexpectedStartOutcome
    }
    try await database.close()

    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    let restored = try await reopened.permissionedRemoteReplicaImportSession(
      id: started.id
    )
    XCTAssertEqual(
      restored.binding.limits.maximumLogicalRestoredBytes,
      logicalLimit
    )
    XCTAssertEqual(restored.binding, binding)
  }

  func testTamperedCommittedLogicalLimitFailsClosedAfterRestart() async throws {
    let fixture = try RemoteReplicaSQLiteFixture(name: "logical-limit-tamper")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let archive = try fixture.archive(
      revision: "222222222222a", values: ["tamper limit"], ikmByte: 0x46
    )
    let installed = try await fixture.install(
      database: database, archive: archive, expectedBase: nil,
      requestID: "logical-limit-tamper",
      publicationAuthorization: fixture.publicationAuthorization
    )
    _ = try await database.connection.query(
      """
      UPDATE permissioned_remote_replica_import_results
      SET maximum_logical_restored_bytes = ?
      WHERE request_id = ?
      """,
      [
        .integer(
          installed.binding.limits.maximumLogicalRestoredBytes - 1
        ),
        .text(installed.binding.requestID),
      ]
    )
    try await database.close()

    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    let beforeHead = try await reopened.permissionedRemoteReplicaHead(
      target: fixture.target
    )
    await assertRemoteReplicaError(.conflictingRequestReuse) {
      try await reopened.createPermissionedRemoteReplicaImportSession(
        binding: installed.binding,
        createdAt: RemoteReplicaSQLiteFixture.createdAt,
        expiresAt: RemoteReplicaSQLiteFixture.expiresAt,
        now: RemoteReplicaSQLiteFixture.operationNow
      )
    }
    let afterHead = try await reopened.permissionedRemoteReplicaHead(
      target: fixture.target
    )
    XCTAssertEqual(afterHead, beforeHead)
  }

  func testLogicalLimitMigrationRejectsNonemptyLegacyResults() async throws {
    let fixture = try RemoteReplicaSQLiteFixture(name: "logical-limit-legacy-full")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let archive = try fixture.archive(
      revision: "222222222222a", values: ["legacy result"], ikmByte: 0x47
    )
    _ = try await fixture.install(
      database: database, archive: archive, expectedBase: nil,
      requestID: "logical-limit-legacy-full",
      publicationAuthorization: fixture.publicationAuthorization
    )
    try await removeLogicalLimitColumnsForMigrationTest(database: database)
    try await database.close()

    do {
      let unexpectedlyOpened = try await fixture.open()
      try await unexpectedlyOpened.close()
      XCTFail("nonempty legacy logical-limit rows were accepted")
    } catch let SQLiteRepositoryError.corruptDatabase(message) {
      XCTAssertTrue(message.contains("logical-limit bindings"))
    }
  }

  func testLogicalLimitMigrationUpgradesEmptyLegacyTables() async throws {
    let fixture = try RemoteReplicaSQLiteFixture(name: "logical-limit-legacy-empty")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    _ = try await database.connection.query(
      "INSERT INTO public_records(uri, value, revision) VALUES (?, ?, ?)",
      [
        .text("at://did:plc:unrelated/app.test.record/logical-limit"),
        .blob(.init(bytes: [0xa0])), .integer(9),
      ]
    )
    try await removeLogicalLimitColumnsForMigrationTest(database: database)
    try await database.close()

    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    for table in [
      "permissioned_remote_replica_import_sessions",
      "permissioned_remote_replica_import_results",
    ] {
      let columns = try await reopened.connection.query(
        "PRAGMA table_info(\(table))"
      )
      XCTAssertTrue(columns.contains {
        $0.column("name")?.string == "maximum_logical_restored_bytes"
      })
    }
    let unrelated = try await reopened.connection.query(
      "SELECT revision FROM public_records WHERE uri = ?",
      [.text("at://did:plc:unrelated/app.test.record/logical-limit")]
    )
    XCTAssertEqual(unrelated.first?.column("revision")?.integer, 9)
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
            now: RemoteReplicaSQLiteFixture.operationNow,
            publicationAuthorization: fixture.publicationAuthorization
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
          requestID: "retry-after-failpoint-\(failpoint)",
          publicationAuthorization: fixture.publicationAuthorization
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
      requestID: "preparing-crash-base",
      publicationAuthorization: fixture.publicationAuthorization
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
          now: RemoteReplicaSQLiteFixture.operationNow,
          publicationAuthorization: fixture.publicationAuthorization
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
          now: RemoteReplicaSQLiteFixture.operationNow,
          publicationAuthorization: fixture.publicationAuthorization
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

  func testVerifiedIncrementalBatchAppliesCreateUpdateDeleteDurably()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-crud")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    do {
      let initial = try fixture.archive(
        revision: "222222222222a",
        values: ["update me", "delete me"],
        ikmByte: 0x71
      )
      let installed = try await fixture.install(
        database: database,
        archive: initial,
        expectedBase: nil,
        requestID: "incremental-crud-bootstrap",
        publicationAuthorization: fixture.publicationAuthorization
      )
      let base = installed.result.head
      let revision = try TID(tidString: "222222222222b")
      let updatedValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
        (key: "text", value: "updated"),
      ]))
      let createdValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
        (key: "text", value: "created"),
      ]))
      let updatedCID = CID.fromDAGCBOR(updatedValue)
      let createdCID = CID.fromDAGCBOR(createdValue)
      let createdURI = try SpaceRecordURI(
        space: fixture.space, author: fixture.repositoryDID,
        collection: initial.records[0].collection, rkey: "created"
      )
      let updatedURI = try SpaceRecordURI(
        space: fixture.space, author: fixture.repositoryDID,
        collection: initial.records[0].collection,
        rkey: initial.records[0].rkey
      )
      let deletedURI = try SpaceRecordURI(
        space: fixture.space, author: fixture.repositoryDID,
        collection: initial.records[1].collection,
        rkey: initial.records[1].rkey
      )
      var terminalHash = try LtHash(serialized: base.ltHash)
      terminalHash.add(element: "\(createdURI.collection)/\(createdURI.rkey)/\(createdCID.string)")
      terminalHash.remove(element: "\(updatedURI.collection)/\(updatedURI.rkey)/\(initial.records[0].cid.string)")
      terminalHash.add(element: "\(updatedURI.collection)/\(updatedURI.rkey)/\(updatedCID.string)")
      terminalHash.remove(element: "\(deletedURI.collection)/\(deletedURI.rkey)/\(initial.records[1].cid.string)")
      let operations: [VerifiedPermissionedRemoteReplicaOperation] = [
          .init(
            operationIndex: 0, wireRevision: revision,
            action: .create, uri: createdURI,
            cid: createdCID, previousCID: nil, value: createdValue
          ),
          .init(
            operationIndex: 1, wireRevision: revision,
            action: .update, uri: updatedURI,
            cid: updatedCID, previousCID: initial.records[0].cid,
            value: updatedValue
          ),
          .init(
            operationIndex: 2, wireRevision: revision,
            action: .delete, uri: deletedURI,
            cid: nil, previousCID: initial.records[1].cid, value: nil
          ),
        ]
      let terminal = try PermissionedRemoteReplicaIncrementalTerminalHead(
        wireRevision: revision,
        ltHash: terminalHash.serialized,
        commitment: terminalHash.commitment,
        recordCount: 2,
        operationCount: operations.count,
        operationDigest:
          PermissionedRemoteReplicaIncrementalOperationWitness
            .digest(operations)
      )
      let digest = PermissionedRemoteReplicaIncrementalBatch.canonicalDigest(
        target: fixture.target, expectedHead: base,
        terminalHead: terminal, operations: operations, requestSequence: 1
      )
      let batch = try PermissionedRemoteReplicaIncrementalBatch(
        target: fixture.target,
        expectedHead: base,
        terminalHead: terminal,
        operations: operations,
        requestID: "incremental-crud",
        requestSequence: 1,
        requestDigest: digest
      )

      let outcome = try await database
        .applyVerifiedPermissionedRemoteReplicaBatch(batch, appliedAt: 301)
      guard case let .applied(result) = outcome else {
        return XCTFail("expected applied incremental result, got \(outcome)")
      }
      XCTAssertEqual(result.head.generation, base.generation)
      XCTAssertEqual(result.head.wireRevision, revision)
      XCTAssertEqual(result.recordCount, 2)
      let durableCreated = try await database.permissionedRemoteReplicaRecord(
        target: fixture.target, collection: createdURI.collection,
        rkey: createdURI.rkey
      )
      let durableUpdated = try await database.permissionedRemoteReplicaRecord(
        target: fixture.target, collection: updatedURI.collection,
        rkey: updatedURI.rkey
      )
      let durableDeleted = try await database.permissionedRemoteReplicaRecord(
        target: fixture.target, collection: deletedURI.collection,
        rkey: deletedURI.rkey
      )
      XCTAssertEqual(durableCreated, createdValue)
      XCTAssertEqual(durableUpdated, updatedValue)
      XCTAssertNil(durableDeleted)
      try await database.close()
    } catch {
      try? await database.close()
      throw error
    }
  }

  func testVerifiedIncrementalBatchAppliesOrderedMultipleWireRevisions()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(
      name: "incremental-multiple-revisions"
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["base"], ikmByte: 0x72
    )
    let base = try await fixture.install(
      database: database, archive: initial, expectedBase: nil,
      requestID: "incremental-multiple-revisions-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let firstRevision = try TID(tidString: "222222222222b")
    let terminalRevision = try TID(tidString: "222222222222c")
    let updatedValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "updated at b"),
    ]))
    let createdValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "created at c"),
    ]))
    let updatedCID = CID.fromDAGCBOR(updatedValue)
    let createdCID = CID.fromDAGCBOR(createdValue)
    let updatedURI = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection,
      rkey: initial.records[0].rkey
    )
    let createdURI = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: "created-at-c"
    )
    let operations: [VerifiedPermissionedRemoteReplicaOperation] = [
      .init(
        operationIndex: 0, wireRevision: firstRevision, action: .update,
        uri: updatedURI, cid: updatedCID,
        previousCID: initial.records[0].cid, value: updatedValue
      ),
      .init(
        operationIndex: 1, wireRevision: terminalRevision, action: .create,
        uri: createdURI, cid: createdCID, previousCID: nil,
        value: createdValue
      ),
    ]
    var terminalHash = try LtHash(serialized: base.ltHash)
    terminalHash.remove(
      element:
        "\(updatedURI.collection)/\(updatedURI.rkey)/\(initial.records[0].cid.string)"
    )
    terminalHash.add(
      element: "\(updatedURI.collection)/\(updatedURI.rkey)/\(updatedCID.string)"
    )
    terminalHash.add(
      element: "\(createdURI.collection)/\(createdURI.rkey)/\(createdCID.string)"
    )
    let batch = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: terminalRevision, terminalHash: terminalHash,
      recordCount: 2, operations: operations,
      requestID: "incremental-multiple-revisions"
    )

    let outcome = try await database.applyVerifiedPermissionedRemoteReplicaBatch(
      batch, appliedAt: 351
    )
    guard case let .applied(result) = outcome else {
      return XCTFail("expected applied incremental result, got \(outcome)")
    }
    XCTAssertEqual(result.head.wireRevision, terminalRevision)
    XCTAssertEqual(result.recordCount, 2)
    let durableUpdated = try await database.permissionedRemoteReplicaRecord(
      target: fixture.target, collection: updatedURI.collection,
      rkey: updatedURI.rkey
    )
    let durableCreated = try await database.permissionedRemoteReplicaRecord(
      target: fixture.target, collection: createdURI.collection,
      rkey: createdURI.rkey
    )
    XCTAssertEqual(durableUpdated, updatedValue)
    XCTAssertEqual(durableCreated, createdValue)
  }

  func testIncrementalLateOperationAndTerminalMismatchRollbackEveryWrite()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-rollback")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["last good"], ikmByte: 0x73
    )
    let base = try await fixture.install(
      database: database, archive: initial, expectedBase: nil,
      requestID: "incremental-rollback-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let before = try await incrementalReplicaWitness(
      database: database, target: fixture.target
    )
    let revision = try TID(tidString: "222222222222b")
    let createdValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "must roll back"),
    ]))
    let createdCID = CID.fromDAGCBOR(createdValue)
    let createdURI = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: "late-failure"
    )
    let existingURI = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection,
      rkey: initial.records[0].rkey
    )
    var afterCreateHash = try LtHash(serialized: base.ltHash)
    afterCreateHash.add(
      element: "\(createdURI.collection)/\(createdURI.rkey)/\(createdCID.string)"
    )
    let wrongPrevious = CID.fromDAGCBOR(Data([0xa0]))
    let lateFailureOperations: [VerifiedPermissionedRemoteReplicaOperation] = [
      .init(
        operationIndex: 0, wireRevision: revision, action: .create,
        uri: createdURI, cid: createdCID, previousCID: nil,
        value: createdValue
      ),
      .init(
        operationIndex: 1, wireRevision: revision, action: .delete,
        uri: existingURI, cid: nil, previousCID: wrongPrevious, value: nil
      ),
    ]
    let lateFailure = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: revision, terminalHash: afterCreateHash,
      recordCount: 1, operations: lateFailureOperations,
      requestID: "incremental-late-failure"
    )
    let lateFailureOutcome = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(lateFailure, appliedAt: 401)
    try await database.close()
    let afterLateFailureDatabase = try await fixture.open()
    let afterLateFailure = try await incrementalReplicaWitness(
      database: afterLateFailureDatabase, target: fixture.target
    )
    try await afterLateFailureDatabase.close()
    XCTAssertEqual(lateFailureOutcome, .integrityFailure)
    XCTAssertEqual(afterLateFailure, before)

    let terminalMismatchOperations = [lateFailureOperations[0]]
    let terminalMismatch = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: revision,
      terminalHash: try LtHash(serialized: base.ltHash),
      recordCount: 1, operations: terminalMismatchOperations,
      requestID: "incremental-terminal-mismatch"
    )
    let terminalMismatchDatabase = try await fixture.open()
    let terminalMismatchOutcome = try await terminalMismatchDatabase
      .applyVerifiedPermissionedRemoteReplicaBatch(
        terminalMismatch, appliedAt: 402
      )
    try await terminalMismatchDatabase.close()
    let afterTerminalMismatchDatabase = try await fixture.open()
    let afterTerminalMismatch = try await incrementalReplicaWitness(
      database: afterTerminalMismatchDatabase, target: fixture.target
    )
    try await afterTerminalMismatchDatabase.close()
    XCTAssertEqual(terminalMismatchOutcome, .integrityFailure)
    XCTAssertEqual(afterTerminalMismatch, before)
  }

  func testIncrementalReplayPersistsAcrossRestartAndConflictsFailClosed()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-replay")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["before"], ikmByte: 0x74
    )
    let base = try await fixture.install(
      database: database, archive: initial, expectedBase: nil,
      requestID: "incremental-replay-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let revision = try TID(tidString: "222222222222b")
    let uri = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: initial.records[0].rkey
    )
    let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "after"),
    ]))
    let cid = CID.fromDAGCBOR(value)
    let operation = VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: 0, wireRevision: revision, action: .update,
      uri: uri, cid: cid, previousCID: initial.records[0].cid, value: value
    )
    var terminalHash = try LtHash(serialized: base.ltHash)
    terminalHash.remove(
      element: "\(uri.collection)/\(uri.rkey)/\(initial.records[0].cid.string)"
    )
    terminalHash.add(element: "\(uri.collection)/\(uri.rkey)/\(cid.string)")
    let batch = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: revision, terminalHash: terminalHash,
      recordCount: 1, operations: [operation], requestID: "durable-replay"
    )
    guard case let .applied(applied) = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(batch, appliedAt: 501)
    else { return XCTFail("initial incremental application did not apply") }
    try await database.close()
    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    let duplicate = try await reopened
      .applyVerifiedPermissionedRemoteReplicaBatch(batch, appliedAt: 999)
    XCTAssertEqual(duplicate, .exactDuplicate(applied))

    let conflictingValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "different replay"),
    ]))
    let conflictingCID = CID.fromDAGCBOR(conflictingValue)
    let conflictingOperation = VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: 0, wireRevision: revision, action: .update,
      uri: uri, cid: conflictingCID,
      previousCID: initial.records[0].cid, value: conflictingValue
    )
    var conflictingHash = try LtHash(serialized: base.ltHash)
    conflictingHash.remove(
      element: "\(uri.collection)/\(uri.rkey)/\(initial.records[0].cid.string)"
    )
    conflictingHash.add(
      element: "\(uri.collection)/\(uri.rkey)/\(conflictingCID.string)"
    )
    let conflicting = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: revision, terminalHash: conflictingHash,
      recordCount: 1, operations: [conflictingOperation],
      requestID: "durable-replay"
    )
    let beforeConflict = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    let conflict = try await reopened
      .applyVerifiedPermissionedRemoteReplicaBatch(conflicting, appliedAt: 502)
    let afterConflict = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    XCTAssertEqual(conflict, .conflictingReplay)
    XCTAssertEqual(afterConflict, beforeConflict)
  }

  func testIncrementalReplayFloorRejectsEvictedSequenceAfterRestart()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-floor")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    var openedDatabases = [database]
    defer {
      let databases = openedDatabases
      Task { for database in databases { try? await database.close() } }
    }
    await database.installTestingHooks(SQLiteTestingHooks(
      incrementalReplayRetentionOperationLimit: 3
    ))
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["floor base"], ikmByte: 0x78
    )
    var head = try await fixture.install(
      database: database, archive: initial, expectedBase: nil,
      requestID: "incremental-floor-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let uri = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: initial.records[0].rkey
    )
    var currentCID = initial.records[0].cid

    let first = try makeChainedIncrementalBatch(
      target: fixture.target, expectedHead: head, uri: uri,
      startingCID: currentCID, terminalRevision: "222222222222b",
      requestID: "evicted-request", requestSequence: 1,
      operationCount: 1, valuePrefix: "evicted"
    )
    guard case let .applied(firstResult) = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(first.batch, appliedAt: 901)
    else { return XCTFail("first incremental batch did not apply") }
    head = firstResult.head
    currentCID = first.terminalCID

    for (sequence, revision, operationCount) in [
      (UInt64(2), "222222222222c", 1),
      (UInt64(3), "222222222222d", 1),
      (UInt64(4), "222222222222e", 1),
    ] {
      let retained = try makeChainedIncrementalBatch(
        target: fixture.target, expectedHead: head, uri: uri,
        startingCID: currentCID, terminalRevision: revision,
        requestID: "retained-\(sequence)", requestSequence: sequence,
        operationCount: operationCount, valuePrefix: "retained-\(sequence)"
      )
      guard case let .applied(result) = try await database
        .applyVerifiedPermissionedRemoteReplicaBatch(
          retained.batch, appliedAt: Int64(900 + sequence)
        )
      else { return XCTFail("retained batch \(sequence) did not apply") }
      head = result.head
      currentCID = retained.terminalCID
    }

    let evictedRows = try await database.connection.query(
      """
      SELECT request_id
      FROM permissioned_remote_replica_incremental_results
      WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
        AND request_id = ?
      """,
      [
        .text(fixture.target.receiverDID), .text(fixture.target.space.rawValue),
        .text(fixture.target.repositoryDID), .text("evicted-request"),
      ]
    )
    XCTAssertTrue(evictedRows.isEmpty, "old replay detail was not evicted")
    try await database.close()

    let reopened = try await fixture.open()
    openedDatabases.append(reopened)
    let beforeRejectedRetries = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    let exactEvictedRetry = try await reopened
      .applyVerifiedPermissionedRemoteReplicaBatch(first.batch, appliedAt: 999)
    XCTAssertEqual(exactEvictedRetry, .staleOrReordered)
    let afterExactEvictedRetry = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    XCTAssertEqual(
      afterExactEvictedRetry,
      beforeRejectedRetries
    )

    let reused = try makeChainedIncrementalBatch(
      target: fixture.target, expectedHead: head, uri: uri,
      startingCID: currentCID, terminalRevision: "222222222222f",
      requestID: "evicted-request", requestSequence: 1,
      operationCount: 1, valuePrefix: "different-reuse"
    )
    let conflictingOldSequence = try await reopened
      .applyVerifiedPermissionedRemoteReplicaBatch(reused.batch, appliedAt: 1_000)
    XCTAssertEqual(conflictingOldSequence, .staleOrReordered)
    let afterConflictingOldSequence = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    XCTAssertEqual(
      afterConflictingOldSequence,
      beforeRejectedRetries
    )

    let next = try makeChainedIncrementalBatch(
      target: fixture.target, expectedHead: head, uri: uri,
      startingCID: currentCID, terminalRevision: "222222222222g",
      requestID: "post-floor-next", requestSequence: 5,
      operationCount: 1, valuePrefix: "post-floor"
    )
    guard case let .applied(nextResult) = try await reopened
      .applyVerifiedPermissionedRemoteReplicaBatch(next.batch, appliedAt: 1_001)
    else { return XCTFail("next sequence after replay floor did not apply") }
    XCTAssertEqual(nextResult.head.wireRevision, next.batch.terminalHead.wireRevision)
    try await reopened.close()
  }

  func testIncrementalMissingRetainedMiddleSequenceFailsCorruptAfterRestart()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-gap")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let history = try await installIncrementalHistory(
      fixture: fixture, database: database, requestPrefix: "gap"
    )
    _ = try await database.connection.query(
      """
      DELETE FROM permissioned_remote_replica_incremental_results
      WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
        AND request_sequence = ?
      """,
      [
        .text(fixture.target.receiverDID), .text(fixture.target.space.rawValue),
        .text(fixture.target.repositoryDID), incrementalSequenceSQLiteData(2),
      ]
    )
    try await database.close()

    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    let before = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    let candidate = try makeChainedIncrementalBatch(
      target: fixture.target, expectedHead: history.head, uri: history.uri,
      startingCID: history.terminalCID, terminalRevision: "222222222222e",
      requestID: "gap-next", requestSequence: 4,
      operationCount: 1, valuePrefix: "gap-next"
    )
    var caught: PermissionedRemoteReplicaRecoveryError?
    do {
      _ = try await reopened.applyVerifiedPermissionedRemoteReplicaBatch(
        candidate.batch, appliedAt: 1_100
      )
    } catch let error as PermissionedRemoteReplicaRecoveryError {
      caught = error
    }
    XCTAssertEqual(caught, .corruptReplica)
    let after = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    XCTAssertEqual(after, before)
  }

  func testIncrementalForgedHighWatermarkFailsCorruptAfterRestart()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-high")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    let history = try await installIncrementalHistory(
      fixture: fixture, database: database, requestPrefix: "high"
    )
    _ = try await database.connection.query(
      """
      UPDATE permissioned_remote_replica_incremental_progress
      SET high_watermark = ?
      WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
      """,
      [
        incrementalSequenceSQLiteData(4), .text(fixture.target.receiverDID),
        .text(fixture.target.space.rawValue),
        .text(fixture.target.repositoryDID),
      ]
    )
    try await database.close()

    let reopened = try await fixture.open()
    defer { Task { try? await reopened.close() } }
    let before = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    let candidate = try makeChainedIncrementalBatch(
      target: fixture.target, expectedHead: history.head, uri: history.uri,
      startingCID: history.terminalCID, terminalRevision: "222222222222e",
      requestID: "high-next", requestSequence: 5,
      operationCount: 1, valuePrefix: "high-next"
    )
    var caught: PermissionedRemoteReplicaRecoveryError?
    do {
      _ = try await reopened.applyVerifiedPermissionedRemoteReplicaBatch(
        candidate.batch, appliedAt: 1_101
      )
    } catch let error as PermissionedRemoteReplicaRecoveryError {
      caught = error
    }
    XCTAssertEqual(caught, .corruptReplica)
    let after = try await incrementalReplicaWitness(
      database: reopened, target: fixture.target
    )
    XCTAssertEqual(after, before)
  }

  func testIncrementalSequenceMigrationRejectsNonemptyLegacyReplayTable()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-legacy-full")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    try await replaceIncrementalResultsWithLegacyTable(
      database: database, insertRow: true
    )
    try await database.close()

    do {
      let unexpectedlyOpened = try await fixture.open()
      try await unexpectedlyOpened.close()
      XCTFail("nonempty legacy incremental replay table was accepted")
    } catch let SQLiteRepositoryError.corruptDatabase(message) {
      XCTAssertTrue(message.contains("legacy incremental replay rows"))
    }
  }

  func testIncrementalSequenceMigrationUpgradesEmptyLegacyReplayTable()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-legacy-empty")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    try await replaceIncrementalResultsWithLegacyTable(
      database: database, insertRow: false
    )
    _ = try await database.connection.query(
      "INSERT INTO public_records(uri, value, revision) VALUES (?, ?, ?)",
      [.text("at://did:plc:unrelated/app.test.record/1"), .blob(.init(bytes: [0xa0])), .integer(7)]
    )
    try await database.close()

    let reopened = try await fixture.open()
    let columns = try await reopened.connection.query(
      "PRAGMA table_info(permissioned_remote_replica_incremental_results)"
    )
    XCTAssertTrue(columns.contains {
      $0.column("name")?.string == "request_sequence"
    })
    let progressTable = try await reopened.connection.query(
      """
      SELECT name FROM sqlite_master
      WHERE type = 'table'
        AND name = 'permissioned_remote_replica_incremental_progress'
      """
    )
    XCTAssertEqual(progressTable.count, 1)
    let unrelated = try await reopened.connection.query(
      "SELECT value, revision FROM public_records WHERE uri = ?",
      [.text("at://did:plc:unrelated/app.test.record/1")]
    )
    XCTAssertEqual(unrelated.count, 1)
    XCTAssertEqual(unrelated.first?.column("revision")?.integer, 7)
    XCTAssertEqual(
      unrelated.first?.column("value"), .blob(.init(bytes: [0xa0]))
    )
    try await reopened.close()
  }

  func testIncrementalExpectedHeadRaceHasOneWinnerAndOneCASConflict()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-cas-race")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let firstDatabase = try await fixture.open()
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["race base"], ikmByte: 0x75
    )
    let base = try await fixture.install(
      database: firstDatabase, archive: initial, expectedBase: nil,
      requestID: "incremental-race-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let secondDatabase = try await fixture.open()
    defer {
      Task {
        try? await firstDatabase.close()
        try? await secondDatabase.close()
      }
    }
    let uri = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: initial.records[0].rkey
    )
    func contender(
      revisionRaw: String, text: String, requestID: String
    ) throws -> PermissionedRemoteReplicaIncrementalBatch {
      let revision = try TID(tidString: revisionRaw)
      let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
        (key: "text", value: text),
      ]))
      let cid = CID.fromDAGCBOR(value)
      let operation = VerifiedPermissionedRemoteReplicaOperation(
        operationIndex: 0, wireRevision: revision, action: .update,
        uri: uri, cid: cid, previousCID: initial.records[0].cid,
        value: value
      )
      var hash = try LtHash(serialized: base.ltHash)
      hash.remove(
        element: "\(uri.collection)/\(uri.rkey)/\(initial.records[0].cid.string)"
      )
      hash.add(element: "\(uri.collection)/\(uri.rkey)/\(cid.string)")
      return try makeIncrementalBatch(
        target: fixture.target, expectedHead: base,
        terminalRevision: revision, terminalHash: hash, recordCount: 1,
        operations: [operation], requestID: requestID
      )
    }
    let leftBatch = try contender(
      revisionRaw: "222222222222b", text: "left", requestID: "race-left"
    )
    let rightBatch = try contender(
      revisionRaw: "222222222222c", text: "right", requestID: "race-right"
    )
    async let left = firstDatabase.applyVerifiedPermissionedRemoteReplicaBatch(
      leftBatch, appliedAt: 601
    )
    async let right = secondDatabase.applyVerifiedPermissionedRemoteReplicaBatch(
      rightBatch, appliedAt: 602
    )
    let outcomes = try await [left, right]
    XCTAssertEqual(outcomes.filter {
      if case .applied = $0 { return true }
      return false
    }.count, 1)
    XCTAssertEqual(outcomes.filter { $0 == .casConflict }.count, 1)
  }

  func testIncrementalRejectsInvalidTransitionsWithoutChangingLastGoodState()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-invalid")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["valid base"], ikmByte: 0x76
    )
    let base = try await fixture.install(
      database: database, archive: initial, expectedBase: nil,
      requestID: "incremental-invalid-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let before = try await incrementalReplicaWitness(
      database: database, target: fixture.target
    )
    let revision = try TID(tidString: "222222222222b")
    let existingURI = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: initial.records[0].rkey
    )
    let missingURI = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: "missing"
    )
    let wrongSpace = try SpaceURI(
      authority: "did:plc:wrong-incremental-space",
      spaceType: "app.swan.remote-replica", skey: "wrong"
    )
    let wrongURI = try SpaceRecordURI(
      space: wrongSpace, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: "wrong"
    )
    let canonical = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "candidate"),
    ]))
    let canonicalCID = CID.fromDAGCBOR(canonical)
    let otherCID = CID.fromDAGCBOR(Data([0xa0]))
    let noncanonical = Data([0x18, 0x00])
    let cases: [VerifiedPermissionedRemoteReplicaOperation] = [
      .init(
        operationIndex: 0, wireRevision: revision, action: .create,
        uri: existingURI, cid: canonicalCID, previousCID: nil,
        value: canonical
      ),
      .init(
        operationIndex: 0, wireRevision: revision, action: .create,
        uri: missingURI, cid: canonicalCID, previousCID: nil, value: nil
      ),
      .init(
        operationIndex: 0, wireRevision: revision, action: .delete,
        uri: existingURI, cid: canonicalCID,
        previousCID: initial.records[0].cid, value: canonical
      ),
      .init(
        operationIndex: 0, wireRevision: revision, action: .update,
        uri: existingURI, cid: canonicalCID, previousCID: otherCID,
        value: canonical
      ),
      .init(
        operationIndex: 0, wireRevision: revision, action: .create,
        uri: missingURI, cid: otherCID, previousCID: nil, value: canonical
      ),
      .init(
        operationIndex: 0, wireRevision: revision, action: .create,
        uri: missingURI, cid: CID.fromDAGCBOR(noncanonical),
        previousCID: nil, value: noncanonical
      ),
      .init(
        operationIndex: 0, wireRevision: revision, action: .create,
        uri: wrongURI, cid: canonicalCID, previousCID: nil, value: canonical
      ),
    ]
    for (index, operation) in cases.enumerated() {
      let batch = try makeIncrementalBatch(
        target: fixture.target, expectedHead: base,
        terminalRevision: revision,
        terminalHash: try LtHash(serialized: base.ltHash),
        recordCount: 1, operations: [operation],
        requestID: "incremental-invalid-\(index)"
      )
      let outcome = try await database
        .applyVerifiedPermissionedRemoteReplicaBatch(
          batch, appliedAt: Int64(700 + index)
        )
      let after = try await incrementalReplicaWitness(
        database: database, target: fixture.target
      )
      XCTAssertEqual(
        outcome, .integrityFailure,
        "invalid case \(index) was accepted"
      )
      XCTAssertEqual(
        after, before,
        "invalid case \(index) changed last-good state"
      )
    }
  }

  func testIncrementalDistinguishesStaleEquivocationAndFullRecovery()
    async throws
  {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-outcomes")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    let initial = try fixture.archive(
      revision: "222222222222a", values: ["outcome base"], ikmByte: 0x77
    )
    let base = try await fixture.install(
      database: database, archive: initial, expectedBase: nil,
      requestID: "incremental-outcomes-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    ).result.head
    let uri = try SpaceRecordURI(
      space: fixture.space, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: "new"
    )
    let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "new"),
    ]))
    let cid = CID.fromDAGCBOR(value)
    let staleOperation = VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: 0, wireRevision: base.wireRevision, action: .create,
      uri: uri, cid: cid, previousCID: nil, value: value
    )
    let stale = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: base.wireRevision,
      terminalHash: try LtHash(serialized: base.ltHash),
      recordCount: 1, operations: [staleOperation],
      requestID: "incremental-stale"
    )
    let staleOutcome = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(stale, appliedAt: 801)
    XCTAssertEqual(staleOutcome, .staleOrReordered)

    let operationDigest =
      PermissionedRemoteReplicaIncrementalOperationWitness
        .digest([staleOperation])
    let equivocalTerminal = try PermissionedRemoteReplicaIncrementalTerminalHead(
      wireRevision: base.wireRevision,
      ltHash: base.ltHash,
      commitment: Data(repeating: 0xe1, count: 32),
      recordCount: 1,
      operationCount: 1,
      operationDigest: operationDigest
    )
    let equivocalDigest = PermissionedRemoteReplicaIncrementalBatch
      .canonicalDigest(
        target: fixture.target, expectedHead: base,
        terminalHead: equivocalTerminal, operations: [staleOperation],
        requestSequence: 1
      )
    let equivocal = try PermissionedRemoteReplicaIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalHead: equivocalTerminal, operations: [staleOperation],
      requestID: "incremental-equivocation",
      requestSequence: 1,
      requestDigest: equivocalDigest
    )
    let equivocalOutcome = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(equivocal, appliedAt: 802)
    XCTAssertEqual(equivocalOutcome, .integrityFailure)

    let missingSpace = try SpaceURI(
      authority: "did:plc:missing-replica-authority",
      spaceType: "app.swan.remote-replica", skey: "missing"
    )
    let missingTarget = try PermissionedRemoteReplicaTarget(
      receiverDID: fixture.receiverDID,
      space: missingSpace,
      repositoryDID: fixture.repositoryDID
    )
    let emptyHash = LtHash()
    let missingBase = try PermissionedRemoteReplicaHead(
      target: missingTarget, generation: 1,
      wireRevision: try TID(tidString: "222222222222a"),
      historyFloorWireRevision: try TID(tidString: "222222222222a"),
      ltHash: emptyHash.serialized, commitment: emptyHash.commitment,
      stateMarker: Data([0x01])
    )
    let missingURI = try SpaceRecordURI(
      space: missingSpace, author: fixture.repositoryDID,
      collection: initial.records[0].collection, rkey: "missing"
    )
    let missingRevision = try TID(tidString: "222222222222b")
    let missingOperation = VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: 0, wireRevision: missingRevision, action: .create,
      uri: missingURI, cid: cid, previousCID: nil, value: value
    )
    var missingTerminalHash = emptyHash
    missingTerminalHash.add(
      element: "\(missingURI.collection)/\(missingURI.rkey)/\(cid.string)"
    )
    let missing = try makeIncrementalBatch(
      target: missingTarget, expectedHead: missingBase,
      terminalRevision: missingRevision, terminalHash: missingTerminalHash,
      recordCount: 1, operations: [missingOperation],
      requestID: "incremental-full-recovery"
    )
    let missingOutcome = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(missing, appliedAt: 803)
    let retainedHead = try await database.permissionedRemoteReplicaHead(
      target: fixture.target
    )
    XCTAssertEqual(missingOutcome, .fullCARRecoveryRequired)
    XCTAssertEqual(retainedHead, base)
  }

  func testIncrementalRevisionNRejectsFullRecoveryNMinusOneAndConflictingN() async throws {
    let fixture = try RemoteReplicaSQLiteFixture(name: "incremental-highwater")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    let initial = try fixture.archive(
      revision: "222222222222a",
      values: ["initial value"],
      ikmByte: 0x51
    )
    _ = try await fixture.install(
      database: database,
      archive: initial,
      expectedBase: nil,
      requestID: "incremental-highwater-bootstrap",
      publicationAuthorization: fixture.publicationAuthorization
    )
    let head = try await database.permissionedRemoteReplicaHead(target: fixture.target)
    let base = try XCTUnwrap(head)

    let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "incremental update"),
    ]))
    let cid = CID.fromDAGCBOR(value)
    let uri = try SpaceRecordURI(
      space: fixture.space,
      author: fixture.repositoryDID,
      collection: initial.records[0].collection,
      rkey: "new-record"
    )
    let revisionB = try TID(tidString: "222222222222b")
    let op = VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: 0, wireRevision: revisionB, action: .create,
      uri: uri, cid: cid, previousCID: nil, value: value
    )
    var terminalHash = try LtHash(serialized: base.ltHash)
    terminalHash.add(element: "\(uri.collection)/\(uri.rkey)/\(cid.string)")
    let batch = try makeIncrementalBatch(
      target: fixture.target, expectedHead: base,
      terminalRevision: revisionB, terminalHash: terminalHash,
      recordCount: 2, operations: [op],
      requestID: "incremental-batch-rev-b"
    )
    guard case .applied = try await database.applyVerifiedPermissionedRemoteReplicaBatch(
      batch, appliedAt: 200
    ) else {
      return XCTFail("incremental batch failed to apply")
    }
    let currentHead = try await database.permissionedRemoteReplicaHead(target: fixture.target)

    // Now try full recovery at wire revision 222222222222a (N-1). It must reject as stale recovery.
    let staleArchive = try fixture.archive(
      revision: "222222222222a",
      values: ["stale full recovery"],
      ikmByte: 0x52
    )
    await assertRemoteReplicaError(.staleRecovery) {
      _ = try await fixture.install(
        database: database,
        archive: staleArchive,
        expectedBase: currentHead,
        requestID: "incremental-highwater-stale",
        publicationAuthorization: fixture.publicationAuthorization
      )
    }

    // Now test conflicting full recovery on a separate fixture with same state
    let fixture2 = try RemoteReplicaSQLiteFixture(name: "incremental-highwater-equivocation")
    defer { try? FileManager.default.removeItem(at: fixture2.root) }
    let database2 = try await fixture2.open()
    defer { Task { try? await database2.close() } }
    let initial2 = try fixture2.archive(
      revision: "222222222222a",
      values: ["initial value"],
      ikmByte: 0x51
    )
    _ = try await fixture2.install(
      database: database2,
      archive: initial2,
      expectedBase: nil,
      requestID: "incremental-highwater-bootstrap-2",
      publicationAuthorization: fixture2.publicationAuthorization
    )
    let head2 = try await database2.permissionedRemoteReplicaHead(target: fixture2.target)
    let base2 = try XCTUnwrap(head2)
    let uri2 = try SpaceRecordURI(
      space: fixture2.space,
      author: fixture2.repositoryDID,
      collection: initial.records[0].collection,
      rkey: "new-record"
    )
    let op2 = VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: 0, wireRevision: revisionB, action: .create,
      uri: uri2, cid: cid, previousCID: nil, value: value
    )
    var terminalHash2 = try LtHash(serialized: base2.ltHash)
    terminalHash2.add(element: "\(uri2.collection)/\(uri2.rkey)/\(cid.string)")
    let batch2 = try makeIncrementalBatch(
      target: fixture2.target, expectedHead: base2,
      terminalRevision: revisionB, terminalHash: terminalHash2,
      recordCount: 2, operations: [op2],
      requestID: "incremental-batch-rev-b-2"
    )
    guard case .applied = try await database2.applyVerifiedPermissionedRemoteReplicaBatch(
      batch2, appliedAt: 200
    ) else {
      return XCTFail("incremental batch 2 failed to apply")
    }
    let currentHead2 = try await database2.permissionedRemoteReplicaHead(target: fixture2.target)

    // Full recovery at wire revision 222222222222b (same N) but different commitment. Must reject as equivocation.
    let conflictingArchive = try fixture2.archive(
      revision: "222222222222b",
      values: ["conflicting commitment"],
      ikmByte: 0x53
    )
    await assertRemoteReplicaError(.equivocation) {
      _ = try await fixture2.install(
        database: database2,
        archive: conflictingArchive,
        expectedBase: currentHead2,
        requestID: "incremental-highwater-conflicting",
        publicationAuthorization: fixture2.publicationAuthorization
      )
    }
  }
}

private struct IncrementalReplicaWitness: Equatable {
  let head: PermissionedRemoteReplicaHead?
  let records: [[SQLiteData]]
  let blocks: [[SQLiteData]]
  let chunks: [[SQLiteData]]
  let replays: [[SQLiteData]]
  let progress: [[SQLiteData]]
}

private func incrementalReplicaWitness(
  database: SQLiteAccountDatabase,
  target: PermissionedRemoteReplicaTarget
) async throws -> IncrementalReplicaWitness {
  let head = try await database.permissionedRemoteReplicaHead(target: target)
  let generation = Int(head?.generation ?? 0)
  let records = try await database.connection.query(
    """
    SELECT collection, rkey, cid
    FROM permissioned_remote_replica_records
    WHERE space_uri = ? AND repository_did = ? AND generation = ?
    ORDER BY collection, rkey
    """,
    [
      .text(target.space.rawValue), .text(target.repositoryDID),
      .integer(generation),
    ]
  )
  let blocks = try await database.connection.query(
    """
    SELECT cid, byte_count, chunk_count
    FROM permissioned_remote_replica_blocks
    WHERE space_uri = ? AND repository_did = ? AND generation = ?
    ORDER BY cid
    """,
    [
      .text(target.space.rawValue), .text(target.repositoryDID),
      .integer(generation),
    ]
  )
  let chunks = try await database.connection.query(
    """
    SELECT cid, chunk_index, bytes
    FROM permissioned_remote_replica_block_chunks
    WHERE space_uri = ? AND repository_did = ? AND generation = ?
    ORDER BY cid, chunk_index
    """,
    [
      .text(target.space.rawValue), .text(target.repositoryDID),
      .integer(generation),
    ]
  )
  let replays = try await database.connection.query(
    """
    SELECT * FROM permissioned_remote_replica_incremental_results
    WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
    ORDER BY request_sequence
    """,
    [
      .text(target.receiverDID), .text(target.space.rawValue),
      .text(target.repositoryDID),
    ]
  )
  let progress = try await database.connection.query(
    """
    SELECT * FROM permissioned_remote_replica_incremental_progress
    WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
    """,
    [
      .text(target.receiverDID), .text(target.space.rawValue),
      .text(target.repositoryDID),
    ]
  )
  let replayColumns = [
    "request_id", "request_sequence", "request_digest", "batch_digest",
    "receiver_did", "space_uri", "repository_did", "expected_generation",
    "expected_wire_revision", "expected_commitment", "expected_marker",
    "installed_generation", "installed_wire_revision",
    "installed_history_floor", "installed_lthash", "installed_commitment",
    "installed_marker", "record_count", "operation_count", "applied_at",
    "integrity_digest",
  ]
  let progressColumns = [
    "receiver_did", "space_uri", "repository_did", "replay_floor",
    "high_watermark",
  ]
  return IncrementalReplicaWitness(
    head: head,
    records: records.map {
      [$0.column("collection")!, $0.column("rkey")!, $0.column("cid")!]
    },
    blocks: blocks.map {
      [$0.column("cid")!, $0.column("byte_count")!, $0.column("chunk_count")!]
    },
    chunks: chunks.map {
      [$0.column("cid")!, $0.column("chunk_index")!, $0.column("bytes")!]
    },
    replays: replays.map { row in replayColumns.map { row.column($0)! } },
    progress: progress.map { row in progressColumns.map { row.column($0)! } }
  )
}

private func replaceIncrementalResultsWithLegacyTable(
  database: SQLiteAccountDatabase,
  insertRow: Bool
) async throws {
  _ = try await database.connection.query(
    "DELETE FROM permissioned_repository_migrations WHERE version = 11"
  )
  _ = try await database.connection.query(
    "DROP TABLE permissioned_remote_replica_incremental_results"
  )
  _ = try await database.connection.query(
    """
    CREATE TABLE permissioned_remote_replica_incremental_results (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL UNIQUE,
      receiver_did TEXT NOT NULL,
      space_uri TEXT NOT NULL,
      repository_did TEXT NOT NULL
    )
    """
  )
  _ = try await database.connection.query(
    """
    CREATE INDEX permissioned_remote_replica_incremental_results_retention
    ON permissioned_remote_replica_incremental_results(
      receiver_did, space_uri, repository_did, sequence
    )
    """
  )
  if insertRow {
    _ = try await database.connection.query(
      """
      INSERT INTO permissioned_remote_replica_incremental_results(
        request_id, receiver_did, space_uri, repository_did
      ) VALUES ('legacy', 'did:plc:legacy', 'at://did:plc:legacy/x/y',
                'did:plc:legacy')
      """
    )
  }
}

private func removeLogicalLimitColumnsForMigrationTest(
  database: SQLiteAccountDatabase
) async throws {
  _ = try await database.connection.query(
    "DELETE FROM permissioned_repository_migrations WHERE version = 12"
  )
  _ = try await database.connection.query(
    """
    ALTER TABLE permissioned_remote_replica_import_sessions
    DROP COLUMN maximum_logical_restored_bytes
    """
  )
  _ = try await database.connection.query(
    """
    ALTER TABLE permissioned_remote_replica_import_results
    DROP COLUMN maximum_logical_restored_bytes
    """
  )
}

private func makeIncrementalBatch(
  target: PermissionedRemoteReplicaTarget,
  expectedHead: PermissionedRemoteReplicaHead,
  terminalRevision: TID,
  terminalHash: LtHash,
  recordCount: Int,
  operations: [VerifiedPermissionedRemoteReplicaOperation],
  requestID: String,
  requestSequence: UInt64 = 1
) throws -> PermissionedRemoteReplicaIncrementalBatch {
  let terminal = try PermissionedRemoteReplicaIncrementalTerminalHead(
    wireRevision: terminalRevision,
    ltHash: terminalHash.serialized,
    commitment: terminalHash.commitment,
    recordCount: recordCount,
    operationCount: operations.count,
    operationDigest:
      PermissionedRemoteReplicaIncrementalOperationWitness.digest(operations)
  )
  let digest = PermissionedRemoteReplicaIncrementalBatch.canonicalDigest(
    target: target,
    expectedHead: expectedHead,
    terminalHead: terminal,
    operations: operations,
    requestSequence: requestSequence
  )
  return try PermissionedRemoteReplicaIncrementalBatch(
    target: target,
    expectedHead: expectedHead,
    terminalHead: terminal,
    operations: operations,
    requestID: requestID,
    requestSequence: requestSequence,
    requestDigest: digest
  )
}

private struct ChainedIncrementalBatchFixture {
  let batch: PermissionedRemoteReplicaIncrementalBatch
  let terminalCID: CID
}

private struct IncrementalHistoryFixture {
  let head: PermissionedRemoteReplicaHead
  let uri: SpaceRecordURI
  let terminalCID: CID
}

private func installIncrementalHistory(
  fixture: RemoteReplicaSQLiteFixture,
  database: SQLiteAccountDatabase,
  requestPrefix: String
) async throws -> IncrementalHistoryFixture {
  let initial = try fixture.archive(
    revision: "222222222222a", values: ["history base"], ikmByte: 0x79
  )
  var head = try await fixture.install(
    database: database, archive: initial, expectedBase: nil,
    requestID: "\(requestPrefix)-bootstrap",
    publicationAuthorization: fixture.publicationAuthorization
  ).result.head
  let uri = try SpaceRecordURI(
    space: fixture.space, author: fixture.repositoryDID,
    collection: initial.records[0].collection, rkey: initial.records[0].rkey
  )
  var currentCID = initial.records[0].cid
  for (sequence, revision) in [
    (UInt64(1), "222222222222b"),
    (UInt64(2), "222222222222c"),
    (UInt64(3), "222222222222d"),
  ] {
    let next = try makeChainedIncrementalBatch(
      target: fixture.target, expectedHead: head, uri: uri,
      startingCID: currentCID, terminalRevision: revision,
      requestID: "\(requestPrefix)-\(sequence)",
      requestSequence: sequence, operationCount: 1,
      valuePrefix: "\(requestPrefix)-\(sequence)"
    )
    guard case let .applied(result) = try await database
      .applyVerifiedPermissionedRemoteReplicaBatch(
        next.batch, appliedAt: Int64(1_050 + sequence)
      ) else {
      throw RemoteReplicaSQLiteTestError.unexpectedOutcome
    }
    head = result.head
    currentCID = next.terminalCID
  }
  return IncrementalHistoryFixture(
    head: head, uri: uri, terminalCID: currentCID
  )
}

private func incrementalSequenceSQLiteData(_ value: UInt64) -> SQLiteData {
  var bigEndian = value.bigEndian
  return withUnsafeBytes(of: &bigEndian) {
    .blob(.init(bytes: $0))
  }
}

private func makeChainedIncrementalBatch(
  target: PermissionedRemoteReplicaTarget,
  expectedHead: PermissionedRemoteReplicaHead,
  uri: SpaceRecordURI,
  startingCID: CID,
  terminalRevision: String,
  requestID: String,
  requestSequence: UInt64,
  operationCount: Int,
  valuePrefix: String
) throws -> ChainedIncrementalBatchFixture {
  let revision = try TID(tidString: terminalRevision)
  var previousCID = startingCID
  var terminalHash = try LtHash(serialized: expectedHead.ltHash)
  var operations: [VerifiedPermissionedRemoteReplicaOperation] = []
  operations.reserveCapacity(operationCount)
  for index in 0 ..< operationCount {
    let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
      (key: "text", value: "\(valuePrefix)-\(index)"),
    ]))
    let cid = CID.fromDAGCBOR(value)
    operations.append(VerifiedPermissionedRemoteReplicaOperation(
      operationIndex: index, wireRevision: revision, action: .update,
      uri: uri, cid: cid, previousCID: previousCID, value: value
    ))
    terminalHash.remove(
      element: "\(uri.collection)/\(uri.rkey)/\(previousCID.string)"
    )
    terminalHash.add(element: "\(uri.collection)/\(uri.rkey)/\(cid.string)")
    previousCID = cid
  }
  return try ChainedIncrementalBatchFixture(
    batch: makeIncrementalBatch(
      target: target, expectedHead: expectedHead,
      terminalRevision: revision, terminalHash: terminalHash,
      recordCount: 1, operations: operations, requestID: requestID,
      requestSequence: requestSequence
    ),
    terminalCID: previousCID
  )
}

private struct RemoteReplicaSQLiteFixture {
  static let createdAt: Int64 = 100
  static let operationNow: Int64 = 101
  static let expiresAt: Int64 = 200

  let root: URL
  let receiverDID = "did:plc:abcdefghijklmnopqrstuvwx"
  let repositoryDID = "did:plc:remote-replica-writer"
  let space: SpaceURI
  let target: PermissionedRemoteReplicaTarget
  let signingKey = P256.Signing.PrivateKey()
  let publicationFence = RemoteReplicaPublicationFence()

  var publicationAuthorization:
    PermissionedRemoteReplicaPublicationAuthorization
  {
    { operation in
      try await publicationFence.authorize(operation)
    }
  }

  init(name: String, skey: String = "acceptance") throws {
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
      skey: skey
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
    ikmByte: UInt8,
    rkeys: [String]? = nil
  ) throws -> RemoteReplicaArchive {
    guard !values.isEmpty, rkeys == nil || rkeys?.count == values.count else {
      throw RemoteReplicaSQLiteTestError.emptyFixture
    }
    let collection = "app.bsky.feed.post"
    var testRecords: [RemoteReplicaRecord] = []
    var encodedRecords: [SpaceRecord] = []
    var ltHash = LtHash()
    for (index, text) in values.enumerated() {
      let rkey = rkeys?[index] ?? (values.count == 1
        ? "record"
        : String(format: "record-%04d", index))
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
    let source = try PermissionedRemoteReplicaSourceIdentity(
      origin: URL(string: "https://writer.example")!,
      repositoryDID: target.repositoryDID,
      verifierIdentity: "key-sha256:" + String(repeating: "a", count: 64)
    )
    return try PermissionedRemoteReplicaImportBinding(
      requestID: requestID,
      requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
      source: source,
      target: target,
      expectedBase: expectedBase,
      freshnessWitness: freshnessWitness,
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
    requestID: String,
    publicationAuthorization:
      @escaping PermissionedRemoteReplicaPublicationAuthorization
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
        now: Self.operationNow,
        publicationAuthorization: publicationAuthorization
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

private actor RemoteReplicaPublicationCounter {
  private(set) var value = 0

  func increment() {
    value += 1
  }
}

private enum RemoteReplicaPublicationFenceError: Error, Equatable {
  case inactive
  case operationEscapedAuthorization
}

private actor RemoteReplicaPublicationFence {
  private var active = true
  private(set) var authorizationAttempted = false
  private(set) var operationActive = false

  func deactivate() {
    active = false
  }

  func authorize(
    _ operation: @escaping @Sendable () async throws
      -> CommittedPermissionedRemoteReplicaRecovery
  ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
    authorizationAttempted = true
    guard active else {
      throw RemoteReplicaPublicationFenceError.inactive
    }
    operationActive = true
    defer { operationActive = false }
    return try await operation()
  }

  func requireOperationActive() throws {
    guard operationActive else {
      throw RemoteReplicaPublicationFenceError.operationEscapedAuthorization
    }
  }
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
  case unexpectedOutcome
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

private func assertRemoteReplicaSpaceClosed<T>(
  file: StaticString = #filePath,
  line: UInt = #line,
  operation: () async throws -> T
) async {
  do {
    _ = try await operation()
    XCTFail("a deleted remote space must remain closed", file: file, line: line)
  } catch let error as SwanError {
    guard case .unauthorized = error else {
      return XCTFail("expected closed-space authorization failure, got \(error)", file: file, line: line)
    }
  } catch {
    XCTFail("expected closed-space authorization failure, got \(error)", file: file, line: line)
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
