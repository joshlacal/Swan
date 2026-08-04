import Foundation
import Petrel
import SwanCore
import SwanPublicFirehose
import XCTest
@testable import SwanSQLite

final class LifecycleEventOutboxStoreTests: XCTestCase {
  private let didA = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
  private let didB = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)
  private let time = "2026-08-04T12:00:00.000Z"

  private static let payloadEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }()

  private var root: URL!
  private var control: SQLiteControlDatabase!

  override func setUp() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-lifecycle-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    self.root = root
    control = try await SQLiteControlDatabase(dataDirectory: root)
  }

  override func tearDown() async throws {
    try? await control?.close()
    if let root {
      try? FileManager.default.removeItem(at: root)
    }
  }

  private func identityItem(
    did: String,
    handle: String? = "alice.test"
  ) -> LifecycleEventItem {
    let material = PublicFirehoseIdentityMaterial(did: did, handle: handle, time: time)
    return LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.identity(did: did, plcOperationCID: "bafyid1"),
      kind: .identity,
      payload: try! Self.payloadEncoder.encode(material),
      carBytes: nil
    )
  }

  private func accountItem(did: String, active: Bool = true) -> LifecycleEventItem {
    let material = PublicFirehoseAccountMaterial(
      did: did,
      active: active,
      status: active ? nil : .deactivated,
      time: time
    )
    return LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.account(did: did, operationID: "op-1"),
      kind: .account,
      payload: try! Self.payloadEncoder.encode(material),
      carBytes: nil
    )
  }

  private func syncItem(did: String) async throws -> LifecycleEventItem {
    let commitCID = CID.fromDAGCBOR(Data([0x01, 0x02, 0x03]))
    let material = PublicFirehoseSyncMaterial(
      did: did,
      rev: "3kabc",
      commitCID: commitCID.string,
      time: time
    )
    let car = try await PublicFirehoseDiffCAR.commitOnly(
      commitCID: commitCID,
      commitBytes: Data([0x01, 0x02, 0x03])
    )
    return LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.syncActivation(did: did, operationID: "op-1"),
      kind: .sync,
      payload: try! Self.payloadEncoder.encode(material),
      carBytes: car
    )
  }

  func testFirstBatchReceivesGenerationOne() async throws {
    let batch = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA)],
      now: epoch
    )
    XCTAssertEqual(batch.generation, 1)
    let generationA = try await control.currentLifecycleGeneration(did: didA)
    XCTAssertEqual(generationA, 1)
    let generationB = try await control.currentLifecycleGeneration(did: didB)
    XCTAssertEqual(generationB, 0)
  }

  func testSecondNewOperationReceivesGenerationTwo() async throws {
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA)],
      now: epoch
    )
    let second = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-2",
      items: [accountItem(did: didA)],
      now: epoch
    )
    XCTAssertEqual(second.generation, 2)
    let generation = try await control.currentLifecycleGeneration(did: didA)
    XCTAssertEqual(generation, 2)
  }

  func testAnotherDIDStartsAtGenerationOne() async throws {
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA)],
      now: epoch
    )
    let firstB = try await control.enqueueLifecycleEventBatch(
      did: didB,
      operationID: "op-1",
      items: [identityItem(did: didB)],
      now: epoch
    )
    XCTAssertEqual(firstB.generation, 1)
  }

  func testExactOperationReplayReturnsStoredBatchWithoutIncrementing() async throws {
    let items = [identityItem(did: didA), accountItem(did: didA)]
    let first = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: items,
      now: epoch
    )
    let replayed = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: items,
      now: epoch
    )
    XCTAssertEqual(replayed, first)
    XCTAssertEqual(replayed.generation, 1)
    let generation = try await control.currentLifecycleGeneration(did: didA)
    XCTAssertEqual(generation, 1)
    let pending = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertEqual(pending?.generation, 1)
  }

  func testSameOperationIDWithChangedContentThrowsConflict() async throws {
    let original = [identityItem(did: didA)]
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: original,
      now: epoch
    )
    var variations: [() throws -> [LifecycleEventItem]] = [
      { [self] in [identityItem(did: didB)] },
      { [self] in [accountItem(did: didA)] },
      { [self] in [identityItem(did: didA), accountItem(did: didA)] },
      { [self] in
        let item = identityItem(did: didA)
        return [LifecycleEventItem(
          sourceKey: PublicFirehoseSourceKey.identity(did: didA, plcOperationCID: "other-cid"),
          kind: item.kind,
          payload: item.payload,
          carBytes: item.carBytes
        )]
      },
      { [self] in
        let item = identityItem(did: didA)
        let different = PublicFirehoseIdentityMaterial(did: didA, handle: "bob.test", time: time)
        return [LifecycleEventItem(
          sourceKey: item.sourceKey,
          kind: item.kind,
          payload: try! Self.payloadEncoder.encode(different),
          carBytes: item.carBytes
        )]
      },
    ]
    for (index, makeItems) in variations.enumerated() {
      let items = try makeItems()
      do {
        _ = try await control.enqueueLifecycleEventBatch(
          did: didA,
          operationID: "op-1",
          items: items,
          now: epoch
        )
        XCTFail("expected conflict for variation \(index)")
      } catch let error as LifecycleEventOutboxError {
        guard case let .conflictingBatch(batchID) = error else {
          return XCTFail("expected conflictingBatch, got \(error)")
        }
        XCTAssertEqual(batchID, PublicFirehoseSourceKey.lifecycleBatch(did: didA, operationID: "op-1"))
      }
    }
    _ = variations.removeAll()
  }

  func testBatchIDIsDIDNamespaced() async throws {
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "shared-op",
      items: [identityItem(did: didA)],
      now: epoch
    )
    let second = try await control.enqueueLifecycleEventBatch(
      did: didB,
      operationID: "shared-op",
      items: [identityItem(did: didB)],
      now: epoch
    )
    XCTAssertEqual(second.batchID, PublicFirehoseSourceKey.lifecycleBatch(did: didB, operationID: "shared-op"))
    XCTAssertNotEqual(
      second.batchID,
      PublicFirehoseSourceKey.lifecycleBatch(did: didA, operationID: "shared-op")
    )
    XCTAssertEqual(second.generation, 1)
  }

  func testEmptyAndOverLimitBatchesRejected() async throws {
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-empty",
        items: [],
        now: epoch
      )
      XCTFail("expected invalidItemCount")
    } catch let error as LifecycleEventOutboxError {
      XCTAssertEqual(error, .invalidItemCount(0))
    }
    let seventeen = (0 ..< 17).map { index in
      let material = PublicFirehoseIdentityMaterial(did: didA, handle: "h\(index)", time: time)
      return LifecycleEventItem(
        sourceKey: "did:plc:aaa|identity|cid\(index)",
        kind: .identity,
        payload: try! Self.payloadEncoder.encode(material),
        carBytes: nil
      )
    }
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-17",
        items: seventeen,
        now: epoch
      )
      XCTFail("expected invalidItemCount")
    } catch let error as LifecycleEventOutboxError {
      XCTAssertEqual(error, .invalidItemCount(17))
    }
  }

  func testCommitKindItemRejected() async throws {
    let commitMaterial = PublicFirehoseCommitMaterial(
      did: didA,
      rev: "3kabc",
      since: nil,
      commitCID: "bafycid",
      prevDataCID: nil,
      ops: [],
      time: time
    )
    let item = LifecycleEventItem(
      sourceKey: "did:plc:aaa|commit|bafycid",
      kind: .commit,
      payload: try! Self.payloadEncoder.encode(commitMaterial),
      carBytes: Data([0x01])
    )
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-commit",
        items: [item],
        now: epoch
      )
      XCTFail("expected invalidItemShape")
    } catch let error as LifecycleEventOutboxError {
      guard case .invalidItemShape = error else {
        return XCTFail("expected invalidItemShape, got \(error)")
      }
    }
  }

  func testSyncWithoutCARRejected() async throws {
    let material = PublicFirehoseSyncMaterial(
      did: didA,
      rev: "3kabc",
      commitCID: CID.fromDAGCBOR(Data([0x01])).string,
      time: time
    )
    let item = LifecycleEventItem(
      sourceKey: "did:plc:aaa|sync|activation|op-1",
      kind: .sync,
      payload: try! Self.payloadEncoder.encode(material),
      carBytes: nil
    )
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-bad-sync",
        items: [item],
        now: epoch
      )
      XCTFail("expected invalidItemShape")
    } catch let error as LifecycleEventOutboxError {
      guard case .invalidItemShape = error else {
        return XCTFail("expected invalidItemShape, got \(error)")
      }
    }
  }

  func testIdentityAndAccountWithCARRejected() async throws {
    let identity = LifecycleEventItem(
      sourceKey: "did:plc:aaa|identity|bafy1",
      kind: .identity,
      payload: try! Self.payloadEncoder.encode(
        PublicFirehoseIdentityMaterial(did: didA, handle: nil, time: time)
      ),
      carBytes: Data([0x01])
    )
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-bad-identity",
        items: [identity],
        now: epoch
      )
      XCTFail("expected invalidItemShape")
    } catch let error as LifecycleEventOutboxError {
      guard case .invalidItemShape = error else {
        return XCTFail("expected invalidItemShape, got \(error)")
      }
    }
    let account = LifecycleEventItem(
      sourceKey: "did:plc:aaa|account|op-1",
      kind: .account,
      payload: try! Self.payloadEncoder.encode(
        PublicFirehoseAccountMaterial(did: didA, active: true, status: nil, time: time)
      ),
      carBytes: Data([0x01])
    )
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-bad-account",
        items: [account],
        now: epoch
      )
      XCTFail("expected invalidItemShape")
    } catch let error as LifecycleEventOutboxError {
      guard case .invalidItemShape = error else {
        return XCTFail("expected invalidItemShape, got \(error)")
      }
    }
  }

  func testMalformedPayloadAndNonPreflightingFrameRejectedBeforeStorage() async throws {
    let malformed = LifecycleEventItem(
      sourceKey: "did:plc:aaa|identity|bafy2",
      kind: .identity,
      payload: Data("not json".utf8),
      carBytes: nil
    )
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-malformed",
        items: [malformed],
        now: epoch
      )
      XCTFail("expected invalidItemMaterial")
    } catch let error as LifecycleEventOutboxError {
      guard case .invalidItemMaterial = error else {
        return XCTFail("expected invalidItemMaterial, got \(error)")
      }
    }
    let badAccount = LifecycleEventItem(
      sourceKey: "did:plc:aaa|account|op-2",
      kind: .account,
      payload: try! Self.payloadEncoder.encode(
        PublicFirehoseAccountMaterial(did: didA, active: true, status: .suspended, time: time)
      ),
      carBytes: nil
    )
    do {
      _ = try await control.enqueueLifecycleEventBatch(
        did: didA,
        operationID: "op-bad-account-frame",
        items: [badAccount],
        now: epoch
      )
      XCTFail("expected invalidItemMaterial")
    } catch let error as LifecycleEventOutboxError {
      guard case .invalidItemMaterial = error else {
        return XCTFail("expected invalidItemMaterial, got \(error)")
      }
    }
    let dids = try await control.pendingLifecycleDIDs()
    XCTAssertEqual(dids, [])
    let generation = try await control.currentLifecycleGeneration(did: didA)
    XCTAssertEqual(generation, 0)
  }

  func testPendingBatchOrderIsGenerationOrderForOneDID() async throws {
    let first = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA)],
      now: epoch
    )
    let second = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-2",
      items: [accountItem(did: didA)],
      now: epoch
    )
    let next = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertEqual(next, first)
    let completedFirst = try await control.completeLifecycleBatch(batchID: first.batchID)
    XCTAssertTrue(completedFirst)
    let nextAfter = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertEqual(nextAfter, second)
    XCTAssertEqual(nextAfter?.generation, 2)
  }

  func testPendingLifecycleDIDsIsUniqueAndSorted() async throws {
    _ = try await control.enqueueLifecycleEventBatch(
      did: didB,
      operationID: "op-1",
      items: [identityItem(did: didB)],
      now: epoch
    )
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA)],
      now: epoch
    )
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-2",
      items: [accountItem(did: didA)],
      now: epoch
    )
    let dids = try await control.pendingLifecycleDIDs()
    XCTAssertEqual(dids, [didA, didB])
  }

  func testCompletionDeletesItemsByCascadeButPreservesGeneration() async throws {
    let batch = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA), accountItem(did: didA), try await syncItem(did: didA)],
      now: epoch
    )
    let completed = try await control.completeLifecycleBatch(batchID: batch.batchID)
    XCTAssertTrue(completed)
    let afterComplete = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertNil(afterComplete)
    let generation = try await control.currentLifecycleGeneration(did: didA)
    XCTAssertEqual(generation, 1)
    let next = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-2",
      items: [identityItem(did: didA)],
      now: epoch
    )
    XCTAssertEqual(next.generation, 2)
  }

  func testCompletionReplayReturnsFalse() async throws {
    let batch = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA)],
      now: epoch
    )
    let firstComplete = try await control.completeLifecycleBatch(batchID: batch.batchID)
    XCTAssertTrue(firstComplete)
    let secondComplete = try await control.completeLifecycleBatch(batchID: batch.batchID)
    XCTAssertFalse(secondComplete)
  }

  func testLifecycleSyncItemRoundTripsWithStoredCAR() async throws {
    let item = try await syncItem(did: didA)
    let batch = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-sync",
      items: [item],
      now: epoch
    )
    XCTAssertEqual(batch.items, [item])
    let pending = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertEqual(pending?.items.first?.carBytes, item.carBytes)
  }
}
