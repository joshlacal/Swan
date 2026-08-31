import Foundation
import PetrelFirehose
import Petrel
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest
@testable import SwanSQLite

final class PublicFirehoseIsolationTests: XCTestCase {
  func testPermissionedWritesProduceNoPublicSourceOrGlobalRows() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-isolation-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }
    let authority = "did:plc:alice"
    let writer = "did:plc:bob"
    let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
    defer { Task { try? await database.close() } }
    let control = try await SQLiteControlDatabase(dataDirectory: root)
    defer { Task { try? await control.close() } }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    let space = try SpaceURI(
      authority: authority,
      spaceType: "app.bsky.bookmarks",
      skey: "isolation"
    )
    let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
    _ = try await lifecycle.create(
      space: space,
      owner: authority,
      configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
      authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
    )
    _ = try await lifecycle.addMember(
      space: space,
      member: writer,
      authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
    )
    let now = Date(timeIntervalSince1970: 1_785_844_800)
    let revision = try TID(tidString: "2222222222223")
    _ = try await database.receiveSpaceWriteNotification(
      AuthorizedSpaceWriteNotification(
        eventID: "permissioned-isolation-write",
        space: space,
        repository: writer,
        wireRevision: revision.toString(),
        commitment: Data(repeating: 0xab, count: 32),
        issuer: writer,
        audience: authority,
        requestBodyDigest: SpaceNotificationRequestDigest.write(
            space: space,
            repository: writer,
            wireRevision: revision.toString(),
            commitment: Data(repeating: 0xab, count: 32)
        )
      ),
      now: now
    )

    let outbox = try await database.pendingPublicFirehoseOutbox()
    XCTAssertTrue(outbox.isEmpty, "permissioned writes must not create public outbox rows")
    let lifecycleDIDs = try await control.pendingLifecycleDIDs()
    XCTAssertTrue(lifecycleDIDs.isEmpty, "permissioned writes must not create lifecycle batches")
    let source = FixedIsolationAccountSource(
      accounts: [
        PublicFirehoseAccountDatabase(did: authority, database: database),
      ]
    )
    let sequencer = PublicFirehoseSequencer(
      accountSource: source,
      control: control,
      firehose: firehose
    )
    let result = try await sequencer.sequenceNext(now: now)
    XCTAssertEqual(result, .idle)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertTrue(events.isEmpty, "permissioned writes must not append global firehose events")
  }
}

private struct FixedIsolationAccountSource: PublicFirehoseAccountDatabaseSource {
  let accounts: [PublicFirehoseAccountDatabase]

  func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
    accounts
  }
}
