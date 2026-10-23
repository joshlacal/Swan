import Foundation
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage
@testable import SwanHTTP
import XCTest

final class ConversationSpaceDeletionServiceTests: XCTestCase, @unchecked Sendable {
    func testRestartRetriesPendingRemoteDeletionAndFinishesOnlyAfterSuccess() async throws {
        let space = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx",
            spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
        let intent = try ConversationSpaceDeletion(space: space, eventID: UUID().uuidString.lowercased())
        let store = PendingDeletionStore(intent: intent)
        let remote = FailingThenSuccessfulDeletion()
        let first = SwanConversationSpaceDeletionService(lifecycle: store, remote: remote, authority: space.authority)
        let firstCount = try await first.runOnce()
        XCTAssertEqual(firstCount, 0)
        let pending = try await store.pendingConversationSpaceDeletions(authority: space.authority)
        XCTAssertEqual(pending, [intent])
        let restarted = SwanConversationSpaceDeletionService(lifecycle: store, remote: remote, authority: space.authority)
        let nextCount = try await restarted.runOnce()
        XCTAssertEqual(nextCount, 1)
        let final = try await store.pendingConversationSpaceDeletions(authority: space.authority)
        XCTAssertTrue(final.isEmpty)
        let finished = await store.finished
        XCTAssertEqual(finished, [intent])
        let observed = await remote.spaces
        XCTAssertEqual(observed, [space, space])
    }
}
private actor FailingThenSuccessfulDeletion: ConversationSpaceDeleting {
    var spaces: [SpaceURI] = []
    func deleteGeneration(space: SpaceURI, now: Date) async throws {
        spaces.append(space)
        if spaces.count == 1 { throw SwanError.unavailable("disposable network failure") }
    }
}
private actor PendingDeletionStore: ConversationSpaceAuthorityLifecycle {
    private var intent: ConversationSpaceDeletion?
    var finished: [ConversationSpaceDeletion] = []
    init(intent: ConversationSpaceDeletion) { self.intent = intent }
    func pendingConversationSpaceDeletions(authority: String) async throws -> [ConversationSpaceDeletion] { intent.map { [$0] } ?? [] }
    func finishConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws {
        guard deletion == intent else { throw SwanError.unauthorized("event changed") }
        finished.append(deletion); intent = nil
    }
    func deferConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws {}
    func registerKnownConversationSpace(space: SpaceURI, now: Date) async throws { throw SwanError.unavailable("not exercised") }
    func requireConversationSpaceActive(space: SpaceURI) async throws { throw SwanError.unavailable("not exercised") }
    func beginConversationSpaceDeletion(space: SpaceURI, authorization: AuthorizationContext, now: Date) async throws -> ConversationSpaceDeletion { throw SwanError.unavailable("not exercised") }
    func receiveMembershipVerifiedConversationSpaceWriteNotification(_ notification: AuthorizedSpaceWriteNotification, now: Date) async throws { throw SwanError.unavailable("not exercised") }
}
