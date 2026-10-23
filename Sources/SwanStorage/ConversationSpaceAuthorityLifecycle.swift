import Foundation
import SwanCore
import SwanSpaces

/// Stable local intent for deleting one exact immutable conversation storage
/// generation. The delivery service owns membership; this registry never does.
public struct ConversationSpaceDeletion: Sendable, Equatable {
    public let space: SpaceURI
    public let eventID: String
    public init(space: SpaceURI, eventID: String) throws {
        guard space.spaceType == "blue.catbird.labyrinth.conversation",
              let generation = UUID(uuidString: space.skey), generation.uuidString.lowercased() == space.skey,
              let event = UUID(uuidString: eventID), event.uuidString.lowercased() == eventID else {
            throw SwanError.malformed("invalid conversation deletion identity")
        }
        self.space = space
        self.eventID = eventID
    }
}

/// Authority-local lifecycle facts, separate from simple-space policy. A
/// successful live membership check must precede registration; registration
/// never authorizes a user, caches membership, or revives a closed generation.
public protocol ConversationSpaceAuthorityLifecycle: Sendable {
    func registerKnownConversationSpace(space: SpaceURI, now: Date) async throws
    func requireConversationSpaceActive(space: SpaceURI) async throws
    func beginConversationSpaceDeletion(space: SpaceURI, authorization: AuthorizationContext, now: Date) async throws -> ConversationSpaceDeletion
    /// The caller must first confirm this writer's current DS membership.
    /// Storage then rechecks the exact generation under its writer transaction.
    func receiveMembershipVerifiedConversationSpaceWriteNotification(_ notification: AuthorizedSpaceWriteNotification, now: Date) async throws
    /// Returns at most 256 oldest pending intents for bounded restart recovery.
    func pendingConversationSpaceDeletions(authority: String) async throws -> [ConversationSpaceDeletion]
    /// Rotate a failed intent behind other pending generations without reopening it.
    func deferConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws
    /// Call only after the delivery service confirms this exact generation.
    func finishConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws
}
