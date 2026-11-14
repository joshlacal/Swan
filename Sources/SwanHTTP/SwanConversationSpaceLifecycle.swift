import Foundation
import Logging
import ServiceLifecycle
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// Keeps a deletion pending locally before asking the committed-membership
/// service to close its immutable generation. A restart retries the same
/// durable event, and success is returned only after recipient fanout exists.
public struct SwanConversationSpaceLifecycle: AuthorizedSimpleSpaceLifecycleDirectory, AuthorizedSpaceNotificationDirectory {
    private let local: any AuthorizedSimpleSpaceLifecycleDirectory
    private let lifecycle: any ConversationSpaceAuthorityLifecycle
    private let remote: any ConversationSpaceDeleting
    private let membership: any ConversationSpaceMembershipChecking
    private let notifications: any AuthorizedSpaceNotificationDirectory
    private let authority: String

    public init(local: any AuthorizedSimpleSpaceLifecycleDirectory,
                lifecycle: any ConversationSpaceAuthorityLifecycle,
                remote: any ConversationSpaceDeleting, membership: any ConversationSpaceMembershipChecking,
                notifications: any AuthorizedSpaceNotificationDirectory, authority: String) {
        self.local = local; self.lifecycle = lifecycle; self.remote = remote; self.authority = authority
        self.membership = membership; self.notifications = notifications
    }

    public func deleteSimpleSpace(_ space: SpaceURI, authorization: AuthorizationContext) async throws {
        guard isConversation(space) else { return try await local.deleteSimpleSpace(space, authorization: authorization) }
        guard space.authority == authority else { throw SwanError.unauthorized("conversation authority mismatch") }
        let deletion = try await lifecycle.beginConversationSpaceDeletion(space: space, authorization: authorization, now: Date())
        try await remote.deleteGeneration(space: space, now: Date())
        try await lifecycle.finishConversationSpaceDeletion(deletion, now: Date())
    }

    public func createSimpleSpace(_ space: SpaceURI, configuration: SimpleSpaceConfiguration, authorization: AuthorizationContext) async throws {
        try requireLocalPolicy(space)
        try await local.createSimpleSpace(space, configuration: configuration, authorization: authorization)
    }
    public func updateSimpleSpace(_ space: SpaceURI, configuration: SimpleSpaceConfiguration, authorization: AuthorizationContext) async throws {
        try requireLocalPolicy(space)
        try await local.updateSimpleSpace(space, configuration: configuration, authorization: authorization)
    }
    public func removeSpaceWriter(_ writer: String, from space: SpaceURI, authorization: AuthorizationContext) async throws {
        try requireLocalPolicy(space)
        try await local.removeSpaceWriter(writer, from: space, authorization: authorization)
    }
    public func putSimpleSpaceMembers(_ members: [AuthorizedSimpleSpaceMemberPage.Member], in space: SpaceURI, authorization: AuthorizationContext) async throws {
        try requireLocalPolicy(space)
        try await local.putSimpleSpaceMembers(members, in: space, authorization: authorization)
    }
    public func removeSimpleSpaceMembers(_ members: [String], from space: SpaceURI, authorization: AuthorizationContext) async throws {
        try requireLocalPolicy(space)
        try await local.removeSimpleSpaceMembers(members, from: space, authorization: authorization)
    }
    public func recentlyRevokedSpaceCredentialIDs(_ space: SpaceURI) async throws -> [String] {
        try await local.recentlyRevokedSpaceCredentialIDs(space)
    }
    public func simpleSpaceMembers(_ space: SpaceURI, limit: Int, cursor: String?, authorization: AuthorizationContext) async throws -> AuthorizedSimpleSpaceMemberPage {
        try requireLocalPolicy(space)
        return try await local.simpleSpaceMembers(space, limit: limit, cursor: cursor, authorization: authorization)
    }
    public func listSpaceWriters(space: SpaceURI, limit: Int, cursor: String?, authorization: AuthorizationContext) async throws -> [AuthorizedSpaceWriter] {
        try await notifications.listSpaceWriters(space: space, limit: limit, cursor: cursor, authorization: authorization)
    }
    public func receiveSpaceWriteNotification(_ notification: AuthorizedSpaceWriteNotification) async throws {
        guard isConversation(notification.space) else { return try await notifications.receiveSpaceWriteNotification(notification) }
        guard notification.space.authority == authority, notification.issuer == notification.repository,
              notification.audience == authority else { throw SwanError.unauthorized("conversation authority notification mismatch") }
        try await membership.requireMembership(space: notification.space, user: notification.repository, now: Date())
        try await lifecycle.registerKnownConversationSpace(space: notification.space, now: Date())
        try await lifecycle.receiveMembershipVerifiedConversationSpaceWriteNotification(notification, now: Date())
    }
    private func isConversation(_ space: SpaceURI) -> Bool { space.spaceType == "blue.catbird.labyrinth.conversation" }
    private func requireLocalPolicy(_ space: SpaceURI) throws {
        guard !isConversation(space) else { throw SwanError.unauthorized("conversation membership is owned by its delivery service") }
    }
}

public struct SwanConversationSpaceDeletionService: Service {
    private let lifecycle: any ConversationSpaceAuthorityLifecycle
    private let remote: any ConversationSpaceDeleting
    private let authority: String
    private let logger = Logger(label: "swan.conversation-deletion")

    public init(lifecycle: any ConversationSpaceAuthorityLifecycle, remote: any ConversationSpaceDeleting, authority: String) {
        self.lifecycle = lifecycle; self.remote = remote; self.authority = authority
    }

    @discardableResult
    public func runOnce(now: Date? = nil) async throws -> Int {
        let pending = try await lifecycle.pendingConversationSpaceDeletions(authority: authority)
        var finished = 0
        for deletion in pending {
            try Task.checkCancellation()
            do {
                try await remote.deleteGeneration(space: deletion.space, now: now ?? Date())
                try await lifecycle.finishConversationSpaceDeletion(deletion, now: now ?? Date())
                finished += 1
            } catch is CancellationError { throw CancellationError() }
            catch {
                try await lifecycle.deferConversationSpaceDeletion(deletion, now: now ?? Date())
                logger.warning("conversation deletion deferred", metadata: ["space": .string(deletion.space.rawValue)])
            }
        }
        return finished
    }
    public func run() async throws {
        try await cancelWhenGracefulShutdown { try await self.runLoop() }
    }

    private func runLoop() async throws {
        while !Task.isCancelled {
            do { _ = try await runOnce() }
            catch is CancellationError { return }
            catch { logger.warning("conversation deletion queue unavailable") }
            do { try await Task.sleep(for: .seconds(10)) }
            catch { return }
        }
    }
}
