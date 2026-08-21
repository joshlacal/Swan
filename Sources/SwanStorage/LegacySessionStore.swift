import Foundation
import SwanCore

/// One legacy session family, resolved from a presented token.
///
/// Carries the app-password ID rather than a scope set, because the scope is
/// re-derived from that row on every use (§D5). tranquil stores the scope on the
/// session and re-mints from it, so editing an app password leaves live sessions
/// at their old authority for the life of a 90-day refresh token.
public struct LegacySessionFamily: Sendable, Equatable {
    public let familyID: String
    public let did: String
    /// `nil` when the session was opened with the ACCOUNT password, which
    /// carries full authority and has no credential row to re-read.
    public let appPasswordID: String?
    public let createdAt: Date
    public let revokedAt: Date?

    public init(
        familyID: String,
        did: String,
        appPasswordID: String?,
        createdAt: Date,
        revokedAt: Date?
    ) {
        self.familyID = familyID
        self.did = did
        self.appPasswordID = appPasswordID
        self.createdAt = createdAt
        self.revokedAt = revokedAt
    }
}

/// What resolving a presented refresh token found.
public enum LegacyRefreshResolution: Sendable, Equatable {
    /// Live, unconsumed, and its family is not revoked.
    case active(LegacySessionFamily)
    /// The token is genuine but was already consumed. The caller MUST revoke the
    /// family: a second presentation means the token was captured, since the
    /// legitimate client would be holding its replacement.
    case reused(LegacySessionFamily)
    /// Unknown, expired, or belonging to a revoked family.
    case rejected
}

public enum LegacySessionTokenKind: String, Sendable, Equatable {
    case access
    case refresh
}

public protocol LegacySessionStore: Sendable {
    /// Opens a family and records its first token pair.
    func createLegacySessionFamily(
        familyID: String,
        did: String,
        appPasswordID: String?,
        accessDigest: Data,
        accessExpiresAt: Date,
        refreshDigest: Data,
        refreshExpiresAt: Date,
        now: Date
    ) async throws

    /// Resolves a live access token to its family, or `nil`.
    func legacyAccessSession(digest: Data, now: Date) async throws -> LegacySessionFamily?

    /// Resolves a refresh token, distinguishing reuse from rejection.
    func legacyRefreshSession(digest: Data, now: Date) async throws -> LegacyRefreshResolution

    /// Atomically consumes a refresh token and records its replacements.
    ///
    /// Returns `false` if the token was not consumable at commit time, which is
    /// how two concurrent refreshes of the same token resolve to exactly one
    /// winner rather than two live sessions.
    func rotateLegacySession(
        familyID: String,
        consuming refreshDigest: Data,
        accessDigest: Data,
        accessExpiresAt: Date,
        replacementRefreshDigest: Data,
        replacementRefreshExpiresAt: Date,
        now: Date
    ) async throws -> Bool

    /// Revokes a whole family and drops its tokens.
    func revokeLegacySessionFamily(familyID: String, now: Date) async throws

    /// Account-bound, idempotent family revocation. The family row is updated
    /// only when it belongs to `did`, so the portal cannot revoke another
    /// account's legacy session by guessing a family identifier.
    func revokeLegacySessionFamily(familyID: String, did: String, now: Date) async throws

    /// Lists the account's legacy session families for the portal projection.
    /// The family `expiresAt` is the latest live token expiry so the UI can
    /// show whether a session is still usable.
    func legacySessionFamilies(did: String, now: Date) async throws -> [LegacySessionFamilyMetadata]

    /// Portal/legacy issuance variant: the revision-bound authorization grant
    /// is consumed in the SAME transaction that inserts the family and its
    /// first token pair. No protected legacy session is created unless the
    /// exact account/channel/session/purpose-bound grant consumes at this
    /// linearization point.
    func createLegacySessionFamilyConsumingGrant(
        familyID: String,
        did: String,
        appPasswordID: String?,
        accessDigest: Data,
        accessExpiresAt: Date,
        refreshDigest: Data,
        refreshExpiresAt: Date,
        authorizationGrantDigest: Data,
        authorizationContext: AccountAuthorizationContext,
        now: Date
    ) async throws

    /// Drops every token row that expired before `now`.
    func pruneLegacySessions(now: Date) async throws
}
