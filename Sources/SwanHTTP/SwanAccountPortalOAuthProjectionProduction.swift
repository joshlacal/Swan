import Foundation
import SwanOAuth
import SwanStorage

/// Production ``SwanAccountPortalOAuthProjection`` backed by the durable OAuth
/// control store.
///
/// The projection lists the account's live token families — never bearer
/// material — and revocation is account-bound and immediately effective
/// (access-token validation re-checks `revoked_at` on every request). The
/// portal service enforces step-up strength before this adapter is reached.
public struct SwanAccountPortalOAuthProjectionProduction:
    SwanAccountPortalOAuthProjection, Sendable
{
    private let store: any OAuthControlStore

    public init(store: any OAuthControlStore) {
        self.store = store
    }

    public func connectedApps(
        accountDID: String,
        now: Date
    ) async throws -> [SwanAccountPortalSnapshot.App] {
        let families = try await store.tokenFamilies(subject: accountDID, now: now)
        return families.map { family in
            SwanAccountPortalSnapshot.App(
                id: family.familyID.uuidString,
                // The client identifier is the durable registration fact; the
                // projection deliberately does not parse remote client
                // metadata documents at read time.
                name: family.binding.clientID,
                scopes: family.binding.scopes.sorted(),
                createdAt: Self.iso8601(family.createdAt ?? family.expiresAt)
            )
        }
    }

    public func revokeConnectedApp(
        accountDID: String,
        appID: String,
        sessionID: String,
        stepUpToken: String?,
        now: Date
    ) async throws {
        guard let familyID = UUID(uuidString: appID) else {
            throw SwanAccountPortalServiceError.invalidRequest
        }
        do {
            try await store.revokeTokenFamily(
                familyID: familyID, subject: accountDID, now: now
            )
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
        _ = sessionID
        _ = stepUpToken
    }

    private static func iso8601(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }
}
