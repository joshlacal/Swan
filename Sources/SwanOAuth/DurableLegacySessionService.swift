import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSpaces
import SwanStorage

/// The credential pair `createSession` returns.
public struct LegacySessionTokens: Sendable, Equatable {
    public let accessJWT: String
    public let refreshJWT: String
    public let did: String
    public let expiresAt: Date
}

/// App-password sessions.
///
/// A SIBLING of `DurableOAuthTokenService`, reusing its design — family,
/// rotation, reuse detection, family-wide revocation, digests at rest — and
/// deliberately not extending it. That service hard-requires a DPoP thumbprint
/// on every token family, and making it nullable to admit a bearer session would
/// weaken the one invariant that currently makes EVERY OAuth token
/// sender-constrained. The two credential types share the authorization model
/// and nothing else.
public actor DurableLegacySessionService {
    private enum DigestPurpose: String {
        case accessToken = "legacy-access-token"
        case refreshToken = "legacy-refresh-token"
    }

    private let store: any LegacySessionStore
    private let appPasswords: any AppPasswordStore
    private let credentials: AppPasswordCredentials
    private let serviceDID: String
    private let signingKey: SymmetricKey
    private let macKey: SymmetricKey

    /// - Parameters:
    ///   - serverKey: the owner-only mounted 32-byte secret behind
    ///     `--legacy-session-signing-key-file`. Used for BOTH the JWT signature
    ///     and the at-rest digests, under separate domain-separated derivations
    ///     so a token's signature can never be confused with its lookup key.
    public init(
        store: any LegacySessionStore,
        appPasswords: any AppPasswordStore,
        credentials: AppPasswordCredentials,
        serviceDID: String,
        serverKey: Data
    ) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("legacy session signing key must be exactly 32 bytes")
        }
        self.store = store
        self.appPasswords = appPasswords
        self.credentials = credentials
        self.serviceDID = serviceDID
        // Domain separation. The same 32 bytes are the root of two independent
        // uses; deriving both from it means neither is the other's key.
        self.signingKey = SymmetricKey(
            data: Data(HMAC<SHA256>.authenticationCode(
                for: Data("swan.legacy-session.jwt-signing".utf8),
                using: SymmetricKey(data: serverKey)
            ))
        )
        self.macKey = SymmetricKey(
            data: Data(HMAC<SHA256>.authenticationCode(
                for: Data("swan.legacy-session.digest".utf8),
                using: SymmetricKey(data: serverKey)
            ))
        )
    }

    /// Opens a session for an already-authenticated app password.
    ///
    /// The caller is responsible for having verified the account password path
    /// first; this mints against a resolved app-password row.
    public func issue(
        did: String,
        appPassword: AppPasswordRecord,
        now: Date = Date()
    ) async throws -> LegacySessionTokens {
        let familyID = UUID().uuidString.lowercased()
        let accessID = UUID().uuidString.lowercased()
        let refreshID = UUID().uuidString.lowercased()
        let accessExpiry = now.addingTimeInterval(LegacySessionJWT.accessLifetime)
        let refreshExpiry = now.addingTimeInterval(LegacySessionJWT.refreshLifetime)

        let access = try mint(.access, subject: did, tokenID: accessID, scope: .appPassword, now: now)
        let refresh = try mint(.refresh, subject: did, tokenID: refreshID, scope: .refresh, now: now)

        try await store.createLegacySessionFamily(
            familyID: familyID,
            did: did,
            appPasswordID: appPassword.id,
            accessDigest: digest(access, purpose: .accessToken),
            accessExpiresAt: accessExpiry,
            refreshDigest: digest(refresh, purpose: .refreshToken),
            refreshExpiresAt: refreshExpiry,
            now: now
        )
        return LegacySessionTokens(
            accessJWT: access,
            refreshJWT: refresh,
            did: did,
            expiresAt: accessExpiry
        )
    }

    /// Resolves a presented access token to an authorization context.
    ///
    /// Two independent gates, in this order: the signature proves this host
    /// minted the token and it has not expired; the durable row proves the
    /// session still exists. Neither alone is sufficient — a signature outlives
    /// revocation, and a row lookup without a signature check would accept a
    /// forged `jti`.
    ///
    /// **The scope is re-derived from the app-password row on every call**, not
    /// carried in the token. So narrowing an app password takes effect on the
    /// next request, and revoking one takes effect at once — rather than at the
    /// end of a 120-minute access-token life.
    public func authorize(
        accessJWT: String,
        now: Date = Date()
    ) async throws -> AuthorizationContext {
        _ = try LegacySessionJWT.verify(accessJWT, kind: .access, key: signingKey, now: now)
        guard let family = try await store.legacyAccessSession(
            digest: digest(accessJWT, purpose: .accessToken),
            now: now
        ) else {
            throw SwanError.unauthorized("legacy session is not active")
        }
        let permissions = try await permissions(for: family)
        return .accountLegacySession(subject: family.did, permissions: permissions)
    }

    /// Rotates a session.
    ///
    /// Reuse of an already-consumed refresh token revokes the whole family. The
    /// legitimate client would be holding the replacement, so a second
    /// presentation of a rotated token means it was captured — and the correct
    /// response is to end every session descended from it, not just to refuse
    /// this one.
    public func refresh(
        refreshJWT: String,
        now: Date = Date()
    ) async throws -> LegacySessionTokens {
        _ = try LegacySessionJWT.verify(refreshJWT, kind: .refresh, key: signingKey, now: now)
        let presented = digest(refreshJWT, purpose: .refreshToken)

        switch try await store.legacyRefreshSession(digest: presented, now: now) {
        case .rejected:
            throw SwanError.unauthorized("legacy session is not active")
        case let .reused(family):
            try await store.revokeLegacySessionFamily(familyID: family.familyID, now: now)
            throw SwanError.unauthorized("legacy session is not active")
        case let .active(family):
            // Re-derived HERE, from the app-password row, so an edited
            // credential narrows this session and a revoked one ends it. Never
            // re-minted from what the previous session carried.
            //
            // A refresh may never WIDEN: this reads the current row and mints
            // nothing from the presented token, so there is no path by which a
            // rotation could grant more than the credential now allows.
            _ = try await permissions(for: family)

            let accessID = UUID().uuidString.lowercased()
            let refreshID = UUID().uuidString.lowercased()
            let accessExpiry = now.addingTimeInterval(LegacySessionJWT.accessLifetime)
            let refreshExpiry = now.addingTimeInterval(LegacySessionJWT.refreshLifetime)
            let access = try mint(
                .access, subject: family.did, tokenID: accessID, scope: .appPassword, now: now
            )
            let replacement = try mint(
                .refresh, subject: family.did, tokenID: refreshID, scope: .refresh, now: now
            )

            guard try await store.rotateLegacySession(
                familyID: family.familyID,
                consuming: presented,
                accessDigest: digest(access, purpose: .accessToken),
                accessExpiresAt: accessExpiry,
                replacementRefreshDigest: digest(replacement, purpose: .refreshToken),
                replacementRefreshExpiresAt: refreshExpiry,
                now: now
            ) else {
                // Lost a race with a concurrent refresh of the same token. Not
                // reuse — the other caller won and holds the replacement.
                throw SwanError.unauthorized("legacy session is not active")
            }
            return LegacySessionTokens(
                accessJWT: access,
                refreshJWT: replacement,
                did: family.did,
                expiresAt: accessExpiry
            )
        }
    }

    /// Ends one session. Used by `deleteSession`.
    public func revoke(refreshJWT: String, now: Date = Date()) async throws {
        guard (try? LegacySessionJWT.verify(
            refreshJWT, kind: .refresh, key: signingKey, now: now
        )) != nil else { return }
        switch try await store.legacyRefreshSession(
            digest: digest(refreshJWT, purpose: .refreshToken),
            now: now
        ) {
        case let .active(family), let .reused(family):
            try await store.revokeLegacySessionFamily(familyID: family.familyID, now: now)
        case .rejected:
            // Idempotent and silent: logging out twice is not an error, and
            // distinguishing the cases would report whether a token was genuine.
            return
        }
    }

    /// The current authority of a session, from its app-password row.
    private func permissions(for family: LegacySessionFamily) async throws -> SwanScopePermissions {
        let rows = try await appPasswords.listAppPasswords(did: family.did)
        guard let record = rows.first(where: { $0.id == family.appPasswordID }) else {
            // The credential was revoked. The family rows cascade on delete, so
            // reaching here means a token survived its credential — fail closed
            // rather than assuming the cascade ran.
            throw SwanError.unauthorized("legacy session is not active")
        }
        return SwanScopePermissions(
            rawScopes: Set(record.scopes.split(separator: " ").map(String.init)),
            subject: family.did
        )
    }

    private func mint(
        _ kind: LegacySessionJWT.Kind,
        subject: String,
        tokenID: String,
        scope: LegacyAuthScope,
        now: Date
    ) throws -> String {
        try LegacySessionJWT.create(
            kind: kind,
            subject: subject,
            audience: serviceDID,
            tokenID: tokenID,
            scope: scope,
            key: signingKey,
            now: now,
            lifetime: kind == .access
                ? LegacySessionJWT.accessLifetime
                : LegacySessionJWT.refreshLifetime
        )
    }

    private func digest(_ token: String, purpose: DigestPurpose) -> Data {
        var input = Data("swan.legacy.\(purpose.rawValue)\u{0}".utf8)
        input.append(contentsOf: token.utf8)
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: macKey))
    }
}
