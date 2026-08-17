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
    /// Narrow durable identity admission for new-token issuance. `nil` keeps
    /// focused fixtures source-compatible; production composition always
    /// supplies it and every issuance path denies (fails closed) when the
    /// identity is a suspended or failed-grace did:web account, or when the
    /// store/resolver is unavailable.
    private let identityAdmission: (any SwanIdentityAdmissionEvaluating)?

    /// - Parameters:
    ///   - serverKey: the owner-only mounted 32-byte secret behind
    ///     `--legacy-session-signing-key-file`. Used for BOTH the JWT signature
    ///     and the at-rest digests, under separate domain-separated derivations
    ///     so a token's signature can never be confused with its lookup key.
    ///   - identityAdmission: optional durable admission evaluated at every
    ///     family creation and refresh rotation.
    public init(
        store: any LegacySessionStore,
        appPasswords: any AppPasswordStore,
        credentials: AppPasswordCredentials,
        serviceDID: String,
        serverKey: Data,
        identityAdmission: (any SwanIdentityAdmissionEvaluating)? = nil
    ) throws {
        guard serverKey.count == 32 else {
            throw SwanError.malformed("legacy session signing key must be exactly 32 bytes")
        }
        self.store = store
        self.appPasswords = appPasswords
        self.credentials = credentials
        self.serviceDID = serviceDID
        self.identityAdmission = identityAdmission
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

    /// Fails closed for new-token issuance: a suspended or failed-grace
    /// did:web identity denies new legacy sessions, and a store/resolver
    /// failure is treated as a denial. PLC-only and active identities pass.
    private func requireIdentityAdmission(did: String, now: Date) async throws {
        guard let identityAdmission else { return }
        do {
            let decision = try await identityAdmission.identityAdmission(
                accountDID: did, now: now
            )
            guard decision.allowsTokenIssuance else {
                throw SwanError.unauthorized("identity does not admit legacy session issuance")
            }
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("identity admission is unavailable")
        }
    }

    /// Opens a session for an already-authenticated credential.
    ///
    /// - Parameter appPassword: the credential the session was opened with, or
    ///   `nil` for the ACCOUNT password. Upstream's `createSession` accepts
    ///   either (`account-manager.ts:587-641`) and Swan matches it. The two
    ///   differ in authority and in the token's `scope` claim, not in mechanism.
    /// - Parameter authorizationGrantDigest/authorizationContext: when a
    ///   revision-bound login grant was created, the family insert consumes it
    ///   in the same durable transaction; no legacy session is created without
    ///   a successful consume result.
    public func issue(
        did: String,
        appPassword: AppPasswordRecord?,
        now: Date = Date(),
        authorizationGrantDigest: Data? = nil,
        authorizationContext: AccountAuthorizationContext? = nil
    ) async throws -> LegacySessionTokens {
        try await requireIdentityAdmission(did: did, now: now)
        let familyID = UUID().uuidString.lowercased()
        let accessID = UUID().uuidString.lowercased()
        let refreshID = UUID().uuidString.lowercased()
        let accessExpiry = now.addingTimeInterval(LegacySessionJWT.accessLifetime)
        let refreshExpiry = now.addingTimeInterval(LegacySessionJWT.refreshLifetime)

        // Upstream's `scope` claim is a credential-TYPE discriminator
        // (`auth-scope.ts:2-9`): `com.atproto.access` for the account password,
        // `com.atproto.appPass` for an app password. Swan carries the same
        // values so the claim keeps its established meaning.
        let access = try mint(
            .access,
            subject: did,
            tokenID: accessID,
            scope: appPassword == nil ? .access : .appPassword,
            now: now
        )
        let refresh = try mint(.refresh, subject: did, tokenID: refreshID, scope: .refresh, now: now)

        if let authorizationGrantDigest {
            guard let authorizationContext else {
                throw SwanError.malformed("legacy session grant context")
            }
            try await store.createLegacySessionFamilyConsumingGrant(
                familyID: familyID,
                did: did,
                appPasswordID: appPassword?.id,
                accessDigest: digest(access, purpose: .accessToken),
                accessExpiresAt: accessExpiry,
                refreshDigest: digest(refresh, purpose: .refreshToken),
                refreshExpiresAt: refreshExpiry,
                authorizationGrantDigest: authorizationGrantDigest,
                authorizationContext: authorizationContext,
                now: now
            )
        } else {
            try await store.createLegacySessionFamily(
                familyID: familyID,
                did: did,
                appPasswordID: appPassword?.id,
                accessDigest: digest(access, purpose: .accessToken),
                accessExpiresAt: accessExpiry,
                refreshDigest: digest(refresh, purpose: .refreshToken),
                refreshExpiresAt: refreshExpiry,
                now: now
            )
        }
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

    /// Resolves a presented access token that must be FULL ACCESS, and returns
    /// its subject.
    ///
    /// Upstream gates the app-password management endpoints on `ACCESS_FULL`
    /// (`createAppPassword.ts:11`), i.e. a session opened with the account
    /// password. The rule that matters is the anti-escalation one: an app
    /// password must not be able to mint further app passwords, or revoke the
    /// credential that would have contained it.
    ///
    /// Upstream ALSO refuses OAuth on those endpoints. Swan matches that rather
    /// than inventing an admission path: gating them on an `account:` scope
    /// instead would mean enforcing a family the route map still lists as NOT
    /// PORTED, and a half-ported check on a privilege-granting endpoint is
    /// worse than no path at all. Admitting OAuth here is a deliberate later
    /// change that starts with porting `assertAccount`.
    public func authorizeFullAccess(
        accessJWT: String,
        now: Date = Date()
    ) async throws -> String {
        _ = try LegacySessionJWT.verify(accessJWT, kind: .access, key: signingKey, now: now)
        guard let family = try await store.legacyAccessSession(
            digest: digest(accessJWT, purpose: .accessToken),
            now: now
        ) else {
            throw SwanError.unauthorized("legacy session is not active")
        }
        guard family.appPasswordID == nil else {
            throw SwanError.unauthorized("app-password sessions cannot manage app passwords")
        }
        return family.did
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
            try await requireIdentityAdmission(did: family.did, now: now)
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
                .access,
                subject: family.did,
                tokenID: accessID,
                // Same discriminator the family was opened with — a rotation
                // must not silently promote an app-password session to a
                // full-access one.
                scope: family.appPasswordID == nil ? .access : .appPassword,
                now: now
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

    /// The current authority of a session.
    ///
    /// An app-password session re-reads its credential row on EVERY call, so
    /// narrowing takes effect at once and revoking ends the session (§D5).
    /// An account-password session has no row to read: it is full authority,
    /// which upstream spells `AuthScope.Access` and which here is the widest
    /// scope set the legacy surface can reach.
    private func permissions(for family: LegacySessionFamily) async throws -> SwanScopePermissions {
        guard let appPasswordID = family.appPasswordID else {
            // Full authority — every transition scope. Still NOT the
            // permissioned-data surface: `allowsSpace` has no transition arm,
            // and `.accountLegacySession` is refused at every space predicate
            // regardless of what it carries.
            return SwanScopePermissions(
                rawScopes: Set(AppPasswordPreset.full.scopes(appViewAudience: "")),
                subject: family.did
            )
        }
        let rows = try await appPasswords.listAppPasswords(did: family.did)
        guard let record = rows.first(where: { $0.id == appPasswordID }) else {
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
