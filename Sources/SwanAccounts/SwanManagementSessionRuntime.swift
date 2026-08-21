import Crypto
import Foundation
import SwanCore
import SwanStorage

public actor SwanInMemoryManagementCSRFStore: SwanManagementCSRFStore {
    private var values: [Data: Data] = [:]
    public init() {}
    public func put(sessionDigest: Data, csrfDigest: Data) async throws { values[sessionDigest] = csrfDigest }
    public func digest(for sessionDigest: Data) async throws -> Data? { values[sessionDigest] }
    public func remove(sessionDigest: Data) async throws { values.removeValue(forKey: sessionDigest) }
}

public actor SwanInMemoryManagementPreAuthStore: SwanManagementPreAuthStore {
    private var values: [Data: Date] = [:]
    public init() {}
    public func put(digest: Data, expiresAt: Date) async { values[digest] = expiresAt }
    public func contains(digest: Data, now: Date) async -> Bool { values[digest].map { $0 >= now } ?? false }
    public func take(digest: Data, now: Date) async -> Bool {
        guard let expiry = values.removeValue(forKey: digest), expiry >= now else { return false }
        return true
    }
}

public actor SwanManagementSessionRuntime {
    public static let sessionCookieName = "__Secure-swan_management"
    public static let csrfCookieName = "swan_csrf"
    public static let preAuthCookieName = "swan_csrf_pre"

    private let store: any ManagementSessionStore
    private let preAuthStore: any SwanManagementPreAuthStore
    private let csrfStore: any SwanManagementCSRFStore
    private let preAuthSessionCoordinator: (any SwanManagementPreAuthSessionCoordinator)?
    private let idleLifetime: TimeInterval
    private let absoluteLifetime: TimeInterval

    public init(
        store: any ManagementSessionStore,
        preAuthStore: any SwanManagementPreAuthStore,
        csrfStore: any SwanManagementCSRFStore,
        preAuthSessionCoordinator: (any SwanManagementPreAuthSessionCoordinator)? = nil,
        idleLifetime: TimeInterval = 12 * 60 * 60,
        absoluteLifetime: TimeInterval = 30 * 24 * 60 * 60
    ) {
        self.store = store
        self.preAuthStore = preAuthStore
        self.csrfStore = csrfStore
        self.preAuthSessionCoordinator = preAuthSessionCoordinator
        self.idleLifetime = idleLifetime
        self.absoluteLifetime = absoluteLifetime
    }

    public func issue(accountDID: String, strength: AuthenticationStrength = .password, now: Date = Date()) async throws -> IssuedManagementSession {
        let issued = try mint(accountDID: accountDID, strength: strength, now: now)
        let sessionDigest = Self.digest(issued.sessionValue)
        let csrfDigest = Self.digest(issued.csrfValue)
        try await store.createManagementSession(issued.metadata, sessionDigest: sessionDigest, csrfDigest: csrfDigest, now: now)
        try await csrfStore.put(sessionDigest: sessionDigest, csrfDigest: csrfDigest)
        return issued
    }

    /// Mints session material without persisting it. The caller persists the
    /// session inside its own atomic transaction (signup finalization); the
    /// non-atomic `issue` path is for flows that own their own transaction.
    public nonisolated func mint(accountDID: String, strength: AuthenticationStrength = .password, now: Date = Date()) throws -> IssuedManagementSession {
        let sessionValue = Self.randomToken()
        let csrfValue = Self.randomToken()
        let sessionID = try ManagementSessionID(digest: Self.digest(sessionValue))
        let metadata = try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: accountDID,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(idleLifetime),
            absoluteExpiresAt: now.addingTimeInterval(absoluteLifetime),
            strength: strength
        )
        return IssuedManagementSession(sessionValue: sessionValue, csrfValue: csrfValue, metadata: metadata)
    }

    public func issuePreAuth(now: Date = Date(), lifetime: TimeInterval = 10 * 60) async -> String {
        let value = Self.randomToken()
        await preAuthStore.put(digest: Self.digest(value), expiresAt: now.addingTimeInterval(lifetime))
        return value
    }

    /// Consume a pre-auth token and issue the authenticated session through
    /// the durable coordinator. There is intentionally no fallback to the
    /// non-atomic `issue` path: production must not be able to create a
    /// session when the one-time pre-auth state was lost to a race.
    public func issueAfterPreAuth(
        _ value: String,
        accountDID: String,
        strength: AuthenticationStrength = .password,
        now: Date = Date()
    ) async throws -> IssuedManagementSession {
        guard Self.validToken(value), let coordinator = preAuthSessionCoordinator else {
            throw SwanManagementSessionError.unavailable
        }
        let sessionValue = Self.randomToken()
        let csrfValue = Self.randomToken()
        let sessionID = try ManagementSessionID(digest: Self.digest(sessionValue))
        let metadata = try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: accountDID,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(idleLifetime),
            absoluteExpiresAt: now.addingTimeInterval(absoluteLifetime),
            strength: strength
        )
        let consumed = try await coordinator.consumePreAuthAndCreateManagementSession(
            preAuthDigest: Self.digest(value),
            session: metadata,
            sessionDigest: Self.digest(sessionValue),
            csrfDigest: Self.digest(csrfValue),
            now: now
        )
        guard consumed else { throw SwanManagementSessionError.unauthorized }
        return IssuedManagementSession(sessionValue: sessionValue, csrfValue: csrfValue, metadata: metadata)
    }

    /// Portal login issuance: pre-auth consumption, revision-bound
    /// authorization-grant consumption, and management-session creation share
    /// one durable transaction. The grant is the one-time receipt created by
    /// the canonical directory at login; no protected portal session is
    /// issued unless the exact context-bound grant consumes here.
    public func issueAfterPreAuth(
        _ value: String,
        accountDID: String,
        strength: AuthenticationStrength,
        authorizationGrantDigest: Data?,
        authorizationContext: AccountAuthorizationContext?,
        now: Date = Date()
    ) async throws -> IssuedManagementSession {
        guard let authorizationGrantDigest else {
            return try await issueAfterPreAuth(
                value, accountDID: accountDID, strength: strength, now: now
            )
        }
        guard let authorizationContext,
              Self.validToken(value),
              let coordinator = preAuthSessionCoordinator else {
            throw SwanManagementSessionError.unavailable
        }
        let sessionValue = Self.randomToken()
        let csrfValue = Self.randomToken()
        let sessionID = try ManagementSessionID(digest: Self.digest(sessionValue))
        let metadata = try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: accountDID,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(idleLifetime),
            absoluteExpiresAt: now.addingTimeInterval(absoluteLifetime),
            strength: strength
        )
        let consumed = try await coordinator.consumePreAuthAndCreateManagementSessionConsumingGrant(
            preAuthDigest: Self.digest(value),
            session: metadata,
            sessionDigest: Self.digest(sessionValue),
            csrfDigest: Self.digest(csrfValue),
            authorizationGrantDigest: authorizationGrantDigest,
            authorizationContext: authorizationContext,
            now: now
        )
        guard consumed else { throw SwanManagementSessionError.unauthorized }
        return IssuedManagementSession(sessionValue: sessionValue, csrfValue: csrfValue, metadata: metadata)
    }

    /// Lists the account's live management sessions for the portal
    /// projection. The returned identifiers are the storage digest-derived
    /// stable values, never bearer session material.
    public func managementSessions(accountDID: String, now: Date = Date()) async throws -> [ManagementSessionMetadata] {
        try await store.managementSessions(accountDID: accountDID, now: now)
    }

    /// Account-bound, idempotent revocation of one management session
    /// selected by its projection identifier (the digest-derived hex value).
    /// The store updates the row only when it belongs to `accountDID`.
    public func revokeManagementSession(id: String, accountDID: String, now: Date = Date()) async throws {
        guard let digest = Self.hexDecode(id), digest.count == 32 else {
            throw SwanManagementSessionError.requestNotAllowed
        }
        try await store.revokeManagementSession(digest: digest, accountDID: accountDID, now: now)
    }

    private static func hexDecode(_ value: String) -> Data? {
        guard value.utf8.count % 2 == 0 else { return nil }
        var output = Data()
        output.reserveCapacity(value.utf8.count / 2)
        var index = value.utf8.startIndex
        while index < value.utf8.endIndex {
            let high = value.utf8[index]
            let low = value.utf8[value.utf8.index(after: index)]
            guard let highValue = nibble(high), let lowValue = nibble(low) else { return nil }
            output.append(highValue << 4 | lowValue)
            index = value.utf8.index(index, offsetBy: 2)
        }
        return output
    }

    private static func nibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48 ... 57: return byte - 48
        case 97 ... 102: return byte - 97 + 10
        case 65 ... 70: return byte - 65 + 10
        default: return nil
        }
    }

    /// Consumes a pre-auth token exactly once. A bootstrap refresh is allowed
    /// to issue a new token, but a successful login/signup cannot replay one.
    public func consumePreAuth(_ value: String, now: Date = Date()) async -> Bool {
        let digest = Self.digest(value)
        guard Self.validToken(value) else { return false }
        return await preAuthStore.take(digest: digest, now: now)
    }

    public func validatesPreAuth(_ value: String, now: Date = Date()) async -> Bool {
        guard Self.validToken(value) else { return false }
        let digest = Self.digest(value)
        return await preAuthStore.contains(digest: digest, now: now)
    }

    public func releasePreAuth(_ value: String) {}

    public func authenticate(sessionValue: String, now: Date = Date()) async throws -> ManagementSessionMetadata {
        guard Self.validToken(sessionValue) else { throw SwanManagementSessionError.unauthorized }
        guard let metadata = try await store.managementSession(digest: Self.digest(sessionValue), now: now),
              metadata.revokedAt == nil,
              metadata.idleExpiresAt >= now,
              metadata.absoluteExpiresAt >= now else {
            throw SwanManagementSessionError.unauthorized
        }
        // Storage intentionally persists only the keyed digest. Re-bind the
        // opaque identifier to the value presented by this authenticated
        // request so callers such as revokeOthers do not hash a synthetic
        // identifier and accidentally revoke the current session as well.
        return try ManagementSessionMetadata(
            sessionID: try ManagementSessionID(digest: Self.digest(sessionValue)),
            accountDID: metadata.accountDID,
            issuedAt: metadata.issuedAt,
            idleExpiresAt: metadata.idleExpiresAt,
            absoluteExpiresAt: metadata.absoluteExpiresAt,
            lastStepUpAt: metadata.lastStepUpAt,
            strength: metadata.strength,
            revokedAt: metadata.revokedAt
        )
    }

    public func acceptsCSRF(sessionValue: String, csrfValue: String, now: Date = Date()) async throws -> Bool {
        guard let metadata = try? await authenticate(sessionValue: sessionValue, now: now),
              metadata.revokedAt == nil,
              Self.validToken(csrfValue) else { return false }
        let digest = Self.digest(sessionValue)
        let expected = (try? await csrfStore.digest(for: digest)) ?? Data()
        return Self.constantTimeEqual(expected, Self.digest(csrfValue))
    }

    public func revoke(sessionValue: String, now: Date = Date()) async throws {
        guard Self.validToken(sessionValue) else { return }
        let digest = Self.digest(sessionValue)
        try await store.revokeManagementSession(digest: digest, now: now)
        try await csrfStore.remove(sessionDigest: digest)
    }

    public func revokeOthers(accountDID: String, except sessionValue: String, now: Date = Date()) async throws {
        let sessionID = try await authenticate(sessionValue: sessionValue, now: now).sessionID
        try await store.revokeOtherManagementSessions(accountDID: accountDID, except: sessionID, now: now)
    }

    /// Consumes a durable MFA step-up receipt and upgrades the same
    /// management session in storage. The token is bound to the session and
    /// account by ``FactorTokenService``; a replay or cross-session use is
    /// rejected before the durable strength update.
    public func upgradeFromStepUp(
        sessionValue: String,
        token: String,
        factorTokens: FactorTokenService,
        now: Date = Date()
    ) async throws -> ManagementSessionMetadata {
        let current = try await authenticate(sessionValue: sessionValue, now: now)
        let record = try await factorTokens.consumeStepUpToken(
            token: token,
            accountDID: current.accountDID,
            sessionID: current.sessionID.rawValue,
            now: now
        )
        let verifiedAt: Date
        switch record.strength {
        case let .stepUpPassword(date), let .stepUpMFA(_, date):
            verifiedAt = date
        default:
            throw SwanManagementSessionError.requestNotAllowed
        }
        guard let stepUpStore = store as? any ManagementSessionStepUpStore else {
            throw SwanManagementSessionError.unavailable
        }
        do {
            try await stepUpStore.upgradeManagementSession(
                digest: Self.digest(sessionValue),
                accountDID: current.accountDID,
                strength: record.strength,
                lastStepUpAt: verifiedAt,
                now: now
            )
        } catch {
            throw SwanManagementSessionError.unavailable
        }
        return try await authenticate(sessionValue: sessionValue, now: now)
    }

    /// Records a fresh password reauthentication on the existing management
    /// session. This path is intentionally separate from MFA token upgrade:
    /// the account directory has already verified the password, and the
    /// durable session store supplies the single write linearization point.
    public func upgradeFromPasswordReauth(
        sessionValue: String,
        accountDID: String,
        now: Date = Date()
    ) async throws -> ManagementSessionMetadata {
        let current = try await authenticate(sessionValue: sessionValue, now: now)
        guard current.accountDID == accountDID,
              let stepUpStore = store as? any ManagementSessionStepUpStore else {
            throw SwanManagementSessionError.requestNotAllowed
        }
        do {
            try await stepUpStore.upgradeManagementSession(
                digest: Self.digest(sessionValue),
                accountDID: accountDID,
                strength: .stepUpPassword(verifiedAt: now),
                lastStepUpAt: now,
                now: now
            )
        } catch {
            throw SwanManagementSessionError.unavailable
        }
        return try await authenticate(sessionValue: sessionValue, now: now)
    }

    public static func digest(_ value: String) -> Data {
        Data(SHA256.hash(data: Data(value.utf8)))
    }

    public static func validToken(_ value: String) -> Bool {
        value.utf8.count >= 43 && value.utf8.count <= 512 && value.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) || byte == 45 || byte == 95
        }
    }

    private static func randomToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max) }
        return Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }
}

public struct IssuedManagementSession: Sendable, Equatable {
    public let sessionValue: String
    public let csrfValue: String
    public let metadata: ManagementSessionMetadata

    public init(sessionValue: String, csrfValue: String, metadata: ManagementSessionMetadata) {
        self.sessionValue = sessionValue
        self.csrfValue = csrfValue
        self.metadata = metadata
    }
}

public enum SwanManagementSessionError: Error, Sendable, Equatable {
    case unauthorized
    case requestNotAllowed
    case unavailable
}
