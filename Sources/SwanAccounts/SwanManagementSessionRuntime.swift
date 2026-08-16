import Crypto
import Foundation
import SwanCore
import SwanStorage

/// Cookie/session boundary for the account portal. The browser sees only the
/// random values; the durable store receives keyed digests and metadata.
/// Durable pre-auth CSRF storage is injected by the integration lane. The
/// default actor keeps local tests useful while production supplies a store
/// backed by the same account database as management sessions.
public protocol SwanManagementPreAuthStore: Sendable {
    func put(digest: Data, expiresAt: Date) async
    func take(digest: Data, now: Date) async -> Bool
}

public actor SwanInMemoryManagementPreAuthStore: SwanManagementPreAuthStore {
    private var values: [Data: Date] = [:]
    public init() {}
    public func put(digest: Data, expiresAt: Date) async { values[digest] = expiresAt }
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
    private var csrfDigests: [Data: Data] = [:]
    private let preAuthStore: any SwanManagementPreAuthStore
    private let idleLifetime: TimeInterval
    private let absoluteLifetime: TimeInterval

    public init(
        store: any ManagementSessionStore,
        preAuthStore: any SwanManagementPreAuthStore = SwanInMemoryManagementPreAuthStore(),
        idleLifetime: TimeInterval = 12 * 60 * 60,
        absoluteLifetime: TimeInterval = 30 * 24 * 60 * 60
    ) {
        self.store = store
        self.preAuthStore = preAuthStore
        self.idleLifetime = idleLifetime
        self.absoluteLifetime = absoluteLifetime
    }

    public func issue(accountDID: String, strength: AuthenticationStrength = .password, now: Date = Date()) async throws -> IssuedManagementSession {
        let sessionValue = Self.randomToken()
        let csrfValue = Self.randomToken()
        let sessionID = try ManagementSessionID(rawValue: sessionValue)
        let metadata = try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: accountDID,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(idleLifetime),
            absoluteExpiresAt: now.addingTimeInterval(absoluteLifetime),
            strength: strength
        )
        let sessionDigest = Self.digest(sessionValue)
        let csrfDigest = Self.digest(csrfValue)
        try await store.createManagementSession(metadata, sessionDigest: sessionDigest, csrfDigest: csrfDigest, now: now)
        csrfDigests[sessionDigest] = csrfDigest
        return IssuedManagementSession(sessionValue: sessionValue, csrfValue: csrfValue, metadata: metadata)
    }

    public func issuePreAuth(now: Date = Date(), lifetime: TimeInterval = 10 * 60) async -> String {
        let value = Self.randomToken()
        await preAuthStore.put(digest: Self.digest(value), expiresAt: now.addingTimeInterval(lifetime))
        return value
    }

    /// Consumes a pre-auth token exactly once. A bootstrap refresh is allowed
    /// to issue a new token, but a successful login/signup cannot replay one.
    public func consumePreAuth(_ value: String, now: Date = Date()) async -> Bool {
        let digest = Self.digest(value)
        guard Self.validToken(value) else { return false }
        return await preAuthStore.take(digest: digest, now: now)
    }

    public func authenticate(sessionValue: String, now: Date = Date()) async throws -> ManagementSessionMetadata {
        guard Self.validToken(sessionValue) else { throw SwanManagementSessionError.unauthorized }
        guard let metadata = try await store.managementSession(digest: Self.digest(sessionValue), now: now),
              metadata.revokedAt == nil,
              metadata.idleExpiresAt >= now,
              metadata.absoluteExpiresAt >= now else {
            throw SwanManagementSessionError.unauthorized
        }
        return metadata
    }

    public func acceptsCSRF(sessionValue: String, csrfValue: String, now: Date = Date()) async throws -> Bool {
        guard let metadata = try? await authenticate(sessionValue: sessionValue, now: now),
              metadata.revokedAt == nil,
              Self.validToken(csrfValue) else { return false }
        let digest = Self.digest(sessionValue)
        let expected = csrfDigests[digest] ?? Data()
        return Self.constantTimeEqual(expected, Self.digest(csrfValue))
    }

    public func revoke(sessionValue: String, now: Date = Date()) async throws {
        guard Self.validToken(sessionValue) else { return }
        let digest = Self.digest(sessionValue)
        try await store.revokeManagementSession(digest: digest, now: now)
        csrfDigests.removeValue(forKey: digest)
    }

    public func revokeOthers(accountDID: String, except sessionValue: String, now: Date = Date()) async throws {
        let sessionID = try await authenticate(sessionValue: sessionValue, now: now).sessionID
        try await store.revokeOtherManagementSessions(accountDID: accountDID, except: sessionID, now: now)
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
}
