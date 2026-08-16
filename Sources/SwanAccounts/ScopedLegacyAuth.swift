import Crypto
import CLibsodium
import Foundation
import SwanCore
import SwanStorage

public struct LegacyAccountRecord: Sendable, Equatable {
    public let did: String
    public let handle: String
    public let passwordVerifier: String?
    public let mfaEnabled: Bool

    public init(did: String, handle: String, passwordVerifier: String? = nil, mfaEnabled: Bool = false) {
        self.did = did
        self.handle = handle
        self.passwordVerifier = passwordVerifier
        self.mfaEnabled = mfaEnabled
    }
}

public struct LegacyAccountResolver: Sendable {
    private let resolveBody: @Sendable (String) async throws -> LegacyAccountRecord?
    private let verifyBody: @Sendable (LegacyAccountRecord, String, String?) async throws -> Bool

    public init(
        resolve: @escaping @Sendable (String) async throws -> LegacyAccountRecord?,
        verifyPassword: @escaping @Sendable (LegacyAccountRecord, String, String?) async throws -> Bool
    ) {
        resolveBody = resolve
        verifyBody = verifyPassword
    }

    public func resolve(_ identifier: String) async throws -> LegacyAccountRecord? {
        try await resolveBody(identifier)
    }

    public func verifyPassword(_ account: LegacyAccountRecord, password: String, authFactorToken: String?) async throws -> Bool {
        try await verifyBody(account, password, authFactorToken)
    }

    public static let fixture = Self(
        resolve: { identifier in
            guard identifier == "did:plc:alice" || identifier == "alice.test" else { return nil }
            return LegacyAccountRecord(did: "did:plc:alice", handle: "alice.test", passwordVerifier: "password")
        },
        verifyPassword: { account, password, factor in
            guard account.passwordVerifier == password else { return false }
            guard !account.mfaEnabled else { return factor == "valid-factor" }
            return true
        }
    )
}

public struct AppPasswordPresentation: Sendable, Equatable {
    public let id: String
    public let name: String
    public let scopes: Set<String>
    /// This is intentionally only returned from create and never appears in
    /// metadata, logs, list responses, or error messages.
    public let secret: String

    public init(id: String, name: String, scopes: Set<String>, secret: String) {
        self.id = id
        self.name = name
        self.scopes = scopes
        self.secret = secret
    }
}

public struct PublicAppPasswordMetadata: Sendable, Equatable, Codable {
    public let id: String
    public let name: String
    public let scopes: Set<String>
    public let createdAt: Date
    public let lastUsedAt: Date?
    public let revokedAt: Date?

    public init(metadata: AppPasswordMetadata) {
        id = metadata.id
        name = metadata.canonicalName
        scopes = metadata.scopeStrings
        createdAt = metadata.createdAt
        lastUsedAt = metadata.lastUsedAt
        revokedAt = metadata.revokedAt
    }
}

public struct LegacySessionTokens: Sendable, Equatable {
    public let accessToken: String
    public let refreshToken: String
    public let did: String
    public let handle: String
    public let scopes: Set<String>
    public let sessionID: LegacySessionID

    public var accessJwt: String { accessToken }
    public var refreshJwt: String { refreshToken }
}

public struct LegacyServiceAuthToken: Sendable, Equatable {
    public let token: String
    public let subject: String
    public let audience: String
    public let expiresAt: Date
}

public actor LegacyAuthService {
    public static let accessLifetime: TimeInterval = 3_600
    public static let refreshLifetime: TimeInterval = 90 * 24 * 3_600
    public static let serviceAuthLifetime: TimeInterval = 60

    private let store: any AppPasswordStore & LegacySessionStore
    private let accountResolver: LegacyAccountResolver
    private let secretKey: SymmetricKey
    private var accessTokens: [String: LegacySessionID] = [:]

    public init(
        store: any AppPasswordStore & LegacySessionStore,
        accountResolver: LegacyAccountResolver,
        secretKey: Data = Data("swan-legacy-auth-development-key".utf8)
    ) throws {
        guard secretKey.count >= 16 else { throw SwanError.invalidIdentifier("legacy auth secret key") }
        self.store = store
        self.accountResolver = accountResolver
        self.secretKey = SymmetricKey(data: secretKey)
    }

    public func createAppPassword(accountDID: String, name: String, scopes: Set<String>, now: Date = Date()) async throws -> AppPasswordPresentation {
        guard try await accountResolver.resolve(accountDID) != nil else {
            throw SwanError.unauthorized("account unavailable")
        }
        let canonicalName = try Self.canonicalName(name)
        let canonicalScopes = try Self.canonicalScopes(scopes, permitFullAccess: false)
        let secret = Self.randomToken(prefix: "ap")
        let metadata = try AppPasswordMetadata(
            id: Self.randomIdentifier(), accountDID: accountDID, canonicalName: canonicalName,
            scopeStrings: canonicalScopes, secretDigest: try secretDigest(secret, accountDID: accountDID), createdAt: now
        )
        try await store.createAppPassword(metadata, now: now)
        return AppPasswordPresentation(id: metadata.id, name: canonicalName, scopes: canonicalScopes, secret: secret)
    }

    public func listAppPasswords(accountDID: String, now: Date = Date()) async throws -> [PublicAppPasswordMetadata] {
        try await store.listAppPasswords(accountDID: accountDID, now: now).map(PublicAppPasswordMetadata.init(metadata:))
    }

    public func updateAppPasswordScopes(accountDID: String, name: String, scopes: Set<String>, now: Date = Date()) async throws {
        try await store.updateAppPasswordScopes(accountDID: accountDID, canonicalName: Self.canonicalName(name), scopes: Self.canonicalScopes(scopes, permitFullAccess: false), now: now)
    }

    public func revokeAppPassword(accountDID: String, name: String, now: Date = Date()) async throws {
        try await store.revokeAppPassword(accountDID: accountDID, canonicalName: Self.canonicalName(name), now: now)
    }

    public func createSession(identifier: String, password: String, authFactorToken: String? = nil, now: Date = Date()) async throws -> LegacySessionTokens {
        guard !password.isEmpty else { throw SwanError.unauthorized("invalid identifier or password") }
        guard let account = try await accountResolver.resolve(identifier) else {
            throw SwanError.unauthorized("invalid identifier or password")
        }
        let passwords = try await store.listAppPasswords(accountDID: account.did, now: now)
        let presentedAppPasswordDigest = try secretDigest(password, accountDID: account.did)
        if let app = passwords.first(where: { $0.revokedAt == nil && constantTimeEqual($0.secretDigest, presentedAppPasswordDigest) }) {
            return try await issueSession(account: account, appPassword: app, now: now)
        }
        guard try await accountResolver.verifyPassword(account, password: password, authFactorToken: authFactorToken) else {
            throw SwanError.unauthorized("invalid identifier or password")
        }
        // Password sessions are deliberately not full-access. The reference
        // server's legacy compatibility grant is represented explicitly and
        // can never be produced by app-password input.
        let sessionScopes: Set<String> = ["atproto"]
        return try await issueSession(account: account, appPassword: nil, scopes: sessionScopes, now: now)
    }

    public func refreshSession(_ refreshToken: String, now: Date = Date()) async throws -> LegacySessionTokens {
        let oldDigest = digest(refreshToken)
        guard let old = try await store.legacySession(digest: oldDigest, now: now) else {
            throw SwanError.unauthorized("invalid refresh token")
        }
        guard old.expiresAt > now else {
            throw SwanError.unauthorized("invalid refresh token")
        }
        let newScopes: Set<String>
        if let appID = old.appPasswordID {
            guard let app = try await store.appPassword(id: appID, now: now), app.revokedAt == nil else {
                throw SwanError.unauthorized("invalid refresh token")
            }
            newScopes = app.scopeStrings
        } else {
            newScopes = old.scopeStrings
        }
        let refresh = Self.randomToken(prefix: "rf")
        let access = Self.randomToken(prefix: "at")
        let replacementID = try LegacySessionID(digest: digest(refresh))
        let replacement = try LegacySessionMetadata(
            sessionID: replacementID, familyID: old.familyID, accountDID: old.accountDID,
            appPasswordID: old.appPasswordID, scopeStrings: newScopes, issuedAt: now,
            expiresAt: now.addingTimeInterval(Self.refreshLifetime), previousSessionDigest: oldDigest
        )
        let outcome = try await store.rotateOrRevokeFamilyOnReuse(try LegacySessionRotationRequest(
            oldDigest: oldDigest, replacement: replacement, replacementDigest: digest(refresh), now: now
        ))
        guard case .rotated = outcome.kind else {
            throw SwanError.unauthorized("refresh token reuse detected")
        }
        accessTokens[access] = replacementID
        return try await makeTokens(access: access, refresh: refresh, session: replacement)
    }

    public func getSession(_ accessToken: String, now: Date = Date()) async throws -> LegacySessionTokens {
        guard let sessionID = accessTokens[accessToken] else {
            throw SwanError.unauthorized("invalid access token")
        }
        guard let digest = Data(hex: sessionID.rawValue),
              let session = try await store.legacySession(digest: digest, now: now),
              session.revokedAt == nil, session.expiresAt > now else {
            throw SwanError.unauthorized("invalid access token")
        }
        return try await makeTokens(access: accessToken, refresh: "", session: session)
    }

    public func deleteSession(_ accessToken: String, now: Date = Date()) async throws {
        guard let sessionID = accessTokens.removeValue(forKey: accessToken),
              let digest = Data(hex: sessionID.rawValue),
              let session = try await store.legacySession(digest: digest, now: now),
              session.revokedAt == nil, session.expiresAt > now else {
            throw SwanError.unauthorized("invalid access token")
        }
        try await store.revokeLegacySessionFamily(familyID: session.familyID, now: now)
    }

    public func getServiceAuth(accessToken: String, lxm: String?, aud: String?, now: Date = Date()) async throws -> LegacyServiceAuthToken {
        guard let lxm, let aud else { throw SwanError.unauthorized("lxm and aud are required") }
        let session = try await getSession(accessToken, now: now)
        let policy = DeclaredMethodScopePolicy(declarations: [lxm: ["rpc:\(lxm)?aud=\(aud)"]])
        try SwanScopeEvaluator().evaluate(credential: .scopes(session.scopes), canonicalMethod: lxm, declaredMethodPolicy: policy, audience: aud)
        return LegacyServiceAuthToken(token: Self.randomToken(prefix: "svc"), subject: session.did, audience: aud, expiresAt: now.addingTimeInterval(Self.serviceAuthLifetime))
    }

    private func issueSession(account: LegacyAccountRecord, appPassword: AppPasswordMetadata?, scopes: Set<String>? = nil, now: Date) async throws -> LegacySessionTokens {
        let familyID = Self.randomIdentifier()
        let refresh = Self.randomToken(prefix: "rf")
        let access = Self.randomToken(prefix: "at")
        let sessionID = try LegacySessionID(digest: digest(refresh))
        let session = try LegacySessionMetadata(sessionID: sessionID, familyID: familyID, accountDID: account.did, appPasswordID: appPassword?.id, scopeStrings: scopes ?? appPassword?.scopeStrings ?? [], issuedAt: now, expiresAt: now.addingTimeInterval(Self.refreshLifetime))
        let family = try LegacySessionFamilyMetadata(familyID: familyID, accountDID: account.did, appPasswordID: appPassword?.id, createdAt: now, expiresAt: session.expiresAt)
        try await store.createLegacySessionFamily(family, session: session, sessionDigest: digest(refresh), now: now)
        accessTokens[access] = sessionID
        return LegacySessionTokens(accessToken: access, refreshToken: refresh, did: account.did, handle: account.handle, scopes: session.scopeStrings, sessionID: sessionID)
    }

    private func makeTokens(access: String, refresh: String, session: LegacySessionMetadata) async throws -> LegacySessionTokens {
        guard let account = try await accountResolver.resolve(session.accountDID) else { throw SwanError.unauthorized("account unavailable") }
        return LegacySessionTokens(accessToken: access, refreshToken: refresh, did: account.did, handle: account.handle, scopes: session.scopeStrings, sessionID: session.sessionID)
    }

    private func digest(_ token: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(token.utf8), using: secretKey))
    }

    /// App-password secrets are high-entropy bearer values, but are still
    /// stored through the same Argon2id primitive used by account verifiers.
    /// A keyed, account-bound salt keeps the fixed-width schema digest
    /// deterministic for lookup without persisting the presented secret.
    private func secretDigest(_ secret: String, accountDID: String) throws -> Data {
        guard Self.sodiumInitializationResult >= 0 else {
            throw SwanError.unavailable("libsodium initialization failed")
        }
        var output = [UInt8](repeating: 0, count: 32)
        let saltMaterial = Data(HMAC<SHA256>.authenticationCode(for: Data(("swan-app-password:" + accountDID).utf8), using: secretKey))
        let salt = saltMaterial.prefix(Int(crypto_pwhash_SALTBYTES))
        let passwordBytes = secret.utf8CString
        let result = passwordBytes.withUnsafeBufferPointer { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                guard let saltBase = saltBuffer.baseAddress else { return -1 }
                crypto_pwhash(
                    &output, UInt64(output.count), passwordBuffer.baseAddress!,
                    UInt64(passwordBuffer.count - 1), saltBase.assumingMemoryBound(to: UInt8.self),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13
                )
            }
        }
        guard result == 0 else { throw SwanError.unavailable("Argon2id app-password hashing failed") }
        return Data(output)
    }

    private static let sodiumInitializationResult = sodium_init()

    private static func canonicalName(_ name: String) throws -> String {
        guard (1 ... 128).contains(name.utf8.count), name == name.trimmingCharacters(in: .whitespacesAndNewlines), name.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else { throw SwanError.malformed("invalid app-password name") }
        return name
    }

    private static func canonicalScopes(_ scopes: Set<String>, permitFullAccess: Bool) throws -> Set<String> {
        guard !scopes.isEmpty, scopes.count <= 64 else { throw SwanError.malformed("scope is empty or too large") }
        var result = Set<String>()
        for scope in scopes {
            let parsed = try SwanScope.parse(scope)
            guard parsed.kind != .include("full") || permitFullAccess else { throw SwanScopeError.wildcardNotAllowed }
            result.insert(parsed.canonicalValue)
        }
        return result
    }

    private static func randomIdentifier() -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() }
    private static func randomToken(prefix: String) -> String { "\(prefix)-" + Data(UUID().uuidString.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool { lhs.count == rhs.count && zip(lhs, rhs).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0 }
}

/// An actor-backed store is useful for deterministic service tests and for
/// local reference interop. The production adapter below uses the existing
/// control database tables and the same protocols.
public actor InMemoryLegacyAuthStore: AppPasswordStore, LegacySessionStore {
    private var appPasswords: [String: AppPasswordMetadata] = [:]
    private var families: [String: LegacySessionFamilyMetadata] = [:]
    private var sessions: [String: LegacySessionMetadata] = [:]

    public init() {}

    public func createAppPassword(_ metadata: AppPasswordMetadata, now: Date) async throws {
        guard appPasswords.values.allSatisfy({ !($0.accountDID == metadata.accountDID && $0.canonicalName == metadata.canonicalName) }) else { throw SwanError.unauthorized("app password already exists") }
        appPasswords[metadata.id] = metadata
    }
    public func appPassword(accountDID: String, canonicalName: String, now: Date) async throws -> AppPasswordMetadata? { appPasswords.values.first { $0.accountDID == accountDID && $0.canonicalName == canonicalName } }
    public func appPassword(id: String, now: Date) async throws -> AppPasswordMetadata? { appPasswords[id] }
    public func listAppPasswords(accountDID: String, now: Date) async throws -> [AppPasswordMetadata] { appPasswords.values.filter { $0.accountDID == accountDID }.sorted { $0.createdAt < $1.createdAt } }
    public func updateAppPasswordScopes(accountDID: String, canonicalName: String, scopes: Set<String>, now: Date) async throws {
        guard let old = appPasswords.values.first(where: { $0.accountDID == accountDID && $0.canonicalName == canonicalName && $0.revokedAt == nil }) else { throw SwanError.unauthorized("app password not found") }
        appPasswords[old.id] = try AppPasswordMetadata(id: old.id, accountDID: old.accountDID, canonicalName: old.canonicalName, scopeStrings: scopes, secretDigest: old.secretDigest, createdAt: old.createdAt, lastUsedAt: now, revokedAt: old.revokedAt)
    }
    public func revokeAppPassword(accountDID: String, canonicalName: String, now: Date) async throws {
        guard let old = appPasswords.values.first(where: { $0.accountDID == accountDID && $0.canonicalName == canonicalName && $0.revokedAt == nil }) else { throw SwanError.unauthorized("app password not found") }
        appPasswords[old.id] = try AppPasswordMetadata(id: old.id, accountDID: old.accountDID, canonicalName: old.canonicalName, scopeStrings: old.scopeStrings, secretDigest: old.secretDigest, createdAt: old.createdAt, lastUsedAt: old.lastUsedAt, revokedAt: now)
        for (id, family) in families where family.appPasswordID == old.id {
            families[id] = try LegacySessionFamilyMetadata(familyID: family.familyID, accountDID: family.accountDID, appPasswordID: family.appPasswordID, createdAt: family.createdAt, expiresAt: family.expiresAt, revokedAt: now, reuseDetectedAt: family.reuseDetectedAt)
            for (key, session) in sessions where session.familyID == id && session.revokedAt == nil {
                sessions[key] = try LegacySessionMetadata(sessionID: session.sessionID, familyID: session.familyID, accountDID: session.accountDID, appPasswordID: session.appPasswordID, scopeStrings: session.scopeStrings, issuedAt: session.issuedAt, expiresAt: session.expiresAt, revokedAt: now, rotatedAt: session.rotatedAt, replacedByDigest: session.replacedByDigest, previousSessionDigest: session.previousSessionDigest, reuseDetectedAt: session.reuseDetectedAt)
            }
        }
    }
    public func createLegacySessionFamily(_ family: LegacySessionFamilyMetadata, session: LegacySessionMetadata, sessionDigest: Data, now: Date) async throws { families[family.familyID] = family; sessions[Hex.encode(sessionDigest)] = session }
    public func legacySession(digest: Data, now: Date) async throws -> LegacySessionMetadata? { sessions[Hex.encode(digest)].flatMap { $0.expiresAt > now && $0.revokedAt == nil ? $0 : $0 } }
    public func legacySessionByID(_ id: LegacySessionID, now: Date) async -> LegacySessionMetadata? { sessions.values.first { $0.sessionID == id && $0.expiresAt > now && $0.revokedAt == nil } }
    public func rotateOrRevokeFamilyOnReuse(_ request: LegacySessionRotationRequest) async throws -> LegacySessionRotationOutcome {
        let oldKey = Hex.encode(request.oldDigest)
        guard let old = sessions[oldKey], old.revokedAt == nil, let family = families[old.familyID], family.revokedAt == nil else {
            guard let old = sessions[oldKey] else { throw SwanError.unauthorized("invalid refresh token") }
            let detected = request.now
            let revoked = request.now
            families[old.familyID] = try LegacySessionFamilyMetadata(familyID: old.familyID, accountDID: old.accountDID, appPasswordID: old.appPasswordID, createdAt: old.issuedAt, expiresAt: old.expiresAt, revokedAt: revoked, reuseDetectedAt: detected)
            for (key, session) in sessions where session.familyID == old.familyID {
                sessions[key] = try LegacySessionMetadata(sessionID: session.sessionID, familyID: session.familyID, accountDID: session.accountDID, appPasswordID: session.appPasswordID, scopeStrings: session.scopeStrings, issuedAt: session.issuedAt, expiresAt: session.expiresAt, revokedAt: revoked, rotatedAt: session.rotatedAt, replacedByDigest: session.replacedByDigest, previousSessionDigest: session.previousSessionDigest, reuseDetectedAt: detected)
            }
            return try .reuseDetectedAndFamilyRevoked(familyID: old.familyID, detectedAt: detected, revokedAt: revoked)
        }
        sessions[oldKey] = try LegacySessionMetadata(sessionID: old.sessionID, familyID: old.familyID, accountDID: old.accountDID, appPasswordID: old.appPasswordID, scopeStrings: old.scopeStrings, issuedAt: old.issuedAt, expiresAt: old.expiresAt, revokedAt: request.now, rotatedAt: request.now, replacedByDigest: request.replacementDigest, previousSessionDigest: old.previousSessionDigest, reuseDetectedAt: old.reuseDetectedAt)
        sessions[Hex.encode(request.replacementDigest)] = request.replacement
        return .rotated(sessionID: request.replacement.sessionID)
    }
    public func revokeLegacySessionFamily(familyID: String, now: Date) async throws { guard let family = families[familyID] else { return }; families[familyID] = try LegacySessionFamilyMetadata(familyID: family.familyID, accountDID: family.accountDID, appPasswordID: family.appPasswordID, createdAt: family.createdAt, expiresAt: family.expiresAt, revokedAt: now, reuseDetectedAt: family.reuseDetectedAt); for (key, session) in sessions where session.familyID == familyID { sessions[key] = try LegacySessionMetadata(sessionID: session.sessionID, familyID: session.familyID, accountDID: session.accountDID, appPasswordID: session.appPasswordID, scopeStrings: session.scopeStrings, issuedAt: session.issuedAt, expiresAt: session.expiresAt, revokedAt: now, rotatedAt: session.rotatedAt, replacedByDigest: session.replacedByDigest, previousSessionDigest: session.previousSessionDigest, reuseDetectedAt: session.reuseDetectedAt) } }
    public func purgeExpiredLegacySessions(now: Date) async throws { sessions = sessions.filter { $0.value.expiresAt > now }; families = families.filter { $0.value.expiresAt > now } }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var data = Data(); data.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte); index = next
        }
        self = data
    }
}
