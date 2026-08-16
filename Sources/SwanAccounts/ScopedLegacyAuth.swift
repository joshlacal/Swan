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
    public let email: String?
    public let emailConfirmed: Bool?
    public let emailAuthFactor: Bool?
    public let active: Bool?
    public let status: String?

    public init(did: String, handle: String, passwordVerifier: String? = nil, mfaEnabled: Bool = false, email: String? = nil, emailConfirmed: Bool? = nil, emailAuthFactor: Bool? = nil, active: Bool? = true, status: String? = nil) {
        self.did = did
        self.handle = handle
        self.passwordVerifier = passwordVerifier
        self.mfaEnabled = mfaEnabled
        self.email = email; self.emailConfirmed = emailConfirmed; self.emailAuthFactor = emailAuthFactor; self.active = active; self.status = status
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
    public let email: String?
    public let emailConfirmed: Bool?
    public let emailAuthFactor: Bool?
    public let active: Bool?
    public let status: String?
    public let fullAccess: Bool

    public var accessJwt: String { accessToken }
    public var refreshJwt: String { refreshToken }
}

public struct LegacyServiceAuthToken: Sendable, Equatable {
    public let token: String
    public let subject: String
    public let audience: String
    public let expiresAt: Date
}

public struct LegacyAccessClaims: Sendable, Equatable {
    public let subject: String
    public let sessionID: LegacySessionID
    public let scopes: Set<String>
    public let issuedAt: Date
    public let expiresAt: Date
    public let tokenID: String
    public let grant: LegacyAccessGrant
}

public protocol LegacyTokenIssuer: Sendable {
    func issueAccess(subject: String, sessionID: LegacySessionID, scopes: Set<String>, grant: LegacyAccessGrant, issuedAt: Date, expiresAt: Date) throws -> String
    func verifyAccess(_ token: String, now: Date) throws -> LegacyAccessClaims
    func issueServiceAuth(subject: String, audience: String, method: String, issuedAt: Date, expiresAt: Date) throws -> String
    func verifyServiceAuth(_ token: String, audience: String, method: String, now: Date) throws -> LegacyServiceAuthToken
}

public struct LegacyManagementAuthorizer: Sendable {
    private let body: @Sendable (String, String, String) async throws -> Bool
    public init(authorize: @escaping @Sendable (String, String, String) async throws -> Bool) { self.body = authorize }
    public func authorize(accountDID: String, managementSessionToken: String, stepUpToken: String) async throws {
        guard try await body(accountDID, managementSessionToken, stepUpToken) else { throw SwanError.unauthorized("management step-up required") }
    }
    public func authorizeSession(accountDID: String, managementSessionToken: String) async throws {
        guard try await body(accountDID, managementSessionToken, "") else { throw SwanError.unauthorized("management session required") }
    }
}

public struct LegacyLoginAdmission: Sendable {
    private let body: @Sendable (String) async throws -> Void
    public init(admit: @escaping @Sendable (String) async throws -> Void) { self.body = admit }
    public func admit(identifier: String) async throws { try await body(identifier) }
}

/// Compact signed JWT implementation used by tests and as the narrow adapter
/// contract for the deployment's existing signed-token issuer/verifier.
public struct HMACLegacyTokenIssuer: LegacyTokenIssuer, Sendable {
    private let key: SymmetricKey
    public let issuer: String
    public init(key: Data, issuer: String) throws {
        guard key.count >= 32, !issuer.isEmpty else { throw SwanError.invalidIdentifier("legacy JWT issuer") }
        self.key = SymmetricKey(data: key); self.issuer = issuer
    }
    public func issueAccess(subject: String, sessionID: LegacySessionID, scopes: Set<String>, grant: LegacyAccessGrant, issuedAt: Date, expiresAt: Date) throws -> String {
        try issue(claims: ["kind": "access", "grant": grant.rawValue, "iss": issuer, "sub": subject, "sid": sessionID.rawValue, "scope": scopes.sorted().joined(separator: " "), "iat": Int(issuedAt.timeIntervalSince1970), "exp": Int(expiresAt.timeIntervalSince1970), "jti": Self.randomID()])
    }
    public func verifyAccess(_ token: String, now: Date) throws -> LegacyAccessClaims {
        let payload = try verify(token)
        guard payload["kind"] as? String == "access", let grantValue = payload["grant"] as? String, let grant = LegacyAccessGrant(rawValue: grantValue), payload["iss"] as? String == issuer, payload["aud"] == nil, payload["lxm"] == nil, let sub = payload["sub"] as? String, let sid = payload["sid"] as? String,
              let iat = payload["iat"] as? Int, let exp = payload["exp"] as? Int, let jti = payload["jti"] as? String,
              iat <= Int(now.timeIntervalSince1970), exp > iat, exp > Int(now.timeIntervalSince1970), exp - iat <= Int(LegacyAuthService.accessLifetime), let sessionID = try? LegacySessionID(rawValue: sid), !jti.isEmpty else { throw SwanError.unauthorized("invalid access token") }
        let scopes = Set((payload["scope"] as? String ?? "").split(separator: " ").map(String.init))
        guard LegacyAccessGrant.validateClaims(scopes: scopes, grant: grant),
              scopes.allSatisfy({ (try? SwanScope.parse($0)) != nil }) else { throw SwanError.unauthorized("invalid access grant") }
        return LegacyAccessClaims(subject: sub, sessionID: sessionID, scopes: scopes, issuedAt: Date(timeIntervalSince1970: TimeInterval(iat)), expiresAt: Date(timeIntervalSince1970: TimeInterval(exp)), tokenID: jti, grant: grant)
    }
    public func issueServiceAuth(subject: String, audience: String, method: String, issuedAt: Date, expiresAt: Date) throws -> String {
        try issue(claims: ["kind": "service", "iss": issuer, "sub": subject, "aud": audience, "lxm": method, "iat": Int(issuedAt.timeIntervalSince1970), "exp": Int(expiresAt.timeIntervalSince1970), "jti": Self.randomID()])
    }
    public func verifyServiceAuth(_ token: String, audience: String, method: String, now: Date) throws -> LegacyServiceAuthToken {
        let payload = try verify(token)
        guard payload["kind"] as? String == "service", payload["iss"] as? String == issuer, payload["aud"] as? String == audience, payload["lxm"] as? String == method,
              let subject = payload["sub"] as? String, let iat = payload["iat"] as? Int, let exp = payload["exp"] as? Int,
              let jti = payload["jti"] as? String, !jti.isEmpty, exp > iat, exp - iat <= 60, exp > Int(now.timeIntervalSince1970), iat <= Int(now.timeIntervalSince1970) else { throw SwanError.unauthorized("invalid service JWT") }
        return LegacyServiceAuthToken(token: token, subject: subject, audience: audience, expiresAt: Date(timeIntervalSince1970: TimeInterval(exp)))
    }
    private func issue(claims: [String: Any]) throws -> String {
        let header = try Self.encode(["alg": "HS256", "typ": "JWT"])
        let body = try Self.encode(claims)
        let signing = header + "." + body
        let signature = Data(HMAC<SHA256>.authenticationCode(for: Data(signing.utf8), using: key)).base64URLSafe
        return signing + "." + signature
    }
    private func verify(_ token: String) throws -> [String: Any] {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, let headerData = Data(base64URLSafe: parts[0]), let header = try JSONSerialization.jsonObject(with: headerData) as? [String: Any], header.count == 2, header["alg"] as? String == "HS256", header["typ"] as? String == "JWT", let payloadData = Data(base64URLSafe: parts[1]), let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else { throw SwanError.unauthorized("invalid JWT") }
        let expected = Data(HMAC<SHA256>.authenticationCode(for: Data((parts[0] + "." + parts[1]).utf8), using: key)).base64URLSafe
        guard Self.constantTime(parts[2], expected) else { throw SwanError.unauthorized("invalid JWT") }
        return payload
    }
    private static func encode(_ value: [String: Any]) throws -> String { try JSONSerialization.data(withJSONObject: value).base64URLSafe }
    private static func randomID() -> String { Data((0..<16).map { _ in UInt8.random(in: .min ... .max) }).base64URLSafe }
    private static func constantTime(_ lhs: String, _ rhs: String) -> Bool { lhs.utf8.count == rhs.utf8.count && zip(lhs.utf8, rhs.utf8).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0 }
}

public actor LegacyAuthService {
    public static let accessLifetime: TimeInterval = 3_600
    public static let refreshLifetime: TimeInterval = 90 * 24 * 3_600
    public static let serviceAuthLifetime: TimeInterval = 60

    private let store: any AppPasswordStore & LegacySessionStore
    private let accountResolver: LegacyAccountResolver
    private let tokenIssuer: any LegacyTokenIssuer
    private let managementAuthorizer: LegacyManagementAuthorizer
    private let loginAdmission: LegacyLoginAdmission
    private let methodPolicy: DeclaredMethodScopePolicy
    private let secretKey: SymmetricKey

    public init(
        store: any AppPasswordStore & LegacySessionStore,
        accountResolver: LegacyAccountResolver,
        secretKey: Data,
        tokenIssuer: any LegacyTokenIssuer,
        managementAuthorizer: LegacyManagementAuthorizer,
        loginAdmission: LegacyLoginAdmission,
        methodPolicy: DeclaredMethodScopePolicy = .referenceLegacy
    ) throws {
        guard secretKey.count >= 16 else { throw SwanError.invalidIdentifier("legacy auth secret key") }
        self.store = store
        self.accountResolver = accountResolver
        self.tokenIssuer = tokenIssuer
        self.managementAuthorizer = managementAuthorizer
        self.loginAdmission = loginAdmission
        self.methodPolicy = methodPolicy
        self.secretKey = SymmetricKey(data: secretKey)
    }

    public func createAppPassword(accountDID: String, name: String, scopes: Set<String>, managementSessionToken: String? = nil, stepUpToken: String? = nil, now: Date = Date()) async throws -> AppPasswordPresentation {
        guard let managementSessionToken, let stepUpToken else { throw SwanError.unauthorized("management step-up required") }
        try await managementAuthorizer.authorize(accountDID: accountDID, managementSessionToken: managementSessionToken, stepUpToken: stepUpToken)
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

    public func listAppPasswords(accountDID: String, managementSessionToken: String? = nil, stepUpToken: String? = nil, now: Date = Date()) async throws -> [PublicAppPasswordMetadata] {
        guard let managementSessionToken else { throw SwanError.unauthorized("management session required") }
        try await managementAuthorizer.authorizeSession(accountDID: accountDID, managementSessionToken: managementSessionToken)
        try await store.listAppPasswords(accountDID: accountDID, now: now).map(PublicAppPasswordMetadata.init(metadata:))
    }

    public func updateAppPasswordScopes(accountDID: String, name: String, scopes: Set<String>, managementSessionToken: String? = nil, stepUpToken: String? = nil, now: Date = Date()) async throws {
        guard let managementSessionToken, let stepUpToken else { throw SwanError.unauthorized("management step-up required") }
        try await managementAuthorizer.authorize(accountDID: accountDID, managementSessionToken: managementSessionToken, stepUpToken: stepUpToken)
        try await store.updateAppPasswordScopes(accountDID: accountDID, canonicalName: Self.canonicalName(name), scopes: Self.canonicalScopes(scopes, permitFullAccess: false), now: now)
    }

    public func revokeAppPassword(accountDID: String, name: String, managementSessionToken: String? = nil, stepUpToken: String? = nil, now: Date = Date()) async throws {
        guard let managementSessionToken, let stepUpToken else { throw SwanError.unauthorized("management step-up required") }
        try await managementAuthorizer.authorize(accountDID: accountDID, managementSessionToken: managementSessionToken, stepUpToken: stepUpToken)
        try await store.revokeAppPassword(accountDID: accountDID, canonicalName: Self.canonicalName(name), now: now)
    }

    public func createSession(identifier: String, password: String, authFactorToken: String? = nil, now: Date = Date()) async throws -> LegacySessionTokens {
        try await loginAdmission.admit(identifier: identifier)
        guard !password.isEmpty else { throw SwanError.unauthorized("invalid identifier or password") }
        guard let account = try await accountResolver.resolve(identifier) else {
            throw SwanError.unauthorized("invalid identifier or password")
        }
        guard account.active != false, !["suspended", "deactivated", "takedown"].contains(account.status?.lowercased()) else {
            throw SwanError.unauthorized("account unavailable")
        }
        let passwords = try await store.listAppPasswords(accountDID: account.did, now: now)
        for app in passwords where app.revokedAt == nil {
            if try verifySecret(password, encoded: app.secretDigest) {
                return try await issueSession(account: account, appPassword: app, now: now)
            }
        }
        guard try await accountResolver.verifyPassword(account, password: password, authFactorToken: authFactorToken) else {
            throw SwanError.unauthorized("invalid identifier or password")
        }
        // Password sessions are deliberately not full-access. The reference
        // server's legacy compatibility grant is represented explicitly and
        // can never be produced by app-password input.
        let sessionScopes: Set<String> = [LegacyAccessGrant.fullAccessMarker]
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
        let replacementID = try LegacySessionID(digest: digest(refresh))
        let replacement = try LegacySessionMetadata.validatedGrant(
            newScopes, sessionID: replacementID, familyID: old.familyID, accountDID: old.accountDID,
            appPasswordID: old.appPasswordID, issuedAt: now,
            // Family expiry is absolute; refresh never slides it forward.
            expiresAt: old.expiresAt, previousSessionDigest: oldDigest
        )
        let outcome = try await store.rotateOrRevokeFamilyOnReuse(try LegacySessionRotationRequest(
            oldDigest: oldDigest, replacement: replacement, replacementDigest: digest(refresh), now: now
        ))
        guard case .rotated = outcome.kind else {
            throw SwanError.unauthorized("refresh token reuse detected")
        }
        let grant: LegacyAccessGrant = newScopes == [LegacyAccessGrant.fullAccessMarker] ? .fullAccessV1 : .scoped
        let access = try tokenIssuer.issueAccess(subject: old.accountDID, sessionID: replacementID, scopes: grant == .fullAccessV1 ? [] : newScopes, grant: grant, issuedAt: now, expiresAt: now.addingTimeInterval(Self.accessLifetime))
        return try await makeTokens(access: access, refresh: refresh, session: replacement)
    }

    public func getSession(_ accessToken: String, now: Date = Date()) async throws -> LegacySessionTokens {
        let claims = try tokenIssuer.verifyAccess(accessToken, now: now)
        guard let digest = Data(hex: claims.sessionID.rawValue),
              let session = try await store.legacySession(digest: digest, now: now),
              session.accountDID == claims.subject,
              (session.scopeStrings.contains(LegacyAccessGrant.fullAccessMarker) ? .fullAccessV1 : .scoped) == claims.grant,
              LegacyAccessGrant.validateClaims(scopes: claims.scopes, grant: claims.grant),
              LegacyAccessGrant.validateStoredSession(scopes: session.scopeStrings, grant: claims.grant),
              (claims.grant == .fullAccessV1 ? session.scopeStrings == [LegacyAccessGrant.fullAccessMarker] : claims.scopes == session.scopeStrings),
              session.revokedAt == nil, session.expiresAt > now else {
            throw SwanError.unauthorized("invalid access token")
        }
        return try await makeTokens(access: accessToken, refresh: "", session: session)
    }

    public func deleteSession(_ accessToken: String, now: Date = Date()) async throws {
        let claims = try tokenIssuer.verifyAccess(accessToken, now: now)
        guard let digest = Data(hex: claims.sessionID.rawValue),
              let session = try await store.legacySession(digest: digest, now: now),
              session.accountDID == claims.subject,
              (session.scopeStrings.contains(LegacyAccessGrant.fullAccessMarker) ? .fullAccessV1 : .scoped) == claims.grant,
              LegacyAccessGrant.validateClaims(scopes: claims.scopes, grant: claims.grant),
              LegacyAccessGrant.validateStoredSession(scopes: session.scopeStrings, grant: claims.grant),
              (claims.grant == .fullAccessV1 ? session.scopeStrings == [LegacyAccessGrant.fullAccessMarker] : claims.scopes == session.scopeStrings),
              session.revokedAt == nil, session.expiresAt > now else {
            throw SwanError.unauthorized("invalid access token")
        }
        try await store.revokeLegacySessionFamily(familyID: session.familyID, now: now)
    }

    public func getServiceAuth(accessToken: String, lxm: String?, aud: String?, requestedExpiry: Date? = nil, now: Date = Date()) async throws -> LegacyServiceAuthToken {
        guard let lxm, let aud else { throw SwanError.unauthorized("lxm and aud are required") }
        let session = try await getSession(accessToken, now: now)
        let isFull = session.fullAccess
        try SwanScopeEvaluator().evaluate(credential: isFull ? .fullAccessV1 : .scopes(session.scopes), canonicalMethod: lxm, declaredMethodPolicy: methodPolicy, audience: aud)
        let issuedEpoch = floor(now.timeIntervalSince1970)
        let expiryEpoch = requestedExpiry.map { floor($0.timeIntervalSince1970) } ?? (issuedEpoch + Self.serviceAuthLifetime)
        guard expiryEpoch > issuedEpoch, expiryEpoch <= issuedEpoch + Self.serviceAuthLifetime else {
            throw SwanError.unauthorized("invalid service auth expiry")
        }
        let issuedAt = Date(timeIntervalSince1970: issuedEpoch)
        let expiry = Date(timeIntervalSince1970: expiryEpoch)
        return LegacyServiceAuthToken(token: try tokenIssuer.issueServiceAuth(subject: session.did, audience: aud, method: lxm, issuedAt: issuedAt, expiresAt: expiry), subject: session.did, audience: aud, expiresAt: expiry)
    }

    private func issueSession(account: LegacyAccountRecord, appPassword: AppPasswordMetadata?, scopes: Set<String>? = nil, now: Date) async throws -> LegacySessionTokens {
        let familyID = Self.randomIdentifier()
        let refresh = Self.randomToken(prefix: "rf")
        let sessionID = try LegacySessionID(digest: digest(refresh))
        let sessionScopes = scopes ?? appPassword?.scopeStrings ?? []
        let session = try LegacySessionMetadata.validatedGrant(sessionScopes, sessionID: sessionID, familyID: familyID, accountDID: account.did, appPasswordID: appPassword?.id, issuedAt: now, expiresAt: now.addingTimeInterval(Self.refreshLifetime))
        let family = try LegacySessionFamilyMetadata(familyID: familyID, accountDID: account.did, appPasswordID: appPassword?.id, createdAt: now, expiresAt: session.expiresAt)
        if let appPassword {
            try await store.createLegacySessionFromAppPassword(appPassword, family: family, session: session, sessionDigest: digest(refresh), now: now)
        } else {
            try await store.createLegacySessionFamily(family, session: session, sessionDigest: digest(refresh), now: now)
        }
        let grant: LegacyAccessGrant = session.scopeStrings == [LegacyAccessGrant.fullAccessMarker] ? .fullAccessV1 : .scoped
        let access = try tokenIssuer.issueAccess(subject: account.did, sessionID: sessionID, scopes: grant == .fullAccessV1 ? [] : session.scopeStrings, grant: grant, issuedAt: now, expiresAt: now.addingTimeInterval(Self.accessLifetime))
        let fullAccess = session.scopeStrings.contains(LegacyAccessGrant.fullAccessMarker)
        return LegacySessionTokens(accessToken: access, refreshToken: refresh, did: account.did, handle: account.handle, scopes: fullAccess ? [] : session.scopeStrings, sessionID: sessionID, email: account.email, emailConfirmed: account.emailConfirmed, emailAuthFactor: account.emailAuthFactor, active: account.active, status: account.status, fullAccess: fullAccess)
    }

    private func makeTokens(access: String, refresh: String, session: LegacySessionMetadata) async throws -> LegacySessionTokens {
        guard let account = try await accountResolver.resolve(session.accountDID) else { throw SwanError.unauthorized("account unavailable") }
        let fullAccess = session.scopeStrings.contains(LegacyAccessGrant.fullAccessMarker)
        return LegacySessionTokens(accessToken: access, refreshToken: refresh, did: account.did, handle: account.handle, scopes: fullAccess ? [] : session.scopeStrings, sessionID: session.sessionID, email: account.email, emailConfirmed: account.emailConfirmed, emailAuthFactor: account.emailAuthFactor, active: account.active, status: account.status, fullAccess: fullAccess)
    }

    private func digest(_ token: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(token.utf8), using: secretKey))
    }

    /// The fixed-width schema stores a version byte, random salt, and Argon2id
    /// digest. The salt is per secret; no raw credential or reusable digest is
    /// persisted.
    private func secretDigest(_ secret: String, accountDID: String) throws -> Data {
        guard Self.sodiumInitializationResult >= 0 else {
            throw SwanError.unavailable("libsodium initialization failed")
        }
        _ = accountDID
        let outputLength = 15
        var output = [UInt8](repeating: 0, count: outputLength)
        let salt = Self.randomBytes(count: Int(crypto_pwhash_SALTBYTES))
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
        return Data([1]) + salt + Data(output)
    }

    private func verifySecret(_ secret: String, encoded: Data) throws -> Bool {
        guard encoded.count == 32, encoded[0] == 1 else { return false }
        let salt = encoded[1..<17]
        let expected = encoded[17...]
        var output = [UInt8](repeating: 0, count: expected.count)
        let passwordBytes = secret.utf8CString
        let result = passwordBytes.withUnsafeBufferPointer { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                guard let saltBase = saltBuffer.baseAddress else { return -1 }
                return crypto_pwhash(
                    &output, UInt64(output.count), passwordBuffer.baseAddress!,
                    UInt64(passwordBuffer.count - 1), saltBase.assumingMemoryBound(to: UInt8.self),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13
                )
            }
        }
        guard result == 0 else { throw SwanError.unavailable("Argon2id app-password verification failed") }
        return constantTimeEqual(Data(output), Data(expected))
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

    private static func randomIdentifier() -> String { randomBytes(count: 32).map { String(format: "%02x", $0) }.joined() }
    private static func randomToken(prefix: String) -> String { "\(prefix)-" + randomBytes(count: 32).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    private static func randomBytes(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: UInt8.min...UInt8.max, using: &generator) })
    }
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
        for (id, family) in families where family.appPasswordID == old.id && family.revokedAt == nil {
            families[id] = try LegacySessionFamilyMetadata(familyID: family.familyID, accountDID: family.accountDID, appPasswordID: family.appPasswordID, createdAt: family.createdAt, expiresAt: family.expiresAt, revokedAt: now, reuseDetectedAt: family.reuseDetectedAt)
            for (key, session) in sessions where session.familyID == id && session.revokedAt == nil {
                sessions[key] = try LegacySessionMetadata(sessionID: session.sessionID, familyID: session.familyID, accountDID: session.accountDID, appPasswordID: session.appPasswordID, scopeStrings: session.scopeStrings, issuedAt: session.issuedAt, expiresAt: session.expiresAt, revokedAt: now, rotatedAt: session.rotatedAt, replacedByDigest: session.replacedByDigest, previousSessionDigest: session.previousSessionDigest, reuseDetectedAt: session.reuseDetectedAt)
            }
        }
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
    public func markAppPasswordUsed(id: String, now: Date) async throws {
        guard let old = appPasswords[id], old.revokedAt == nil else { return }
        appPasswords[id] = try AppPasswordMetadata(id: old.id, accountDID: old.accountDID, canonicalName: old.canonicalName, scopeStrings: old.scopeStrings, secretDigest: old.secretDigest, createdAt: old.createdAt, lastUsedAt: now, revokedAt: old.revokedAt)
    }
    public func createLegacySessionFromAppPassword(_ metadata: AppPasswordMetadata, family: LegacySessionFamilyMetadata, session: LegacySessionMetadata, sessionDigest: Data, now: Date) async throws {
        guard let current = appPasswords[metadata.id], current.revokedAt == nil, current.scopeStrings == metadata.scopeStrings else { throw SwanError.unauthorized("app password changed or revoked") }
        appPasswords[metadata.id] = try AppPasswordMetadata(id: current.id, accountDID: current.accountDID, canonicalName: current.canonicalName, scopeStrings: current.scopeStrings, secretDigest: current.secretDigest, createdAt: current.createdAt, lastUsedAt: now, revokedAt: current.revokedAt)
        families[family.familyID] = family; sessions[Hex.encode(sessionDigest)] = session
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
    var base64URLSafe: String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init?(base64URLSafe value: String) {
        var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        text += String(repeating: "=", count: (4 - text.count % 4) % 4)
        self.init(base64Encoded: text)
    }
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
