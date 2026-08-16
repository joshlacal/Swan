import Crypto
import Foundation
import SwanCore
import SwanStorage

public enum MFAError: Error, Equatable, Sendable {
    case invalidCode
    case replay
    case expired
    case invalidEnvelope
    case invalidChallenge
    case invalidOrigin
    case invalidRelyingParty
    case invalidClientData
    case invalidAuthenticatorData
    case invalidSignature
    case credentialNotFound
    case counterRollback
    case tokenInvalid
    case stepUpRequired
}

public enum TOTPAlgorithm: String, Sendable, Codable { case sha1, sha256, sha512 }

public struct TOTPConfiguration: Sendable, Equatable {
    public let period: TimeInterval
    public let digits: Int
    public let algorithm: TOTPAlgorithm
    public let drift: Int

    public init(period: TimeInterval = 30, digits: Int = 6, algorithm: TOTPAlgorithm = .sha1, drift: Int = 1) {
        precondition(period > 0 && (digits == 6 || digits == 8) && drift >= 0)
        self.period = period; self.digits = digits; self.algorithm = algorithm; self.drift = drift
    }
}

public protocol TOTPEnvelopeKeyStore: Sendable {
    func key(reference: String) async throws -> Data?
}

public enum TOTPEnvelopeCrypto {
    public static func seal(secret: Data, factorID: String, keyReference: String, key: Data) throws -> TOTPSecretEnvelope {
        guard key.count == 32, !secret.isEmpty else { throw MFAError.invalidEnvelope }
        let nonceData = randomBytes(count: 12)
        let sealed = try AES.GCM.seal(secret, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonceData), authenticating: Data(factorID.utf8))
        return try TOTPSecretEnvelope(factorID: factorID, keyReference: keyReference, nonce: nonceData, ciphertext: sealed.ciphertext, authenticationTag: sealed.tag)
    }

    public static func open(_ envelope: TOTPSecretEnvelope, key: Data) throws -> Data {
        guard key.count == 32 else { throw MFAError.invalidEnvelope }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: envelope.nonce), ciphertext: envelope.ciphertext, tag: envelope.authenticationTag)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: Data(envelope.factorID.utf8))
    }
}

public enum TOTPAuthenticator {
    public static func decodeBase32(_ value: String) throws -> Data {
        let normalized = value.replacingOccurrences(of: "=", with: "").replacingOccurrences(of: " ", with: "").uppercased()
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var output: [UInt8] = []; var buffer = 0; var bits = 0
        for character in normalized {
            guard let index = alphabet.firstIndex(of: character) else { throw MFAError.invalidCode }
            buffer = (buffer << 5) | index; bits += 5
            if bits >= 8 { bits -= 8; output.append(UInt8((buffer >> bits) & 0xff)) }
        }
        guard bits < 5, (bits == 0 || (buffer & ((1 << bits) - 1)) == 0) else { throw MFAError.invalidCode }
        return Data(output)
    }

    public static func code(secret: Data, counter: UInt64, configuration: TOTPConfiguration = TOTPConfiguration()) throws -> String {
        guard !secret.isEmpty else { throw MFAError.invalidCode }
        var moving = counter.bigEndian
        let message = withUnsafeBytes(of: &moving) { Data($0) }
        let digest: [UInt8]
        switch configuration.algorithm {
        case .sha1: digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        case .sha256: digest = Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        case .sha512: digest = Array(HMAC<SHA512>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        }
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset]) & 0x7f) << 24 | UInt32(digest[offset + 1]) << 16 | UInt32(digest[offset + 2]) << 8 | UInt32(digest[offset + 3])
        let modulus: UInt32 = configuration.digits == 8 ? 100_000_000 : 1_000_000
        return String(format: "%0*u", configuration.digits, binary % modulus)
    }

    public static func verify(code presented: String, secret: Data, at date: Date, configuration: TOTPConfiguration = TOTPConfiguration()) throws -> UInt64? {
        guard presented.utf8.count == configuration.digits, presented.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
        let counter = UInt64(max(0, floor(date.timeIntervalSince1970 / configuration.period)))
        for delta in -configuration.drift ... configuration.drift {
            let candidate = delta < 0 && UInt64(-delta) > counter ? nil : UInt64(Int64(counter) + Int64(delta))
            if let candidate, constantTimeEqual(Data(try code(secret: secret, counter: candidate, configuration: configuration).utf8), Data(presented.utf8)) { return candidate }
        }
        return nil
    }
}

public actor TOTPReplayGuard {
    private var accepted: [String: UInt64] = [:]
    private let configuration: TOTPConfiguration
    public init(configuration: TOTPConfiguration = TOTPConfiguration()) { self.configuration = configuration }

    public func accept(factorID: String, code: String, secret: Data, at date: Date) throws -> Bool {
        guard let counter = try TOTPAuthenticator.verify(code: code, secret: secret, at: date, configuration: configuration) else { return false }
        if let previous = accepted[factorID], counter <= previous { return false }
        accepted[factorID] = counter
        return true
    }
}

/// Coordinates external-key envelope opening with the replay guard. The
/// control database sees only ``TOTPSecretEnvelope``; plaintext seeds remain
/// inside this service call and are never handed to a storage adapter.
public struct TOTPFactorService: Sendable {
    private let keyStore: any TOTPEnvelopeKeyStore
    private let replayGuard: TOTPReplayGuard
    private let configuration: TOTPConfiguration

    public init(keyStore: any TOTPEnvelopeKeyStore, replayGuard: TOTPReplayGuard = TOTPReplayGuard(), configuration: TOTPConfiguration = TOTPConfiguration()) {
        self.keyStore = keyStore
        self.replayGuard = replayGuard
        self.configuration = configuration
    }

    public func verify(envelope: TOTPSecretEnvelope, factorID: String, code: String, at date: Date) async throws -> Bool {
        guard envelope.factorID == factorID, let key = try await keyStore.key(reference: envelope.keyReference) else { throw MFAError.invalidEnvelope }
        let secret = try TOTPEnvelopeCrypto.open(envelope, key: key)
        return try await replayGuard.accept(factorID: factorID, code: code, secret: secret, at: date)
    }
}

public struct RecoveryCodeService: Sendable {
    public static let defaultCount = 10
    private let store: any RecoveryCodeStore
    public init(store: any RecoveryCodeStore) { self.store = store }

    public func replace(accountDID: String, count: Int = defaultCount, now: Date) async throws -> [String] {
        guard (1 ... 32).contains(count) else { throw MFAError.invalidCode }
        let codes = (0 ..< count).map { _ in Self.recoveryCode() }
        let digests = try codes.map { try RecoveryCodeDigest(accountDID: accountDID, digest: Self.digest($0), issuedAt: now) }
        try await store.replaceRecoveryCodeDigests(accountDID: accountDID, digests: digests, now: now)
        return codes
    }

    public func consume(_ code: String, accountDID: String, now: Date) async throws -> Bool {
        do { _ = try await store.consumeRecoveryCode(digest: Self.digest(code), accountDID: accountDID, now: now); return true }
        catch { return false }
    }

    public static func digest(_ code: String) -> Data { Data(SHA256.hash(data: Data(("swan-recovery-v1:" + code.uppercased()).utf8))) }
    private static func recoveryCode() -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        return String((0 ..< 24).map { _ in alphabet[Int.random(in: 0 ..< alphabet.count)] })
    }
}

public enum FactorTokenPurpose: String, Sendable, Codable { case stepUp, managementLogin, oauthToken }
public struct IssuedFactorToken: Sendable, Equatable { public let token: String; public let expiresAt: Date; public let factor: AuthenticationFactorKind }
private struct FactorTokenRecord: Sendable { let digest: Data; let accountDID: String; let purpose: FactorTokenPurpose; let factor: AuthenticationFactorKind; let expiresAt: Date }

public actor FactorTokenService {
    private var records: [Data: FactorTokenRecord] = [:]
    public init() {}
    public func issue(accountDID: String, purpose: FactorTokenPurpose, factor: AuthenticationFactorKind, now: Date, lifetime: TimeInterval = 120) throws -> IssuedFactorToken {
        guard lifetime > 0 && lifetime <= 600 else { throw MFAError.tokenInvalid }
        let token = randomBytes(count: 32).base64URLEncodedString(); let digest = Data(SHA256.hash(data: Data(token.utf8)))
        let expires = now.addingTimeInterval(lifetime)
        records[digest] = FactorTokenRecord(digest: digest, accountDID: accountDID, purpose: purpose, factor: factor, expiresAt: expires)
        return IssuedFactorToken(token: token, expiresAt: expires, factor: factor)
    }
    public func consume(_ token: String, accountDID: String, purpose: FactorTokenPurpose, factor: AuthenticationFactorKind, now: Date) throws -> Bool {
        let digest = Data(SHA256.hash(data: Data(token.utf8)))
        guard let record = records[digest], record.accountDID == accountDID, record.purpose == purpose, record.factor == factor, now < record.expiresAt else { throw MFAError.tokenInvalid }
        records.removeValue(forKey: digest)
        return true
    }
}

public enum SensitiveAccountOperation: String, CaseIterable, Sendable { case emailChange, passwordChange, handleChange, identityChange, factorChange, appPassword, export, migration, connectedAppRevocation, deleteAccount, sessionRevocation }
public struct StepUpPolicy: Sendable {
    public let maximumAge: TimeInterval
    public init(maximumAge: TimeInterval = 600) { self.maximumAge = maximumAge }
    public func authorize(_ operation: SensitiveAccountOperation, strength: AuthenticationStrength, mfaEnabled: Bool, now: Date) throws {
        let verifiedAt: Date?; let hasMFA: Bool
        switch strength {
        case let .stepUpPassword(date): verifiedAt = date; hasMFA = false
        case let .stepUpMFA(_, date): verifiedAt = date; hasMFA = true
        default: verifiedAt = nil; hasMFA = false
        }
        guard let verifiedAt, now.timeIntervalSince(verifiedAt) >= 0, now.timeIntervalSince(verifiedAt) <= maximumAge else { throw MFAError.stepUpRequired }
        guard !mfaEnabled || hasMFA else { throw MFAError.stepUpRequired }
        _ = operation
    }
}

/// The MFA audit surface intentionally carries only bounded identifiers and
/// outcomes. Raw TOTP codes, recovery codes, challenges, signatures, and
/// factor bearer tokens are never accepted by this type.
public enum MFAAuditEventKind: String, Codable, Sendable, CaseIterable {
    case factorEnrolled
    case factorDisabled
    case totpAccepted
    case recoveryCodeAccepted
    case passkeyAccepted
    case stepUpAccepted
    case authenticationRejected
}

public struct MFAAuditEvent: Codable, Equatable, Sendable {
    public let kind: MFAAuditEventKind
    public let accountDID: String
    public let factor: AuthenticationFactorKind?
    public let success: Bool
    public let occurredAt: Date

    public init(kind: MFAAuditEventKind, accountDID: String, factor: AuthenticationFactorKind? = nil, success: Bool, occurredAt: Date) throws {
        guard !accountDID.isEmpty else { throw MFAError.invalidEnvelope }
        self.kind = kind
        self.accountDID = accountDID
        self.factor = factor
        self.success = success
        self.occurredAt = occurredAt
    }
}

/// An in-process bounded sink is suitable for wiring to the account audit
/// adapter. It prevents an authentication storm from growing memory without
/// bound while retaining the newest security decisions.
public actor MFAAuditLog {
    public let capacity: Int
    private var events: [MFAAuditEvent] = []

    public init(capacity: Int = 256) {
        self.capacity = max(1, capacity)
    }

    public func append(_ event: MFAAuditEvent) {
        events.append(event)
        if events.count > capacity { events.removeFirst(events.count - capacity) }
    }

    public func snapshot() -> [MFAAuditEvent] { events }
}

public struct WebAuthnAssertion: Sendable, Equatable {
    public let credentialID: Data
    public let clientDataJSON: Data
    public let authenticatorData: Data
    public let signature: Data
    public let userHandle: Data?
    public init(credentialID: Data, clientDataJSON: Data, authenticatorData: Data, signature: Data, userHandle: Data? = nil) { self.credentialID = credentialID; self.clientDataJSON = clientDataJSON; self.authenticatorData = authenticatorData; self.signature = signature; self.userHandle = userHandle }
}

public protocol WebAuthnPublicKeyStore: Sendable { func publicKey(reference: String) async throws -> P256.Signing.PublicKey? }
public struct WebAuthnVerificationResult: Sendable, Equatable { public let accountDID: String; public let newSignCount: UInt32 }

public struct WebAuthnVerifier: Sendable {
    private let keyStore: any WebAuthnPublicKeyStore
    private let credentialStore: any WebAuthnCredentialStore
    private let challengeStore: any WebAuthnChallengeStore
    private let configuredRelyingPartyID: String?
    private let configuredOrigin: String?
    public init(keyStore: any WebAuthnPublicKeyStore, credentialStore: any WebAuthnCredentialStore, challengeStore: any WebAuthnChallengeStore, relyingPartyID: String? = nil, origin: String? = nil) {
        self.keyStore = keyStore
        self.credentialStore = credentialStore
        self.challengeStore = challengeStore
        self.configuredRelyingPartyID = relyingPartyID
        self.configuredOrigin = origin
    }

    public func verify(assertion: WebAuthnAssertion, accountDID: String, challenge: Data, now: Date) async throws -> WebAuthnVerificationResult {
        let credentialDigest = Data(SHA256.hash(data: assertion.credentialID))
        guard let credential = try await credentialStore.webAuthnCredential(credentialIDDigest: credentialDigest, accountDID: accountDID, now: now), credential.disabledAt == nil else { throw MFAError.credentialNotFound }
        let challengeDigest = Data(SHA256.hash(data: challenge))
        let challengeRecord: WebAuthnChallenge
        do { challengeRecord = try await challengeStore.consumeWebAuthnChallenge(digest: challengeDigest, accountDID: accountDID, now: now) } catch { throw MFAError.invalidChallenge }
        guard now >= challengeRecord.issuedAt && now < challengeRecord.expiresAt,
              challengeRecord.credentialIDDigest == nil || challengeRecord.credentialIDDigest == credentialDigest else { throw MFAError.invalidChallenge }
        let expectedOrigin = configuredOrigin ?? challengeRecord.origin
        let expectedRelyingPartyID = configuredRelyingPartyID ?? challengeRecord.relyingPartyID
        guard expectedOrigin == challengeRecord.origin, expectedOrigin.hasPrefix("https://") else { throw MFAError.invalidOrigin }
        guard let json = try? JSONDecoder().decode(ClientData.self, from: assertion.clientDataJSON), json.type == "webauthn.get", json.origin == expectedOrigin, let receivedChallenge = Data(base64URLEncoded: json.challenge), constantTimeEqual(receivedChallenge, challenge) else { throw MFAError.invalidClientData }
        guard assertion.authenticatorData.count >= 37 else { throw MFAError.invalidAuthenticatorData }
        guard constantTimeEqual(Data(assertion.authenticatorData.prefix(32)), Data(SHA256.hash(data: Data(expectedRelyingPartyID.utf8)))) else { throw MFAError.invalidRelyingParty }
        let flags = assertion.authenticatorData[32]; guard flags & 0x01 != 0, flags & 0x04 != 0 else { throw MFAError.invalidAuthenticatorData }
        let count = assertion.authenticatorData[33 ..< 37].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard let key = try await keyStore.publicKey(reference: credential.publicKeyReference), let signature = try? P256WireSignature.decodeCanonical(assertion.signature), key.isValidSignature(signature, for: assertion.authenticatorData + Data(SHA256.hash(data: assertion.clientDataJSON))) else { throw MFAError.invalidSignature }
        // A zero counter is explicitly supported by WebAuthn. There is no
        // monotonic signal to CAS in that mode, so the one-time challenge is
        // the replay boundary until an authenticator reports a positive count.
        if count == 0 && credential.signCount == 0 {
            return WebAuthnVerificationResult(accountDID: accountDID, newSignCount: 0)
        }
        guard count > credential.signCount else { throw MFAError.counterRollback }
        switch try await credentialStore.compareAndSwapWebAuthnSignCount(try WebAuthnSignCountUpdate(credentialIDDigest: credentialDigest, accountDID: accountDID, expectedCurrent: credential.signCount, proposed: count, now: now)) {
        case let .updated(newCount): return WebAuthnVerificationResult(accountDID: accountDID, newSignCount: newCount)
        case .rollbackDetected: throw MFAError.counterRollback
        }
    }
    private struct ClientData: Decodable { let type: String; let challenge: String; let origin: String }
}

/// Registration accepts only the ES256/P-256 credential form used by this
/// service. Attestation is deliberately not required in v1; the authenticator
/// data still binds the credential to the configured RP and requires UP+UV.
public struct WebAuthnRegistrationResult: Sendable, Equatable {
    public let credentialIDDigest: Data
    public let publicKey: P256.Signing.PublicKey
    public let signCount: UInt32

    public static func == (lhs: WebAuthnRegistrationResult, rhs: WebAuthnRegistrationResult) -> Bool {
        lhs.credentialIDDigest == rhs.credentialIDDigest && lhs.publicKey.x963Representation == rhs.publicKey.x963Representation && lhs.signCount == rhs.signCount
    }
}

public enum WebAuthnRegistrationVerifier {
    public static func verify(credentialID: Data, authenticatorData: Data, publicKeyX963: Data, relyingPartyID: String) throws -> WebAuthnRegistrationResult {
        guard !credentialID.isEmpty, !relyingPartyID.isEmpty, authenticatorData.count >= 37 else { throw MFAError.invalidAuthenticatorData }
        guard constantTimeEqual(Data(authenticatorData.prefix(32)), Data(SHA256.hash(data: Data(relyingPartyID.utf8)))) else { throw MFAError.invalidRelyingParty }
        let flags = authenticatorData[32]
        guard flags & 0x01 != 0, flags & 0x04 != 0 else { throw MFAError.invalidAuthenticatorData }
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyX963) else { throw MFAError.invalidSignature }
        let signCount = authenticatorData[33 ..< 37].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return WebAuthnRegistrationResult(credentialIDDigest: Data(SHA256.hash(data: credentialID)), publicKey: publicKey, signCount: signCount)
    }
}

private func randomBytes(count: Int) -> Data { var generator = SystemRandomNumberGenerator(); return Data((0 ..< count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }) }
private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool { guard lhs.count == rhs.count else { return false }; var result: UInt8 = 0; for (a, b) in zip(lhs, rhs) { result |= a ^ b }; return result == 0 }
private extension Data {
    func base64URLEncodedString() -> String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init?(base64URLEncoded value: String) { var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"); text += String(repeating: "=", count: (4 - text.count % 4) % 4); self.init(base64Encoded: text) }
}
