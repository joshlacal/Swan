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
    case storageUnavailable
}

public enum TOTPAlgorithm: String, Sendable, Codable { case sha1, sha256, sha512 }

public struct TOTPConfiguration: Sendable, Equatable {
    public let period: TimeInterval
    public let digits: Int
    public let algorithm: TOTPAlgorithm
    public let drift: Int

    public init(period: TimeInterval = 30, digits: Int = 6, algorithm: TOTPAlgorithm = .sha1, drift: Int = 1) {
        precondition(period.isFinite && period > 0 && period <= 300 && (digits == 6 || digits == 8) && drift >= 0 && drift <= 2)
        self.period = period; self.digits = digits; self.algorithm = algorithm; self.drift = drift
    }
}

public protocol TOTPEnvelopeKeyStore: Sendable {
    func key(reference: String) async throws -> Data?
}

public enum TOTPEnvelopeCrypto {
    public static func seal(secret: Data, factorID: String, keyReference: String, key: Data) throws -> TOTPSecretEnvelope {
        guard key.count == 32, !secret.isEmpty, secret.count <= 128, factorID.utf8.count <= 128, keyReference.utf8.count <= 256 else { throw MFAError.invalidEnvelope }
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
        guard value.utf8.count <= 512 else { throw MFAError.invalidCode }
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
    private let store: any TOTPReplayStore
    private let configuration: TOTPConfiguration
    public init(store: any TOTPReplayStore, configuration: TOTPConfiguration = TOTPConfiguration()) { self.store = store; self.configuration = configuration }

    public func accept(factorID: String, accountDID: String, code: String, secret: Data, at date: Date) async throws -> Bool {
        guard let counter = try TOTPAuthenticator.verify(code: code, secret: secret, at: date, configuration: configuration) else { return false }
        // First acceptance is a CAS from no row; every subsequent acceptance
        // must advance the durable counter atomically.
        return try await store.compareAndSwapTOTPReplay(factorID: factorID, accountDID: accountDID, expected: nil, proposed: counter, now: date)
    }
}

/// Coordinates external-key envelope opening with the replay guard. The
/// control database sees only ``TOTPSecretEnvelope``; plaintext seeds remain
/// inside this service call and are never handed to a storage adapter.
public struct TOTPFactorService: Sendable {
    private let keyStore: any TOTPEnvelopeKeyStore
    private let replayGuard: TOTPReplayGuard
    private let factorStore: any AuthenticationFactorStore
    private let configuration: TOTPConfiguration

    public init(keyStore: any TOTPEnvelopeKeyStore, replayGuard: TOTPReplayGuard, factorStore: any AuthenticationFactorStore, configuration: TOTPConfiguration = TOTPConfiguration()) {
        self.keyStore = keyStore
        self.replayGuard = replayGuard
        self.factorStore = factorStore
        self.configuration = configuration
    }

    public func verify(envelope: TOTPSecretEnvelope, accountDID: String, factorID: String, code: String, at date: Date) async throws -> Bool {
        let factors: [AuthenticationFactorMetadata]
        do { factors = try await factorStore.listFactors(accountDID: accountDID, now: date) } catch { throw MFAError.storageUnavailable }
        guard envelope.factorID == factorID, factors.contains(where: { $0.id == factorID && $0.kind == .totp && $0.disabledAt == nil }) else { throw MFAError.credentialNotFound }
        let key: Data?
        do { key = try await keyStore.key(reference: envelope.keyReference) } catch { throw MFAError.storageUnavailable }
        guard let key else { throw MFAError.invalidEnvelope }
        let secret = try TOTPEnvelopeCrypto.open(envelope, key: key)
        return try await replayGuard.accept(factorID: factorID, accountDID: accountDID, code: code, secret: secret, at: date)
    }
}

public struct RecoveryCodeService: Sendable {
    public static let defaultCount = 10
    private let store: any RecoveryCodeStore
    private let factorStore: any AuthenticationFactorStore
    public init(store: any RecoveryCodeStore, factorStore: any AuthenticationFactorStore) { self.store = store; self.factorStore = factorStore }

    public func replace(accountDID: String, count: Int = defaultCount, now: Date) async throws -> [String] {
        guard (1 ... 32).contains(count) else { throw MFAError.invalidCode }
        let codes = (0 ..< count).map { _ in Self.recoveryCode() }
        let digests = try codes.map { try RecoveryCodeDigest(accountDID: accountDID, digest: Self.digest($0), issuedAt: now) }
        try await store.replaceRecoveryCodeDigests(accountDID: accountDID, digests: digests, now: now)
        return codes
    }

    public func consume(_ code: String, accountDID: String, now: Date) async throws -> Bool {
        do { guard try await factorStore.listFactors(accountDID: accountDID, now: now).contains(where: { $0.kind == .recoveryCode && $0.disabledAt == nil }) else { return false } } catch { throw MFAError.storageUnavailable }
        do { _ = try await store.consumeRecoveryCode(digest: Self.digest(code), accountDID: accountDID, now: now); return true }
        catch let error as AccountControlStoreError where error == .notFound { return false }
        catch let error as AccountControlStoreError where error == .invalidInput { return false }
        catch { throw MFAError.storageUnavailable }
    }

    public static func digest(_ code: String) -> Data { Data(SHA256.hash(data: Data(("swan-recovery-v1:" + code.uppercased()).utf8))) }
    private static func recoveryCode() -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        return String((0 ..< 24).map { _ in alphabet[Int.random(in: 0 ..< alphabet.count)] })
    }
}

public enum FactorTokenPurpose: String, Sendable, Codable { case stepUp, managementLogin, oauthToken, loginRecovery }
public struct IssuedFactorToken: Sendable, Equatable { public let token: String; public let expiresAt: Date; public let factor: AuthenticationFactorKind; public let sessionID: String }

public actor FactorTokenService {
    private let store: any DurableFactorTokenStore
    public init(store: any DurableFactorTokenStore) { self.store = store }
    public func issue(accountDID: String, sessionID: String, purpose: FactorTokenPurpose, factor: AuthenticationFactorKind, strength: AuthenticationStrength, now: Date, lifetime: TimeInterval = 120) async throws -> IssuedFactorToken {
        guard lifetime > 0 && lifetime <= 600 else { throw MFAError.tokenInvalid }
        let valid: Bool
        switch purpose {
        case .stepUp:
            if factor == .totp { if case .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: _) = strength { valid = true } else { valid = false } }
            else if factor == .passkey { if case .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: _) = strength { valid = true } else { valid = false } }
            else { valid = false }
        case .loginRecovery: valid = factor == .recoveryCode && strength == .emailRecovery
        case .managementLogin, .oauthToken:
            if factor == .totp { if case .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: _) = strength { valid = true } else { valid = false } }
            else if factor == .passkey { if case .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: _) = strength { valid = true } else { valid = false } }
            else { valid = false }
        }
        guard valid else { throw MFAError.stepUpRequired }
        let verifiedAt: Date
        if case let .stepUpMFA(_, date) = strength { verifiedAt = date } else { throw MFAError.stepUpRequired }
        guard verifiedAt <= now, now.timeIntervalSince(verifiedAt) <= 600 else { throw MFAError.stepUpRequired }
        let token = randomBytes(count: 32).base64URLEncodedString(); let digest = Data(SHA256.hash(data: Data(token.utf8)))
        let expires = now.addingTimeInterval(lifetime)
        try await store.saveFactorToken(try DurableFactorTokenRecord(digest: digest, accountDID: accountDID, sessionID: sessionID, purpose: purpose.rawValue, factor: factor, strength: strength, issuedAt: now, expiresAt: expires), now: now)
        return IssuedFactorToken(token: token, expiresAt: expires, factor: factor, sessionID: sessionID)
    }
    public func consume(_ token: String, accountDID: String, sessionID: String, purpose: FactorTokenPurpose, factor: AuthenticationFactorKind, strength: AuthenticationStrength, now: Date) async throws -> Bool {
        let digest = Data(SHA256.hash(data: Data(token.utf8)))
        _ = try await store.consumeFactorToken(digest: digest, accountDID: accountDID, sessionID: sessionID, purpose: purpose.rawValue, factor: factor, strength: strength, now: now)
        return true
    }
}

public enum SensitiveAccountOperation: String, CaseIterable, Sendable { case emailChange, passwordChange, handleChange, identityChange, factorChange, appPassword, export, migration, connectedAppRevocation, deleteAccount, sessionRevocation }
public struct StepUpPolicy: Sendable {
    public let maximumAge: TimeInterval
    public init(maximumAge: TimeInterval = 600) { precondition(maximumAge.isFinite && maximumAge > 0 && maximumAge <= 600); self.maximumAge = maximumAge }
    public func authorize(_ operation: SensitiveAccountOperation, strength: AuthenticationStrength, mfaEnabled: Bool, now: Date) throws {
        let verifiedAt: Date?; let hasMFA: Bool
        switch strength {
        case let .stepUpPassword(date): verifiedAt = date; hasMFA = false
        case let .stepUpMFA(_, date): verifiedAt = date; hasMFA = true
        default: verifiedAt = nil; hasMFA = false
        }
        guard let verifiedAt, now.timeIntervalSince(verifiedAt) >= 0, now.timeIntervalSince(verifiedAt) <= maximumAge else { throw MFAError.stepUpRequired }
        guard operation != .export || hasMFA else { throw MFAError.stepUpRequired }
        guard !mfaEnabled || hasMFA else { throw MFAError.stepUpRequired }
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
    private let store: (any MFAAuditStore)?
    private var events: [MFAAuditEvent] = []

    public init(capacity: Int = 256, store: (any MFAAuditStore)? = nil) {
        self.capacity = max(1, capacity)
        self.store = store
    }

    public func append(_ event: MFAAuditEvent) async throws {
        events.append(event)
        if events.count > capacity { events.removeFirst(events.count - capacity) }
        if let store { try await store.appendMFAAuditEvent(try MFAAuditEventRecord(event: event.kind.rawValue, accountDID: event.accountDID, factorID: event.factor.map(\.rawValue), success: event.success, occurredAt: event.occurredAt), now: event.occurredAt) }
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
    private let challengeStore: any WebAuthnChallengeLookupStore
    private let factorStore: any AuthenticationFactorStore
    private let configuredRelyingPartyID: String?
    private let configuredOrigin: String?
    public init(keyStore: any WebAuthnPublicKeyStore, credentialStore: any WebAuthnCredentialStore, challengeStore: any WebAuthnChallengeLookupStore, factorStore: any AuthenticationFactorStore, relyingPartyID: String? = nil, origin: String? = nil) {
        self.keyStore = keyStore
        self.credentialStore = credentialStore
        self.challengeStore = challengeStore
        self.factorStore = factorStore
        self.configuredRelyingPartyID = relyingPartyID
        self.configuredOrigin = origin
    }

    public func verify(assertion: WebAuthnAssertion, accountDID: String, challenge: Data, purpose: FactorChallengePurpose = .assertion, now: Date) async throws -> WebAuthnVerificationResult {
        guard assertion.credentialID.count <= 1024, assertion.clientDataJSON.count <= 4096, assertion.authenticatorData.count <= 4096, assertion.signature.count <= 512, challenge.count <= 256 else { throw MFAError.invalidChallenge }
        let credentialDigest = Data(SHA256.hash(data: assertion.credentialID))
        guard let credential = try await credentialStore.webAuthnCredential(credentialIDDigest: credentialDigest, accountDID: accountDID, now: now), credential.disabledAt == nil else { throw MFAError.credentialNotFound }
        guard try await factorStore.listFactors(accountDID: accountDID, now: now).contains(where: { $0.id == credential.factorID && $0.kind == .passkey && $0.disabledAt == nil }) else { throw MFAError.credentialNotFound }
        let challengeDigest = Data(SHA256.hash(data: challenge))
        guard let challengeRecord = try await challengeStore.webAuthnChallenge(digest: challengeDigest, accountDID: accountDID, now: now) else { throw MFAError.invalidChallenge }
        guard now >= challengeRecord.issuedAt && now < challengeRecord.expiresAt,
              challengeRecord.purpose == purpose,
              challengeRecord.credentialIDDigest == credentialDigest else { throw MFAError.invalidChallenge }
        guard let expectedOrigin = configuredOrigin, let expectedRelyingPartyID = configuredRelyingPartyID else { throw MFAError.invalidOrigin }
        guard expectedOrigin == challengeRecord.origin, expectedRelyingPartyID == challengeRecord.relyingPartyID,
              let originURL = URL(string: expectedOrigin), originURL.scheme == "https", originURL.host == expectedRelyingPartyID, originURL.user == nil, originURL.password == nil, originURL.query == nil, originURL.fragment == nil, originURL.path.isEmpty || originURL.path == "/" else { throw MFAError.invalidOrigin }
        guard let json = try? JSONDecoder().decode(ClientData.self, from: assertion.clientDataJSON), json.type == "webauthn.get", json.origin == expectedOrigin, json.crossOrigin == false, let receivedChallenge = Data(base64URLEncoded: json.challenge), constantTimeEqual(receivedChallenge, challenge) else { throw MFAError.invalidClientData }
        guard assertion.authenticatorData.count >= 37 else { throw MFAError.invalidAuthenticatorData }
        guard constantTimeEqual(Data(assertion.authenticatorData.prefix(32)), Data(SHA256.hash(data: Data(expectedRelyingPartyID.utf8)))) else { throw MFAError.invalidRelyingParty }
        let flags = assertion.authenticatorData[32]; guard flags & 0x01 != 0, flags & 0x04 != 0 else { throw MFAError.invalidAuthenticatorData }
        let count = assertion.authenticatorData[33 ..< 37].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard let key = try await keyStore.publicKey(reference: credential.publicKeyReference), let signature = try? decodeWebAuthnSignature(assertion.signature), key.isValidSignature(signature, for: assertion.authenticatorData + Data(SHA256.hash(data: assertion.clientDataJSON))) else { throw MFAError.invalidSignature }
        // A zero counter is explicitly supported by WebAuthn. There is no
        // monotonic signal to CAS in that mode, so the one-time challenge is
        // the replay boundary until an authenticator reports a positive count.
        if count == 0 && credential.signCount == 0 {
            do { _ = try await challengeStore.consumeWebAuthnChallenge(digest: challengeDigest, accountDID: accountDID, now: now) } catch { throw MFAError.invalidChallenge }
            return WebAuthnVerificationResult(accountDID: accountDID, newSignCount: 0)
        }
        guard count > credential.signCount else { throw MFAError.counterRollback }
        guard let atomic = challengeStore as? any WebAuthnAtomicVerificationStore else { throw MFAError.storageUnavailable }
        switch try await atomic.compareAndSwapWebAuthnSignCountAndConsumeChallenge(try WebAuthnSignCountUpdate(credentialIDDigest: credentialDigest, accountDID: accountDID, expectedCurrent: credential.signCount, proposed: count, now: now), challengeDigest: challengeDigest, now: now) {
        case let .updated(newCount):
            return WebAuthnVerificationResult(accountDID: accountDID, newSignCount: newCount)
        case .rollbackDetected: throw MFAError.counterRollback
        }
    }

    private func decodeWebAuthnSignature(_ data: Data) throws -> P256.Signing.ECDSASignature {
        if data.count == 64 { return try P256WireSignature.decodeMalleabilityTolerant(data) }
        guard data.count >= 8 && data[0] == 0x30 else { throw MFAError.invalidSignature }
        var i = 1
        func length() throws -> Int { guard i < data.count else { throw MFAError.invalidSignature }; let b = data[i]; i += 1; guard b & 0x80 == 0 else { throw MFAError.invalidSignature }; return Int(b) }
        func integer() throws -> Data { guard i < data.count && data[i] == 0x02 else { throw MFAError.invalidSignature }; i += 1; let n = try length(); guard n > 0, n <= 33, i + n <= data.count else { throw MFAError.invalidSignature }; let value = Data(data[i ..< i + n]); i += n; guard value[0] & 0x80 == 0, !(n > 1 && value[0] == 0 && value[1] & 0x80 == 0), !(n == 33 && (value[0] != 0 || value[1] & 0x80 == 0)) else { throw MFAError.invalidSignature }; return value }
        let total = try length(); guard total == data.count - i else { throw MFAError.invalidSignature }; let r = try integer(); let s = try integer(); guard i == data.count, r.count <= 33, s.count <= 33 else { throw MFAError.invalidSignature }
        let rawR = r.count == 33 ? Data(r.dropFirst()) : Data(repeating: 0, count: 32 - r.count) + r
        let rawS = s.count == 33 ? Data(s.dropFirst()) : Data(repeating: 0, count: 32 - s.count) + s
        return try P256WireSignature.decodeMalleabilityTolerant(rawR + rawS)
    }
    private struct ClientData: Decodable { let type: String; let challenge: String; let origin: String; let crossOrigin: Bool
        enum CodingKeys: String, CodingKey { case type, challenge, origin, crossOrigin }
        init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); type = try c.decode(String.self, forKey: .type); challenge = try c.decode(String.self, forKey: .challenge); origin = try c.decode(String.self, forKey: .origin); crossOrigin = try c.decodeIfPresent(Bool.self, forKey: .crossOrigin) ?? false }
    }
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
    public static func verify(clientDataJSON: Data, authenticatorData: Data, challenge: Data, accountDID: String, challengeRecord: WebAuthnChallenge, expectedOrigin: String, relyingPartyID: String, now: Date) throws -> WebAuthnRegistrationResult {
        guard !accountDID.isEmpty, challengeRecord.accountDID == accountDID, challengeRecord.credentialIDDigest == nil,
              challengeRecord.purpose == .enrollment,
              challengeRecord.challengeDigest == Data(SHA256.hash(data: challenge)), now >= challengeRecord.issuedAt, now < challengeRecord.expiresAt,
              challengeRecord.origin == expectedOrigin, challengeRecord.relyingPartyID == relyingPartyID,
              expectedOrigin == challengeRecord.origin, expectedOrigin.hasPrefix("https://"),
              let originURL = URL(string: expectedOrigin), originURL.scheme == "https", originURL.host == relyingPartyID, originURL.user == nil, originURL.password == nil, originURL.query == nil, originURL.fragment == nil, originURL.path.isEmpty || originURL.path == "/" else { throw MFAError.invalidChallenge }
        guard let client = try? JSONDecoder().decode(RegistrationClientData.self, from: clientDataJSON), client.type == "webauthn.create", client.origin == expectedOrigin, client.crossOrigin == false,
              let receivedChallenge = Data(base64URLEncoded: client.challenge), constantTimeEqual(receivedChallenge, challenge) else { throw MFAError.invalidClientData }
        guard authenticatorData.count >= 55 else { throw MFAError.invalidAuthenticatorData }
        guard constantTimeEqual(Data(authenticatorData.prefix(32)), Data(SHA256.hash(data: Data(relyingPartyID.utf8)))) else { throw MFAError.invalidRelyingParty }
        let flags = authenticatorData[32]
        guard flags & 0x01 != 0, flags & 0x04 != 0, flags & 0x40 != 0 else { throw MFAError.invalidAuthenticatorData }
        let signCount = authenticatorData[33 ..< 37].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        var offset = 53
        guard offset + 2 <= authenticatorData.count else { throw MFAError.invalidAuthenticatorData }
        let credentialLength = Int(authenticatorData[offset]) << 8 | Int(authenticatorData[offset + 1]); offset += 2
        guard credentialLength > 0, offset + credentialLength < authenticatorData.count else { throw MFAError.invalidAuthenticatorData }
        let credentialID = Data(authenticatorData[offset ..< offset + credentialLength]); offset += credentialLength
        guard let publicKey = try parseCOSEES256(Data(authenticatorData[offset...])) else { throw MFAError.invalidSignature }
        return WebAuthnRegistrationResult(credentialIDDigest: Data(SHA256.hash(data: credentialID)), publicKey: publicKey, signCount: signCount)
    }

    private struct RegistrationClientData: Decodable {
        let type: String; let challenge: String; let origin: String; let crossOrigin: Bool
        enum CodingKeys: String, CodingKey { case type, challenge, origin, crossOrigin }
        init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); type = try c.decode(String.self, forKey: .type); challenge = try c.decode(String.self, forKey: .challenge); origin = try c.decode(String.self, forKey: .origin); crossOrigin = try c.decodeIfPresent(Bool.self, forKey: .crossOrigin) ?? false }
    }

    private static func parseCOSEES256(_ data: Data) throws -> P256.Signing.PublicKey? {
        guard data.count <= 4096 else { return nil }
        var reader = CBORReader(data: data)
        guard let mapLength = try? reader.readMapLength(), mapLength >= 5 else { return nil }
        var keyType: Int64?; var algorithm: Int64?; var curve: Int64?; var x: Data?; var y: Data?
        for _ in 0 ..< mapLength {
            let key = try reader.readInt()
            switch key {
            case 1: keyType = try reader.readInt()
            case 3: algorithm = try reader.readInt()
            case -1: curve = try reader.readInt()
            case -2: x = try reader.readBytes()
            case -3: y = try reader.readBytes()
            default: try reader.skipValue()
            }
        }
        guard reader.index == data.count else { return nil }
        guard keyType == 2, algorithm == -7, curve == 1, let x, let y, x.count == 32, y.count == 32 else { return nil }
        return try P256.Signing.PublicKey(rawRepresentation: x + y)
    }

    private struct CBORReader {
        let data: Data; var index: Int = 0
        mutating func readByte() throws -> UInt8 { guard index < data.count else { throw MFAError.invalidSignature }; defer { index += 1 }; return data[index] }
        mutating func readLength(_ initial: UInt8) throws -> Int { let additional = initial & 0x1f; guard additional != 31 else { throw MFAError.invalidSignature }; if additional < 24 { return Int(additional) }; let count = 1 << Int(additional - 24); guard count <= 8 else { throw MFAError.invalidSignature }; var value = 0; for _ in 0 ..< count { let byte = Int(try readByte()); guard value <= (Int.max - byte) / 256 else { throw MFAError.invalidSignature }; value = value * 256 + byte }; return value }
        mutating func readMapLength() throws -> Int { let initial = try readByte(); guard initial >> 5 == 5 else { throw MFAError.invalidSignature }; let length = try readLength(initial); guard length <= 16 else { throw MFAError.invalidSignature }; return length }
        mutating func readInt() throws -> Int64 { let initial = try readByte(); let major = initial >> 5; let raw = try readLength(initial); guard raw <= Int(Int64.max) else { throw MFAError.invalidSignature }; let value = Int64(raw); if major == 0 { return value }; if major == 1 { guard value < Int64.max else { throw MFAError.invalidSignature }; return -1 - value }; throw MFAError.invalidSignature }
        mutating func readBytes() throws -> Data { let initial = try readByte(); guard initial >> 5 == 2 else { throw MFAError.invalidSignature }; let length = try readLength(initial); guard length <= 1024, length <= data.count - index else { throw MFAError.invalidSignature }; defer { index += length }; return Data(data[index ..< index + length]) }
        mutating func skipValue(depth: Int = 0) throws { guard depth <= 8 else { throw MFAError.invalidSignature }; let initial = try readByte(); let major = initial >> 5; let length = try readLength(initial); if major == 2 || major == 3 { guard length <= data.count - index else { throw MFAError.invalidSignature }; index += length } else if major == 4 { guard length <= 64 else { throw MFAError.invalidSignature }; for _ in 0 ..< length { try skipValue(depth: depth + 1) } } else if major == 5 { guard length <= 16 else { throw MFAError.invalidSignature }; for _ in 0 ..< length { try skipValue(depth: depth + 1); try skipValue(depth: depth + 1) } } else if major == 0 || major == 1 || major == 7 {} else { throw MFAError.invalidSignature } }
    }
}

/// Persists enrollment only through the challenge-consuming transaction. A
/// consumed, expired, or malformed challenge therefore cannot create a
/// credential, even if the caller retries after a process restart.
public struct WebAuthnEnrollmentService: Sendable {
    private let store: any WebAuthnEnrollmentStore
    private let factorStore: any AuthenticationFactorStore
    public init(store: any WebAuthnEnrollmentStore, factorStore: any AuthenticationFactorStore) { self.store = store; self.factorStore = factorStore }
    public func enroll(clientDataJSON: Data, authenticatorData: Data, challenge: Data, accountDID: String, factorID: String, publicKeyReference: String, transports: Set<String>, challengeRecord: WebAuthnChallenge, expectedOrigin: String, relyingPartyID: String, now: Date) async throws -> WebAuthnRegistrationResult {
        guard try await factorStore.listFactors(accountDID: accountDID, now: now).contains(where: { $0.id == factorID && $0.kind == .passkey && $0.disabledAt == nil }) else { throw MFAError.credentialNotFound }
        guard let current = try await store.webAuthnChallenge(digest: challengeRecord.challengeDigest, accountDID: accountDID, now: now), current.purpose == .enrollment, current.credentialIDDigest == nil else { throw MFAError.invalidChallenge }
        let result = try WebAuthnRegistrationVerifier.verify(clientDataJSON: clientDataJSON, authenticatorData: authenticatorData, challenge: challenge, accountDID: accountDID, challengeRecord: current, expectedOrigin: expectedOrigin, relyingPartyID: relyingPartyID, now: now)
        let credential = try WebAuthnCredentialMetadata(credentialIDDigest: result.credentialIDDigest, accountDID: accountDID, factorID: factorID, publicKeyReference: publicKeyReference, signCount: result.signCount, transports: transports, createdAt: now)
        do { try await store.consumeEnrollmentChallengeAndSaveCredential(challengeDigest: current.challengeDigest, accountDID: accountDID, credential: credential, now: now) } catch { throw MFAError.storageUnavailable }
        return result
    }
}

private func randomBytes(count: Int) -> Data { var generator = SystemRandomNumberGenerator(); return Data((0 ..< count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }) }
private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool { guard lhs.count == rhs.count else { return false }; var result: UInt8 = 0; for (a, b) in zip(lhs, rhs) { result |= a ^ b }; return result == 0 }
private extension Data {
    func base64URLEncodedString() -> String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    init?(base64URLEncoded value: String) { var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"); text += String(repeating: "=", count: (4 - text.count % 4) % 4); self.init(base64Encoded: text) }
}
