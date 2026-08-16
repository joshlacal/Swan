import Crypto
import Foundation
import SwanAccounts
import SwanCore
@testable import SwanSQLite
import SwanStorage
import XCTest

final class Task7MFATests: XCTestCase {
    func testSQLiteFactorStoreRoundTripsAndConsumesAtomically() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-task7-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('did:plc:alice', 'alice.example', 'active', 1)")
        let factor = try AuthenticationFactorMetadata(id: "factor", accountDID: "did:plc:alice", kind: .totp, label: "Authenticator", lookupDigest: Data(repeating: 1, count: 32), createdAt: Date(timeIntervalSince1970: 1))
        try await database.saveFactor(factor, now: Date(timeIntervalSince1970: 1))
        let factors = try await database.listFactors(accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(factors, [factor])
        let code = try RecoveryCodeDigest(accountDID: "did:plc:alice", digest: Data(repeating: 2, count: 32), issuedAt: Date(timeIntervalSince1970: 1))
        try await database.replaceRecoveryCodeDigests(accountDID: "did:plc:alice", digests: [code], now: Date(timeIntervalSince1970: 1))
        _ = try await database.consumeRecoveryCode(digest: code.digest, accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 2))
        do { _ = try await database.consumeRecoveryCode(digest: code.digest, accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 3)); XCTFail("recovery code replay") } catch {}
    }

    func testRFC6238SHA1Vectors() throws {
        let secret = Data("12345678901234567890".utf8)
        XCTAssertEqual(try TOTPAuthenticator.code(secret: secret, counter: 1), "287082")
        XCTAssertEqual(try TOTPAuthenticator.code(secret: secret, counter: 20), "328281")
        XCTAssertEqual(try TOTPAuthenticator.code(secret: secret, counter: 59 / 30), "287082")
    }

    func testTOTPUsesOneStepDriftAndRejectsReplay() async throws {
        let replay = TOTPReplayGuard()
        let secret = Data("12345678901234567890".utf8)
        let now = Date(timeIntervalSince1970: 60)
        let adjacent = try TOTPAuthenticator.code(secret: secret, counter: 1)
        let first = try await replay.accept(factorID: "factor", code: adjacent, secret: secret, at: now)
        let second = try await replay.accept(factorID: "factor", code: adjacent, secret: secret, at: now)
        let other = try await replay.accept(factorID: "other", code: adjacent, secret: secret, at: Date(timeIntervalSince1970: 120))
        XCTAssertTrue(first); XCTAssertFalse(second); XCTAssertFalse(other)
    }

    func testTOTPEnvelopeAndConcurrentReplayAreBounded() async throws {
        let key = Data(repeating: 7, count: 32)
        let envelope = try TOTPEnvelopeCrypto.seal(secret: Data("12345678901234567890".utf8), factorID: "factor", keyReference: "kms:1", key: key)
        let service = TOTPFactorService(keyStore: InMemoryTOTPKeyStore(reference: "kms:1", key: key))
        let code = try TOTPAuthenticator.code(secret: Data("12345678901234567890".utf8), counter: 1)
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0 ..< 8 { group.addTask { (try? await service.verify(envelope: envelope, factorID: "factor", code: code, at: Date(timeIntervalSince1970: 30))) == true } }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
    }

    func testRecoveryCodesAreHighEntropyAndSingleUse() async throws {
        let store = InMemoryRecoveryCodeStore()
        let service = RecoveryCodeService(store: store)
        let codes = try await service.replace(accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(codes.count, RecoveryCodeService.defaultCount)
        XCTAssertTrue(codes.allSatisfy { $0.count >= 20 })
        let consumed = try await service.consume(codes[0], accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 2))
        let replayed = try await service.consume(codes[0], accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 3))
        XCTAssertTrue(consumed); XCTAssertFalse(replayed)
    }

    func testRecoveryCodeConcurrentConsumeHasOneWinner() async throws {
        let store = InMemoryRecoveryCodeStore()
        let service = RecoveryCodeService(store: store)
        let code = try await service.replace(accountDID: "did:plc:alice", count: 1, now: Date(timeIntervalSince1970: 1))[0]
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0 ..< 8 { group.addTask { (try? await service.consume(code, accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 2))) == true } }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
    }

    func testFactorTokensAreShortLivedSinglePurposeAndBoundToAccount() async throws {
        let service = FactorTokenService()
        let issued = try await service.issue(accountDID: "did:plc:alice", purpose: .stepUp, factor: .totp, now: Date(timeIntervalSince1970: 10))
        let consumed = try? await service.consume(issued.token, accountDID: "did:plc:alice", purpose: .stepUp, factor: .totp, now: Date(timeIntervalSince1970: 11))
        let replayed = try? await service.consume(issued.token, accountDID: "did:plc:alice", purpose: .stepUp, factor: .totp, now: Date(timeIntervalSince1970: 11))
        XCTAssertNotNil(consumed); XCTAssertNil(replayed)
        let other = try await service.issue(accountDID: "did:plc:alice", purpose: .stepUp, factor: .passkey, now: Date(timeIntervalSince1970: 10))
        let wrongAccount = try? await service.consume(other.token, accountDID: "did:plc:bob", purpose: .stepUp, factor: .passkey, now: Date(timeIntervalSince1970: 11))
        XCTAssertNil(wrongAccount)
    }

    func testStepUpPolicyRequiresPasswordAndConfiguredMFAForSensitiveOperations() throws {
        let policy = StepUpPolicy()
        XCTAssertThrowsError(try policy.authorize(.deleteAccount, strength: .stepUpPassword(verifiedAt: Date(timeIntervalSince1970: 10)), mfaEnabled: true, now: Date(timeIntervalSince1970: 11)))
        XCTAssertNoThrow(try policy.authorize(.deleteAccount, strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 10)), mfaEnabled: true, now: Date(timeIntervalSince1970: 11)))
        XCTAssertThrowsError(try policy.authorize(.deleteAccount, strength: .emailRecovery, mfaEnabled: false, now: Date(timeIntervalSince1970: 11)))
        XCTAssertThrowsError(try policy.authorize(.deleteAccount, strength: .stepUpPassword(verifiedAt: Date(timeIntervalSince1970: 0)), mfaEnabled: false, now: Date(timeIntervalSince1970: 601)))
    }

    func testWebAuthnRejectsWrongOriginRPChallengeTypeUVSignatureAndAccount() async throws {
        let key = P256.Signing.PrivateKey()
        let credentialID = Data("credential".utf8)
        let challenge = Data("challenge".utf8)
        let clientData = try JSONSerialization.data(withJSONObject: [
            "type": "webauthn.get",
            "challenge": testBase64URL(challenge),
            "origin": "https://example.com"
        ])
        let authData = Data(SHA256.hash(data: Data("example.com".utf8))) + Data([0x05, 0, 0, 0, 1])
        let signature = try P256WireSignature.sign(authData + Data(SHA256.hash(data: clientData)), using: key)
        let assertion = WebAuthnAssertion(credentialID: credentialID, clientDataJSON: clientData, authenticatorData: authData, signature: signature)
        let challengeRecord = try WebAuthnChallenge(challengeDigest: Data(SHA256.hash(data: challenge)), accountDID: "did:plc:alice", credentialIDDigest: Data(SHA256.hash(data: credentialID)), relyingPartyID: "example.com", origin: "https://example.com", issuedAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 30))
        let credential = try WebAuthnCredentialMetadata(credentialIDDigest: Data(SHA256.hash(data: credentialID)), accountDID: "did:plc:alice", factorID: "factor", publicKeyReference: "key", signCount: 0, createdAt: Date(timeIntervalSince1970: 1))
        let keys = InMemoryWebAuthnKeyStore(reference: "key", key: key.publicKey)
        let store = InMemoryWebAuthnStore(credential: credential, challenge: challengeRecord)
        let verifier = WebAuthnVerifier(keyStore: keys, credentialStore: store, challengeStore: store)
        let result = try await verifier.verify(assertion: assertion, accountDID: "did:plc:alice", challenge: challenge, now: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(result.accountDID, "did:plc:alice")
        do {
            _ = try await verifier.verify(assertion: assertion, accountDID: "did:plc:alice", challenge: challenge, now: Date(timeIntervalSince1970: 2))
            XCTFail("challenge replay should be rejected")
        } catch {}
    }

    func testWebAuthnRegistrationAcceptsOnlyP256UPAndUV() throws {
        let key = P256.Signing.PrivateKey()
        let authData = Data(SHA256.hash(data: Data("example.com".utf8))) + Data([0x05, 0, 0, 0, 0])
        let result = try WebAuthnRegistrationVerifier.verify(credentialID: Data("credential".utf8), authenticatorData: authData, publicKeyX963: key.publicKey.x963Representation, relyingPartyID: "example.com")
        XCTAssertEqual(result.signCount, 0)
        XCTAssertEqual(result.publicKey.x963Representation, key.publicKey.x963Representation)
        XCTAssertThrowsError(try WebAuthnRegistrationVerifier.verify(credentialID: Data("credential".utf8), authenticatorData: Data(SHA256.hash(data: Data("wrong.example".utf8))) + Data([0x01, 0, 0, 0, 0]), publicKeyX963: key.publicKey.x963Representation, relyingPartyID: "example.com"))
    }
}

private actor InMemoryRecoveryCodeStore: RecoveryCodeStore {
    private var digests: [Data: RecoveryCodeDigest] = [:]
    private var plaintexts: Set<String> = []
    func replaceRecoveryCodeDigests(accountDID: String, digests: [RecoveryCodeDigest], now: Date) async throws {
        self.digests = Dictionary(uniqueKeysWithValues: digests.map { ($0.digest, $0) })
    }
    func consumeRecoveryCode(digest: Data, accountDID: String, now: Date) async throws -> RecoveryCodeDigest {
        guard let value = digests[digest], value.accountDID == accountDID, value.consumedAt == nil else { throw SwanError.invalidIdentifier("recovery code") }
        let consumed = try RecoveryCodeDigest(accountDID: value.accountDID, digest: value.digest, issuedAt: value.issuedAt, consumedAt: now)
        digests[digest] = consumed
        return consumed
    }
    func containsPlaintext(_ value: String) -> Bool { plaintexts.contains(value) }
}

private actor InMemoryWebAuthnStore: WebAuthnCredentialStore, WebAuthnChallengeStore {
    var credential: WebAuthnCredentialMetadata
    var challenge: WebAuthnChallenge
    init(credential: WebAuthnCredentialMetadata, challenge: WebAuthnChallenge) { self.credential = credential; self.challenge = challenge }
    func saveWebAuthnCredential(_ value: WebAuthnCredentialMetadata, now: Date) async throws { credential = value }
    func webAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws -> WebAuthnCredentialMetadata? { credential.credentialIDDigest == credentialIDDigest && credential.accountDID == accountDID ? credential : nil }
    func compareAndSwapWebAuthnSignCount(_ update: WebAuthnSignCountUpdate) async throws -> WebAuthnSignCountUpdateOutcome {
        guard credential.signCount == update.expectedCurrent else { return .rollbackDetected(storedCount: credential.signCount) }
        credential = try WebAuthnCredentialMetadata(credentialIDDigest: credential.credentialIDDigest, accountDID: credential.accountDID, factorID: credential.factorID, publicKeyReference: credential.publicKeyReference, signCount: update.proposed, transports: credential.transports, createdAt: credential.createdAt, lastUsedAt: update.now, disabledAt: credential.disabledAt)
        return .updated(newCount: update.proposed)
    }
    func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws {}
    func reserveWebAuthnChallenge(_ value: WebAuthnChallenge, now: Date) async throws { challenge = value }
    func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge {
        guard challenge.challengeDigest == digest, challenge.accountDID == accountDID, challenge.consumedAt == nil else { throw SwanError.invalidIdentifier("challenge") }
        let value = try WebAuthnChallenge(challengeDigest: challenge.challengeDigest, accountDID: challenge.accountDID, credentialIDDigest: challenge.credentialIDDigest, relyingPartyID: challenge.relyingPartyID, origin: challenge.origin, issuedAt: challenge.issuedAt, expiresAt: challenge.expiresAt, consumedAt: now)
        challenge = value
        return value
    }
}

private struct InMemoryWebAuthnKeyStore: WebAuthnPublicKeyStore {
    let reference: String
    let key: P256.Signing.PublicKey
    func publicKey(reference: String) async throws -> P256.Signing.PublicKey? { reference == self.reference ? key : nil }
}

private struct InMemoryTOTPKeyStore: TOTPEnvelopeKeyStore {
    let reference: String
    let key: Data
    func key(reference: String) async throws -> Data? { reference == self.reference ? key : nil }
}

private func testBase64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
