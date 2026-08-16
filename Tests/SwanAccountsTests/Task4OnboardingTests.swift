import Crypto
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanStorage
import XCTest

final class Task4OnboardingTests: XCTestCase {
    func testSignupPolicyAdvertisementIsDerived() {
        XCTAssertFalse(SignupPolicy.closed.permitsPublicSignup)
        XCTAssertFalse(SignupPolicy.closed.advertisesInviteCodeRequired)
        XCTAssertTrue(SignupPolicy.inviteRequired.advertisesInviteCodeRequired)
        XCTAssertFalse(SignupPolicy.inviteRequired.requiresTurnstile)
        XCTAssertTrue(SignupPolicy.openProtected.permitsPublicSignup)
        XCTAssertTrue(SignupPolicy.openProtected.requiresTurnstile)

        let description = SignupPolicyDescription(policy: .inviteRequired)
        XCTAssertTrue(description.inviteCodeRequired)
        XCTAssertEqual(description.policy, .inviteRequired)
    }

    func testInviteCodeIsHashedAndSingleUse() throws {
        let key = try SignupSecret(Data(repeating: 7, count: 32))
        let service = SignupInviteService(secret: key)
        let issued = try service.issue(code: "invite-one-123456", expiresAt: Date().addingTimeInterval(60))
        XCTAssertEqual(issued.code, "invite-one-123456")
        XCTAssertEqual(try service.digest(code: "invite-one-123456"), issued.digest)
        XCTAssertNotEqual(issued.digest, Data("invite-one-123456".utf8))
    }

    func testTurnstileRejectsMissingDuplicateWrongHostAndAction() async throws {
        let transport = StubTurnstileTransport(response: .init(success: true, challengeTimestamp: Date(), hostname: "other.example", action: "wrong", errorCodes: []))
        let verifier = try TurnstileVerifier(secret: Data(repeating: 2, count: 32), hostname: "accounts.example", action: "signup", transport: transport)
        do {
            try await verifier.verify(token: "", remoteIP: nil, now: Date())
            XCTFail("missing token must fail closed")
        } catch is TurnstileVerificationError {}
        do {
            try await verifier.verify(token: "token", remoteIP: nil, now: Date())
            XCTFail("hostname/action mismatch must fail")
        } catch is TurnstileVerificationError {}
    }

    func testTurnstileAcceptsOnlyFreshSingleUseExactResult() async throws {
        let now = Date()
        let transport = StubTurnstileTransport(response: .init(success: true, challengeTimestamp: now, hostname: "accounts.example", action: "signup", errorCodes: []))
        let verifier = try TurnstileVerifier(secret: Data(repeating: 2, count: 32), hostname: "accounts.example", action: "signup", transport: transport)
        try await verifier.verify(token: "token", remoteIP: "192.0.2.1", now: now)
        do {
            try await verifier.verify(token: "token", remoteIP: nil, now: now)
            XCTFail("tokens are one-use")
        } catch TurnstileVerificationError.duplicate {}
    }

    func testTurnstileRejectsFutureChallengeTimestamp() async throws {
        let now = Date()
        let transport = StubTurnstileTransport(response: .init(success: true, challengeTimestamp: now.addingTimeInterval(6), hostname: "accounts.example", action: "signup"))
        let verifier = try TurnstileVerifier(secret: Data(repeating: 2, count: 32), hostname: "accounts.example", action: "signup", transport: transport)
        do {
            try await verifier.verify(token: "future-token", remoteIP: nil, now: now)
            XCTFail("future challenge timestamps must fail closed")
        } catch TurnstileVerificationError.expired {}
    }

    func testSignupRejectsUnsupportedIdentityMethodAndLifetime() async throws {
        let store = InMemorySignupAuthorizationStore()
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.1")
        let input = try SignupAuthorizationInput.make(
            requestID: "request-2", authorizationID: SignupAuthorizationID(rawValue: "authorization-2"),
            handle: "alice.example.com", email: AccountEmailAddress("alice@example.com"),
            identityDID: "did:key:z6Mk", emailProofDigest: Data(repeating: 4, count: 32), inviteDigest: nil,
            peer: peer
        )
        let service = try SignupService(policy: SignupPolicyService(policy: .openProtected), store: store)
        do {
            _ = try await service.authorize(input, lifetime: 901)
            XCTFail("authorization lifetime must be bounded")
        } catch SwanError.invalidIdentifier {}
    }

    func testOpenAndInviteSignupRequireVerifiedEmailProof() async throws {
        let store = InMemorySignupAuthorizationStore()
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.1")
        let input = try SignupAuthorizationInput.make(
            requestID: "request-1",
            authorizationID: SignupAuthorizationID(rawValue: "authorization-1"),
            handle: "alice.example.com",
            email: AccountEmailAddress("alice@example.com"),
            identityDID: "did:plc:alice",
            emailProofDigest: nil,
            inviteDigest: nil,
            peer: peer
        )
        let service = try SignupService(policy: SignupPolicyService(policy: .openProtected), store: store)
        do {
            _ = try await service.authorize(input)
            XCTFail("missing verified email proof must fail")
        } catch SignupServiceError.emailProofRequired {}
    }

    func testAuthenticatedSMTPRequiresTLSHostnameAndDeduplicates() throws {
        XCTAssertThrowsError(try AuthenticatedSMTPConfiguration(host: "relay.example", port: 587, mode: .startTLS))
        XCTAssertNoThrow(try AuthenticatedSMTPConfiguration(host: "relay.example", port: 587, mode: .startTLS, username: "u", password: "p", mechanism: .plain, expectedHostname: "relay.example"))
    }

    func testSignupEmailEnvelopeRoundTripsAndRejectsTampering() throws {
        let proof = try SignupSecret(Data(repeating: 8, count: 32))
        let service = SignupEmailProofService(secret: proof)
        let email = try AccountEmailAddress("alice@example.com")
        let envelope = try service.protectedEnvelope(code: "code-123456789012", email: email, handle: "alice.example.com", deliveryID: "delivery-1")
        XCTAssertEqual(try service.openProtectedEnvelope(envelope, email: email, handle: "alice.example.com", deliveryID: "delivery-1"), "code-123456789012")
        var tampered = envelope; tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try service.openProtectedEnvelope(tampered, email: email, handle: "alice.example.com", deliveryID: "delivery-1"))
    }
}

private struct StubTurnstileTransport: TurnstileHTTPTransport {
    let response: TurnstileSiteVerifyResponse
    func verify(_: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        response
    }
}

private actor InMemorySignupAuthorizationStore: SignupAuthorizationStore {
    private var values: [SignupAuthorizationID: SignupAuthorization] = [:]
    func reserve(_ authorization: SignupAuthorization, now _: Date) async throws {
        if let existing = values[authorization.id], existing != authorization { throw AccountControlStoreError.duplicateDID }
        values[authorization.id] = authorization
    }

    func authorization(id: SignupAuthorizationID, now _: Date) async throws -> SignupAuthorization? {
        values[id]
    }

    func fail(id _: SignupAuthorizationID, now _: Date) async throws {}
    func finalize(_: SignupFinalizationRequest, now _: Date) async throws -> SignupFinalizationResult {
        throw AccountControlStoreError.unavailable
    }

    func purgeExpiredSignupState(now _: Date) async throws {}
}
