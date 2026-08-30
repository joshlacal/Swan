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
        let service = try SignupService(policy: SignupPolicyService(policy: .openProtected), store: store, rateAdmission: try SignupInviteRateAdmission())
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
        let service = try SignupService(policy: SignupPolicyService(policy: .openProtected), store: store, rateAdmission: try SignupInviteRateAdmission())
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

    func testWrongOrMissingLocalEmailProofCausesZeroTurnstileCalls() async throws {
        let store = InMemorySignupAuthorizationStore()
        let secret = try SignupSecret(Data(repeating: 3, count: 32))
        let proofService = SignupEmailProofService(secret: secret)
        let email = try AccountEmailAddress("alice@example.com")
        let handle = "alice.example.com"
        let issue = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.1")
        let input = try SignupAuthorizationInput.make(
            requestID: "request-1",
            authorizationID: SignupAuthorizationID(rawValue: "authorization-1"),
            handle: handle,
            email: email,
            identityDID: "did:plc:abcdefghijklmnopqrstuvwx",
            emailProofDigest: issue.digest,
            inviteDigest: nil,
            peer: peer
        )
        let transport = RecordingTurnstileTransport()
        let turnstile = try TurnstileVerifier(
            secret: Data(repeating: 2, count: 32),
            hostname: "accounts.example",
            action: "signup",
            transport: transport
        )
        let rateAdmission = try SignupInviteRateAdmission(maximum: 5, globalMaximum: 100, window: 60)
        let verifier = LocalTestEmailProofVerifier()
        let service = try SignupService(
            policy: SignupPolicyService(policy: .openProtected),
            store: store,
            turnstile: turnstile,
            rateAdmission: rateAdmission,
            proofVerifier: verifier,
            proofService: proofService
        )

        // Wrong verification code must fail without calling Turnstile
        do {
            _ = try await service.authorize(
                input,
                verificationCode: "wrong-code-1234567890",
                turnstileToken: "valid-token",
                remoteIP: "192.0.2.1"
            )
            XCTFail("wrong verification code must fail")
        } catch SignupServiceError.emailProofRequired {
            let count = await transport.callCount
            XCTAssertEqual(count, 0, "Turnstile must not be called when local email proof fails")
        }

        // Missing verification code must fail without calling Turnstile
        do {
            _ = try await service.authorize(
                input,
                verificationCode: nil,
                turnstileToken: "valid-token",
                remoteIP: "192.0.2.1"
            )
            XCTFail("missing verification code must fail")
        } catch SignupServiceError.emailProofRequired {
            let count = await transport.callCount
            XCTAssertEqual(count, 0, "Turnstile must not be called when verification code is missing")
        }
    }

    func testOpenProtectedAndInviteSignupsObeyPerPeerAndGlobalAdmission() async throws {
        let store = InMemorySignupAuthorizationStore()
        let secret = try SignupSecret(Data(repeating: 4, count: 32))
        let proofService = SignupEmailProofService(secret: secret)
        let email = try AccountEmailAddress("bob@example.com")
        let handle = "bob.example.com"
        let transport = RecordingTurnstileTransport()
        let turnstile = try TurnstileVerifier(
            secret: Data(repeating: 2, count: 32),
            hostname: "accounts.example",
            action: "signup",
            transport: transport
        )
        let rateAdmission = try SignupInviteRateAdmission(maximum: 2, globalMaximum: 3, window: 60)
        let verifier = LocalTestEmailProofVerifier()
        let service = try SignupService(
            policy: SignupPolicyService(policy: .openProtected),
            store: store,
            turnstile: turnstile,
            rateAdmission: rateAdmission,
            proofVerifier: verifier,
            proofService: proofService
        )
        let extractor = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
        let peer1 = try extractor.bucket(forCanonicalPeerIP: "192.0.2.1")
        let peer2 = try extractor.bucket(forCanonicalPeerIP: "192.0.2.2")
        let peer3 = try extractor.bucket(forCanonicalPeerIP: "192.0.2.3")

        // Peer 1: attempt 1 -> allowed
        let issue1 = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let input1 = try SignupAuthorizationInput.make(requestID: "req-1", authorizationID: SignupAuthorizationID(rawValue: "auth-1"), handle: handle, email: email, identityDID: "did:plc:abcdefghijklmnopqrstuvwx", emailProofDigest: issue1.digest, inviteDigest: nil, peer: peer1)
        _ = try await service.authorize(input1, verificationCode: issue1.code, turnstileToken: "tok-1", remoteIP: "192.0.2.1")
        let c1 = await transport.callCount; XCTAssertEqual(c1, 1)

        // Peer 1: attempt 2 -> allowed (peer 1 budget exhausted)
        let issue2 = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let input2 = try SignupAuthorizationInput.make(requestID: "req-2", authorizationID: SignupAuthorizationID(rawValue: "auth-2"), handle: handle, email: email, identityDID: "did:plc:abcdefghijklmnopqrstuvwx", emailProofDigest: issue2.digest, inviteDigest: nil, peer: peer1)
        _ = try await service.authorize(input2, verificationCode: issue2.code, turnstileToken: "tok-2", remoteIP: "192.0.2.1")
        let c2 = await transport.callCount; XCTAssertEqual(c2, 2)

        // Peer 1: attempt 3 -> rateLimited before Turnstile is called
        let issue3 = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let input3 = try SignupAuthorizationInput.make(requestID: "req-3", authorizationID: SignupAuthorizationID(rawValue: "auth-3"), handle: handle, email: email, identityDID: "did:plc:abcdefghijklmnopqrstuvwx", emailProofDigest: issue3.digest, inviteDigest: nil, peer: peer1)
        do {
            _ = try await service.authorize(input3, verificationCode: issue3.code, turnstileToken: "tok-3", remoteIP: "192.0.2.1")
            XCTFail("peer 1 must be rate limited on 3rd attempt")
        } catch SignupServiceError.rateLimited {
            let count = await transport.callCount
            XCTAssertEqual(count, 2, "Turnstile must not be called when rate limited")
        }

        // Peer 2: attempt 1 -> allowed (global attempt 3 of 3)
        let issue4 = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let input4 = try SignupAuthorizationInput.make(requestID: "req-4", authorizationID: SignupAuthorizationID(rawValue: "auth-4"), handle: handle, email: email, identityDID: "did:plc:abcdefghijklmnopqrstuvwx", emailProofDigest: issue4.digest, inviteDigest: nil, peer: peer2)
        _ = try await service.authorize(input4, verificationCode: issue4.code, turnstileToken: "tok-4", remoteIP: "192.0.2.2")
        let c3 = await transport.callCount; XCTAssertEqual(c3, 3)

        // Peer 3: attempt 1 -> rateLimited by global budget (global attempt 4 > 3)
        let issue5 = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let input5 = try SignupAuthorizationInput.make(requestID: "req-5", authorizationID: SignupAuthorizationID(rawValue: "auth-5"), handle: handle, email: email, identityDID: "did:plc:abcdefghijklmnopqrstuvwx", emailProofDigest: issue5.digest, inviteDigest: nil, peer: peer3)
        do {
            _ = try await service.authorize(input5, verificationCode: issue5.code, turnstileToken: "tok-5", remoteIP: "192.0.2.3")
            XCTFail("peer 3 must be rate limited by global budget")
        } catch SignupServiceError.rateLimited {
            let count = await transport.callCount
            XCTAssertEqual(count, 3, "Turnstile must not be called when global budget is exhausted")
        }
    }

    func testValidProofPlusValidTurnstileSucceeds() async throws {
        let store = InMemorySignupAuthorizationStore()
        let secret = try SignupSecret(Data(repeating: 5, count: 32))
        let proofService = SignupEmailProofService(secret: secret)
        let email = try AccountEmailAddress("carol@example.com")
        let handle = "carol.example.com"
        let issue = try proofService.issue(email: email, handle: handle, expiresAt: Date().addingTimeInterval(600))
        let transport = RecordingTurnstileTransport()
        let turnstile = try TurnstileVerifier(
            secret: Data(repeating: 2, count: 32),
            hostname: "accounts.example",
            action: "signup",
            transport: transport
        )
        let verifier = LocalTestEmailProofVerifier()
        let service = try SignupService(
            policy: SignupPolicyService(policy: .openProtected),
            store: store,
            turnstile: turnstile,
            rateAdmission: try SignupInviteRateAdmission(),
            proofVerifier: verifier,
            proofService: proofService
        )
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.1")
        let input = try SignupAuthorizationInput.make(
            requestID: "req-carol",
            authorizationID: SignupAuthorizationID(rawValue: "auth-carol"),
            handle: handle,
            email: email,
            identityDID: "did:plc:abcdefghijklmnopqrstuvwx",
            emailProofDigest: issue.digest,
            inviteDigest: nil,
            peer: peer
        )
        let auth = try await service.authorize(
            input,
            verificationCode: issue.code,
            turnstileToken: "valid-turnstile",
            remoteIP: "192.0.2.1"
        )
        XCTAssertEqual(auth.handle, handle)
        let count = await transport.callCount; XCTAssertEqual(count, 1)
        let stored = try await store.authorization(id: auth.id, now: Date())
        XCTAssertNotNil(stored)
    }

    func testInviteBehaviorRemainsUnchanged() async throws {
        let store = InMemorySignupAuthorizationStore()
        let secret = try SignupSecret(Data(repeating: 6, count: 32))
        let invites = SignupInviteService(secret: secret)
        let issued = try invites.generate(expiresAt: Date().addingTimeInterval(600))
        let rateAdmission = try SignupInviteRateAdmission()
        let service = try SignupService(
            policy: SignupPolicyService(policy: .inviteRequired),
            store: store,
            rateAdmission: rateAdmission
        )
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.1")
        let email = try AccountEmailAddress("dave@example.com")

        // Missing invite -> inviteRequired
        let inputMissingInvite = try SignupAuthorizationInput.make(
            requestID: "req-dave-1",
            authorizationID: SignupAuthorizationID(rawValue: "auth-dave-1"),
            handle: "dave.example.com",
            email: email,
            identityDID: "did:plc:abcdefghijklmnopqrstuvwx",
            emailProofDigest: Data(repeating: 1, count: 32),
            inviteDigest: nil,
            peer: peer
        )
        do {
            _ = try await service.authorize(inputMissingInvite)
            XCTFail("missing invite must fail")
        } catch SignupServiceError.inviteRequired {}
        // Valid invite digest -> succeeds
        let inputWithInvite = try SignupAuthorizationInput.make(
            requestID: "req-dave-2",
            authorizationID: SignupAuthorizationID(rawValue: "auth-dave-2"),
            handle: "dave.example.com",
            email: email,
            identityDID: "did:plc:abcdefghijklmnopqrstuvwx",
            emailProofDigest: Data(repeating: 1, count: 32),
            inviteDigest: issued.digest,
            peer: peer
        )
        let auth = try await service.authorize(inputWithInvite)
        XCTAssertEqual(auth.handle, "dave.example.com")
    }
    func testOpenProtectedSignupRequiresAdmission() async throws {
        let store = InMemorySignupAuthorizationStore()
        let service = try SignupService(policy: SignupPolicyService(policy: .openProtected), store: store)
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.9")
        let input = try SignupAuthorizationInput.make(
            requestID: "req-no-admission",
            authorizationID: SignupAuthorizationID(rawValue: "auth-no-admission"),
            handle: "no-admission.example.com",
            email: try AccountEmailAddress("nobody@example.com"),
            identityDID: "did:plc:abcdefghijklmnopqrstuvwx",
            emailProofDigest: Data(repeating: 1, count: 32),
            inviteDigest: nil,
            peer: peer
        )
        do {
            _ = try await service.authorize(input)
            XCTFail("open-protected signup without admission must fail closed")
        } catch SwanError.unavailable(let reason) {
            XCTAssertEqual(reason, "signup admission")
        }
    }
}

private struct LocalTestEmailProofVerifier: SignupEmailProofVerifier {
    func verifySubmittedCode(_ code: String, email: AccountEmailAddress, handle: String, authorizationID: SignupAuthorizationID, proof: SignupEmailProofService, now: Date) async throws -> Data {
        guard let digest = try? proof.digest(code: code, email: email, handle: handle) else {
            return Data()
        }
        return digest
    }
}
private actor RecordingTurnstileTransport: TurnstileHTTPTransport {
    private var count = 0
    let response: TurnstileSiteVerifyResponse

    init(response: TurnstileSiteVerifyResponse = .init(success: true, challengeTimestamp: Date(), hostname: "accounts.example", action: "signup", errorCodes: [])) {
        self.response = response
    }

    func verify(_: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        count += 1
        return response
    }

    var callCount: Int {
        count
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
