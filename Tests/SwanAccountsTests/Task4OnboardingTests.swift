import Crypto
@testable import SwanAccounts
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
}

private struct StubTurnstileTransport: TurnstileHTTPTransport {
    let response: TurnstileSiteVerifyResponse
    func verify(_: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        response
    }
}
