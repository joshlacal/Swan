import Crypto
import XCTest
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanStorage

final class SwanDidWebIdentityTests: XCTestCase {
    private let did = "did:web:example.com"
    private let handle = "alice.example"
    private let pds = "https://pds.example.test"
    private let issuer = "https://swan.example.test"

    func testCanonicalClaimBytesAreLengthDelimitedAndStable() throws {
        let nonce = Data(repeating: 7, count: 32)
        let first = try SwanDidWebClaimCanonicalizer.canonicalBytes(
            did: did, handle: handle, pdsURL: pds, keyID: "#atproto",
            keyType: "Multikey", publicKey: Data(repeating: 1, count: 32), nonce: nonce,
            expiresAt: Date(timeIntervalSince1970: 1.234)
        )
        let second = try SwanDidWebClaimCanonicalizer.canonicalBytes(
            did: did, handle: handle, pdsURL: pds, keyID: "#atproto",
            keyType: "Multikey", publicKey: Data(repeating: 1, count: 32), nonce: nonce,
            expiresAt: Date(timeIntervalSince1970: 1.234)
        )
        XCTAssertEqual(first, second)
        XCTAssertEqual(first.prefix(SwanDidWebClaimCanonicalizer.domainSeparator.count), SwanDidWebClaimCanonicalizer.domainSeparator)
        XCTAssertEqual(
            SwanDidWebClaimCanonicalizer.receiptDigest(for: first).count, 32
        )
    }

    func testDocumentValidationRequiresExactSubjectAliasKeyEndpointAndClaimService() throws {
        let key = try SwanReservedSigningKey(
            keyID: "#atproto", keyType: "Multikey", publicKey: Data(repeating: 1, count: 32)
        )
        let nonce = Data(repeating: 9, count: 32)
        let claimEndpoint = "\(issuer)/.well-known/swan/did-web-claim/\(nonce.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""))"
        let json = try SwanDidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: key, claimEndpoint: claimEndpoint
        )
        let validated = try SwanDidWebDocumentValidator.validate(
            json: json, did: did, handle: handle, pdsURL: pds,
            reservedKey: key, claimEndpoint: claimEndpoint
        )
        XCTAssertEqual(validated.did, did)
        XCTAssertEqual(validated.documentDigest.count, 32)
        XCTAssertThrowsError(try SwanDidWebDocumentValidator.validate(
            json: json, did: "did:web:other.example", handle: handle, pdsURL: pds,
            reservedKey: key, claimEndpoint: claimEndpoint
        ))
    }

    func testReservationAndClaimAreOneTimeAndRetryIsIdempotent() async throws {
        let keys = InMemorySwanSigningKeyReservationService()
        let store = InMemoryIdentityBindingStore()
        let stepUps = InMemorySwanStepUpReceiptConsumptionStore()
        let service = SwanDidWebIdentityService(
            reservations: keys, bindings: store, publicPDSURL: pds, publicURL: issuer, stepUps: stepUps
        )
        let reservation = try await service.reserveSigningKey(
            requestID: "claim-1", accountDID: "did:plc:abcdefghijklmnopqrstuvwx",
            targetDID: did, handle: handle, expiresAt: Date().addingTimeInterval(300)
        )
        let json = try SwanDidWebDocumentFixture.json(
            did: did, handle: handle, pds: pds, key: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        let result = try await service.claim(
            reservation: reservation, documentJSON: json, now: Date()
        )
        let retry = try await service.claim(
            reservation: reservation, documentJSON: json, now: Date()
        )
        XCTAssertEqual(result, retry)
        let replayedNonce = try SwanDidWebClaimReservation(
            requestID: "claim-2", accountDID: "did:plc:bcdefghijklmnopqrstuvwxy",
            targetDID: reservation.targetDID, handle: reservation.handle,
            key: reservation.key, nonce: reservation.nonce,
            expiresAt: reservation.expiresAt, claimBytes: reservation.claimBytes,
            claimReceiptDigest: reservation.claimReceiptDigest,
            claimServiceEndpoint: reservation.claimServiceEndpoint
        )
        await XCTAssertThrowsAsyncError {
            _ = try await service.claim(reservation: replayedNonce, documentJSON: json, now: Date())
        }
    }

    func testForgedReservationAndReplacementRequireFreshAccountBoundStepUp() async throws {
        let keys = InMemorySwanSigningKeyReservationService()
        let store = InMemoryIdentityBindingStore()
        let service = SwanDidWebIdentityService(reservations: keys, bindings: store, publicPDSURL: pds, publicURL: issuer, gracePeriod: 120, replacementAuthorizer: TestReplacementAuthorizer(), stepUps: InMemorySwanStepUpReceiptConsumptionStore())
        let account = "did:plc:abcdefghijklmnopqrstuvwx"
        let reservation = try await service.reserveSigningKey(requestID: "replace-1", accountDID: account, targetDID: did, handle: handle, expiresAt: Date().addingTimeInterval(300))
        let json = try SwanDidWebDocumentFixture.json(did: did, handle: handle, pds: pds, key: reservation.key, claimEndpoint: reservation.claimServiceEndpoint)
        _ = try await service.claim(reservation: reservation, documentJSON: json)

        let forged = try SwanDidWebClaimReservation(
            requestID: reservation.requestID, accountDID: account, targetDID: reservation.targetDID,
            handle: reservation.handle, key: reservation.key, nonce: Data(repeating: 1, count: 32),
            expiresAt: reservation.expiresAt, claimBytes: reservation.claimBytes,
            claimReceiptDigest: reservation.claimReceiptDigest, claimServiceEndpoint: reservation.claimServiceEndpoint)
        await XCTAssertThrowsAsyncError { _ = try await service.claim(reservation: forged, documentJSON: json) }

        let replacement = try await service.reserveSigningKey(requestID: "replace-2", accountDID: account, targetDID: "did:web:new.example", handle: handle, expiresAt: Date().addingTimeInterval(300))
        let replacementJSON = try SwanDidWebDocumentFixture.json(did: replacement.targetDID, handle: handle, pds: pds, key: replacement.key, claimEndpoint: replacement.claimServiceEndpoint)
        await XCTAssertThrowsAsyncError { _ = try await service.claim(reservation: replacement, documentJSON: replacementJSON) }
        let auth = try SwanDidWebReplacementAuthorization(accountDID: account, sessionAccountDID: account, sessionID: "session-1", stepUpAt: Date(), stepUpReceiptDigest: Data(repeating: 7, count: 32), mfaStrength: .phishingResistant)
        _ = try await service.claim(reservation: replacement, documentJSON: replacementJSON, authorization: auth)
    }

    func testProviderReleaseReclaimsReservationAndJCSCanonicalizesEdges() async throws {
        let keys = InMemorySwanSigningKeyReservationService()
        let first = try await keys.reserveSigningKey(requestID: "release-1")
        try await keys.releaseSigningKeyReservation(requestID: "release-1")
        let second = try await keys.reserveSigningKey(requestID: "release-1")
        XCTAssertNotEqual(first.nonce, second.nonce)
        let input = Data(#"{"b":1.0,"a":1e-6,"n":-1e-6,"s":"slash/é"}"#.utf8)
        XCTAssertEqual(String(data: try SwanRFC8785JSON.canonicalize(input), encoding: .utf8), #"{"a":0.000001,"b":1,"n":-0.000001,"s":"slash/é"}"#)
    }

    func testConfiguredGracePersistsTransientFailureThenSuspendsAndFencesAdmission() async throws {
        let keys = InMemorySwanSigningKeyReservationService()
        let store = InMemoryIdentityBindingStore()
        let service = SwanDidWebIdentityService(reservations: keys, bindings: store, publicPDSURL: pds, publicURL: issuer, gracePeriod: 120, stepUps: InMemorySwanStepUpReceiptConsumptionStore())
        let account = "did:plc:abcdefghijklmnopqrstuvwx"
        let reservation = try await service.reserveSigningKey(requestID: "grace-1", accountDID: account, targetDID: did, handle: handle, expiresAt: Date().addingTimeInterval(300))
        let json = try SwanDidWebDocumentFixture.json(did: did, handle: handle, pds: pds, key: reservation.key, claimEndpoint: reservation.claimServiceEndpoint)
        _ = try await service.claim(reservation: reservation, documentJSON: json)
        guard let active = try await store.identityBinding(accountDID: account) else {
            XCTFail("claim did not persist binding"); return
        }
        let transient = try IdentityBinding(accountDID: active.accountDID, identityDID: active.identityDID, method: active.method, handle: active.handle, documentDigest: active.documentDigest, claimReceiptDigest: active.claimReceiptDigest, reservedKeyID: active.reservedKeyID, lastValidatedAt: active.lastValidatedAt, graceExpiresAt: active.graceExpiresAt, state: .active)
        _ = try await store.persistIdentityContinuity(transient)
        let persistedTransient = try await store.identityBinding(accountDID: account)
        XCTAssertEqual(persistedTransient?.state, .active)
        let decision = await service.admission(for: transient, now: Date(), revalidationFailed: true)
        XCTAssertTrue(decision.allowsRead); XCTAssertFalse(decision.allowsWrite); XCTAssertFalse(decision.allowsTokenIssuance)
        let expired = try IdentityBinding(accountDID: active.accountDID, identityDID: active.identityDID, method: active.method, handle: active.handle, documentDigest: active.documentDigest, claimReceiptDigest: active.claimReceiptDigest, reservedKeyID: active.reservedKeyID, lastValidatedAt: active.lastValidatedAt, graceExpiresAt: active.graceExpiresAt, state: .suspended)
        _ = try await store.persistIdentityContinuity(expired)
        let persistedSuspended = try await store.identityBinding(accountDID: account)
        XCTAssertEqual(persistedSuspended?.state, .suspended)
    }

    func testProviderCommitFailureIsRepairableByIdempotentRetry() async throws {
        let keys = InMemorySwanSigningKeyReservationService()
        let store = InMemoryIdentityBindingStore()
        let service = SwanDidWebIdentityService(reservations: keys, bindings: store, publicPDSURL: pds, publicURL: issuer, stepUps: InMemorySwanStepUpReceiptConsumptionStore())
        let reservation = try await service.reserveSigningKey(requestID: "repair-1", accountDID: "did:plc:abcdefghijklmnopqrstuvwx", targetDID: did, handle: handle, expiresAt: Date().addingTimeInterval(300))
        let json = try SwanDidWebDocumentFixture.json(did: did, handle: handle, pds: pds, key: reservation.key, claimEndpoint: reservation.claimServiceEndpoint)
        await keys.failNextCommitFinalization()
        await XCTAssertThrowsAsyncError { _ = try await service.claim(reservation: reservation, documentJSON: json) }
        let repaired = try await service.claim(reservation: reservation, documentJSON: json)
        XCTAssertEqual(repaired.identityDID, did)
    }

    func testContinuityGraceFencesWritesButPreservesReads() throws {
        let now = Date(timeIntervalSince1970: 100)
        XCTAssertEqual(
            SwanIdentityContinuity.evaluate(state: .active, lastValidatedAt: now, now: now.addingTimeInterval(60), grace: 86_400),
            .active
        )
        XCTAssertEqual(
            SwanIdentityContinuity.evaluate(state: .active, lastValidatedAt: now, now: now.addingTimeInterval(86_401), grace: 86_400),
            .suspended
        )
        XCTAssertTrue(SwanIdentityContinuity.allowsRead(.suspended))
        XCTAssertFalse(SwanIdentityContinuity.allowsWrite(.suspended))
    }

}

private extension XCTestCase {
    func XCTAssertThrowsAsyncError(_ expression: @escaping () async throws -> Void) async {
        do { try await expression(); XCTFail("expected error") } catch { }
    }
}

private enum SwanDidWebDocumentFixture {
    static func json(did: String, handle: String, pds: String, key: SwanReservedSigningKey, claimEndpoint: String) throws -> Data {
        let object: [String: Any] = [
            "id": did,
            "alsoKnownAs": ["at://\(handle)"],
            "verificationMethod": [["id": "\(did)\(key.keyID)", "type": key.keyType, "controller": did, "publicKeyMultibase": try SwanATMultikey.encode(publicKey: key.publicKey)]],
            "assertionMethod": ["\(did)\(key.keyID)"],
            "service": [["id": "\(did)#pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": pds], ["id": "\(did)#swan-claim", "type": "SwanDidWebClaim", "serviceEndpoint": claimEndpoint]],
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }
}

private struct TestReplacementAuthorizer: SwanDidWebReplacementAuthorizing {
    func authorize(_ authorization: SwanDidWebReplacementAuthorization, now: Date) async throws -> Bool {
        authorization.accountDID == authorization.sessionAccountDID && authorization.stepUpAt <= now
    }
}
