import Crypto
import XCTest
@testable import SwanAccounts
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
            keyType: "Multikey", publicKey: Data([1, 2, 3]), nonce: nonce,
            expiresAt: Date(timeIntervalSince1970: 1.234)
        )
        let second = try SwanDidWebClaimCanonicalizer.canonicalBytes(
            did: did, handle: handle, pdsURL: pds, keyID: "#atproto",
            keyType: "Multikey", publicKey: Data([1, 2, 3]), nonce: nonce,
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
            keyID: "#atproto", keyType: "Multikey", publicKey: Data([1, 2, 3])
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
        let service = SwanDidWebIdentityService(
            reservations: keys, bindings: store, publicPDSURL: pds, publicURL: issuer
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
            "verificationMethod": [["id": "\(did)\(key.keyID)", "type": key.keyType, "controller": did, "publicKeyBase64": key.publicKey.base64EncodedString()]],
            "assertionMethod": ["\(did)\(key.keyID)"],
            "service": [["id": "\(did)#pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": pds], ["id": "\(did)#swan-claim", "type": "SwanDidWebClaim", "serviceEndpoint": claimEndpoint]],
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }
}
