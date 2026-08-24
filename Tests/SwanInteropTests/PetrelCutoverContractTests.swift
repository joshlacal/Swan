import Crypto
import Foundation
import Petrel
import PetrelCrypto
import PetrelFirehose
import PetrelPLC
import PetrelRepo
import XCTest
final class PetrelCutoverContractTests: XCTestCase {
    func testPublicRepositoryTIDAcceptsAndPreservesRevision() throws {
        let rev = "3jzfcijpj2z2a"
        let tid = try PublicRepositoryTID(rev)
        XCTAssertEqual(tid.value, rev)
        XCTAssertEqual(tid.description, rev)
    }

    func testFirehoseFrameLimitsAcceptsValidSequenceAndRejectsZero() throws {
        XCTAssertNoThrow(try FirehoseFrameLimits.validateSequence(1))
        XCTAssertThrowsError(try FirehoseFrameLimits.validateSequence(0))
    }

    func testAccountIdentifiersValidatesPLCAndCanonicalizesHandle() throws {
        let validDID = "did:plc:z72i7hdynmk6r22z27h6tvur"
        let validated = try AccountIdentifiers.validateDID(validDID)
        XCTAssertEqual(validated, validDID)

        let canonical = try AccountIdentifiers.canonicalHandle("Alice.Example.COM")
        XCTAssertEqual(canonical, "alice.example.com")
    }

    func testHexRoundtripsBytes() {
        let original = Data([0x00, 0xab, 0xff])
        let encoded = Hex.encode(original)
        XCTAssertEqual(encoded.lowercased(), "00abff")
        let decoded = Hex.decode(encoded)
        XCTAssertEqual(decoded, original)
    }

    func testP256WireSignatureProducesCanonicalLowS() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("contract-test-message".utf8)
        let signature = try P256WireSignature.sign(message, using: key)
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(signature))
        let decoded = try P256WireSignature.decodeCanonical(signature)
        XCTAssertTrue(key.publicKey.isValidSignature(decoded, for: message))
    }

    func testStrictJSONRejectsDuplicateKeys() throws {
        let valid = Data(#"{"a": 1, "b": 2}"#.utf8)
        XCTAssertNoThrow(try StrictJSON.validate(valid))
        let duplicate = Data(#"{"a": 1, "a": 2}"#.utf8)
        XCTAssertThrowsError(try StrictJSON.validate(duplicate))
    }

    func testServiceJWTMintAndVerify() throws {
        let key = P256.Signing.PrivateKey()
        let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
        let audience = "did:web:api.bsky.app"
        let token = try ProxyServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: "app.bsky.actor.getProfile",
            eventID: "event-123",
            key: key,
            lifetime: 60
        )
        let verificationKey = ATProtoJWTVerificationKey.p256(key.publicKey)
        let claims = try SpaceServiceJWT.verify(
            token,
            publicKey: verificationKey,
            expectedAudience: audience,
            expectedMethod: "app.bsky.actor.getProfile"
        )
        XCTAssertEqual(claims.iss, issuer)
        XCTAssertEqual(claims.aud, audience)
        XCTAssertEqual(claims.lxm, "app.bsky.actor.getProfile")
        XCTAssertEqual(claims.jti, "event-123")
    }
}
