import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
import XCTest
@testable import SwanOAuth

/// atproto#5569 HTTP Message Signatures. The cases mirror the reference's
/// `packages/space/src/http-signature.test.ts` at 679724ad, plus signatures
/// produced independently by Node.js `crypto.sign(..., { dsaEncoding:
/// 'ieee-p1363' })` so Swan is not only checked against itself.
final class SpaceHTTPMessageSignatureTests: XCTestCase {
    private static let authorization = "Atproto-Space credential"
    private static let audience = "did:example:repo"

    private var key: P256.Signing.PrivateKey {
        get throws { try SpaceCredentialGoldenFixtures.holderKey }
    }

    private var keyID: String { SpaceCredentialGoldenFixtures.holderKeyID }

    private func signed(
        authorization: String = authorization,
        audience: String? = audience,
        key: P256.Signing.PrivateKey? = nil
    ) throws -> Fields {
        Fields(try SpaceHTTPSignature.sign(
            authorization: authorization,
            audience: audience,
            key: key ?? self.key
        ))
    }

    func testKeyIDIsTheCanonicalP256DIDKey() throws {
        XCTAssertEqual(SpaceHTTPSignature.keyID(for: try key), keyID)
    }

    func testCredentialSignatureCoversTheRFC9421BaseWithACompactSignature() throws {
        let fields = try signed()
        XCTAssertEqual(
            fields.signatureInput,
            ["atproto-space=(\"authorization\" \"atproto-space-audience\")"]
        )
        let base = "\"authorization\": \(Self.authorization)\n"
            + "\"atproto-space-audience\": \(Self.audience)\n"
            + "\"@signature-params\": (\"authorization\" \"atproto-space-audience\")"
        let raw = try XCTUnwrap(fields.signatureBytes)
        XCTAssertEqual(raw.count, 64)
        XCTAssertTrue(try key.publicKey.isValidSignature(
            P256.Signing.ECDSASignature(rawRepresentation: raw),
            for: Data(base.utf8)
        ))
        XCTAssertEqual(try fields.verify(keyID: keyID), keyID)
    }

    func testDelegationSignatureNamesItsKeyAndHasNoAudience() throws {
        let fields = try signed(authorization: "Bearer delegation", audience: nil)
        XCTAssertEqual(fields.signatureInput, ["atproto-space=(\"authorization\");keyid=\"\(keyID)\""])
        XCTAssertNil(fields.audience)
        XCTAssertEqual(try fields.verify(keyID: nil), keyID)
        XCTAssertThrowsError(try fields.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .duplicateOrMissingField)
        }
    }

    func testIndependentNodeSignaturesVerifyIncludingHighS() throws {
        let input = "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";keyid=\"\(keyID)\""
        for signature in [NodeGoldens.credentialLowS, NodeGoldens.credentialHighS] {
            let fields = Fields(
                authorization: [Self.authorization],
                audience: [Self.audience],
                signatureInput: ["atproto-space=\(input)"],
                signature: ["atproto-space=:\(signature):"]
            )
            XCTAssertEqual(try fields.verify(keyID: keyID), keyID)
        }
        // The two goldens really are the two S forms of one signature.
        let low = try XCTUnwrap(Data(base64Encoded: NodeGoldens.credentialLowS))
        let high = try XCTUnwrap(Data(base64Encoded: NodeGoldens.credentialHighS))
        XCTAssertEqual(low.prefix(32), high.prefix(32))
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(low))
        XCTAssertFalse(P256WireSignature.isCanonicalLowS(high))

        let delegation = Fields(
            authorization: ["Bearer delegation"],
            audience: nil,
            signatureInput: ["atproto-space=(\"authorization\");keyid=\"\(keyID)\""],
            signature: ["atproto-space=:\(NodeGoldens.delegation):"]
        )
        XCTAssertEqual(try delegation.verify(keyID: nil), keyID)
    }

    func testSwanAcceptsHighSFromItsOwnSigner() throws {
        var fields = try signed()
        let raw = try XCTUnwrap(fields.signatureBytes)
        XCTAssertTrue(P256WireSignature.isCanonicalLowS(raw))
        let high = raw.prefix(32) + NodeGoldens.negate(Data(raw.suffix(32)))
        XCTAssertFalse(P256WireSignature.isCanonicalLowS(high))
        fields.signature = ["atproto-space=:\(high.base64EncodedString()):"]
        XCTAssertEqual(try fields.verify(keyID: keyID), keyID)
    }

    func testDelegationAcceptsOptionalAlg() throws {
        let input = "(\"authorization\");keyid=\"\(keyID)\";alg=\"ecdsa-p256-sha256\""
        let base = "\"authorization\": Bearer delegation\n\"@signature-params\": \(input)"
        let signature = try P256WireSignature.sign(Data(base.utf8), using: try key)
        let fields = Fields(
            authorization: ["Bearer delegation"],
            audience: nil,
            signatureInput: ["atproto-space=\(input)"],
            signature: ["atproto-space=:\(signature.base64EncodedString()):"]
        )
        XCTAssertEqual(try fields.verify(keyID: nil), keyID)
    }

    func testOptionalCredentialParametersAndOtherLabelsAreAccepted() throws {
        let input = "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";keyid=\"\(keyID)\""
        let base = "\"authorization\": \(Self.authorization)\n"
            + "\"atproto-space-audience\": \(Self.audience)\n"
            + "\"@signature-params\": \(input)"
        let signature = try P256WireSignature.sign(Data(base.utf8), using: try key)
        let combined = Fields(
            authorization: [Self.authorization],
            audience: [Self.audience],
            signatureInput: ["other=(\"authorization\");keyid=\"other\", atproto-space=\(input)"],
            signature: ["other=:YWJj:, atproto-space=:\(signature.base64EncodedString()):"]
        )
        XCTAssertEqual(try combined.verify(keyID: keyID), keyID)
        // The same members split across repeated field lines combine per
        // RFC 9110 §5.3.
        let split = Fields(
            authorization: [Self.authorization],
            audience: [Self.audience],
            signatureInput: ["other=(\"authorization\");keyid=\"other\"", "atproto-space=\(input)"],
            signature: ["other=:YWJj:", "atproto-space=:\(signature.base64EncodedString()):"]
        )
        XCTAssertEqual(try split.verify(keyID: keyID), keyID)
    }

    func testChangedAuthorizationOrAudienceIsRejected() throws {
        var changedAuthorization = try signed()
        changedAuthorization.authorization = [Self.authorization + "-changed"]
        XCTAssertThrowsError(try changedAuthorization.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidSignature)
        }
        var changedAudience = try signed()
        changedAudience.audience = [Self.audience + "-changed"]
        XCTAssertThrowsError(try changedAudience.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidSignature)
        }
    }

    func testDuplicateAuthorizationOrAudienceFieldsAreRejected() throws {
        var duplicateAuthorization = try signed()
        duplicateAuthorization.authorization = [Self.authorization, Self.authorization]
        XCTAssertThrowsError(try duplicateAuthorization.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .duplicateOrMissingField)
        }
        var duplicateAudience = try signed()
        duplicateAudience.audience = [Self.audience, Self.audience]
        XCTAssertThrowsError(try duplicateAudience.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .duplicateOrMissingField)
        }
    }

    func testMissingFieldsAreRejected() throws {
        let original = try signed()
        var fields = original
        fields.authorization = []
        XCTAssertThrowsError(try fields.verify(keyID: keyID))
        fields = original
        fields.audience = []
        XCTAssertThrowsError(try fields.verify(keyID: keyID))
        fields = original
        fields.signatureInput = []
        XCTAssertThrowsError(try fields.verify(keyID: keyID))
        fields = original
        fields.signature = []
        XCTAssertThrowsError(try fields.verify(keyID: keyID))
    }

    func testAudienceMustBeCovered() throws {
        var fields = try signed(audience: nil)
        fields.audience = [Self.audience]
        XCTAssertThrowsError(try fields.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .wrongCoveredComponents)
        }
    }

    func testAnotherSigningKeyIsRejected() throws {
        let fields = try signed(key: P256.Signing.PrivateKey())
        XCTAssertThrowsError(try fields.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidSignature)
        }
    }

    func testOptionalKeyIDMustMatchTheCredentialKey() throws {
        var fields = try signed()
        let other = SpaceHTTPSignature.keyID(for: P256.Signing.PrivateKey())
        fields.signatureInput = [fields.signatureInput[0] + ";keyid=\"\(other)\""]
        XCTAssertThrowsError(try fields.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .keyMismatch)
        }
        var tokenKeyID = try signed()
        tokenKeyID.signatureInput = [tokenKeyID.signatureInput[0] + ";keyid=abc"]
        XCTAssertThrowsError(try tokenKeyID.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .keyMismatch)
        }
    }

    func testMissingOrInvalidDelegationKeyIDIsRejected() throws {
        for parameters in ["", ";keyid", ";keyid=123", ";keyid=\"not-a-key\""] {
            var fields = try signed(authorization: "Bearer delegation", audience: nil)
            fields.signatureInput = ["atproto-space=(\"authorization\")\(parameters)"]
            XCTAssertThrowsError(try fields.verify(keyID: nil), parameters) {
                XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidKey, parameters)
            }
        }
    }

    func testCoveredComponentsMustBeExactlyTheProfiledList() throws {
        for components in [
            "(\"atproto-space-audience\")",
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
            "(\"authorization\" \"authorization\" \"atproto-space-audience\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
            "(authorization \"atproto-space-audience\")",
        ] {
            var fields = try signed()
            fields.signatureInput = ["atproto-space=\(components)"]
            XCTAssertThrowsError(try fields.verify(keyID: keyID), components) {
                XCTAssertEqual($0 as? SpaceHTTPSignatureError, .wrongCoveredComponents, components)
            }
        }
        var malformed = try signed()
        malformed.signatureInput = ["atproto-space=not-a-list"]
        XCTAssertThrowsError(try malformed.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .malformedSignature)
        }
    }

    func testCredentialSignaturesAreRejectedOnTheDelegationExchange() throws {
        XCTAssertThrowsError(try signed().verify(keyID: nil)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .wrongCoveredComponents)
        }
    }

    func testChangedSignatureParametersAreRejected() throws {
        var fields = try signed()
        fields.signatureInput = [fields.signatureInput[0] + ";alg=\"ecdsa-p256-sha256\""]
        XCTAssertThrowsError(try fields.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidSignature)
        }
    }

    func testOtherAlgorithmsAreRejected() throws {
        for audience in [nil, Self.audience] {
            var fields = try signed(audience: audience)
            fields.signatureInput = [fields.signatureInput[0] + ";alg=\"ecdsa-p384-sha384\""]
            XCTAssertThrowsError(try fields.verify(keyID: audience == nil ? nil : keyID)) {
                XCTAssertEqual($0 as? SpaceHTTPSignatureError, .unsupportedAlgorithm)
            }
        }
        var token = try signed()
        token.signatureInput = [token.signatureInput[0] + ";alg=ecdsa-p256-sha256"]
        XCTAssertThrowsError(try token.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .unsupportedAlgorithm)
        }
    }

    func testOtherKeyTypesAreRejected() throws {
        // secp256k1 did:key for scalar 2 (the ES256K credential goldens' key).
        let secp256k1 = "did:key:zQ3shajmTb29MxR6htjD79Hdo6vneJLvyKCzZSRcawNWks9JC"
        XCTAssertThrowsError(try signed().verify(keyID: secp256k1)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidKey)
        }
        var fields = try signed(authorization: "Bearer delegation", audience: nil)
        fields.signatureInput = ["atproto-space=(\"authorization\");keyid=\"\(secp256k1)\""]
        XCTAssertThrowsError(try fields.verify(keyID: nil)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidKey)
        }
    }

    func testInvalidSignatureEncodingsAreRejected() throws {
        for signature in ["not-a-byte-sequence", ":YWJj:", ":!!!:", ":YWJj:;p=1"] {
            var fields = try signed()
            fields.signature = ["atproto-space=\(signature)"]
            XCTAssertThrowsError(try fields.verify(keyID: keyID), signature)
        }
    }

    func testDEREncodedSignatureIsRejected() throws {
        var fields = try signed()
        let compact = try XCTUnwrap(fields.signatureBytes)
        let der = try P256.Signing.ECDSASignature(rawRepresentation: compact).derRepresentation
        XCTAssertTrue(try key.publicKey.isValidSignature(
            P256.Signing.ECDSASignature(derRepresentation: der),
            for: SpaceHTTPSignature.signatureBase(
                authorization: Self.authorization,
                audience: Self.audience,
                signatureParams: "(\"authorization\" \"atproto-space-audience\")"
            )
        ), "positive control: the DER form is the same valid signature")
        fields.signature = ["atproto-space=:\(der.base64EncodedString()):"]
        XCTAssertThrowsError(try fields.verify(keyID: keyID)) {
            XCTAssertEqual($0 as? SpaceHTTPSignatureError, .invalidSignature)
        }
    }

    func testSignatureIsReusableForTheSameCredentialAndAudience() throws {
        let fields = try signed()
        for _ in 0 ..< 3 {
            XCTAssertEqual(try fields.verify(keyID: keyID), keyID)
        }
    }

    func testStructuredFieldCanonicalizationFeedsTheSignatureBase() throws {
        // Extra inner-list whitespace and a non-canonical decimal parse to the
        // same RFC 8941 value; the base uses the canonical serialization.
        let canonical = "(\"authorization\" \"atproto-space-audience\");created=1;tag=1.5"
        let base = "\"authorization\": \(Self.authorization)\n"
            + "\"atproto-space-audience\": \(Self.audience)\n"
            + "\"@signature-params\": \(canonical)"
        let signature = try P256WireSignature.sign(Data(base.utf8), using: try key)
        let fields = Fields(
            authorization: [Self.authorization],
            audience: [Self.audience],
            signatureInput: ["atproto-space=(  \"authorization\"   \"atproto-space-audience\" );created=001;tag=1.500"],
            signature: ["atproto-space=:\(signature.base64EncodedString()):"]
        )
        XCTAssertEqual(try fields.verify(keyID: keyID), keyID)
    }

    func testCredentialPresentationBindsCnfKid() async throws {
        let authorityKey = P256.Signing.PrivateKey()
        let space = try SpaceURI(
            authority: "did:plc:abcdefghijklmnopqrstuvwx",
            spaceType: "app.bsky.bookmarks",
            skey: "binding"
        )
        let now = Date()
        let token = try PermissionedDataJWT.createSpaceCredential(
            issuer: space.authority,
            space: space,
            key: authorityKey,
            confirmationKeyID: keyID,
            now: now
        )
        XCTAssertEqual(try PermissionedDataJWT.inspectSpaceCredential(token).claims.cnf.kid, keyID)
        let verifier = DurableSpaceCredentialVerifier(
            publicKeys: try PinnedSpaceCredentialPublicKeyResolver(pins: [
                try .init(authority: space.authority, generation: 1, publicKey: authorityKey.publicKey),
            ])
        )
        let authorization = "Atproto-Space \(token)"
        let good = try signed(authorization: authorization, audience: "did:plc:repoowner")
        let verified = try await verifier.verifiedPresentation(
            token, expectedSpace: space, presentation: good.presentation, now: now
        )
        XCTAssertEqual(verified.audience, "did:plc:repoowner")
        XCTAssertEqual(verified.credentialID, try PermissionedDataJWT.inspectSpaceCredential(token).claims.jti)

        // Signed by a key other than cnf.kid.
        let wrongKey = try signed(
            authorization: authorization,
            audience: "did:plc:repoowner",
            key: P256.Signing.PrivateKey()
        )
        await assertPresentationFailure(.badSignature) {
            try await verifier.verifiedPresentation(
                token, expectedSpace: space, presentation: wrongKey.presentation, now: now
            )
        }
        // An audience that is not a DID.
        let notDID = try signed(authorization: authorization, audience: "repo.example.com")
        await assertPresentationFailure(.badSignature) {
            try await verifier.verifiedPresentation(
                token, expectedSpace: space, presentation: notDID.presentation, now: now
            )
        }
        // A signed Authorization value that is not this credential.
        let otherToken = try signed(authorization: "Atproto-Space other", audience: "did:plc:repoowner")
        await assertPresentationFailure(.badSignature) {
            try await verifier.verifiedPresentation(
                token, expectedSpace: space, presentation: otherToken.presentation, now: now
            )
        }

        for invalid in ["", "not-a-did-key", keyID + "x", "did:key:zQ3shajmTb29MxR6htjD79Hdo6vneJLvyKCzZSRcawNWks9JC"] {
            XCTAssertThrowsError(try PermissionedDataJWT.createSpaceCredential(
                issuer: space.authority, space: space, key: authorityKey,
                confirmationKeyID: invalid, now: now
            ), invalid)
        }
    }

    private func assertPresentationFailure<T>(
        _ expected: SpaceCredentialPresentationFailure,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ operation: () async throws -> T
    ) async {
        do {
            _ = try await operation()
            XCTFail("presentation was accepted", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? SpaceCredentialPresentationFailure, expected, file: file, line: line)
        }
    }
}

private struct Fields {
    var authorization: [String]
    var audience: [String]?
    var signatureInput: [String]
    var signature: [String]

    init(authorization: [String], audience: [String]?, signatureInput: [String], signature: [String]) {
        self.authorization = authorization
        self.audience = audience
        self.signatureInput = signatureInput
        self.signature = signature
    }

    init(_ headers: SpaceHTTPSignature.Headers) {
        authorization = [headers.authorization]
        audience = headers.audience.map { [$0] }
        signatureInput = [headers.signatureInput]
        signature = [headers.signature]
    }

    var signatureBytes: Data? {
        guard let value = signature.first,
              value.hasPrefix("atproto-space=:"), value.hasSuffix(":") else { return nil }
        return Data(base64Encoded: String(value.dropFirst("atproto-space=:".count).dropLast()))
    }

    var presentation: SpaceCredentialHTTPPresentation {
        SpaceCredentialHTTPPresentation(
            authorization: authorization,
            audience: audience ?? [],
            signatureInput: signatureInput,
            signature: signature
        )
    }

    func verify(keyID: String?) throws -> String {
        try SpaceHTTPSignature.verify(
            authorization: authorization,
            audience: keyID == nil ? audience : (audience ?? []),
            signatureInput: signatureInput,
            signature: signature,
            credentialKeyID: keyID
        )
    }
}

/// Signatures over ``SpaceHTTPMessageSignatureTests`` bases produced by
/// Node.js v22 `crypto.sign('sha256', base, { key, dsaEncoding:
/// 'ieee-p1363' })` with the P-256 scalar `0x3c` repeated, and confirmed with
/// `crypto.verify` (which, like the reference, accepts both S forms).
private enum NodeGoldens {
    /// Credential use with `;alg="ecdsa-p256-sha256";keyid="<holder>"`.
    static let credentialLowS =
        "4jA67cZT0OUNrEC1yBckd6VwFDDk55koukqW2/gjg0ZDRA6gJ9XMALoAedFLueBJG56XAstR+EAYMJQv5qBWkQ=="
    static let credentialHighS =
        "4jA67cZT0OUNrEC1yBckd6VwFDDk55koukqW2/gjg0a8u/Fe2Co0AEX/hi60Rh+2oUhjqtvFpkTbiTaTFcLOwA=="
    /// Delegation exchange, minimal `("authorization");keyid="<holder>"`.
    static let delegation =
        "Mi+Dvgl44u9gYcZ+a2P5ppu5nHKyuvOzcu9e6ShvyDRAQTouF8Np0fAmB4+35oshNlkS1V3X7UNDOl94cWO/NA=="

    private static let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]

    /// `n - s` for a 32-byte big-endian scalar.
    static func negate(_ s: Data) -> Data {
        let value = [UInt8](s)
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var difference = Int(order[index]) - Int(value[index]) - borrow
            borrow = difference < 0 ? 1 : 0
            if difference < 0 { difference += 256 }
            result[index] = UInt8(difference)
        }
        return Data(result)
    }
}
