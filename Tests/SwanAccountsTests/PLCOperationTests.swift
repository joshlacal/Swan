import Crypto
import Foundation
import Petrel
import SwanCore
import SwanStorage
import XCTest
@testable import SwanAccounts

final class PLCOperationTests: XCTestCase {
    private let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
    private let rotationKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))

    func testP256DIDKeyMatchesPinnedTypeScriptCompressedGoldenAndRoundTrips() throws {
        let encoded = SwanAccounts.P256DIDKey(publicKey: privateKey.publicKey)
        XCTAssertEqual(
            encoded.value,
            "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF"
        )
        XCTAssertEqual(try SwanAccounts.P256DIDKey(encoded.value).publicKey.x963Representation, privateKey.publicKey.x963Representation)
        XCTAssertEqual(try SwanAccounts.P256DIDKey(encoded.value).value, encoded.value)
    }

    func testP256DIDKeyRejectsWrongCodecUncompressedPointAndNonCanonicalBase58() throws {
        let valid = SwanAccounts.P256DIDKey(publicKey: privateKey.publicKey).value
        for malformed in [
            valid.replacingOccurrences(of: "did:key:z", with: "did:key:x"),
            "did:key:z\(String(valid.dropFirst("did:key:z".count)).uppercased())",
            "did:key:z1\(valid.dropFirst("did:key:z".count))",
            "did:key:z6MkiTBz1yXLP7QKgQDeq5DgxdBdXKvg8u3Yu1B7S5K6M2HTh",
            "did:key:z4oJ8aP4p91UJupm9qqYqdmqYucG7LvoPBydLL1FY5JhmF6gqCeLRyBYB7vM7GXKPyhujKbVUqZh9gQ5rvuz49hchqusY",
        ] {
            XCTAssertThrowsError(try SwanAccounts.P256DIDKey(malformed), malformed)
        }
    }

    func testSecp256k1DIDKeyCodecAcceptsPinnedTypeScriptFormOnly() throws {
        let value = "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc"
        let key = try SwanAccounts.PLCDIDKeyCodec.decode(value)
        guard case let .secp256k1(bytes) = key else {
            return XCTFail("expected secp256k1 key")
        }
        XCTAssertEqual(bytes.count, 33)
        XCTAssertEqual(bytes.first, 0x03)
        XCTAssertTrue(SwanAccounts.PLCDIDKeyCodec.isCanonical(value))
        XCTAssertThrowsError(try SwanAccounts.PLCDIDKeyCodec.decode(
            value.replacingOccurrences(of: "zQ3s", with: "zDna")
        ))
    }

    func testATProfileCreatesExactGenesisMapsAndOriginPolicy() throws {
        let unsigned = try PLCATProfile.regularOperation(
            handle: "Alice.Example.COM",
            signingPublicKey: privateKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        XCTAssertEqual(unsigned.alsoKnownAs, ["at://alice.example.com"])
        XCTAssertEqual(unsigned.verificationMethods, ["atproto": SwanAccounts.P256DIDKey(publicKey: privateKey.publicKey).value])
        XCTAssertEqual(unsigned.rotationKeys, [SwanAccounts.P256DIDKey(publicKey: rotationKey.publicKey).value])
        XCTAssertEqual(
            unsigned.services,
            ["atproto_pds": .init(type: "AtprotoPersonalDataServer", endpoint: "https://pds.example.com")]
        )
        XCTAssertNil(unsigned.prev)

        for rejected in [
            "http://pds.example.com", "https://pds.example.com/path",
            "https://user@pds.example.com", "https://pds.example.com?x=1",
            "http://localhost:2583", "http://192.168.1.2:2583",
        ] {
            XCTAssertThrowsError(try PLCATProfile.regularOperation(
                handle: "alice.example.com",
                signingPublicKey: privateKey.publicKey,
                rotationPublicKeys: [rotationKey.publicKey],
                pdsOrigin: URL(string: rejected)!,
                prev: nil
            ), rejected)
        }
        XCTAssertNoThrow(try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: privateKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "http://127.0.0.1:2583")!,
            prev: nil
        ))
    }

    func testRegularOperationSigningCIDAndGenesisDIDAreStable() throws {
        let signed = try PLCOperationCodec.decodeSignedJSON(Data(Self.goldenOperationJSON.utf8))
        XCTAssertEqual(
            try signed.canonicalDAGCBOR,
            try PLCOperationCodec.decodeSignedJSON(signed.canonicalJSON).canonicalDAGCBOR
        )
        XCTAssertEqual(try signed.cid, CID.fromDAGCBOR(try signed.canonicalDAGCBOR))
        XCTAssertEqual(try signed.cid.string, "bafyreig2iwkavnqsibui4muzj7bbs5rnpxf332w3fgdzyusjkaqoxp7xfq")
        XCTAssertEqual(try PLCOperationCodec.genesisDID(for: signed).count, 32)
        XCTAssertEqual(try PLCOperationCodec.genesisDID(for: signed), "did:plc:3jczicvwcjagrdrstfh4eglw")
        XCTAssertNoThrow(try PLCOperationCodec.verifyGenesis(signed, expectedDID: "did:plc:3jczicvwcjagrdrstfh4eglw"))
    }

    func testPublicIdentityVerifierAuthenticatesCompleteGenesisAndRejectsTampering() throws {
        let operation = try PLCOperationCodec.sign(
            .regular(try profileUnsigned()),
            using: rotationKey
        )
        let regular = try XCTUnwrap(operation.regular)
        let did = try PLCOperationCodec.genesisDID(for: operation)
        let facts = PublicPLCGenesisFacts(
            signingDIDKey: try XCTUnwrap(
                regular.verificationMethods["atproto"]
            ),
            rotationDIDKey: try XCTUnwrap(regular.rotationKeys.first),
            canonicalHandle: "alice.example.com",
            pdsOrigin: "https://pds.example.com",
            signature: regular.signature
        )
        let verifier = SwanPublicPLCGenesisVerifier()
        XCTAssertEqual(
            try verifier.verifyGenesis(facts: facts, expectedDID: did),
            try operation.cid.string
        )
        XCTAssertThrowsError(try verifier.verifyGenesis(
            facts: .init(
                signingDIDKey: facts.signingDIDKey,
                rotationDIDKey: facts.rotationDIDKey,
                canonicalHandle: "tampered.example.com",
                pdsOrigin: facts.pdsOrigin,
                signature: facts.signature
            ),
            expectedDID: did
        ))
        // Mutate a significant base64url character.  Replacing only the
        // final character can be a no-op when the generated signature already
        // ends in `A`, which made this negative assertion probabilistic.
        let tamperedSignature = String(
            facts.signature.first == "A" ? "B" : "A"
        ) + facts.signature.dropFirst()
        XCTAssertThrowsError(try verifier.verifyGenesis(
            facts: .init(
                signingDIDKey: facts.signingDIDKey,
                rotationDIDKey: facts.rotationDIDKey,
                canonicalHandle: facts.canonicalHandle,
                pdsOrigin: facts.pdsOrigin,
                signature: tamperedSignature
            ),
            expectedDID: did
        ))
        XCTAssertThrowsError(try verifier.verifyGenesis(
            facts: facts,
            expectedDID: "did:plc:abcdefghijklmnopqrstuvwx"
        ))
    }

    func testPublicIdentityHistoryAuthenticatesRotationAndRejectsBranches() throws {
        let genesis = try PLCOperationCodec.sign(
            .regular(try profileUnsigned()),
            using: rotationKey
        )
        let did = try PLCOperationCodec.genesisDID(for: genesis)
        let nextSigningKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 11, count: 32)
        )
        let nextRotationKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 13, count: 32)
        )
        let rotatedUnsigned = try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: nextSigningKey.publicKey,
            rotationPublicKeys: [nextRotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: try genesis.cid.string
        )
        let rotated = try PLCOperationCodec.sign(
            .regular(rotatedUnsigned),
            using: rotationKey
        )
        let genesisEntry = try PublicPLCOperationHistoryEntry(
            cid: try genesis.cid.string,
            previousCID: nil,
            canonicalJSON: try genesis.canonicalJSON,
            createdAt: Date(timeIntervalSince1970: 1),
            signingKeyGeneration: 1,
            rotationKeyGeneration: 1
        )
        let rotatedEntry = try PublicPLCOperationHistoryEntry(
            cid: try rotated.cid.string,
            previousCID: try genesis.cid.string,
            canonicalJSON: try rotated.canonicalJSON,
            createdAt: Date(timeIntervalSince1970: 2),
            signingKeyGeneration: 2,
            rotationKeyGeneration: 2
        )

        let state = try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
            [genesisEntry, rotatedEntry],
            expectedDID: did
        )
        XCTAssertEqual(state.genesisOperationCID, genesisEntry.cid)
        XCTAssertEqual(state.terminalOperationCID, rotatedEntry.cid)
        XCTAssertEqual(state.keyGeneration, 2)
        XCTAssertEqual(
            state.signingDIDKey,
            SwanAccounts.P256DIDKey(publicKey: nextSigningKey.publicKey).value
        )

        let wrongParent = try PublicPLCOperationHistoryEntry(
            cid: rotatedEntry.cid,
            previousCID: nil,
            canonicalJSON: rotatedEntry.canonicalJSON,
            createdAt: rotatedEntry.createdAt,
            signingKeyGeneration: 2,
            rotationKeyGeneration: 2
        )
        XCTAssertThrowsError(try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
            [genesisEntry, wrongParent],
            expectedDID: did
        ))

        let generationGap = try PublicPLCOperationHistoryEntry(
            cid: rotatedEntry.cid,
            previousCID: rotatedEntry.previousCID,
            canonicalJSON: rotatedEntry.canonicalJSON,
            createdAt: rotatedEntry.createdAt,
            signingKeyGeneration: 3,
            rotationKeyGeneration: 3
        )
        XCTAssertThrowsError(try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
            [genesisEntry, generationGap],
            expectedDID: did
        ))

        let attacker = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 17, count: 32)
        )
        let forged = try PLCOperationCodec.sign(
            .regular(rotatedUnsigned),
            using: attacker
        )
        let forgedEntry = try PublicPLCOperationHistoryEntry(
            cid: try forged.cid.string,
            previousCID: try genesis.cid.string,
            canonicalJSON: try forged.canonicalJSON,
            createdAt: Date(timeIntervalSince1970: 2),
            signingKeyGeneration: 2,
            rotationKeyGeneration: 2
        )
        XCTAssertThrowsError(try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
            [genesisEntry, forgedEntry],
            expectedDID: did
        ))
    }

    func testSigningBytesOmitSignatureAndGenesisPrevIsExplicitNull() throws {
        let signed = try PLCOperationCodec.sign(.regular(try profileUnsigned()), using: rotationKey)
        let json = String(decoding: try signed.canonicalJSON, as: UTF8.self)
        XCTAssertTrue(json.contains(#""prev":null"#))
        XCTAssertTrue(json.contains(#""sig":"#))
        XCTAssertFalse(String(decoding: try signed.signingDAGCBOR, as: UTF8.self).contains("sig"))
        XCTAssertLessThan(try signed.signingDAGCBOR.count, try signed.canonicalDAGCBOR.count)
    }

    func testUpdateRequiresCanonicalDAGCBORSHA256CIDString() throws {
        let genesis = try PLCOperationCodec.sign(.regular(try profileUnsigned()), using: rotationKey)
        let update = try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: privateKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://new.example.com")!,
            prev: genesis.cid.string
        )
        let signedUpdate = try PLCOperationCodec.sign(.regular(update), using: rotationKey)
        XCTAssertEqual(try PLCOperationCodec.verify(
            signedUpdate,
            authorizedRotationKeys: [
                SwanAccounts.P256DIDKey(publicKey: privateKey.publicKey).value,
                SwanAccounts.P256DIDKey(publicKey: rotationKey.publicKey).value,
            ]
        ), 1)
        for invalid in [
            CID.fromBlob(Data("wrong-codec".utf8)).string,
            try genesis.cid.string.uppercased(),
            "not-a-cid",
        ] {
            XCTAssertThrowsError(try PLCATProfile.regularOperation(
                handle: "alice.example.com",
                signingPublicKey: privateKey.publicKey,
                rotationPublicKeys: [rotationKey.publicKey],
                pdsOrigin: URL(string: "https://new.example.com")!,
                prev: invalid
            ))
        }
    }

    func testTombstoneSignsItsCanonicalPrevAndVerifiesWithPriorRotationKey() throws {
        let genesis = try PLCOperationCodec.sign(.regular(try profileUnsigned()), using: rotationKey)
        let tombstone = try PLCOperationCodec.sign(
            .tombstone(.init(prev: genesis.cid.string)),
            using: rotationKey
        )
        XCTAssertNil(tombstone.regular)
        XCTAssertEqual(tombstone.prev, try genesis.cid.string)
        XCTAssertEqual(try tombstone.cid, CID.fromDAGCBOR(try tombstone.canonicalDAGCBOR))
        XCTAssertNoThrow(try PLCOperationCodec.verify(
            tombstone,
            authorizedRotationKeys: [SwanAccounts.P256DIDKey(publicKey: rotationKey.publicKey).value]
        ))
        let json = String(decoding: try tombstone.canonicalJSON, as: UTF8.self)
        XCTAssertTrue(json.contains(#""type":"plc_tombstone""#))
        XCTAssertFalse(json.contains("rotationKeys"))
        XCTAssertThrowsError(try PLCUnsignedTombstoneOperation(
            prev: CID.fromBlob(Data("not dag-cbor".utf8)).string
        ))
    }

    func testRejectsDuplicateRotationKeysHighSSignatureTamperingAndOversize() throws {
        let didKey = SwanAccounts.P256DIDKey(publicKey: rotationKey.publicKey).value
        XCTAssertThrowsError(try PLCUnsignedRegularOperation(
            rotationKeys: [didKey, didKey],
            verificationMethods: ["atproto": SwanAccounts.P256DIDKey(publicKey: privateKey.publicKey).value],
            alsoKnownAs: ["at://alice.example.com"],
            services: ["atproto_pds": .init(type: "AtprotoPersonalDataServer", endpoint: "https://pds.example.com")],
            prev: nil
        ))

        let signed = try PLCOperationCodec.sign(.regular(try profileUnsigned()), using: rotationKey)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: signed.canonicalJSON) as? [String: Any])
        object["alsoKnownAs"] = ["at://mallory.example.com"]
        let tampered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertThrowsError(try PLCOperationCodec.verifyGenesis(
            PLCOperationCodec.decodeSignedJSON(tampered),
            expectedDID: try PLCOperationCodec.genesisDID(for: signed)
        ))

        object = try XCTUnwrap(JSONSerialization.jsonObject(with: signed.canonicalJSON) as? [String: Any])
        let canonical = try XCTUnwrap(Data(base64URLEncodedWithoutPadding: object["sig"] as! String))
        object["sig"] = highSSignature(from: canonical).base64URLEncodedWithoutPadding
        XCTAssertThrowsError(try PLCOperationCodec.decodeSignedJSON(
            JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        ))

        let oversizedAKA = Array(repeating: "https://example.com/" + String(repeating: "x", count: 1_000), count: 8)
        XCTAssertThrowsError(try PLCUnsignedRegularOperation(
            rotationKeys: [didKey],
            verificationMethods: ["atproto": SwanAccounts.P256DIDKey(publicKey: privateKey.publicKey).value],
            alsoKnownAs: oversizedAKA,
            services: [:],
            prev: nil
        ))
    }

    func testStrictJSONRejectsDuplicateSemanticKeysAndPaddedSignature() throws {
        let signed = try PLCOperationCodec.sign(.regular(try profileUnsigned()), using: rotationKey)
        let json = String(decoding: try signed.canonicalJSON, as: UTF8.self)
        let duplicate = json.replacingOccurrences(
            of: #"{"alsoKnownAs":"#,
            with: #"{"alsoKnownAs":[],"alsoKnownAs":"#
        )
        XCTAssertThrowsError(try PLCOperationCodec.decodeSignedJSON(Data(duplicate.utf8)))

        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: signed.canonicalJSON) as? [String: Any])
        object["sig"] = (object["sig"] as! String) + "="
        XCTAssertThrowsError(try PLCOperationCodec.decodeSignedJSON(
            JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        ))
    }

    func testStrictJSONRejectsHostilePLCJSONNestingBeforeRecursiveDescent() throws {
        let hostileDepth = 10_000
        let deeplyNestedPLCJSON =
            #"{"type":"plc_operation","nested":"#
            + String(repeating: "[", count: hostileDepth)
            + "null"
            + String(repeating: "]", count: hostileDepth)
            + "}"
        let data = Data(deeplyNestedPLCJSON.utf8)
        XCTAssertLessThan(data.count, 32 * 1_024)
        XCTAssertThrowsError(
            try PLCOperationCodec.decodeSignedJSON(data)
        ) { error in
            XCTAssertEqual(
                error as? SwanError,
                .malformed("PLC JSON exceeds maximum nesting depth")
            )
        }
    }

    private func profileUnsigned() throws -> PLCUnsignedRegularOperation {
        try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: privateKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
    }

    private static let goldenOperationJSON = #"{"alsoKnownAs":["at://alice.example.com"],"prev":null,"rotationKeys":["did:key:zDnaeY3trVxVedZS1deaj8NG4QRMu5yrkGMAmcq4VWMckY7fA"],"services":{"atproto_pds":{"endpoint":"https://pds.example.com","type":"AtprotoPersonalDataServer"}},"sig":"9iRdVfzU6ADbVi3zm0V5Qephpl3Dae5odEdDhUBV8aA2TdS1kezQ_9E1YFevVRGE451G_Rdg514dat4ckLGVQg","type":"plc_operation","verificationMethods":{"atproto":"did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF"}}"#

    private func highSSignature(from canonical: Data) -> Data {
        let order = [UInt8]([
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ])
        let s = [UInt8](canonical.suffix(32))
        var result = Array(repeating: UInt8.zero, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(order[index]) - Int(s[index]) - borrow
            if value < 0 {
                value += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(value)
        }
        return Data(canonical.prefix(32)) + Data(result)
    }
}

private extension Data {
    init?(base64URLEncodedWithoutPadding value: String) {
        guard !value.contains("=") else { return nil }
        var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded.append(String(repeating: "=", count: (4 - padded.count % 4) % 4))
        self.init(base64Encoded: padded)
    }

    var base64URLEncodedWithoutPadding: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
