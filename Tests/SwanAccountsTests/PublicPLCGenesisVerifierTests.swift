import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import PetrelRepo
import SwanAccounts
import SwanCore
import SwanStorage
import XCTest
@testable import SwanAccounts

final class PublicPLCGenesisVerifierTests: XCTestCase {
    private let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
    private let rotationKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))

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
            P256DIDKey(publicKey: nextSigningKey.publicKey).value
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

    private func profileUnsigned() throws -> PLCUnsignedRegularOperation {
        try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: privateKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
    }
}
