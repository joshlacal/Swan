import Crypto
import Foundation
import SwanAccounts
import SwanCore
@testable import SwanSQLite
import SwanPublicRepository
import SwanStorage
import XCTest

final class PublicRepositoryRotatedIdentityTests: XCTestCase {
    func testPublicDescriptionUsesAuthenticatedTerminalPLCIdentity() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let didHandle = "alice.example.com"
        let pdsOrigin = "https://swan.example"
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 47, count: 32)
        )
        let rotationKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 53, count: 32)
        )
        let nextSigningKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 59, count: 32)
        )
        let nextRotationKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 61, count: 32)
        )
        let genesisUnsigned = try PLCATProfile.regularOperation(
            handle: didHandle,
            signingPublicKey: signingKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: pdsOrigin)!,
            prev: nil
        )
        let genesis = try PLCOperationCodec.sign(
            .regular(genesisUnsigned),
            using: rotationKey
        )
        let did = try PLCOperationCodec.genesisDID(for: genesis)
        let nextUnsigned = try PLCATProfile.regularOperation(
            handle: didHandle,
            signingPublicKey: nextSigningKey.publicKey,
            rotationPublicKeys: [nextRotationKey.publicKey],
            pdsOrigin: URL(string: pdsOrigin)!,
            prev: try genesis.cid.string
        )
        let rotated = try PLCOperationCodec.sign(.regular(nextUnsigned), using: rotationKey)

        let accountDatabase = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let repositoryGenesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: nextSigningKey
        )
        _ = try await accountDatabase.installPublicRepositoryGenesis(
            repositoryGenesis,
            signingPublicKey: nextSigningKey.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let journal = try PLCAccountPreparationJournal(
            requestID: "rotation-read",
            canonicalHandle: didHandle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: "3jzfcijpj2z2a",
            operation: try PLCAccountPreparationOperationFacts(
                signingDIDKey: try XCTUnwrap(
                    genesis.regular?.verificationMethods["atproto"]
                ),
                rotationDIDKey: try XCTUnwrap(genesis.regular?.rotationKeys.first),
                signature: try XCTUnwrap(genesis.regular?.signature)
            ),
            signingKey: try AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        _ = try await accountDatabase.installPLCAccountPreparationJournal(journal)
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: repositoryGenesis.commitCID.string
        )
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
        _ = try await accountDatabase.installPublicPLCOperation(
            try PublicPLCOperationHistoryEntry(
                cid: try genesis.cid.string,
                previousCID: nil,
                canonicalJSON: try genesis.canonicalJSON,
                createdAt: Date(timeIntervalSince1970: 1_750_000_001),
                signingKeyGeneration: 1,
                rotationKeyGeneration: 1
            )
        )
        _ = try await accountDatabase.installPublicPLCOperation(
            try PublicPLCOperationHistoryEntry(
                cid: try rotated.cid.string,
                previousCID: try genesis.cid.string,
                canonicalJSON: try rotated.canonicalJSON,
                createdAt: Date(timeIntervalSince1970: 1_750_000_002),
                signingKeyGeneration: 2,
                rotationKeyGeneration: 2
            )
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let initialAccount = try await control.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: didHandle,
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try AccountControlKeyReference(
                    purpose: .signing, generation: 1
                ),
                rotationKey: try AccountControlKeyReference(
                    purpose: .rotation, generation: 1
                ),
                publicGenesisCommitCID: repositoryGenesis.commitCID.string,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        let rotatedAccount = try await control.rotateAccountKeys(
            did: did,
            request: try AccountControlKeyRotationRequest(
                expectedGeneration: 1,
                signingKey: try AccountControlKeyReference(
                    purpose: .signing, generation: 2
                ),
                rotationKey: try AccountControlKeyReference(
                    purpose: .rotation, generation: 2
                )
            ),
            now: Date(timeIntervalSince1970: 1_750_000_003)
        )
        XCTAssertEqual(initialAccount.signingKey?.generation, 1)
        XCTAssertEqual(rotatedAccount.signingKey?.generation, 2)

        let description = try await accountDatabase.readPublicRepositoryDescription(
            account: rotatedAccount,
            identityVerifier: SwanPublicPLCGenesisVerifier()
        )
        XCTAssertEqual(description.did, did)
        XCTAssertEqual(description.identity.canonicalHandle, didHandle)
        XCTAssertEqual(description.identity.pdsOrigin, pdsOrigin)
        XCTAssertEqual(
            description.identity.signingDIDKey,
            P256DIDKey(publicKey: nextSigningKey.publicKey).value
        )
        XCTAssertEqual(
            description.identity.terminalOperationCID,
            try rotated.cid.string
        )
        XCTAssertEqual(
            description.identity.genesisOperationCID,
            try genesis.cid.string
        )

        try await accountDatabase.close()
        try await control.close()
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicRotatedIdentityTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}
