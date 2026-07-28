import Foundation
import SwanAccounts
import SwanCore
import SwanInterop
import SwanPublicRepository
import XCTest

final class PublicRepositoryDIDResolverTests: XCTestCase {
    private let repositoryDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private let referenceSecp256k1Key =
        "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc"

    func testPLCResolverSelectsPinnedTypeScriptSecp256k1Key() async throws {
        let plc = FixturePLCClient(
            state: PLCDocumentData(
                did: repositoryDID,
                rotationKeys: [referenceSecp256k1Key],
                verificationMethods: ["atproto": referenceSecp256k1Key],
                alsoKnownAs: [],
                services: [:]
            )
        )
        let resolver = PLCPublicRepositoryCommitKeyResolver(plc: plc)

        let verifier = try await resolver.resolveCommitVerifier(for: repositoryDID)

        XCTAssertEqual(
            verifier.signingAlgorithm,
            PublicRepositorySigningAlgorithm.secp256k1
        )
        XCTAssertTrue(verifier.verificationIdentity.hasPrefix("secp256k1-sha256:"))
    }

    func testPLCResolverRejectsInvalidIdentityAndMissingAtprotoKey() async throws {
        let missingKeyResolver = PLCPublicRepositoryCommitKeyResolver(
            plc: FixturePLCClient(
                state: PLCDocumentData(
                    did: repositoryDID,
                    rotationKeys: [referenceSecp256k1Key],
                    verificationMethods: [:],
                    alsoKnownAs: [],
                    services: [:]
                )
            )
        )
        do {
            _ = try await missingKeyResolver.resolveCommitVerifier(for: repositoryDID)
            XCTFail("missing atproto key should fail closed")
        } catch let error as PublicRepositoryDIDResolutionError {
            XCTAssertEqual(error, .missingSigningKey)
        }

        do {
            _ = try await missingKeyResolver.resolveCommitVerifier(for: "did:web:example.com")
            XCTFail("non-PLC repository identity should be rejected")
        } catch let error as PublicRepositoryDIDResolutionError {
            XCTAssertEqual(error, .invalidRepositoryDID)
        }
    }
}

private struct FixturePLCClient: PLCClient {
    let state: PLCDocumentData

    func submit(did: String, operation: PLCSignedOperation) async throws {
        throw SwanError.unavailable("fixture PLC does not accept writes")
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        guard did == state.did else {
            throw SwanError.unavailable("fixture PLC has no such DID")
        }
        return state
    }

    func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        throw SwanError.unavailable("fixture PLC audit is not needed by this resolver")
    }

    func fetchAuditIfPresent(did: String) async throws -> [PLCAuditEntry]? {
        nil
    }
}
