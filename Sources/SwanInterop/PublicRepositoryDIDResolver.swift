import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanOAuth
import SwanCore

/// A resolver is deliberately separated from CAR fetching. The caller binds
/// the resolved verifier identity into the import request before any remote
/// repository bytes are staged.
public protocol PublicRepositoryCommitKeyResolving: Sendable {
    func resolveCommitVerifier(
        for repositoryDID: String
    ) async throws -> PermissionedDataPublicRepositoryCommitVerifier
}

public enum PublicRepositoryDIDResolutionError: Error, Sendable, Equatable {
    case invalidRepositoryDID
    case missingSigningKey
    case unsupportedSigningKey
    case identityMismatch
    case pdsServiceMismatch
}

/// PLC-backed key discovery for public repository imports. `PLCDirectoryClient`
/// authenticates the returned state against the complete PLC audit chain before
/// this resolver accepts the `atproto` verification method, including the
/// secp256k1 keys emitted by the pinned TypeScript PDS.
public struct PLCPublicRepositoryCommitKeyResolver: Sendable,
    PublicRepositoryCommitKeyResolving
{
    private let plc: any PLCClient

    public init(plc: any PLCClient) {
        self.plc = plc
    }

    public init(
        configuration: PLCClientConfiguration
    ) throws {
        self.plc = try PLCDirectoryClient(configuration: configuration)
    }

    public func resolveCommitVerifier(
        for repositoryDID: String
    ) async throws -> PermissionedDataPublicRepositoryCommitVerifier {
        guard (try? AccountIdentifiers.validateDID(repositoryDID)) != nil,
              repositoryDID.hasPrefix("did:plc:") else {
            throw PublicRepositoryDIDResolutionError.invalidRepositoryDID
        }
        let state: PLCDocumentData
        do {
            state = try await plc.fetchState(did: repositoryDID)
        } catch {
            throw PublicRepositoryDIDResolutionError.identityMismatch
        }
        guard state.did == repositoryDID else {
            throw PublicRepositoryDIDResolutionError.identityMismatch
        }
        guard let signingDIDKey = state.verificationMethods["atproto"] else {
            throw PublicRepositoryDIDResolutionError.missingSigningKey
        }
        let resolved: PLCDIDVerificationKey
        do {
            resolved = try PLCDIDKeyCodec.decode(signingDIDKey)
        } catch {
            throw PublicRepositoryDIDResolutionError.unsupportedSigningKey
        }
        switch resolved {
        case let .p256(publicKey):
            return PermissionedDataPublicRepositoryCommitVerifier(key: .p256(publicKey))
        case let .secp256k1(publicKey):
            do {
                return PermissionedDataPublicRepositoryCommitVerifier(
                    key: try .init(secp256k1PublicKey: publicKey)
                )
            } catch {
                throw PublicRepositoryDIDResolutionError.unsupportedSigningKey
            }
        }
    }
}
