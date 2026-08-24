import Foundation
import PetrelPLC
import SwanAccounts

/// Repository admission consumes a verified method-specific provider. It does
/// not infer PLC authority from a DID string and never lets a did:web account
/// fall through to the PLC resolver.
public protocol MethodNeutralRepositoryIdentityProvider: Sendable {
    func resolveCommitVerifier(for repositoryDID: String) async throws -> PermissionedDataPublicRepositoryCommitVerifier
}

public struct ClosureRepositoryIdentityProvider: MethodNeutralRepositoryIdentityProvider {
    private let resolve: @Sendable (String) async throws -> PermissionedDataPublicRepositoryCommitVerifier

    public init(resolve: @escaping @Sendable (String) async throws -> PermissionedDataPublicRepositoryCommitVerifier) {
        self.resolve = resolve
    }

    public func resolveCommitVerifier(for repositoryDID: String) async throws -> PermissionedDataPublicRepositoryCommitVerifier {
        try await resolve(repositoryDID)
    }
}

extension PLCPublicRepositoryCommitKeyResolver: MethodNeutralRepositoryIdentityProvider {}

public struct SwanMethodNeutralRepositoryIdentityAdmission: Sendable {
    private let plc: (any MethodNeutralRepositoryIdentityProvider)?
    private let didWeb: (any MethodNeutralRepositoryIdentityProvider)?

    public init(
        plc: (any MethodNeutralRepositoryIdentityProvider)?,
        didWeb: (any MethodNeutralRepositoryIdentityProvider)?
    ) {
        self.plc = plc; self.didWeb = didWeb
    }

    public func resolveCommitVerifier(for repositoryDID: String) async throws -> PermissionedDataPublicRepositoryCommitVerifier {
        let canonical = try AccountIdentifiers.validateDID(repositoryDID)
        if canonical.hasPrefix("did:plc:") {
            guard let plc else { throw PublicRepositoryDIDResolutionError.unsupportedSigningKey }
            return try await plc.resolveCommitVerifier(for: canonical)
        }
        if canonical.hasPrefix("did:web:") {
            guard let didWeb else { throw PublicRepositoryDIDResolutionError.unsupportedSigningKey }
            return try await didWeb.resolveCommitVerifier(for: canonical)
        }
        throw PublicRepositoryDIDResolutionError.invalidRepositoryDID
    }
}
