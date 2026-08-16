import Foundation
import SwanAccounts
import SwanStorage

/// Versioned identity-only export. It is intentionally separate from the
/// existing v2 portable manifest: PLC history artifacts retain their original
/// bytes and continue through the legacy verifier unchanged.
public struct SwanIdentitySnapshot: Codable, Sendable, Equatable {
    public static let currentVersion = 1

    public let version: Int
    public let binding: IdentityBinding
    public let history: [IdentityBindingHistoryEntry]

    public init(binding: IdentityBinding, history: [IdentityBindingHistoryEntry]) throws {
        guard history.count <= 64 else { throw SwanPortableExportError.invalidManifest }
        self.version = Self.currentVersion
        self.binding = binding
        self.history = history
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    public static func decode(_ data: Data) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == currentVersion else { throw SwanPortableExportError.invalidManifest }
        guard value.history.count <= 64 else { throw SwanPortableExportError.invalidManifest }
        return value
    }

    /// Restore admission validates ownership and method material before a
    /// caller installs the snapshot into its durable account store.
    public func validatedForRestore(accountDID: String) throws -> Self {
        guard binding.accountDID == accountDID,
              try AccountIdentifiers.validateDID(binding.accountDID) == binding.accountDID,
              try AccountIdentifiers.validateDID(binding.identityDID) == binding.identityDID,
              try AccountIdentifiers.canonicalHandle(binding.handle) == binding.handle,
              history.allSatisfy({ $0.accountDID == accountDID }) else {
            throw SwanPortableExportError.invalidManifest
        }
        if binding.method == .didWeb {
            guard binding.documentDigest?.count == 32,
                  binding.claimReceiptDigest?.count == 32,
                  binding.reservedKeyID?.isEmpty == false,
                  binding.identityDID.hasPrefix("did:web:") else {
                throw SwanPortableExportError.invalidManifest
            }
        }
        return self
    }

    /// Compatibility assertion used by restore callers: this API returns the
    /// supplied legacy PLC archive bytes without transcoding or rewriting.
    public static func plcArchiveCompatibility(_ bytes: Data) -> Data { bytes }
}
