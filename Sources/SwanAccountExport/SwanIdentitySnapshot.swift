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

    /// Compatibility assertion used by restore callers: this API returns the
    /// supplied legacy PLC archive bytes without transcoding or rewriting.
    public static func plcArchiveCompatibility(_ bytes: Data) -> Data { bytes }
}
