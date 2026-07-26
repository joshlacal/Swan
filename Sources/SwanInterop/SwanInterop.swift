import Foundation
import SwanCore
import SwanSpaces

public struct ReferenceSourcePin: Codable, Sendable, Equatable {
    public let repository: URL
    public let commit: String
    public let archiveSHA256: String?

    public init(
        repository: URL = URL(string: "https://github.com/bluesky-social/atproto")!,
        commit: String = "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354",
        archiveSHA256: String? = nil
    ) {
        self.repository = repository
        self.commit = commit
        self.archiveSHA256 = archiveSHA256
    }
}

public enum FaultMode: String, Codable, Sendable, CaseIterable {
    case offline
    case delayed
    case duplicated
    case reordered
    case corrupted
}

public struct SanitizedFixture: Codable, Sendable, Equatable {
    public let scenario: String
    public let requestSummary: [String: String]
    public let responseSummary: [String: String]
    public let commitmentHex: String?
    public let expectedError: String?
}

public enum FixtureSanitizer {
    private static let forbiddenKeys: Set<String> = [
        "authorization", "access_token", "refresh_token", "password", "dpop", "private_key", "ikm",
    ]

    public static func sanitize(_ fields: [String: String]) throws -> [String: String] {
        guard !fields.keys.contains(where: { forbiddenKeys.contains($0.lowercased()) }) else {
            throw SwanError.unauthorized("fixtures may not contain credential or key material")
        }
        return fields
    }
}
