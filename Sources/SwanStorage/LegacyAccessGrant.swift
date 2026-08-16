import Foundation

/// Dependency-neutral credential grant carried by legacy authorization
/// contexts and signed access tokens.
public enum LegacyAccessGrant: String, Codable, Sendable, Equatable {
    case fullAccessV1
    case scoped

    public static let fullAccessMarker = "__swan_fullAccessV1"

    public static func validate(scopes: Set<String>, grant: Self) -> Bool {
        let hasMarker = scopes.contains(fullAccessMarker)
        switch grant {
        case .fullAccessV1: return scopes == [fullAccessMarker]
        case .scoped: return !scopes.isEmpty && !hasMarker
        }
    }
}

public extension LegacySessionMetadata {
    static func validatedGrant(_ scopes: Set<String>, sessionID: LegacySessionID, familyID: String, accountDID: String, appPasswordID: String?, issuedAt: Date, expiresAt: Date, revokedAt: Date? = nil, rotatedAt: Date? = nil, replacedByDigest: Data? = nil, previousSessionDigest: Data? = nil, reuseDetectedAt: Date? = nil) throws -> Self {
        let grant: LegacyAccessGrant = scopes == [LegacyAccessGrant.fullAccessMarker] ? .fullAccessV1 : .scoped
        guard LegacyAccessGrant.validate(scopes: scopes, grant: grant) else { throw SwanError.invalidIdentifier("legacy access grant") }
        return try Self(sessionID: sessionID, familyID: familyID, accountDID: accountDID, appPasswordID: appPasswordID, scopeStrings: scopes, issuedAt: issuedAt, expiresAt: expiresAt, revokedAt: revokedAt, rotatedAt: rotatedAt, replacedByDigest: replacedByDigest, previousSessionDigest: previousSessionDigest, reuseDetectedAt: reuseDetectedAt)
    }
}
