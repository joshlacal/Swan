import Foundation

/// The one canonical scope grammar shared by OAuth and legacy credentials.
/// User input is parsed once at issuance and the canonical value is what is
/// persisted and evaluated later.
public struct SwanScope: Codable, Hashable, Sendable, Equatable {
    public enum Kind: Codable, Hashable, Sendable, Equatable {
        case atproto
        case repo(String)
        case blob(String)
        case rpc(methodPrefix: String, audience: String)
        case account(String)
        case identity(String)
        case transition(String)
        case include(String)
    }

    public let kind: Kind
    public let canonicalValue: String

    public init(_ value: String) throws {
        let parsed = try Self.parse(value)
        self = parsed
    }

    private init(kind: Kind, canonicalValue: String) {
        self.kind = kind
        self.canonicalValue = canonicalValue
    }

    public static func parse(_ value: String) throws -> Self {
        guard !value.isEmpty, value.utf8.count <= 512,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanScopeError.malformed
        }
        if value == "atproto" {
            return Self(kind: .atproto, canonicalValue: value)
        }
        if let prefix = value.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first,
           let remainder = value.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).dropFirst().first {
            switch prefix {
            case "repo":
                guard Self.isPathComponent(remainder) else { throw SwanScopeError.malformed }
                return Self(kind: .repo(String(remainder)), canonicalValue: value)
            case "blob":
                guard Self.isPathComponent(remainder) else { throw SwanScopeError.malformed }
                return Self(kind: .blob(String(remainder)), canonicalValue: value)
            case "account":
                guard Self.isPathComponent(remainder) else { throw SwanScopeError.malformed }
                return Self(kind: .account(String(remainder)), canonicalValue: value)
            case "identity":
                guard Self.isPathComponent(remainder) else { throw SwanScopeError.malformed }
                return Self(kind: .identity(String(remainder)), canonicalValue: value)
            case "transition":
                guard Self.isPathComponent(remainder) else { throw SwanScopeError.malformed }
                return Self(kind: .transition(String(remainder)), canonicalValue: value)
            case "include":
                // Includes have no expansion registry in this lane. Accepting
                // one would create an unevaluated authority string.
                throw SwanScopeError.wildcardNotAllowed
            case "rpc":
                return try Self.parseRPC(String(remainder))
            default:
                break
            }
        }
        throw SwanScopeError.malformed
    }

    public func allows(method: String, audience: String? = nil) -> Bool {
        guard DeclaredMethodScopePolicy.isCanonicalMethod(method) else { return false }
        switch kind {
        case .rpc(let prefix, let expectedAudience):
            guard Self.dotBoundaryPrefix(method, prefix), let audience else { return false }
            return Self.audienceMatches(expectedAudience, audience)
        default:
            return false
        }
    }

    public static func audienceMatches(_ expected: String, _ actual: String) -> Bool {
        let expected = stripFragment(expected)
        let actual = stripFragment(actual)
        guard !expected.isEmpty, !actual.isEmpty else { return false }
        guard let expectedURL = URLComponents(string: expected), let actualURL = URLComponents(string: actual),
              let expectedScheme = expectedURL.scheme?.lowercased(), let actualScheme = actualURL.scheme?.lowercased(),
              let expectedHost = expectedURL.host?.lowercased(), let actualHost = actualURL.host?.lowercased(),
              expectedScheme == actualScheme, expectedHost == actualHost,
              normalizedPort(expectedURL) == normalizedPort(actualURL) else { return actual == expected }
        let expectedPath = expectedURL.path.isEmpty ? "/" : expectedURL.path
        let actualPath = actualURL.path.isEmpty ? "/" : actualURL.path
        return actualPath == expectedPath || actualPath.hasPrefix(expectedPath.hasSuffix("/") ? expectedPath : expectedPath + "/")
    }

    private static func normalizedPort(_ value: URLComponents) -> Int? {
        if let port = value.port { return port }
        switch value.scheme?.lowercased() { case "https": return 443; case "http": return 80; default: return nil }
    }

    public static func dotBoundaryPrefix(_ value: String, _ prefix: String) -> Bool {
        value == prefix || value.hasPrefix(prefix + ".")
    }

    private static func parseRPC(_ remainder: String) throws -> Self {
        let pieces = remainder.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        guard pieces.count == 2, isMethodPrefix(pieces[0]) else { throw SwanScopeError.malformed }
        let query = String(pieces[1])
        guard query.hasPrefix("aud="), !query.dropFirst(4).isEmpty,
              !query.dropFirst(4).contains("&") else {
            throw SwanScopeError.malformed
        }
        let rawAudience = String(query.dropFirst(4))
        guard rawAudience != "*", rawAudience != "*#fragment",
              !rawAudience.contains("?") else { throw SwanScopeError.malformed }
        let audience = stripFragment(rawAudience)
        guard !audience.isEmpty, audience != "*", audience.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanScopeError.malformed
        }
        return Self(kind: .rpc(methodPrefix: String(pieces[0]), audience: audience), canonicalValue: "rpc:\(pieces[0])?aud=\(audience)")
    }

    private static func stripFragment(_ value: String) -> String {
        String(value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
    }

    private static func isMethodPrefix(_ value: Substring) -> Bool {
        DeclaredMethodScopePolicy.isCanonicalMethod(String(value))
    }

    private static func isPathComponent(_ value: Substring) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 && value.utf8.allSatisfy {
            ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a)
                || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2e || $0 == 0x2d || $0 == 0x5f || $0 == 0x2a
        }
    }
}

public enum SwanScopeError: Error, Sendable, Equatable {
    case malformed
    case empty
    case undeclaredMethod
    case missingRequiredScope(String)
    case wildcardNotAllowed
}

public enum SwanScopePreset: String, Codable, CaseIterable, Sendable {
    case bluesky
    case full
    case readOnly = "read-only"
    case postOnly = "post-only"

    public var scopes: Set<String> {
        switch self {
        case .bluesky:
            return ["repo:read", "repo:write", "blob:read", "blob:write", "rpc:app.bsky?aud=https://api.bsky.app", "rpc:chat.bsky?aud=https://api.bsky.app"]
        case .full: return [] // fullAccessV1 is internal and cannot be requested
        case .readOnly: return ["repo:read", "blob:read", "account:read"]
        case .postOnly: return ["repo:write", "blob:write"]
        }
    }
}

public struct SwanScopeEvaluator: Sendable {
    public init() {}

    public func evaluate(
        credential: ScopeCredential,
        canonicalMethod: String,
        declaredMethodPolicy: DeclaredMethodScopePolicy,
        audience: String? = nil
    ) throws {
        guard DeclaredMethodScopePolicy.isCanonicalMethod(canonicalMethod) else {
            throw SwanScopeError.undeclaredMethod
        }
        // Even the internal full-access sentinel is constrained by the
        // canonical method registry. A missing declaration is never a grant.
        guard declaredMethodPolicy.declares(canonicalMethod) else {
            throw SwanScopeError.undeclaredMethod
        }
        if credential == .fullAccessV1 {
            guard declaredMethodPolicy.allows(credential: credential, method: canonicalMethod) else {
                throw SwanScopeError.undeclaredMethod
            }
            return
        }
        guard case let .scopes(rawScopes) = credential, !rawScopes.isEmpty else {
            throw SwanScopeError.empty
        }
        let scopes = try rawScopes.map(SwanScope.parse)
        guard let required = declaredMethodPolicy.requiredScopes(for: canonicalMethod), !required.isEmpty else {
            throw SwanScopeError.undeclaredMethod
        }
        for requirement in required {
            if scopes.contains(where: { $0.canonicalValue == requirement }) { continue }
            if scopes.contains(where: { $0.allows(method: canonicalMethod, audience: audience) && requirement.hasPrefix("rpc:") }) { continue }
            throw SwanScopeError.missingRequiredScope(requirement)
        }
    }
}
