import Foundation

/// The internal full-access grant is intentionally not a user-supplied scope
/// string. Every other credential must have a declared method policy.
public enum ScopeGrant: String, Codable, Sendable, Equatable {
    case fullAccessV1
}

public enum ScopeCredential: Sendable, Equatable {
    case scopes(Set<String>)
    case fullAccessV1
}

public protocol MethodScopePolicy: Sendable {
    func allows(credential: ScopeCredential, method: String) -> Bool
}

/// Dependency-neutral declaration used by OAuth, legacy sessions, and app
/// passwords. Missing declarations and malformed methods deny by default.
public struct DeclaredMethodScopePolicy: MethodScopePolicy, Sendable, Equatable {
    private let declarations: [String: Set<String>]
    private let permitsFullAccess: Bool

    public static let denyAll = DeclaredMethodScopePolicy()
    public static let fullAccessV1 = DeclaredMethodScopePolicy(permitsFullAccess: true)

    public init(declarations: [String: Set<String>] = [:], permitsFullAccess: Bool = false) {
        self.declarations = declarations.filter { Self.isCanonicalMethod($0.key) }
        self.permitsFullAccess = permitsFullAccess
    }

    public func allows(credential: ScopeCredential, method: String) -> Bool {
        guard Self.isCanonicalMethod(method) else { return false }
        switch credential {
        case .fullAccessV1:
            return permitsFullAccess
        case let .scopes(scopes):
            guard let required = declarations[method], !required.isEmpty else { return false }
            return required.isSubset(of: scopes)
        }
    }

    public func declares(_ method: String) -> Bool {
        declarations[method] != nil
    }

    public func requiredScopes(for method: String) -> Set<String>? {
        declarations[method]
    }

    public static func isCanonicalMethod(_ method: String) -> Bool {
        guard method.utf8.count <= 512 else { return false }
        let parts = method.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3 else { return false }
        for (index, part) in parts.enumerated() {
            guard !part.isEmpty else { return false }
            let bytes = part.utf8
            guard bytes.allSatisfy({
                ($0 >= 97 && $0 <= 122) || ($0 >= 65 && $0 <= 90)
                    || ($0 >= 48 && $0 <= 57) || $0 == 45
            }) else { return false }
            guard let first = bytes.first,
                  (first >= 65 && first <= 90) || (first >= 97 && first <= 122) else { return false }
            if index < parts.count - 1,
               bytes.contains(where: { $0 >= 65 && $0 <= 90 }) { return false }
        }
        return true
    }
}
