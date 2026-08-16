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
        self.declarations = declarations
        self.permitsFullAccess = permitsFullAccess
    }

    public func allows(credential: ScopeCredential, method: String) -> Bool {
        guard !method.isEmpty, method.utf8.count <= 512 else { return false }
        switch credential {
        case .fullAccessV1:
            return permitsFullAccess
        case let .scopes(scopes):
            guard let required = declarations[method], !required.isEmpty else { return false }
            return required.isSubset(of: scopes)
        }
    }
}
