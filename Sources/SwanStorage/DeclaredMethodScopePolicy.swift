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
    /// Explicitly enumerated legacy methods. Full access is still bounded by
    /// this registry; it is never a wildcard over arbitrary route strings.
    public static let fullAccessV1 = DeclaredMethodScopePolicy(
        declarations: [
            "com.atproto.server.createSession": [], "com.atproto.server.refreshSession": [],
            "com.atproto.server.getSession": [], "com.atproto.server.deleteSession": [],
            "com.atproto.server.getServiceAuth": [], "com.atproto.server.createAppPassword": [],
            "com.atproto.server.listAppPasswords": [], "com.atproto.server.revokeAppPassword": [],
            // Reference-compatible account/session methods.
            "com.atproto.repo.applyWrites": [], "com.atproto.repo.createRecord": [],
            "com.atproto.repo.deleteRecord": [], "com.atproto.repo.describeRepo": [],
            "com.atproto.repo.getRecord": [], "com.atproto.repo.listRecords": [],
            "com.atproto.repo.putRecord": [], "com.atproto.repo.uploadBlob": [],
            "com.atproto.sync.getBlob": [], "com.atproto.sync.getLatestCommit": [],
            "com.atproto.sync.getRepo": [], "com.atproto.sync.getRepoStatus": [],
            "com.atproto.identity.resolveHandle": [],
            // Official-client AppView feed/identity methods.
            "app.bsky.actor.getPreferences": [], "app.bsky.actor.getPreferencesExtended": [],
            "app.bsky.actor.getProfile": [], "app.bsky.actor.putPreferences": [],
            "app.bsky.actor.searchActors": [],
            "app.bsky.feed.getAuthorFeed": [], "app.bsky.feed.getFeedSkeleton": [],
            "app.bsky.feed.getPostThread": [], "app.bsky.feed.getPosts": [],
            "app.bsky.feed.getTimeline": [], "app.bsky.feed.post": [],
            "app.bsky.graph.getBlocks": [], "app.bsky.graph.getFollowers": [],
            "app.bsky.graph.getFollows": [], "app.bsky.graph.getMutes": [],
            "app.bsky.graph.getLists": [], "app.bsky.graph.muteActor": [],
            "app.bsky.graph.unmuteActor": [],
            "app.bsky.notification.listNotifications": [],
            "app.bsky.notification.updateSeen": [],
            // Official-client chat methods.
            "chat.bsky.convo.getConvo": [], "chat.bsky.convo.getMessages": [],
            "chat.bsky.convo.listConvos": [], "chat.bsky.convo.sendMessage": []
        ], permitsFullAccess: true
    )

    public init(declarations: [String: Set<String>] = [:], permitsFullAccess: Bool = false) {
        self.declarations = declarations.filter { Self.isCanonicalMethod($0.key) }
        self.permitsFullAccess = permitsFullAccess
    }

    public func allows(credential: ScopeCredential, method: String) -> Bool {
        guard Self.isCanonicalMethod(method), declarations[method] != nil else { return false }
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
