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
        declarations: GeneratedLegacyMethodRegistry.declarations, permitsFullAccess: true
    )
    /* Legacy method declarations are generated from the pinned lexicons.
        The old hand-written map is intentionally retained below as a review
        reference in history, not as an authorization source.
    public static let legacyReviewMap: [String: Set<String>] = [
            "com.atproto.server.createSession": [], "com.atproto.server.refreshSession": [],
            "com.atproto.server.getSession": [], "com.atproto.server.deleteSession": [],
            "com.atproto.server.getServiceAuth": [], "com.atproto.server.createAppPassword": [],
            "com.atproto.server.listAppPasswords": [], "com.atproto.server.revokeAppPassword": [],
            // Reference-compatible account/session methods.
            "com.atproto.repo.applyWrites": ["repo:write"], "com.atproto.repo.createRecord": ["repo:write"],
            "com.atproto.repo.deleteRecord": ["repo:write"], "com.atproto.repo.describeRepo": ["repo:read"],
            "com.atproto.repo.getRecord": ["repo:read"], "com.atproto.repo.listRecords": ["repo:read"],
            "com.atproto.repo.putRecord": ["repo:write"], "com.atproto.repo.uploadBlob": ["blob:write"],
            "com.atproto.sync.getBlob": ["blob:read"], "com.atproto.sync.getLatestCommit": ["repo:read"],
            "com.atproto.sync.getRepo": ["repo:read"], "com.atproto.sync.getRepoStatus": ["repo:read"],
            "com.atproto.identity.resolveHandle": ["identity:read"],
            // Official-client AppView feed/identity methods.
            "app.bsky.actor.getPreferences": ["rpc:app.bsky"], "app.bsky.actor.getPreferencesExtended": ["rpc:app.bsky"],
            "app.bsky.actor.getProfile": ["rpc:app.bsky"], "app.bsky.actor.getProfiles": ["rpc:app.bsky"], "app.bsky.actor.putPreferences": ["rpc:app.bsky"],
            "app.bsky.actor.searchActors": ["rpc:app.bsky"],
            "app.bsky.feed.getAuthorFeed": ["rpc:app.bsky"], "app.bsky.feed.getFeed": ["rpc:app.bsky"], "app.bsky.feed.getFeedSkeleton": ["rpc:app.bsky"],
            "app.bsky.feed.getPostThread": ["rpc:app.bsky"], "app.bsky.feed.getPosts": ["rpc:app.bsky"],
            "app.bsky.feed.getTimeline": ["rpc:app.bsky"], "app.bsky.feed.post": ["rpc:app.bsky"],
            "app.bsky.graph.getBlocks": ["rpc:app.bsky"], "app.bsky.graph.getFollowers": ["rpc:app.bsky"],
            "app.bsky.graph.getFollows": ["rpc:app.bsky"], "app.bsky.graph.getMutes": ["rpc:app.bsky"],
            "app.bsky.graph.getLists": ["rpc:app.bsky"], "app.bsky.graph.muteActor": ["rpc:app.bsky"],
            "app.bsky.graph.unmuteActor": ["rpc:app.bsky"],
            "app.bsky.notification.listNotifications": ["rpc:app.bsky"],
            "app.bsky.notification.updateSeen": ["rpc:app.bsky"],
            // Official-client chat methods.
            "chat.bsky.convo.getConvo": ["rpc:chat.bsky"], "chat.bsky.convo.getMessages": ["rpc:chat.bsky"],
            "chat.bsky.convo.listConvos": ["rpc:chat.bsky"], "chat.bsky.convo.sendMessage": ["rpc:chat.bsky"]
            ,"tools.ozone.moderation.emitEvent": ["rpc:tools.ozone"],
            "tools.ozone.moderation.getRepo": ["rpc:tools.ozone"],
            "com.atproto.moderation.createReport": ["rpc:com.atproto.moderation"],
            "com.atproto.label.queryLabels": ["rpc:com.atproto.label"]
        ]
    */
    /// The default reference policy uses exactly the same declarations and
    /// required capabilities as the scoped evaluator, while permitting only
    /// the internal full-access grant in addition.
    public static let referenceLegacy = DeclaredMethodScopePolicy(
        declarations: fullAccessV1.declarations, permitsFullAccess: true
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

    /// Stable manifest view used by parity tests and integration diagnostics.
    /// Callers still must use `allows` for authorization decisions.
    public var declaredMethods: Set<String> { Set(declarations.keys) }

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
