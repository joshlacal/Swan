/// Source: `oauth-scopes/scopes/repo-permission.ts:15-102`.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.4.
public enum RepoAction: String, Sendable, Hashable, CaseIterable {
    case create, update, delete // repo-permission.ts:15-19
}

/// Canonical order for normalization. `*` is NOT a valid action
/// (`repo:*?action=*` → nil, repo-permission.test.ts:78).
public let REPO_ACTIONS: [RepoAction] = [.create, .update, .delete]

public enum CollectionParam: Sendable, Hashable, Comparable {
    case any // "*"
    case nsid(String) // repo-permission.ts:23-25

    public var stringValue: String {
        switch self {
        case .any: "*"
        case let .nsid(value): value
        }
    }

    public static func < (lhs: CollectionParam, rhs: CollectionParam) -> Bool {
        lhs.stringValue < rhs.stringValue
    }
}

public struct RepoPermission: ScopePermission {
    /// Positional key. multiple, required, NO default. Never empty.
    public let collection: [CollectionParam]
    /// multiple, not required, default [create, update, delete]
    /// (repo-permission.ts:69-72).
    public let action: [RepoAction]

    private let parameters: ScopeParameterValues

    public init(collection: [CollectionParam], action: [RepoAction] = REPO_ACTIONS) {
        self.collection = collection
        self.action = action
        var values = ScopeParameterValues()
        values.set("collection", collection.map(\.stringValue))
        values.set("action", action.map(\.rawValue))
        self.parameters = values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        let collectionRaw = parameters.multiple("collection")
        guard !collectionRaw.isEmpty else {
            throw .emptyMultiValuedParameter(prefix: Self.schema.prefix, key: "collection")
        }
        self.collection = collectionRaw.map { $0 == "*" ? .any : .nsid($0) }
        let actionRaw = parameters.multiple("action")
        let action = actionRaw.compactMap(RepoAction.init(rawValue:))
        guard action.count == actionRaw.count else {
            throw .invalidParameterValue(prefix: Self.schema.prefix, key: "action", value: actionRaw.joined(separator: ","))
        }
        self.action = action
        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "repo",
        positionalKey: "collection",
        parameters: [
            // Declaration order IS canonical order: `collection` precedes
            // `action`, which is NOT alphabetical (parser.ts:54).
            .init(key: "collection", arity: .multiple, isRequired: true,
                  // repo-permission.ts:60-66: >1 value → if any is `*` collapse
                  // to ["*"]; else dedupe and SORT.
                  normalize: { $0.contains("*") && $0.count > 1 ? ["*"] : Array(Set($0)).sorted() },
                  validate: { $0 == "*" || AtprotoSyntax.isValidNSID($0) }),
            .init(key: "action", arity: .multiple,
                  defaultValue: REPO_ACTIONS.map(\.rawValue),
                  // :73-77 — filter REPO_ACTIONS by membership, preserving
                  // REPO_ACTIONS order, so `action=delete&action=create`
                  // canonicalises to create,delete.
                  normalize: { given in RepoAction.allCases.map(\.rawValue).filter(given.contains) },
                  validate: { RepoAction(rawValue: $0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        public let collection: String
        public let action: RepoAction
        public init(collection: String, action: RepoAction) {
            self.collection = collection
            self.action = action
        }
    }

    /// repo-permission.ts:41-47. The collection wildcard is exact membership of
    /// `.any` in the set — never a prefix or glob match.
    public func matches(_ target: Target) -> Bool {
        guard action.contains(target.action) else { return false }
        if collection.contains(.any) { return true }
        return collection.contains(.nsid(target.collection))
    }

    /// `scopeNeeded({collection:"com.example.foo", action:.create})` →
    /// `repo:com.example.foo?action=create` (`:87-93`). Does **not** validate
    /// its input — `{collection:"invalid", action:.create}` →
    /// `repo:invalid?action=create` (`:104-116`).
    public static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String {
        var values = ScopeParameterValues()
        values.set("collection", [target.collection])
        values.set("action", [target.action.rawValue])
        return try schema.format(values)
    }
}
