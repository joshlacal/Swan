/// Anything with a prefix, a schema, a parse and a canonical form. `IncludeScope`
/// stops here — it names a permission SET and matches nothing itself. Upstream
/// has the same split cleanly: `ResourcePermission<R,T> extends Matchable<T>`
/// (`lib/resource-permission.ts:8`); `IncludeScope` extends neither.
///
/// **The protocol is split in two, and it must be.** A single protocol carrying
/// `associatedtype Target`, `matches` and `scopeNeeded` cannot be conformed to by
/// `IncludeScope`, which implements no `Matchable` (`include-scope.ts:22-26`) and
/// has no `matches`. Without the split, `IncludeScope.prefix`,
/// `IncludeScope.parse(_:)` and `s.canonicalScopeString()` in the dispatcher
/// below would be three compile errors in the type the whole PAR path routes
/// through.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.7.
public protocol ScopeFamily: Sendable, Hashable {
    static var schema: ScopeParameterSchema { get }

    init(parameters: ScopeParameterValues) throws(ScopeParseError)
    var scopeParameters: ScopeParameterValues { get }
}

extension ScopeFamily {
    public static var prefix: String { schema.prefix }

    public static func parse(_ scope: String) throws(ScopeParseError) -> Self {
        guard ScopeStringSyntax.isScopeString(scope, for: schema.prefix) else {
            throw .prefixMismatch(expected: schema.prefix, actual: scope)
        }
        return try Self(parameters: schema.parse(ScopeStringSyntax.parse(scope)))
    }

    public func canonicalScopeString() throws(ScopeParseError) -> String {
        try Self.schema.format(scopeParameters)
    }
}

/// One permission family (`space:`, `repo:`, `rpc:`, ...) — a `ScopeFamily` that
/// additionally answers "does this grant cover that request". The subset
/// ("grants") relation is deliberately NOT part of `Equatable` — the Rust
/// reference keeps it a separate exhaustive function with per-family exceptions
/// (scopes.rs:896-991), and `space:` opts out of subset reduction entirely
/// (scopes.rs:985-988).
public protocol ScopePermission: ScopeFamily {
    associatedtype Target: Sendable

    func matches(_ target: Target) -> Bool
    /// The minimal scope string that WOULD satisfy `target` — the message
    /// content of a denial (scopes-set.ts:57-65, :90-112).
    ///
    /// **Must be total over `Target`.** Every case of every `Target` enum needs
    /// an arm, including Swan-shaped ones such as
    /// `SpaceScopeTarget.Operation.delegationExchange` (§5.6.6).
    static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String
}

/// Every scope Swan can interpret. Dispatch is a fixed prefix table (as in
/// scopes.rs:347), not upstream's try-each-family-in-order
/// (atproto-oauth-scope.ts:64-83): O(1), and it yields a real error instead of
/// a `null` that cannot say which family rejected the string. Safe because
/// `isScopeString` makes the prefixes disjoint (§4.4) — `identity` never eats
/// `identityfoo`.
public enum AtprotoScope: Sendable, Hashable {
    case atproto
    case transitionEmail
    case transitionGeneric
    case transitionChatBsky
    case account(AccountPermission)
    case blob(BlobPermission)
    case identity(IdentityPermission)
    case include(IncludeScope)
    case repo(RepoPermission)
    case rpc(RpcPermission)
    case space(SpacePermission)

    public static func parse(_ scope: String) throws(ScopeParseError) -> AtprotoScope {
        switch scope {
        case "atproto": return .atproto
        case "transition:email": return .transitionEmail
        case "transition:generic": return .transitionGeneric
        case "transition:chat.bsky": return .transitionChatBsky
        default: break
        }
        if ScopeStringSyntax.isScopeString(scope, for: AccountPermission.prefix) {
            return .account(try AccountPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: BlobPermission.prefix) {
            return .blob(try BlobPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: IdentityPermission.prefix) {
            return .identity(try IdentityPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: IncludeScope.prefix) {
            return .include(try IncludeScope.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: RepoPermission.prefix) {
            return .repo(try RepoPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: RpcPermission.prefix) {
            return .rpc(try RpcPermission.parse(scope))
        }
        if ScopeStringSyntax.isScopeString(scope, for: SpacePermission.prefix) {
            return .space(try SpacePermission.parse(scope))
        }
        throw .unknownPrefix(scope)
    }

    public func canonicalScopeString() throws(ScopeParseError) -> String {
        switch self {
        case .atproto: "atproto"
        case .transitionEmail: "transition:email"
        case .transitionGeneric: "transition:generic"
        case .transitionChatBsky: "transition:chat.bsky"
        case let .account(p): try p.canonicalScopeString()
        case let .blob(p): try p.canonicalScopeString()
        case let .identity(p): try p.canonicalScopeString()
        case let .include(s): try s.canonicalScopeString()
        case let .repo(p): try p.canonicalScopeString()
        case let .rpc(p): try p.canonicalScopeString()
        case let .space(p): try p.canonicalScopeString()
        }
    }
}
