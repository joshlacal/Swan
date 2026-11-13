/// The second `ScopeSyntax` implementation — lexicon JSON rather than a scope
/// string — and the generic parse path both of them share.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.7.3.
/// Upstream: `oauth-scopes/lib/syntax-lexicon.ts:9-69`, `lib/syntax.ts:37-45`.

// MARK: - The abstract syntax interface (`lib/syntax.ts:37-45`)

/// The `null` / `undefined` / value tri-state for a MULTI-valued lookup, the
/// mirror image of `ScopeParameterBag.SingleLookup`.
///
/// `.rejected` is `getMulti`'s upstream `null` (`syntax-lexicon.ts:62`): the key
/// is PRESENT but is not an array. `parser.ts:121-122` turns it into a
/// whole-entry rejection, and collapsing it into `.absent` — or into a
/// one-element `.values([…])` — is the widening §5.7.3 gate 3 exists to stop.
public enum ScopeMultiLookup: Sendable, Hashable {
    case absent
    case rejected
    case values([String])
}

/// `ScopeSyntax<P>` (`lib/syntax.ts:37-45`). `ScopeParameterSchema.parse` is
/// generic over this exactly as `Parser.parse` is (`parser.ts:101-160`), so
/// every rejection rule — unknown key, repeated single, non-array multi, empty
/// multi, `validate`, required — is reached by ONE code path from both a scope
/// string and a lexicon permission. Two copies of that logic is how a lexicon
/// entry acquires a rule the wire form does not have, or loses one it does.
public protocol ScopeSyntax: Sendable {
    var prefix: String { get }
    /// `nil` for every lexicon permission (`syntax-lexicon.ts:18-20`): there is
    /// no scope string here to lex, so there is no positional segment.
    var positional: String? { get }
    /// Surface keys, in a stable order. The unknown-key gate (`parser.ts:105-107`)
    /// reads exactly this.
    func keys() -> [String]
    func getSingle(_ key: String) -> ScopeParameterBag.SingleLookup
    func getMulti(_ key: String) -> ScopeMultiLookup
}

extension ScopeStringSyntax: ScopeSyntax {
    public func keys() -> [String] { parameters.orderedKeys() }

    public func getSingle(_ key: String) -> ScopeParameterBag.SingleLookup {
        parameters.single(key)
    }

    /// A query string can never carry "present but not an array", so
    /// `.rejected` is unreachable from this side — which is precisely why the
    /// case had to be introduced for the lexicon side.
    public func getMulti(_ key: String) -> ScopeMultiLookup {
        guard let values = parameters.multiple(key) else { return .absent }
        return .values(values)
    }
}

// MARK: - LexPermissionSyntax

/// Port of `oauth-scopes/lib/syntax-lexicon.ts:9-69`. The ONLY adapter from
/// lexicon JSON into the schema layer. It is a second `ScopeSyntax`
/// implementation, not a `ScopeStringSyntax` — there is no scope string here to
/// lex, and manufacturing one would re-introduce the encoding round-trip.
public struct LexPermissionSyntax: Sendable, ScopeSyntax {
    public let permission: LexiconPermission

    public init(permission: LexiconPermission) {
        self.permission = permission
    }

    /// `:14-16`.
    public var prefix: String { permission.resource }

    /// `:18-20`.
    public var positional: String? { nil }

    /// Surface fields from the already-filtered permission payload.
    ///
    /// `LexiconPermission` removes the reserved `type` and `resource`
    /// discriminators while decoding. Permission-set space entries already use
    /// `spaceType`, which is now also the scope schema's named key, so no key
    /// remapping is required.
    private func get(_ key: String) -> LexiconValue? {
        permission.fields[key]
    }

    /// Surface keys in the permission's stable insertion order.
    public func keys() -> [String] {
        Array(permission.fields.keys)
    }

    /// `:53-57`. `.repeated` <-> upstream `null`: present, but an ARRAY where a
    /// single value is required. `.absent` <-> `undefined`.
    public func getSingle(_ key: String) -> ScopeParameterBag.SingleLookup {
        switch get(key) {
        case .none:
            return .absent
        case .some(.list):
            // parser.ts:121-122 -> whole-entry rejection.
            return .repeated([])
        case let .some(value):
            return value.scalarText.map { .present($0) } ?? .absent
        }
    }

    /// `:59-64`. `undefined` == absent; `null` == present but NOT an array,
    /// which `parser.ts:121-122` rejects.
    ///
    /// An array whose ITEMS are not scalars (a nested array) is `.rejected` too,
    /// agreeing with upstream by a different route: upstream hands the nested
    /// array to `validate`, which is a string predicate and returns false
    /// (`parser.ts:132-134`). Both reject; neither flattens.
    public func getMulti(_ key: String) -> ScopeMultiLookup {
        switch get(key) {
        case .none:
            return .absent
        case let .some(.list(items)):
            let texts = items.compactMap(\.scalarText)
            return texts.count == items.count ? .values(texts) : .rejected
        case .some:
            // A scalar where an array is required. NOT a one-element list.
            return .rejected
        }
    }

    /// The nested spelling §5.7.3 gives. `ScopeMultiLookup` is shared with
    /// `ScopeStringSyntax` so the generic parse can consume both.
    public typealias MultiLookup = ScopeMultiLookup
}
