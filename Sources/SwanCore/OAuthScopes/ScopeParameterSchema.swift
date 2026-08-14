/// One declared parameter. Declaration ORDER in `ScopeParameterSchema.parameters`
/// is the canonical serialisation order (parser.ts:54, :95). An Array, never a
/// Dictionary — a Dictionary would randomise canonical order.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.6.
public struct ScopeParameter: Sendable {
    public enum Arity: Sendable, Hashable { case single, multiple }

    public let key: String
    public let arity: Arity
    public let isRequired: Bool
    /// Absent = no default at all (`include`'s `aud`); `[]` is a real, distinct
    /// default meaning "empty set" (`space`'s `collection`).
    public let defaultValue: [String]?
    public let validate: @Sendable (String) -> Bool
    /// Applied BEFORE default comparison and before serialisation
    /// (parser.ts:61-65), not as a separate post-parse pass.
    public let normalize: @Sendable ([String]) -> [String]

    public init(
        key: String,
        arity: Arity,
        isRequired: Bool = false,
        defaultValue: [String]? = nil,
        normalize: @escaping @Sendable ([String]) -> [String] = { $0 },
        validate: @escaping @Sendable (String) -> Bool
    ) {
        self.key = key
        self.arity = arity
        self.isRequired = isRequired
        self.defaultValue = defaultValue
        self.normalize = normalize
        self.validate = validate
    }
}

/// Parsed, validated, defaulted parameter values for one scope.
///
/// **Provenance is stored alongside the value and is load-bearing.** Two of
/// Swan's three existing space predicates are written against the *literal*
/// text of the scope, not its parsed meaning:
///
///  * `permitsAggregateSpaceList` (`SwanCore.swift:299-303`) requires a
///    **literal** `skey=*` and a **literal** `action=read`, reading
///    `strictQualifiedParameters` (`:352-375`), which only ever reports keys
///    physically present in the string.
///  * `permitsWholeSpaceRead` (`:270-277`) requires `parameters.count == 3` and
///    `Set(parameters.keys) == ["authority","skey","action"]` — i.e. the grant
///    named `action` and named nothing else.
///
/// `space`'s schema defaults `skey` to `["*"]` (spec §5.6.2) and `action` to the
/// full record list, so without provenance "the client wrote `skey=*`" and "the
/// client wrote nothing" become indistinguishable and both predicates silently
/// widen. Collapsing this into a plain `[String: [String]]` is the same class of
/// mistake as collapsing `ScopeParameterBag`'s tri-state into `String?`.
///
/// Provenance is **never** consulted by upstream-conformant matching — only by
/// the two Swan-specific narrowings (`isExactReadOnlyDelegationGrant`,
/// `allowsSpaceListing`) and by the fence tests.
///
/// **These bits must be DURABLE — see §9-D23, which is a blocker.** They have to
/// survive parse → admission → mint (where `self` is resolved) → persistence →
/// reload → match, and they must be persisted beside the effective grant rather
/// than re-derived. A serialised scope string cannot carry them in either
/// direction: resolving `self` makes a defaulted `authority` *look* stated
/// (which would flip the delegation fence open), and canonical serialisation
/// deletes values equal to their defaults, which destroys a stated `skey=*`
/// (which would silently disable the listing fence). Consequently
/// `SpacePermission.withResolvedAuthority` preserves the ORIGINAL provenance of
/// the `authority` key when it rewrites the value — resolution changes the
/// value, never the statedness.
public struct ScopeParameterValues: Sendable, Hashable {
    public enum Provenance: Sendable, Hashable {
        /// The key appeared in the scope string (named or positional form).
        case stated
        /// The key was absent and `ScopeParameter.defaultValue` supplied it.
        case defaulted
    }

    private struct Slot: Sendable, Hashable {
        let values: [String]
        let provenance: Provenance
    }

    private var storage: [String: Slot]

    public init() { self.storage = [:] }

    public func single(_ key: String) -> String? { storage[key]?.values.first }
    public func multiple(_ key: String) -> [String] { storage[key]?.values ?? [] }
    public func has(_ key: String) -> Bool { storage[key] != nil }

    /// True iff the key was physically present in the scope string. This is the
    /// witness `isExactReadOnlyDelegationGrant` and `allowsSpaceListing` need.
    public func wasStated(_ key: String) -> Bool { storage[key]?.provenance == .stated }

    /// The raw provenance for `key`, or `nil` if the key is absent entirely.
    /// Exposed alongside `wasStated(_:)` because a caller that needs to
    /// PRESERVE a key's provenance while changing its value (as
    /// `SpacePermission.withResolvedAuthority` does for `authority`, §9-D23)
    /// needs to read the exact case, not merely test it.
    public func provenance(for key: String) -> Provenance? { storage[key]?.provenance }

    /// Every key that was physically present in the scope string, in no
    /// particular order. Useful to a persistence layer that must serialise
    /// "which keys were stated" beside the effective grant (§9-D23) without
    /// re-deriving it from a canonical string later.
    public var statedKeys: Set<String> {
        Set(storage.compactMap { $0.value.provenance == .stated ? $0.key : nil })
    }

    public mutating func set(_ key: String, _ values: [String], _ provenance: Provenance = .stated) {
        storage[key] = Slot(values: values, provenance: provenance)
    }
}

public struct ScopeParameterSchema: Sendable {
    public let prefix: String
    /// The schema key that may ALSO be spelled as the `:positional` segment.
    public let positionalKey: String?
    public let parameters: [ScopeParameter]

    public init(prefix: String, positionalKey: String? = nil, parameters: [ScopeParameter]) {
        self.prefix = prefix
        self.positionalKey = positionalKey
        self.parameters = parameters
    }

    private var keys: Set<String> { Set(parameters.map(\.key)) }

    // MARK: parse — parser.ts:101-160, every `return null` becomes a typed throw

    public func parse(_ syntax: ScopeStringSyntax) throws(ScopeParseError) -> ScopeParameterValues {
        guard syntax.prefix == prefix else {
            throw .prefixMismatch(expected: prefix, actual: syntax.prefix)
        }

        // parser.ts:105-107 — any key not in the schema kills the whole scope.
        // This is why `identity:*?action=manage` is rejected: `identity` has no
        // `action` key at all (identity-permission.test.ts:24-36).
        let declared = keys
        for key in syntax.parameters.orderedKeys() where !declared.contains(key) {
            throw .unknownParameter(prefix: prefix, key: key)
        }

        var result = ScopeParameterValues()
        for parameter in parameters {
            let named: [String]?
            switch parameter.arity {
            case .single:
                switch syntax.parameters.single(parameter.key) {
                case .absent:
                    named = nil
                case let .present(value):
                    named = [value]
                case .repeated:
                    // parser.ts:121-122 via syntax-string.ts:21-22
                    throw .repeatedSingleValuedParameter(prefix: prefix, key: parameter.key)
                }
            case .multiple:
                named = syntax.parameters.multiple(parameter.key)
            }

            if let named {
                // parser.ts:124-127 — positional and named form of the same key
                // are mutually exclusive. Enforced HERE, not in the lexer: the
                // lexer is deliberately permissive (syntax-string.test.ts:107-113).
                if parameter.key == positionalKey, syntax.positional != nil {
                    throw .positionalAndNamedConflict(prefix: prefix, key: parameter.key)
                }
                // parser.ts:131 — an empty multi-value array is invalid.
                guard !named.isEmpty else {
                    throw .emptyMultiValuedParameter(prefix: prefix, key: parameter.key)
                }
                // parser.ts:132-138
                for value in named where !parameter.validate(value) {
                    throw .invalidParameterValue(prefix: prefix, key: parameter.key, value: value)
                }
                result.set(parameter.key, named, .stated)
            } else if parameter.key == positionalKey, let positional = syntax.positional {
                // parser.ts:146-151
                guard parameter.validate(positional) else {
                    throw .invalidPositionalValue(prefix: prefix, key: parameter.key, value: positional)
                }
                result.set(parameter.key, [positional], .stated)
            } else if parameter.isRequired {
                // parser.ts:152-153
                throw .missingRequiredParameter(prefix: prefix, key: parameter.key)
            } else if let defaultValue = parameter.defaultValue {
                // parser.ts:155 — omit the key entirely when defaultValue == nil.
                // `.defaulted` is the provenance witness; see the type's docs.
                result.set(parameter.key, defaultValue, .defaulted)
            }
        }
        return result
    }

    // MARK: format — parser.ts:50-96, the canonicalisation direction

    public func format(_ values: ScopeParameterValues) throws(ScopeParseError) -> String {
        var bag = ScopeParameterBag()
        var positional: String?

        for parameter in parameters { // declaration order == canonical order
            guard values.has(parameter.key) else { continue } // parser.ts:57
            let normalized = parameter.normalize(values.multiple(parameter.key))

            // parser.ts:67-76 — a non-required value equal to its default is
            // omitted entirely. `arrayParamEquals` (:169-176) is order- and
            // duplicate-INSENSITIVE, so the Swift equivalent is Set==Set,
            // NOT array ==.
            if !parameter.isRequired, let defaultValue = parameter.defaultValue,
               Set(defaultValue) == Set(normalized) {
                continue
            }

            switch parameter.arity {
            case .single:
                guard let value = normalized.first else { continue }
                if parameter.key == positionalKey { positional = value } else {
                    bag.set(key: parameter.key, value: value)
                }
            case .multiple:
                if parameter.key == positionalKey, normalized.count == 1 {
                    positional = normalized[0] // parser.ts:79-80, :87-88
                } else {
                    var seen = Set<String>() // parser.ts:82-85: dedupe,
                    for value in normalized where seen.insert(value).inserted {
                        bag.append(key: parameter.key, value: value) // insertion order, NOT sorted
                    }
                }
            }
        }

        return try ScopeStringSyntax(prefix: prefix, positional: positional, parameters: bag)
            .canonicalString()
    }
}
