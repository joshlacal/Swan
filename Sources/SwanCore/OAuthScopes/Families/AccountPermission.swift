/// Source: `oauth-scopes/scopes/account-permission.ts:11-83`.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.1.
public enum AccountAttribute: String, Sendable, Hashable, CaseIterable {
    case email, repo, status // account-permission.ts:11-15
}

public enum AccountAction: String, Sendable, Hashable, CaseIterable {
    case read, manage // account-permission.ts:18-19
}

public struct AccountPermission: ScopePermission {
    /// Positional key. single, required, no default.
    public let attr: AccountAttribute
    /// multiple, not required, default ["read"] (account-permission.ts:54-58).
    /// Never empty.
    public let action: [AccountAction]

    private let parameters: ScopeParameterValues

    public init(attr: AccountAttribute, action: [AccountAction] = [.read]) {
        self.attr = attr
        self.action = action
        var values = ScopeParameterValues()
        values.set("attr", [attr.rawValue])
        values.set("action", action.map(\.rawValue))
        self.parameters = values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        guard let attrRaw = parameters.single("attr"), let attr = AccountAttribute(rawValue: attrRaw) else {
            throw .missingRequiredParameter(prefix: Self.schema.prefix, key: "attr")
        }
        let actionRaw = parameters.multiple("action")
        let action = actionRaw.compactMap(AccountAction.init(rawValue:))
        guard action.count == actionRaw.count, !action.isEmpty else {
            throw .invalidParameterValue(prefix: Self.schema.prefix, key: "action", value: actionRaw.joined(separator: ","))
        }
        self.attr = attr
        self.action = action
        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "account",
        positionalKey: "attr",
        parameters: [
            .init(key: "attr", arity: .single, isRequired: true,
                  validate: { AccountAttribute(rawValue: $0) != nil }),
            // NO `normalize`. `account-permission.ts:54-59` declares exactly
            // `multiple` / `required` / `validate` / `default` — verified by
            // reading the whole declaration. It is the ONLY multi-valued
            // parameter in the seven families without a normalizer, and the
            // omission is upstream's, not an oversight in the port.
            //
            // Inventing one (`AccountAction.allCases.filter(given.contains)`)
            // would diverge the canonical BYTES: `account:email?action=manage&action=read`
            // would canonicalise to `account:email?action=read&action=manage`
            // with a normalizer and to `account:email?action=manage&action=read`
            // without one, because `format` appends the deduped set in
            // INSERTION order (parser.ts:82-85). Since §9-D7 makes canonical
            // form load-bearing for the registration subset check, that is not
            // cosmetic.
            .init(key: "action", arity: .multiple,
                  defaultValue: [AccountAction.read.rawValue],
                  validate: { AccountAction(rawValue: $0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        public let attr: AccountAttribute
        public let action: AccountAction

        public init(attr: AccountAttribute, action: AccountAction) {
            self.attr = attr
            self.action = action
        }
    }

    /// account-permission.ts:35-40. `manage` subsumes `read`; the implication is
    /// one-directional — a `read` grant never satisfies a `manage` request.
    public func matches(_ target: Target) -> Bool {
        guard attr == target.attr else { return false }
        return action.contains(.manage) || action.contains(target.action)
    }

    /// account-permission.ts:49-59. Does not validate its input (§5.4); builds
    /// the parameter set directly so an out-of-band `Target` (there is none
    /// today, since `AccountAttribute`/`AccountAction` are closed enums) still
    /// formats rather than throwing on construction.
    public static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String {
        var values = ScopeParameterValues()
        values.set("attr", [target.attr.rawValue])
        values.set("action", [target.action.rawValue])
        return try schema.format(values)
    }
}
