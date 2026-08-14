/// Source: `oauth-scopes/scopes/identity-permission.ts:7-55`. The smallest
/// family: one parameter, no `action`, and the wildcard lives **inside the
/// enum**.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.3.
public enum IdentityAttribute: String, Sendable, Hashable, CaseIterable {
    case handle
    case any = "*" // identity-permission.ts:7-8
}

public struct IdentityPermission: ScopePermission {
    /// Positional key. single, required, no default. There is no second
    /// parameter — any `?action=…` makes the whole scope invalid via the
    /// unknown-key rejection at parser.ts:105-107.
    public let attr: IdentityAttribute

    private let parameters: ScopeParameterValues

    public init(_ attr: IdentityAttribute) {
        self.attr = attr
        var values = ScopeParameterValues()
        values.set("attr", [attr.rawValue])
        self.parameters = values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        guard let attrRaw = parameters.single("attr"), let attr = IdentityAttribute(rawValue: attrRaw) else {
            throw .missingRequiredParameter(prefix: Self.schema.prefix, key: "attr")
        }
        self.attr = attr
        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "identity",
        positionalKey: "attr",
        parameters: [
            .init(key: "attr", arity: .single, isRequired: true,
                  validate: { IdentityAttribute(rawValue: $0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        public let attr: IdentityAttribute
        public init(attr: IdentityAttribute) { self.attr = attr }
    }

    /// identity-permission.ts:20-22. Asymmetric: a `*` GRANT satisfies any
    /// request, but a `handle` grant does NOT satisfy a `*` request.
    public func matches(_ target: Target) -> Bool {
        attr == .any || attr == target.attr
    }

    public static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String {
        var values = ScopeParameterValues()
        values.set("attr", [target.attr.rawValue])
        return try schema.format(values)
    }
}
