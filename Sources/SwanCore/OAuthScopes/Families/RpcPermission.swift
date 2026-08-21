/// Source: `oauth-scopes/scopes/rpc-permission.ts:22-98`.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.5.
public enum LxmParam: Sendable, Hashable, Comparable {
    case any // "*"
    case nsid(String) // rpc-permission.ts:22-24

    public var stringValue: String {
        switch self {
        case .any: "*"
        case let .nsid(value): value
        }
    }

    public static func < (lhs: LxmParam, rhs: LxmParam) -> Bool {
        lhs.stringValue < rhs.stringValue
    }
}

public enum AudParam: Sendable, Hashable {
    case any // "*"
    /// An atproto DID (`plc` or `web` only) plus a MANDATORY non-empty RFC 3986
    /// fragment — `isAtprotoDidRefAbsolute`, `packages/did/src/atproto.ts:230-235`,
    /// reached from `rpc-permission.ts:25-27`. Grammar and vectors: §4.1.
    case service(String)

    public var stringValue: String {
        switch self {
        case .any: "*"
        case let .service(value): value
        }
    }
}

public struct RpcPermission: ScopePermission {
    /// single, REQUIRED, NO DEFAULT. Omitting `aud` always fails the parse
    /// (rpc-permission.ts:67-70; test :58-62).
    public let aud: AudParam
    /// Positional key. multiple, required, no default.
    public let lxm: [LxmParam]

    private let parameters: ScopeParameterValues

    /// `rpc:*?aud=*` is forbidden even though this initializer would otherwise
    /// accept it — the check lives in the parse path, not here
    /// (rpc-permission.ts:86-88 → ScopeParseError.forbiddenParameterCombination).
    /// Keep that split: a caller constructing `RpcPermission(.any, [.any])`
    /// directly exercises a path upstream also leaves open (no test calls it).
    public init(aud: AudParam, lxm: [LxmParam]) {
        self.aud = aud
        self.lxm = lxm
        var values = ScopeParameterValues()
        values.set("lxm", lxm.map(\.stringValue))
        values.set("aud", [aud.stringValue])
        self.parameters = values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        let lxmRaw = parameters.multiple("lxm")
        guard !lxmRaw.isEmpty else {
            throw .emptyMultiValuedParameter(prefix: Self.schema.prefix, key: "lxm")
        }
        let lxm = lxmRaw.map { $0 == "*" ? LxmParam.any : .nsid($0) }
        guard let audRaw = parameters.single("aud") else {
            throw .missingRequiredParameter(prefix: Self.schema.prefix, key: "aud")
        }
        let aud: AudParam = audRaw == "*" ? .any : .service(audRaw)
        // rpc-permission.ts:86-88 — "any audience + any method" is never a
        // valid grant (rpc-permission.test.ts:96-99).
        if case .any = aud, lxm.contains(.any) {
            throw .forbiddenParameterCombination(
                prefix: Self.schema.prefix, detail: "aud=* and lxm=* together"
            )
        }
        self.aud = aud
        self.lxm = lxm
        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "rpc",
        positionalKey: "lxm",
        parameters: [
            .init(key: "lxm", arity: .multiple, isRequired: true,
                  normalize: { $0.contains("*") && $0.count > 1 ? ["*"] : Array(Set($0)).sorted() },
                  validate: { $0 == "*" || AtprotoSyntax.isValidNSID($0) }),
            // rpc-permission.ts:25-27 — `value === '*' || isAtprotoDidRefAbsolute(value)`,
            // imported from `@atproto/did` (`packages/did/src/atproto.ts:230-235`).
            // NOT the generic DID validator: `aud=did:foo:bar#baz` must be nil.
            .init(key: "aud", arity: .single, isRequired: true,
                  validate: { $0 == "*" || AtprotoSyntax.isValidAtprotoDIDRefAbsolute($0) }),
        ]
    )

    public struct Target: Sendable, Hashable {
        public let lxm: String
        public let aud: String
        public init(lxm: String, aud: String) {
            self.lxm = lxm
            self.aud = aud
        }
    }

    /// rpc-permission.ts:43-49. Both dimensions are exact-string; there is no
    /// prefix matching on `lxm`.
    public func matches(_ target: Target) -> Bool {
        switch aud {
        case .any: break
        case let .service(s): guard s == target.aud else { return false }
        }
        if lxm.contains(.any) { return true }
        return lxm.contains(.nsid(target.lxm))
    }

    public static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String {
        var values = ScopeParameterValues()
        values.set("lxm", [target.lxm])
        values.set("aud", [target.aud])
        return try schema.format(values)
    }
}
