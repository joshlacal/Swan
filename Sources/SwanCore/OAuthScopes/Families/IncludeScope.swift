/// `include:` — the family Swan has no equivalent of. Source:
/// `oauth-scopes/scopes/include-scope.ts:27-226`, consumed by
/// `oauth-provider/lexicon/lexicon-manager.ts` and `lexicon-getter.ts`.
///
/// `IncludeScope` is **not** a permission. It does not implement `Matchable`
/// (`include-scope.ts:22-26`) and has no `matches`. It names a *lexicon-defined
/// permission set* that must be fetched and expanded into concrete
/// `repo:` / `rpc:` / `space:` scopes before anything can be matched against it
/// — hence `ScopeFamily` conformance only, not `ScopePermission` (§4.7).
///
/// **Phase 1 ships the type, not the resolver (§9-D4):** `include:` parses, is
/// persisted verbatim, and grants nothing at request time. Phase 2 (the
/// lexicon-fetch-and-expand resolver, §5.7.3-§5.7.6 of the spec) is a port of
/// `packages/lex/lex-resolver/src/lex-resolver.ts` requiring a network fetcher
/// and CBOR/CAR/signature verification — structurally out of reach of
/// `SwanCore`, which imports no network layer (§3's module fence) — and is
/// therefore explicitly OUT OF SCOPE for this grammar/core lane. See this
/// lane's receipt.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.7.1.
public struct IncludeScope: Sendable, Hashable, ScopeFamily {
    /// Positional key. single, required, no default.
    public let nsid: String
    /// single, not required, NO DEFAULT (absent stays absent — this is why
    /// `ScopeParameterSchema.parse` must omit the key rather than store an
    /// empty array). include-scope.ts:184-188.
    public let aud: AudParam?

    private let parameters: ScopeParameterValues

    public init(nsid: String, aud: AudParam? = nil) {
        self.nsid = nsid
        self.aud = aud
        var values = ScopeParameterValues()
        values.set("nsid", [nsid])
        if let aud { values.set("aud", [aud.stringValue]) }
        self.parameters = values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        guard let nsid = parameters.single("nsid") else {
            throw .missingRequiredParameter(prefix: Self.schema.prefix, key: "nsid")
        }
        self.nsid = nsid
        if let audRaw = parameters.single("aud") {
            self.aud = audRaw == "*" ? .any : .service(audRaw)
        } else {
            self.aud = nil
        }
        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "include",
        positionalKey: "nsid",
        parameters: [
            .init(key: "nsid", arity: .single, isRequired: true,
                  validate: AtprotoSyntax.isValidNSID),
            // include-scope.ts:16, :184-188 — same `@atproto/did` predicate as
            // `rpc:`'s `aud` (§5.5): `isAtprotoDidRefAbsolute`,
            // `packages/did/src/atproto.ts:230-235`. Methods are restricted to
            // `plc` and `web` (`atproto.ts:19`); the fragment is mandatory and
            // non-empty (`did-ref.ts:14-15`).
            .init(key: "aud", arity: .single, defaultValue: nil,
                  validate: { $0 == "*" || AtprotoSyntax.isValidAtprotoDIDRefAbsolute($0) }),
        ]
    )
}
