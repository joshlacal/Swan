/// Source: `oauth-scopes/scopes/blob-permission.ts:21-106`, matcher in
/// `oauth-scopes/lib/mime.ts`.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.2.
///
/// `*/*` | `type/*` | `type/subtype`. Never `*/subtype`, never `**`. mime.ts:21-28.
public enum AcceptPattern: Sendable, Equatable, Hashable, Comparable {
    case any // "*/*"
    case type(String) // "image/*" — stores "image"
    case exact(String, String) // "image/png"

    public var stringValue: String {
        switch self {
        case .any: "*/*"
        case let .type(t): "\(t)/*"
        case let .exact(t, s): "\(t)/\(s)"
        }
    }

    /// mime.ts:3-13 + :23-28. Exactly one "/", non-empty both sides, no spaces,
    /// and "*" only as the whole value or as the trailing subtype.
    public init?(_ raw: String) {
        guard !raw.isEmpty, !raw.contains(" ") else { return nil }
        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let type = String(parts[0]), subtype = String(parts[1])
        guard !type.isEmpty, !subtype.isEmpty else { return nil }
        if type == "*" {
            guard subtype == "*" else { return nil } // "*/subtype" is never valid
            self = .any
        } else if subtype == "*" {
            guard !type.contains("*") else { return nil }
            self = .type(type)
        } else {
            guard !type.contains("*"), !subtype.contains("*") else { return nil }
            self = .exact(type, subtype)
        }
    }

    public static func < (lhs: AcceptPattern, rhs: AcceptPattern) -> Bool {
        lhs.stringValue < rhs.stringValue
    }
}

/// mime.ts:17-19 — `isStringSlashString` AND contains no "*".
public struct ConcreteMime: Sendable, Hashable {
    public let type: String
    public let subtype: String

    public init?(_ raw: String) {
        guard !raw.isEmpty, !raw.contains(" "), !raw.contains("*") else { return nil }
        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let type = String(parts[0]), subtype = String(parts[1])
        guard !type.isEmpty, !subtype.isEmpty else { return nil }
        self.type = type
        self.subtype = subtype
    }
}

public struct BlobPermission: ScopePermission {
    /// Positional key. multiple, required, NO default — bare `blob` is rejected
    /// (blob-permission.ts:38-40, test :21-24). Never empty.
    public let accept: [AcceptPattern]

    private let parameters: ScopeParameterValues

    public init(accept: [AcceptPattern]) {
        self.accept = accept
        var values = ScopeParameterValues()
        values.set("accept", accept.map(\.stringValue))
        self.parameters = values
    }

    public init(parameters: ScopeParameterValues) throws(ScopeParseError) {
        let raw = parameters.multiple("accept")
        let accept = raw.compactMap(AcceptPattern.init)
        guard accept.count == raw.count, !accept.isEmpty else {
            throw .invalidParameterValue(prefix: Self.schema.prefix, key: "accept", value: raw.joined(separator: ","))
        }
        self.accept = accept
        self.parameters = parameters
    }

    public var scopeParameters: ScopeParameterValues { parameters }

    public static let schema = ScopeParameterSchema(
        prefix: "blob",
        positionalKey: "accept",
        parameters: [
            .init(key: "accept", arity: .multiple, isRequired: true,
                  normalize: Self.normalizeAccept, // blob-permission.ts:42-50, :84-106
                  validate: { AcceptPattern($0) != nil }),
        ]
    )

    public struct Target: Sendable, Hashable {
        /// The declared Content-Type of the blob being uploaded.
        public let mime: String
        public init(mime: String) { self.mime = mime }
    }

    /// mime.ts:45-47, :66-71. The REQUEST mime is gated FIRST: it must itself be
    /// a concrete `type/subtype` with no `*` anywhere, or nothing matches — not
    /// even `*/*` (mime.test.ts:73-74).
    public func matches(_ target: Target) -> Bool {
        guard let concrete = ConcreteMime(target.mime) else { return false }
        return accept.contains { Self.covers($0, concrete) }
    }

    /// mime.ts:35-43. First-match-wins OR. Upstream's `type/*` arm is
    /// `mime.startsWith(accept.slice(0, -1))`, i.e. a prefix test on "type/";
    /// comparing the parsed type is equivalent because ConcreteMime already
    /// required exactly one "/".
    private static func covers(_ pattern: AcceptPattern, _ mime: ConcreteMime) -> Bool {
        switch pattern {
        case .any: true
        case let .type(t): mime.type == t
        case let .exact(t, s): mime.type == t && mime.subtype == s
        }
    }

    /// blob-permission.ts:42-50, :84-106:
    ///  1. if the list contains `*/*` → collapse to exactly ["*/*"];
    ///  2. else lowercase every value, drop each `type/subtype` already covered
    ///     by a `type/*` in the same list, then sort lexicographically.
    /// Duplicate removal is handled downstream by `ScopeParameterSchema.format`
    /// (parser.ts:82-85), not here.
    static let normalizeAccept: @Sendable ([String]) -> [String] = { given in
        let lowered = given.map { $0.lowercased() }
        if lowered.contains("*/*") { return ["*/*"] }
        let parsed = lowered.map { (raw: $0, pattern: AcceptPattern($0)) }
        let typeWildcards = Set(parsed.compactMap { entry -> String? in
            if case let .type(t)? = entry.pattern { return t }
            return nil
        })
        return parsed
            .filter { entry in
                if case let .exact(t, _)? = entry.pattern, typeWildcards.contains(t) { return false }
                return true
            }
            .map(\.raw)
            .sorted()
    }

    /// blob-permission.ts:42-45. Does not validate its input (§5.4) — builds
    /// the parameter set directly from the raw target mime string rather than
    /// round-tripping through `AcceptPattern`, which is a failable parse and
    /// would make a malformed target unrepresentable rather than merely
    /// unmatchable.
    public static func scopeNeeded(for target: Target) throws(ScopeParseError) -> String {
        var values = ScopeParameterValues()
        values.set("accept", [target.mime])
        return try schema.format(values)
    }
}
