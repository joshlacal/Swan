import Foundation

/// The lexicon-JSON side of `include:` expansion — the three types a resolved
/// `com.atproto.lexicon.schema` permission-set document decodes into.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.7.3.
/// Upstream: `oauth-scopes/lib/lexicon.ts:6-21`.

// MARK: - LexiconValue

/// `ParamValue = string | number | boolean` (`lib/syntax.ts:1`), plus the array
/// form the `LexiconPermission` index signature also admits
/// (`lib/lexicon.ts:9`).
///
/// **THE ARITY IS PART OF THE VALUE and must not be erased.** `.scalar` and a
/// one-element `.list` are different values with different security meanings:
/// `getMulti` returns upstream `null` — a whole-entry rejection — for a scalar
/// where an array is required (`syntax-lexicon.ts:59-64`, `parser.ts:121-122`).
/// Stringify a scalar `collection` into a one-element array and the entry that
/// upstream *rejects* (`include-scope.test.ts:493-507`) expands instead into a
/// live `repo:` create/update/delete grant. Do NOT collapse the two cases, and
/// do not add a convenience initializer that does it for a caller.
public enum LexiconValue: Sendable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case list([LexiconValue])

    /// The stringification `ScopeParameterSchema` consumes, applied only AFTER
    /// arity has been checked by `getSingle` / `getMulti`.
    ///
    /// `nil` for `.list`: an array has no scalar text, and every caller treats
    /// `nil` as "reject", never as "absent".
    ///
    /// The numeric branch is hardened against its own input. The spec's sketch
    /// reads `n == n.rounded() ? String(Int(n)) : String(n)`; `Int(n)` **traps**
    /// on any magnitude outside `Int`'s range, and `n` arrives from an
    /// attacker-reachable lexicon document, so `{"collection": 1e300}` would be
    /// a remote crash rather than a rejected entry. The guard below is the only
    /// deviation, and it changes no accepted value: no `repo:` / `rpc:` /
    /// `space:` parameter has a `validate` that any numeric text can satisfy, so
    /// every numeric field is rejected either way — this only decides *how*.
    var scalarText: String? {
        switch self {
        case let .string(value):
            return value
        case let .number(value):
            guard value.isFinite else { return nil }
            // 2^53: above it `Double` cannot represent consecutive integers, and
            // `String(Int(_:))` stops agreeing with JavaScript's `String(number)`.
            if value == value.rounded(), value.magnitude < 9_007_199_254_740_992 {
                return String(Int(value))
            }
            return String(value)
        case let .bool(value):
            return value ? "true" : "false"
        case .list:
            return nil
        }
    }
}

extension LexiconValue: Decodable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        // JSON `null` is NOT a `ParamValue`. Upstream reaches it (`Object.hasOwn`
        // is true, `get()` returns it) and rejects the entry that carries it;
        // Swan rejects the whole DOCUMENT instead, which is strictly narrower —
        // see `LexiconPermission`'s doc comment for why that direction is safe.
        guard !container.decodeNil() else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "null is not a lexicon permission parameter value"
            )
        }
        // Bool BEFORE Double: `inheritAud: true` is genuinely a boolean and must
        // not decode as the number 1 (`include-scope.ts:97` compares `=== true`).
        if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([LexiconValue].self) {
            self = .list(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "not a string, number, boolean, or array of those"
            )
        }
    }
}

// MARK: - LexiconPermission

/// A permission entry as it appears in lexicon JSON (`lib/lexicon.ts:6-10`).
///
/// `type` and `resource` are the two reserved discriminators; `fields` holds
/// EVERYTHING ELSE, `spaceType` included, and by construction contains neither
/// `type` nor `resource` — `LexPermissionSyntax` is what makes that safe against
/// §4.6's unknown-key rule.
///
/// **Decoding is fail-closed on a malformed field, and that is a deliberate,
/// narrow divergence.** Upstream drops only the offending *entry* when a field
/// is `null` or otherwise not a `ParamValue`; Swan fails the whole document
/// decode, which surfaces as "document fails lexicon-schema validation" in
/// §5.7.5's matrix (`invalid_scope` at PAR, `invalid_request` at mint). It
/// grants strictly less than upstream, never more, and it hands no new lever to
/// the authority — an authority that can put `null` in a field can equally
/// decline to serve the document at all.
public struct LexiconPermission: Sendable, Equatable {
    /// Must be exactly `"permission"` (`lexicon.ts:7`). Retained rather than
    /// asserted here: `include-scope.ts:76-108` dispatches on `resource` alone
    /// and never reads `type`, so enforcing it at decode would reject documents
    /// upstream accepts.
    public let type: String
    public let resource: String
    public let fields: [String: LexiconValue]

    public init(type: String = "permission", resource: String, fields: [String: LexiconValue]) {
        self.type = type
        self.resource = resource
        self.fields = fields
    }
}

extension LexiconPermission: Decodable {
    private struct DynamicKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue _: Int) { nil }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: DynamicKey.self)
        self.type = try container.decode(String.self, forKey: DynamicKey(stringValue: "type"))
        self.resource = try container.decode(String.self, forKey: DynamicKey(stringValue: "resource"))
        var fields: [String: LexiconValue] = [:]
        for key in container.allKeys where key.stringValue != "type" && key.stringValue != "resource" {
            fields[key.stringValue] = try container.decode(LexiconValue.self, forKey: key)
        }
        self.fields = fields
    }
}

// MARK: - LexiconPermissionSet

/// Mirrors `LexiconPermissionSet` (`oauth-scopes/lib/lexicon.ts:14-21`) INCLUDING
/// the `type` discriminator, which `lexicon-manager.ts:126-129` keys its "not a
/// permission set" rejection off. Dropping it makes that rejection
/// unimplementable.
///
/// `title:lang` / `detail:lang` (`lexicon.ts:17`, `:20`) are accepted and
/// ignored: they are display-localisation maps and contribute no capability.
public struct LexiconPermissionSet: Sendable, Equatable, Decodable {
    /// Must decode to exactly `"permission-set"` (`lexicon.ts:15`). Checked by
    /// the resolver (P2-E, §5.7.4), not here — expansion is given a document
    /// that has already been classified.
    public let type: String
    public let permissions: [LexiconPermission]
    public let title: String?
    public let detail: String?

    public init(
        type: String = "permission-set",
        permissions: [LexiconPermission],
        title: String? = nil,
        detail: String? = nil
    ) {
        self.type = type
        self.permissions = permissions
        self.title = title
        self.detail = detail
    }
}
