/// Insertion-ordered multimap over a scope's query string.
///
/// Order is load-bearing: canonical serialisation is *schema-declaration*
/// order, never alphabetical (parser.ts:54 iterates `schemaKeys`, a `Set`
/// built from `Object.keys(schema)`; nothing in `format`/`toString` sorts).
/// A Swift `Dictionary` would randomise that, so the storage is an array.
///
/// Upstream distinguishes `undefined` (key absent) from `null` (key present but
/// structurally invalid): `lib/syntax-string.ts:18-23` returns `null` when
/// `getSingle` finds more than one value; `lib/parser.ts:121-122` rejects on
/// `null` while `:142-156` treats `undefined` as "fall through to positional,
/// then default". Collapsing both into Swift's `String?` silently turns
/// `space:x?skey=a&skey=b` from *reject* into *use the default*.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.3.
public struct ScopeParameterBag: Sendable, Hashable {
    public struct Entry: Sendable, Hashable {
        public let key: String
        public let value: String
        public init(key: String, value: String) { self.key = key; self.value = value }
    }

    /// The three states mirror upstream's `undefined | value | null` convention
    /// exactly (syntax-string.ts:18-23): `.repeated` means "present but
    /// malformed", never "absent".
    public enum SingleLookup: Sendable, Hashable {
        case absent
        case present(String)
        case repeated([String])
    }

    public private(set) var entries: [Entry]

    public init(_ entries: [Entry] = []) { self.entries = entries }

    public var isEmpty: Bool { entries.isEmpty }

    /// Distinct keys in first-appearance order (syntax-string.ts:14-16).
    public func orderedKeys() -> [String] {
        var seen = Set<String>()
        return entries.compactMap { seen.insert($0.key).inserted ? $0.key : nil }
    }

    public func values(for key: String) -> [String] {
        entries.lazy.filter { $0.key == key }.map(\.value)
    }

    public func single(_ key: String) -> SingleLookup {
        let found = values(for: key)
        switch found.count {
        case 0: return .absent
        case 1: return .present(found[0])
        default: return .repeated(found)
        }
    }

    /// `nil` when absent; `[]` is never produced by the parser but is a legal
    /// programmatic value that the schema rejects (parser.ts:131).
    public func multiple(_ key: String) -> [String]? {
        let found = values(for: key)
        return found.isEmpty ? nil : found
    }

    public mutating func append(key: String, value: String) {
        entries.append(Entry(key: key, value: value))
    }

    public mutating func set(key: String, value: String) {
        entries.removeAll { $0.key == key }
        entries.append(Entry(key: key, value: value))
    }
}
