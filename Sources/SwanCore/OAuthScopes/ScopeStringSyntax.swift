import Foundation

/// Lexical decomposition of a scope string:
///   scope = prefix [ ":" positional ] [ "?" query ]
/// Positional runs to the first `?`; everything after the *first* `?` is one
/// query string, so a literal `?` inside a value belongs to the preceding
/// value rather than starting a new pair (syntax-string.test.ts:36-42). A later
/// `#` is likewise a literal — this is a query string, not a URL, so there is
/// no fragment (include-scope.test.ts:32-39).
///
/// Direct port of `syntax-string.ts:44-75` with `minIdx` (`util.ts:5-9`) inlined.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.4, §4.5.
public struct ScopeStringSyntax: Sendable, Hashable {
    public let prefix: String
    /// `nil` = no `:` segment. `""` is legal and distinct: `"my-res:"` parses
    /// to an empty positional (syntax-string.test.ts:16-18). Load-bearing —
    /// it is why `"rpc:?aud=…"` is rejected for an INVALID (empty) `lxm`
    /// rather than for a missing one (rpc-permission.test.ts:53-55).
    public let positional: String?
    public let parameters: ScopeParameterBag

    public init(prefix: String, positional: String? = nil, parameters: ScopeParameterBag = .init()) {
        self.prefix = prefix
        self.positional = positional
        self.parameters = parameters
    }

    // MARK: parse

    public static func parse(_ scope: String) throws(ScopeParseError) -> ScopeStringSyntax {
        guard ScopeToken.isScopeToken(scope) else { throw .notAScopeToken(scope) }

        let bytes = Array(scope.utf8)
        let questionIdx = bytes.firstIndex(of: 0x3f) // "?"
        let colonIdx = bytes.firstIndex(of: 0x3a) // ":"

        // util.ts:5-9 minIdx — min of the two, ignoring "absent".
        let prefixEnd: Int? = switch (colonIdx, questionIdx) {
        case (nil, nil): nil
        case let (value?, nil): value
        case let (nil, value?): value
        case let (a?, b?): Swift.min(a, b)
        }

        guard let prefixEnd else {
            return ScopeStringSyntax(prefix: scope)
        }

        let prefix = String(decoding: bytes[..<prefixEnd], as: UTF8.self)

        // syntax-string.ts:58-66: a positional exists only when `:` precedes `?`.
        var positional: String?
        if let colonIdx {
            if let questionIdx {
                if colonIdx < questionIdx {
                    positional = try decodeURIComponent(bytes[(colonIdx + 1)..<questionIdx], in: scope)
                }
            } else {
                positional = try decodeURIComponent(bytes[(colonIdx + 1)...], in: scope)
            }
        }

        // syntax-string.ts:68-72: an empty query (`"x?"`) yields no params at all.
        var parameters = ScopeParameterBag()
        if let questionIdx, questionIdx < bytes.count - 1 {
            parameters = parseQueryString(bytes[(questionIdx + 1)...])
        }

        return ScopeStringSyntax(prefix: prefix, positional: positional, parameters: parameters)
    }

    /// `application/x-www-form-urlencoded` decoding, matching `URLSearchParams`:
    /// split on `&`, split each pair on the FIRST `=`, `+` decodes to SPACE,
    /// `%XX` decodes bytewise. A pair with no `=` yields an empty value; an
    /// empty pair (from `a=1&&b=2`) is SKIPPED, matching URLSearchParams and
    /// NOT SwanCore.swift:218-227, which rejects it (fence vector D10, §7.3).
    /// NON-THROWING by design — see the decoder table below.
    private static func parseQueryString(_ bytes: ArraySlice<UInt8>) -> ScopeParameterBag {
        var bag = ScopeParameterBag()
        for pair in bytes.split(separator: 0x26, omittingEmptySubsequences: true) { // "&"
            let split = pair.split(separator: 0x3d, maxSplits: 1, omittingEmptySubsequences: false) // "="
            let key = decodeFormComponent(split[0])
            let value = split.count > 1 ? decodeFormComponent(split[1]) : ""
            bag.append(key: key, value: value)
        }
        return bag
    }

    /// `URLSearchParams` semantics: LOSSY, never throws (syntax-string.ts:71).
    /// A malformed `%` sequence survives as literal bytes; invalid UTF-8 becomes
    /// U+FFFD.
    ///
    /// Percent-decoding is NOT symmetric upstream:
    ///   positional -> `decodeURIComponent(...)` -> THROWS on a malformed `%`
    ///   query      -> `new URLSearchParams(...)` -> NEVER throws
    /// `%` is in the DID charset (`syntax/src/did.ts:51`), so
    /// `space:*?authority=did:web:ex%ample.com` parses upstream and would throw
    /// under a symmetric-strict decoder — do NOT unify the two decoders.
    private static func decodeFormComponent(_ bytes: ArraySlice<UInt8>) -> String {
        let folded = bytes.map { $0 == 0x2b ? 0x20 : $0 }[...] // "+" -> SP
        return lossyPercentDecode(folded)
    }

    /// `decodeURIComponent` semantics: STRICT, throws (syntax-string.ts:62-64).
    /// Used for the positional segment only. No `+` folding outside a query.
    private static func decodeURIComponent(
        _ bytes: ArraySlice<UInt8>, in scope: String
    ) throws(ScopeParseError) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let byte = bytes[index]
            if byte == 0x25 { // "%"
                let high = bytes.index(index, offsetBy: 1, limitedBy: bytes.endIndex - 1)
                let low = bytes.index(index, offsetBy: 2, limitedBy: bytes.endIndex - 1)
                guard let high, let low,
                      let hi = hexValue(bytes[high]), let lo = hexValue(bytes[low])
                else { throw .malformedPercentEncoding(scope) }
                out.append(hi << 4 | lo)
                index = bytes.index(index, offsetBy: 3)
            } else {
                out.append(byte)
                index = bytes.index(after: index)
            }
        }
        guard let decoded = String(bytes: out, encoding: .utf8) else {
            throw .malformedPercentEncoding(scope)
        }
        return decoded
    }

    private static func lossyPercentDecode(_ bytes: ArraySlice<UInt8>) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let byte = bytes[index]
            if byte == 0x25,
               let high = bytes.index(index, offsetBy: 1, limitedBy: bytes.endIndex - 1),
               let low = bytes.index(index, offsetBy: 2, limitedBy: bytes.endIndex - 1),
               let hi = hexValue(bytes[high]), let lo = hexValue(bytes[low]) {
                out.append(hi << 4 | lo)
                index = bytes.index(index, offsetBy: 3)
            } else {
                // Literal `%` (or a truncated / non-hex escape) passes through
                // verbatim — URLSearchParams does not reject it.
                out.append(byte)
                index = bytes.index(after: index)
            }
        }
        // `String(decoding:as:)` substitutes U+FFFD, matching the WHATWG URL
        // spec's UTF-8 decode-without-BOM-or-fail behaviour. Never nil.
        return String(decoding: out, as: UTF8.self)
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }

    // MARK: prefix matching — syntax.ts:16-33

    /// True iff `value` names this prefix: exact match, or prefix followed by
    /// `:` or `?`. Rejects superstring false positives such as
    /// `isScopeString("prefixes", for: "prefix")` (syntax.test.ts:32-42).
    /// This is what makes the seven prefixes disjoint and the §4.7 dispatcher
    /// safe.
    public static func isScopeString(_ value: String, for prefix: String) -> Bool {
        let value = Array(value.utf8), prefix = Array(prefix.utf8)
        guard value.count > prefix.count else { return value == prefix }
        let next = value[prefix.count]
        guard next == 0x3a || next == 0x3f else { return false }
        return value.starts(with: prefix)
    }
}

// MARK: - Canonical serialiser (§4.5) — two encoders that must not be unified

extension ScopeStringSyntax {
    /// Canonical wire form. syntax-string.ts:30-42.
    public func canonicalString() throws(ScopeParseError) -> String {
        var scope = prefix
        if let positional {
            scope += ":" + Self.normalizeAllowedChars(Self.encodeURIComponent(positional))
        }
        if !parameters.isEmpty {
            let query = parameters.entries
                .map { Self.encodeFormComponent($0.key) + "=" + Self.encodeFormComponent($0.value) }
                .joined(separator: "&")
            scope += "?" + Self.normalizeAllowedChars(query)
        }
        guard ScopeToken.isScopeToken(scope) else { throw .notAScopeToken(scope) }
        return scope
    }

    /// JavaScript `encodeURIComponent`: leaves A-Za-z0-9 and `-_.!~*'()` raw.
    static func encodeURIComponent(_ value: String) -> String {
        percentEncode(
            value,
            unreserved: Set(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()".utf8
            )
        )
    }

    /// `application/x-www-form-urlencoded` serialiser, as `URLSearchParams`
    /// does it: unreserved set is A-Za-z0-9 plus `*-._`, and SPACE becomes `+`
    /// (NOT `%20` — Foundation's `addingPercentEncoding` would emit `%20` and
    /// break byte-equality with the reference implementation).
    static func encodeFormComponent(_ value: String) -> String {
        var out = ""
        for byte in value.utf8 {
            if byte == 0x20 { out += "+" } else if Self.formUnreserved.contains(byte) {
                out.unicodeScalars.append(Unicode.Scalar(byte))
            } else {
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }

    private static let formUnreserved: Set<UInt8> = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._".utf8
    )

    private static func percentEncode(_ value: String, unreserved: Set<UInt8>) -> String {
        var out = ""
        for byte in value.utf8 {
            if unreserved.contains(byte) {
                out.unicodeScalars.append(Unicode.Scalar(byte))
            } else {
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }

    /// `normalizeURIComponent`, syntax-string.ts:82-132. Un-escapes exactly
    /// `: / + , @ %` and nothing else — never `?` or `&`, which would break
    /// query parsing (the @NOTE at syntax-string.ts:83-84).
    ///
    /// **Pinned upstream lossiness, deliberately reproduced.** `+` is in
    /// `ALLOWED_SCOPE_CHARS` (`syntax-string.ts:85`), so a param value
    /// containing a literal `+` is encoded to `%2B` by
    /// `URLSearchParams.toString()` and then un-escaped back to a raw `+` by
    /// this function — which re-parses as a SPACE. Round-trip of `+` inside a
    /// query value is **not** stable upstream (e.g. `blob:image/svg+xml` inside
    /// a multi-value `accept` list). Swan reproduces this rather than
    /// diverging — see §4.5.
    static func normalizeAllowedChars(_ value: String) -> String {
        var out = value
        for (encoded, raw) in [("%3A", ":"), ("%2F", "/"), ("%2B", "+"), ("%2C", ","), ("%40", "@"), ("%25", "%")] {
            out = out.replacingOccurrences(of: encoded, with: raw)
        }
        return out
    }
}
