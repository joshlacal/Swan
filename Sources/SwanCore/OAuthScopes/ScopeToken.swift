/// A single RFC 6749 §3.3 `scope-token`:
///   scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// SP terminates a token, and `"` / `\` are excluded so a grant survives being
/// carried inside a quoted string. Every serialiser output and every value
/// interpolated into a scope passes through here — mirrors
/// `atproto-oauth/src/scopes.rs:1040-1061`, which calls the token charset check
/// load-bearing, not cosmetic: anything that builds a scope by interpolating a
/// value it did not choose must check it, or "a field that reads as a name is
/// free to append a second grant to it."
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.2.
public struct ScopeToken: Sendable, Hashable, CustomStringConvertible {
    public let rawValue: String

    public init?(_ rawValue: String) {
        guard Self.isScopeToken(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    public static func isScopeToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { byte in
            byte == 0x21 || (0x23...0x5b).contains(byte) || (0x5d...0x7e).contains(byte)
        }
    }

    public var description: String { rawValue }
}
