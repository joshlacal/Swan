import Foundation

/// AT Protocol identifier syntax shared by the scope grammar and the space
/// resource domain. Three near-identical private copies existed before this
/// (SwanCore.swift:399-424, SwanSpaces.swift:77-102, SwanSpaces.swift:397+);
/// a scope grammar that disagrees with the resource matcher about what a DID
/// is turns a parse into an authorization difference.
///
/// Spec: docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4.1.
public enum AtprotoSyntax {
    /// syntax/src/did.ts:51, :67-70 — length <= 2048 and
    /// `^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$`.
    /// STRICTER than Swan's current SpaceURI.isValidDID (SwanSpaces.swift:77-82),
    /// which accepts a trailing `:` and a method containing digits/uppercase.
    /// `space:*?authority=did:` must be nil (space-permission.test.ts:91).
    ///
    /// THIS FUNCTION IS NOT MUTATED BY THE Q1 RULING (§9-D13). It is the
    /// permissive, method-AGNOSTIC `@atproto/syntax` DID, and it is the correct
    /// validator for `space:?authority=` (§5.6.2) and for `SpaceURI`. The strict,
    /// atproto-constrained DID reference is a SEPARATE function
    /// (`isValidAtprotoDIDRefAbsolute`, below) — never fold the two together.
    public static func isValidDID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count <= 2048, bytes.count >= 7 else { return false }
        guard bytes[0] == 0x64, bytes[1] == 0x69, bytes[2] == 0x64, bytes[3] == 0x3a else { return false } // "did:"
        // method = 1*[a-z]
        var i = 4
        let methodStart = i
        while i < bytes.count, (0x61...0x7A).contains(bytes[i]) { i += 1 }
        guard i > methodStart else { return false }
        guard i < bytes.count, bytes[i] == 0x3a else { return false } // ":"
        i += 1
        let msidStart = i
        guard i < bytes.count else { return false }
        while i < bytes.count, isDIDMSIDChar(bytes[i]) { i += 1 }
        guard i == bytes.count, i > msidStart else { return false }
        // Last character must NOT be ":" — [a-zA-Z0-9._-] only for the final byte.
        guard let last = bytes.last, isDIDMSIDCharExcludingColon(last) else { return false }
        return true
    }

    /// `[a-zA-Z0-9._:%-]`
    private static func isDIDMSIDChar(_ c: UInt8) -> Bool {
        (0x41...0x5A).contains(c) || (0x61...0x7A).contains(c) || (0x30...0x39).contains(c)
            || c == 0x2E || c == 0x5F || c == 0x3A || c == 0x25 || c == 0x2D
    }

    /// `[a-zA-Z0-9._-]` — the MSID charset minus `:` and `%`, used only for the
    /// final byte (did.ts:67-70 forbids a trailing `:` or an unterminated `%`).
    private static func isDIDMSIDCharExcludingColon(_ c: UInt8) -> Bool {
        (0x41...0x5A).contains(c) || (0x61...0x7A).contains(c) || (0x30...0x39).contains(c)
            || c == 0x2E || c == 0x5F || c == 0x2D
    }

    /// Re-derived from syntax/src/nsid.ts:86-118, NOT copied from SpaceURI.
    /// Total <= 317 bytes (nsid.ts:87), each segment <= 63, >= 3 segments.
    /// Three divergences from Swan's current SpaceURI.isValidNSID
    /// (SwanSpaces.swift:83-93), all resolved in upstream's favour (§9-D3):
    ///   com.example.foo-bar  upstream REJECT (last segment is a "name" and may
    ///                        not contain "-", nsid.ts:112-117) / Swan accepts
    ///   com.example-.foo     upstream REJECT (no segment ends in "-", :104-106)
    ///                        / Swan accepts
    ///   com.9example.foo     upstream ACCEPT (only segment 0 may not start with
    ///                        a digit, :109-111) / Swan rejects
    public static func isValidNSID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count <= 317, !bytes.isEmpty else { return false }
        let segments = splitOnDots(bytes)
        guard segments.count >= 3 else { return false }
        for (index, segment) in segments.enumerated() {
            guard segment.count >= 1, segment.count <= 63 else { return false }
            guard !segment.isEmpty else { return false }
            let isLastSegment = index == segments.count - 1
            for (offset, byte) in segment.enumerated() {
                let isAlpha = (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
                let isDigit = (0x30...0x39).contains(byte)
                let isHyphen = byte == 0x2D
                if isLastSegment {
                    // The final ("name") segment: alnum, but NO hyphen anywhere
                    // (nsid.ts:112-117) — e.g. "com.example.method1" is a valid
                    // NSID (digits are fine in the name segment; upstream's
                    // rejection of "foo-bar" is about the hyphen specifically,
                    // not about digits). Only segment 0 bans a leading digit
                    // (below), so the name segment may start with one.
                    guard isAlpha || isDigit else { return false }
                } else {
                    guard isAlpha || isDigit || isHyphen else { return false }
                    if offset == 0, isDigit, index == 0 {
                        // Only segment 0 may not start with a digit (nsid.ts:109-111).
                        return false
                    }
                    if offset == 0, isHyphen { return false }
                    if offset == segment.count - 1, isHyphen { return false }
                }
            }
        }
        return true
    }

    private static func splitOnDots(_ bytes: [UInt8]) -> [[UInt8]] {
        var segments: [[UInt8]] = []
        var current: [UInt8] = []
        for byte in bytes {
            if byte == 0x2E {
                segments.append(current)
                current = []
            } else {
                current.append(byte)
            }
        }
        segments.append(current)
        return segments
    }

    /// 1...512 bytes, not "." or "..", charset alnum + `-._:~`.
    /// SwanCore.swift:418-424 and SpaceURI.isValidRecordKey (SwanSpaces.swift:95-102)
    /// BOTH already agree with upstream here: they accept exactly
    /// space-permission.test.ts:114-126 (`self`, `3jui7kd54zh2y`, `a.b-c_d~e:f`,
    /// 512x`x`) and reject exactly :128-143 (`hello world`, `.`, `..`, `a/b`,
    /// `a#b`, 513x`x`). Keep the behaviour, delete the duplicates.
    public static func isValidRecordKey(_ value: String) -> Bool {
        guard value != ".", value != ".." else { return false }
        let bytes = Array(value.utf8)
        guard bytes.count >= 1, bytes.count <= 512 else { return false }
        return bytes.allSatisfy { byte in
            (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte) || (0x30...0x39).contains(byte)
                || byte == 0x2D || byte == 0x2E || byte == 0x5F || byte == 0x3A || byte == 0x7E
        }
    }

    /// Generic, method-AGNOSTIC absolute DID reference. Ported byte-for-byte
    /// from `packages/did/src/did-ref.ts:11-18`:
    ///   1. exactly one `#` — `:14` rejects "no `#`", `:16` rejects a second
    ///      `#` anywhere after the first (`value.includes('#', hashIndex + 1)`);
    ///   2. the fragment is NON-EMPTY — `:15`, `hashIndex === value.length - 1`;
    ///   3. the fragment satisfies RFC 3986 §3.5 `fragment = *( pchar / "/" / "?" )`
    ///      — `isFragment`, `packages/did/src/lib/uri.ts:5-59`;
    ///   4. the did-part satisfies the generic `isDid` (`did.ts:233-245`).
    /// Use this wherever a did-ref is a REQUEST TARGET.
    public static func isValidDIDRefAbsolute(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard let hash = bytes.firstIndex(of: 0x23) else { return false } // :14 no '#'
        guard hash != bytes.count - 1 else { return false } // :15 empty fragment
        guard !bytes[(hash + 1)...].contains(0x23) else { return false } // :16 second '#'
        guard isFragment(bytes, from: hash + 1, to: bytes.count) else { return false } // :17
        return isValidDID(String(decoding: bytes[..<hash], as: UTF8.self)) // :17 isDid
    }

    /// The ATPROTO-CONSTRAINED absolute DID reference — a DID whose method is
    /// `plc` or `web`, plus a MANDATORY non-empty RFC 3986 fragment. This is the
    /// validator `rpc:`'s and `include:`'s `aud=` use (`rpc-permission.ts:25-27`,
    /// `include-scope.ts:16`).
    ///
    /// PORTED, NOT RECONSTRUCTED. The definition is
    /// `packages/did/src/atproto.ts:230-235`:
    ///   `isDidRefAbsolute(value) && isAtprotoDid(value.slice(0, value.indexOf('#')))`
    /// — two independent passes, not one fused predicate.
    public static func isValidAtprotoDIDRefAbsolute(_ value: String) -> Bool {
        guard isValidDIDRefAbsolute(value) else { return false }
        let bytes = Array(value.utf8)
        guard let hash = bytes.firstIndex(of: 0x23) else { return false }
        return isValidAtprotoDID(String(decoding: bytes[..<hash], as: UTF8.self))
    }

    /// atproto.ts:27-29. Exposed separately because the atproto DID constraint
    /// is meaningful without a fragment (it is what `isValidAtprotoDIDRefAbsolute`
    /// applies to the did-part).
    public static func isValidAtprotoDID(_ value: String) -> Bool {
        if value.hasPrefix("did:plc:") { return isValidDIDPlc(value) }
        if value.hasPrefix("did:web:") { return isValidAtprotoDIDWeb(value) }
        return false // atproto.ts:19 — plc | web, closed set
    }

    /// plc.ts:10-19. Length-and-charset only; no MSID grammar.
    private static func isValidDIDPlc(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 32 else { return false } // plc.ts:6, :13
        guard value.hasPrefix("did:plc:") else { return false } // plc.ts:14
        for i in 8..<32 { // plc.ts:15-17
            let c = bytes[i]
            guard (0x61...0x7A).contains(c) || (0x32...0x37).contains(c) else { return false }
        } // isBase32Char, plc.ts:53-54: a-z 2-7
        return true
    }

    /// atproto.ts:74-88 layered on web.ts:10-23.
    private static func isValidAtprotoDIDWeb(_ value: String) -> Bool {
        guard isValidDIDWeb(value) else { return false } // atproto.ts:75-77
        guard !didWebHasPath(value) else { return false } // atproto.ts:79-81 / :90-92
        guard !didWebHasHTTPSPort(value) else { return false } // atproto.ts:83-85 / :102-116
        return true
    }

    /// methods/web.ts:10-23: prefix, no leading `:` at web.ts:13, `assertDidMsid`
    /// over the remainder, URL-parseability of the rebuilt `https://` URL.
    private static func isValidDIDWeb(_ value: String) -> Bool {
        guard value.hasPrefix("did:web:") else { return false }
        let msid = String(value.dropFirst(8))
        guard !msid.isEmpty, !msid.hasPrefix(":") else { return false }
        let bytes = Array(msid.utf8)
        guard bytes.allSatisfy(isDIDMSIDChar), let last = bytes.last, isDIDMSIDCharExcludingColon(last) else {
            return false
        }
        // Rebuild as an https:// URL to confirm parseability, mirroring upstream's
        // `%3A` -> `:` (port) and `:` -> `/` (path) reconstruction before parsing.
        let reconstructed = msid.replacingOccurrences(of: "%3A", with: ":").replacingOccurrences(of: ":", with: "/")
        guard URL(string: "https://" + reconstructed) != nil else { return false }
        return true
    }

    /// atproto.ts:90-92 — ANY `:` after the 8-byte `did:web:` prefix is a path.
    private static func didWebHasPath(_ did: String) -> Bool {
        did.dropFirst(8).contains(":")
    }

    /// atproto.ts:94-116. Localhost is exempt (`:95-100`), so a dev PDS at
    /// `did:web:localhost%3A8080` stays valid.
    private static func didWebHasHTTPSPort(_ did: String) -> Bool {
        if did == "did:web:localhost"
            || did.hasPrefix("did:web:localhost:")
            || did.hasPrefix("did:web:localhost%3A") { return false } // :95-100
        let tail = did.dropFirst(8)
        guard let pathIdx = tail.firstIndex(of: ":") else {
            // No path component: an encoded colon anywhere after the prefix is
            // a port. atproto.ts:105, :107-111.
            return tail.contains("%3A")
        }
        // There is a path component: an encoded colon BEFORE it is a port.
        // atproto.ts:112-114 (`did.lastIndexOf('%3A', pathIdx) !== -1`).
        return tail[..<pathIdx].range(of: "%3A", options: .backwards) != nil
    }

    // MARK: - RFC 3986 fragment grammar

    /// Ported from `packages/did/src/lib/uri.ts:5-59`. Operates on a UTF-8 byte
    /// slice so the charcode comparisons are literal transcriptions of upstream's
    /// `charCodeAt` switch rather than Character-level approximations.
    /// The caller MUST separately reject an empty range — see `did-ref.ts:15`.
    static func isFragment(_ value: [UInt8], from start: Int, to end: Int) -> Bool {
        var i = start
        while i < end {
            switch value[i] {
            case 0x41...0x5A, 0x61...0x7A, 0x30...0x39,
                 0x2D, 0x2E, 0x5F, 0x7E: // unreserved, uri.ts:20-27
                break
            case 0x21, 0x24, 0x26, 0x27, 0x28, 0x29,
                 0x2A, 0x2B, 0x2C, 0x3B, 0x3D: // sub-delims, uri.ts:28-41
                break
            case 0x3A, 0x40: // ":" "@", uri.ts:42-43
                break
            case 0x2F, 0x3F: // "/" "?", uri.ts:44-45
                break
            case 0x25: // "%", uri.ts:46-51
                guard i + 2 < end,
                      isHexDigit(value[i + 1]),
                      isHexDigit(value[i + 2]) else { return false }
                i += 2
            default:
                return false // uri.ts:52-54
            }
            i += 1
        }
        return true
    }

    /// uri.ts:61-67.
    private static func isHexDigit(_ c: UInt8) -> Bool {
        (0x30...0x39).contains(c) || (0x41...0x46).contains(c) || (0x61...0x66).contains(c)
    }
}
