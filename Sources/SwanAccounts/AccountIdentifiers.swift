import Foundation
import SwanCore

/// Swan intentionally supports only the two ATProto DID methods it can
/// canonicalize without network resolution: strict `did:plc` identifiers and
/// DNS-canonical `did:web` identifiers.
public enum AccountIdentifiers {
    public static func validateDID(_ did: String) throws -> String {
        let bytes = Array(did.utf8)
        guard bytes.count <= 2_048,
              bytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.invalidIdentifier("account DID")
        }
        let components = did.split(separator: ":", omittingEmptySubsequences: false)
        guard components.count >= 3, components[0] == "did" else {
            throw SwanError.invalidIdentifier("account DID")
        }

        switch components[1] {
        case "plc":
            guard components.count == 3,
                  components[2].utf8.count == 24,
                  components[2].utf8.allSatisfy({
                      ($0 >= 97 && $0 <= 122) || ($0 >= 50 && $0 <= 55)
                  }) else {
                throw SwanError.invalidIdentifier("account DID")
            }
        case "web":
            try validateWebDIDComponents(components)
        default:
            throw SwanError.invalidIdentifier("unsupported account DID method")
        }
        return did
    }

    public static func canonicalHandle(_ handle: String) throws -> String {
        let input = Array(handle.utf8)
        guard !input.isEmpty, input.count <= 253,
              input.allSatisfy({
                  ($0 >= 65 && $0 <= 90)
                      || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57)
                      || $0 == 45
                      || $0 == 46
              }) else {
            throw SwanError.invalidIdentifier("account handle")
        }

        let canonical = handle.lowercased()
        let labels = canonical.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2,
              labels.allSatisfy({
                  !$0.isEmpty
                      && $0.utf8.count <= 63
                      && $0.first != "-"
                      && $0.last != "-"
              }),
              labels.last?.allSatisfy(\.isNumber) == false else {
            throw SwanError.invalidIdentifier("account handle")
        }
        return canonical
    }

    private static func validateWebDIDComponents(_ components: [Substring]) throws {
        let authority = String(components[2])
        let authorityParts = authority.components(separatedBy: "%3A")
        guard (1 ... 2).contains(authorityParts.count),
              !authorityParts[0].contains("%") else {
            throw SwanError.invalidIdentifier("account DID")
        }
        try validateCanonicalDNSName(authorityParts[0])
        if authorityParts.count == 2 {
            let port = authorityParts[1]
            guard !port.isEmpty, !port.contains("%"),
                  port.count == 1 || port.first != "0",
                  let value = UInt16(port), value > 0 else {
                throw SwanError.invalidIdentifier("account DID")
            }
        }

        for component in components.dropFirst(3) {
            guard !component.isEmpty, component != ".", component != ".." else {
                throw SwanError.invalidIdentifier("account DID")
            }
            try validateCanonicalWebPathSegment(component)
        }
    }

    private static func validateCanonicalDNSName(_ name: String) throws {
        guard name.utf8.count <= 253,
              name.utf8.allSatisfy({
                  ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57)
                      || $0 == 45
                      || $0 == 46
              }) else {
            throw SwanError.invalidIdentifier("account DID")
        }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2,
              labels.allSatisfy({
                  !$0.isEmpty
                      && $0.utf8.count <= 63
                      && $0.first != "-"
                      && $0.last != "-"
              }),
              labels.last?.allSatisfy(\.isNumber) == false else {
            throw SwanError.invalidIdentifier("account DID")
        }
    }

    private static func validateCanonicalWebPathSegment(_ segment: Substring) throws {
        let bytes = Array(segment.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x25 {
                guard index + 2 < bytes.count,
                      isUppercaseHex(bytes[index + 1]),
                      isUppercaseHex(bytes[index + 2]),
                      let decoded = decodedHex(bytes[index + 1], bytes[index + 2]),
                      !isUnreserved(decoded) else {
                    throw SwanError.invalidIdentifier("account DID")
                }
                index += 3
            } else {
                guard isUnreserved(bytes[index]) else {
                    throw SwanError.invalidIdentifier("account DID")
                }
                index += 1
            }
        }
    }

    private static func isUnreserved(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122)
            || (byte >= 48 && byte <= 57)
            || byte == 45
            || byte == 46
            || byte == 95
            || byte == 126
    }

    private static func isUppercaseHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 70)
    }

    private static func decodedHex(_ first: UInt8, _ second: UInt8) -> UInt8? {
        guard let high = hexValue(first), let low = hexValue(second) else { return nil }
        return high * 16 + low
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        if byte >= 48, byte <= 57 { return byte - 48 }
        if byte >= 65, byte <= 70 { return byte - 55 }
        return nil
    }
}
