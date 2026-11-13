import Foundation

/// Structured Field headers for the October 22 Spaces response MAC protocol.
/// Cryptographic key parsing and decapsulation remain the caller's next step.
public enum SpaceMACHeaders {
    public static let requestHeader = "Atproto-Space-Want-Mac"
    public static let responseHeader = "Atproto-Space-Mac"

    public enum MACType: String, Sendable, Equatable {
        case repository = "atproto-space-repo"
        case record = "atproto-space-record"
    }

    public struct Request: Sendable, Equatable {
        public let keyShare: String
    }

    /// These failures map to the XRPC `InvalidSpaceMac` error, without
    /// reflecting untrusted header content in diagnostics.
    public enum HeaderError: Error, Sendable, Equatable {
        case badSpaceMAC
    }

    public static func parseWantMAC(_ value: String?, type: MACType) throws -> Request {
        let fields = try dictionary(value, type: type)
        guard case let .string(keyShare) = fields["key_share"],
              !keyShare.isEmpty else { throw HeaderError.badSpaceMAC }
        return Request(keyShare: keyShare)
    }

    public static func parseMAC(_ value: String?, type: MACType) throws -> Data {
        let fields = try dictionary(value, type: type)
        guard case let .byteSequence(mac) = fields["mac"], mac.count == 32 else {
            throw HeaderError.badSpaceMAC
        }
        return mac
    }

    public static func formatWantMAC(keyShare: String, type: MACType) throws -> String {
        guard !keyShare.isEmpty,
              keyShare.utf8.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else {
            throw HeaderError.badSpaceMAC
        }
        let escaped = keyShare.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "type=\"\(type.rawValue)\", ver=1, key_share=\"\(escaped)\""
    }

    public static func formatMAC(_ mac: Data, type: MACType) throws -> String {
        guard mac.count == 32 else { throw HeaderError.badSpaceMAC }
        return "type=\"\(type.rawValue)\", ver=1, mac=:\(mac.base64EncodedString()):"
    }

    private static func dictionary(
        _ value: String?, type: MACType
    ) throws -> [String: StructuredFieldBareItem] {
        guard let value, value.utf8.count <= 8_192 else { throw HeaderError.badSpaceMAC }
        let dictionary: StructuredFieldDictionary
        do { dictionary = try StructuredFieldParser.parseDictionary(value) }
        catch { throw HeaderError.badSpaceMAC }
        var fields: [String: StructuredFieldBareItem] = [:]
        for (key, member) in dictionary.entries {
            guard case let .item(item) = member else { throw HeaderError.badSpaceMAC }
            fields[key] = item.value
        }
        guard fields["type"] == .string(type.rawValue), fields["ver"] == .integer(1) else {
            throw HeaderError.badSpaceMAC
        }
        return fields
    }
}
