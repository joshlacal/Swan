import Foundation
import Petrel

/// The AT data-model subset accepted by public repository records.
///
/// The explicit enum makes floats, non-string map keys, and generated
/// transport-only/error cases unrepresentable at the repository boundary.
public indirect enum PublicRecordValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case integer(Int)
    case string(String)
    case bytes(Data)
    case link(CID)
    case array([PublicRecordValue])
    case object([String: PublicRecordValue])
}

public struct PublicRecord: Sendable, Equatable, ExpressibleByDictionaryLiteral {
    public let fields: [String: PublicRecordValue]

    public init(_ fields: [String: PublicRecordValue]) {
        self.fields = fields
    }

    public init(dictionaryLiteral elements: (String, PublicRecordValue)...) {
        var fields: [String: PublicRecordValue] = [:]
        for (key, value) in elements {
            fields[key] = value
        }
        self.fields = fields
    }
}

public struct PreparedPublicRecord: Sendable, Equatable {
    public let bytes: Data
    public let cid: CID
}

public enum PublicRepositoryRecordCodec {
    /// AT Protocol integers are limited to JavaScript's exactly representable
    /// signed integer range even though DAG-CBOR itself can encode wider ints.
    public static let maximumSafeInteger = 9_007_199_254_740_991
    public static let minimumSafeInteger = -9_007_199_254_740_991

    /// Converts Petrel's transport container without passing through JSON.
    /// This is deliberately kept at the repository boundary so public writes
    /// and permissioned writes cannot accidentally share a permissive JSON
    /// bridge. Typed blob references are accepted only in the modern,
    /// content-addressed form used by the public blob endpoint. Unresolved
    /// typed values remain rejected.
    public static func publicRecord(
        from value: ATProtocolValueContainer,
        collection: String,
        limits: PublicRepositoryLimits = .standard
    ) throws -> PublicRecord {
        let converted: PublicRecordValue
        switch value {
        case .knownType:
            converted = try convertCBOR(value.toCBORValue(), depth: 1, limits: limits)
        case let .object(fields):
            converted = try convertObject(fields, depth: 1, limits: limits)
        case let .unknownType(type, value):
            converted = try convertUnknownType(
                type, value: value, depth: 1, limits: limits
            )
        case .decodeError:
            throw PublicRepositoryDomainError.invalidRecordType
        default:
            throw PublicRepositoryDomainError.invalidRecordType
        }
        guard case var .object(fields) = converted else {
            throw PublicRepositoryDomainError.invalidRecordType
        }
        if let existing = fields["$type"] {
            guard case let .string(type) = existing, type == collection else {
                throw PublicRepositoryDomainError.invalidRecordType
            }
        } else {
            fields["$type"] = .string(collection)
        }
        return PublicRecord(fields)
    }

    private static func convertObject(
        _ fields: [String: ATProtocolValueContainer],
        depth: Int,
        limits: PublicRepositoryLimits
    ) throws -> PublicRecordValue {
        guard depth <= limits.maximumCBORNestingDepth else {
            throw PublicRepositoryDomainError.recordNestingTooDeep
        }
        var output: [String: PublicRecordValue] = [:]
        for (key, value) in fields {
            output[key] = try convert(value, depth: depth, limits: limits)
        }
        if case let .string(type)? = output["$type"], type == "blob" {
            try validateTypedBlob(output)
        }
        return .object(output)
    }

    private static func convert(
        _ value: ATProtocolValueContainer,
        depth: Int,
        limits: PublicRepositoryLimits
    ) throws -> PublicRecordValue {
        switch value {
        case .knownType:
            return try convertCBOR(value.toCBORValue(), depth: depth, limits: limits)
        case let .string(value): return .string(value)
        case let .number(value):
            guard (minimumSafeInteger...maximumSafeInteger).contains(value) else {
                throw PublicRepositoryDomainError.invalidRecordInteger
            }
            return .integer(value)
        case .bigNumber: throw PublicRepositoryDomainError.invalidRecordInteger
        case let .object(fields): return try convertObject(fields, depth: depth, limits: limits)
        case let .array(values):
            guard depth < limits.maximumCBORNestingDepth else {
                throw PublicRepositoryDomainError.recordNestingTooDeep
            }
            return .array(try values.map { try convert($0, depth: depth + 1, limits: limits) })
        case let .bool(value): return .bool(value)
        case .null: return .null
        case let .link(link): return .link(try validatedLink(link.cid))
        case let .bytes(bytes): return .bytes(bytes.data)
        case let .unknownType(type, value):
            return try convertUnknownType(type, value: value, depth: depth, limits: limits)
        case .decodeError:
            throw PublicRepositoryDomainError.invalidRecordType
        }
    }

    private static func convertUnknownType(
        _ type: String,
        value: ATProtocolValueContainer,
        depth: Int,
        limits: PublicRepositoryLimits
    ) throws -> PublicRecordValue {
        guard type == "blob", case let .object(fields) = value else {
            throw PublicRepositoryDomainError.invalidRecordType
        }
        guard case var .object(object) = try convertObject(
            fields, depth: depth, limits: limits
        ) else {
            throw PublicRepositoryDomainError.invalidRecordType
        }
        if let existing = object["$type"] {
            guard existing == .string(type) else {
                throw PublicRepositoryDomainError.invalidRecordType
            }
        } else {
            object["$type"] = .string(type)
        }
        try validateTypedBlob(object)
        return .object(object)
    }

    private static func convertCBOR(
        _ value: Any,
        depth: Int,
        limits: PublicRepositoryLimits
    ) throws -> PublicRecordValue {
        if let map = value as? OrderedCBORMap {
            var fields: [String: PublicRecordValue] = [:]
            for entry in map.entries {
                guard fields[entry.key] == nil else {
                    throw PublicRepositoryDomainError.invalidRecordType
                }
                fields[entry.key] = try convertCBOR(entry.value, depth: depth, limits: limits)
            }
            if case let .string(type)? = fields["$type"], type == "blob" {
                try validateTypedBlob(fields)
            }
            return .object(fields)
        }
        if let map = value as? [String: Any] {
            var fields: [String: PublicRecordValue] = [:]
            for (key, item) in map {
                fields[key] = try convertCBOR(item, depth: depth, limits: limits)
            }
            if case let .string(type)? = fields["$type"], type == "blob" {
                try validateTypedBlob(fields)
            }
            return .object(fields)
        }
        if let link = value as? ATProtoLink { return .link(try validatedLink(link.cid)) }
        if let data = value as? Data { return .bytes(data) }
        if let string = value as? String { return .string(string) }
        if let bool = value as? Bool { return .bool(bool) }
        if value is NSNull { return .null }
        if let integer = value as? Int {
            guard (minimumSafeInteger...maximumSafeInteger).contains(integer) else {
                throw PublicRepositoryDomainError.invalidRecordInteger
            }
            return .integer(integer)
        }
        if let values = value as? [Any] {
            guard depth < limits.maximumCBORNestingDepth else {
                throw PublicRepositoryDomainError.recordNestingTooDeep
            }
            return .array(try values.map { try convertCBOR($0, depth: depth + 1, limits: limits) })
        }
        throw PublicRepositoryDomainError.invalidRecordType
    }

    /// Validates the modern AT Protocol blob object without resolving or
    /// opening the referenced payload. Reachability is checked by the HTTP
    /// mutation layer against the public blob namespace before the record is
    /// committed.
    private static func validateTypedBlob(
        _ fields: [String: PublicRecordValue]
    ) throws {
        let allowedKeys: Set<String> = ["$type", "ref", "mimeType", "size"]
        guard Set(fields.keys) == allowedKeys,
              fields["$type"] == .string("blob"),
              case let .link(cid)? = fields["ref"],
              cid.codec == .raw,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              case let .string(mimeType)? = fields["mimeType"],
              validBlobMIMEType(mimeType),
              case let .integer(size)? = fields["size"],
              (0...PublicRepositoryLimits.requiredStreamingCARBytes).contains(size)
        else {
            throw PublicRepositoryDomainError.invalidRecordType
        }
    }

    private static func validBlobMIMEType(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= 255,
              value.filter({ $0 == "/" }).count == 1,
              !value.hasPrefix("/"),
              !value.hasSuffix("/") else {
            return false
        }
        return value.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || "!#$&^_.+-/".utf8.contains(byte)
        }
    }

    private static func validatedLink(_ cid: CID) throws -> CID {
        guard cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.codec == .raw || cid.codec == .dagCBOR else {
            throw PublicRepositoryDomainError.invalidRecordLink
        }
        return cid
    }

    public static func prepare(
        _ record: PublicRecord,
        for path: PublicRepositoryPath,
        limits: PublicRepositoryLimits = .standard
    ) throws -> PreparedPublicRecord {
        guard case let .string(type)? = record.fields["$type"], type == path.collection else {
            throw PublicRepositoryDomainError.invalidRecordType
        }

        let encodedValue = try encodeObject(
            record.fields,
            depth: 1,
            maximumDepth: limits.maximumCBORNestingDepth
        )
        let bytes = try DAGCBOR.encodeValue(encodedValue)
        guard bytes.count <= limits.maximumRecordBlockBytes else {
            throw PublicRepositoryDomainError.recordTooLarge
        }
        return PreparedPublicRecord(bytes: bytes, cid: CID.fromDAGCBOR(bytes))
    }

    /// Returns the raw CIDs embedded in a public record. In AT repository
    /// values, raw CIDs are blob references while DAG-CBOR CIDs identify
    /// repository blocks and are not blob-namespace references. The result is
    /// deterministic and de-duplicated so callers can perform bounded,
    /// metadata-only reachability checks before committing a mutation.
    public static func publicBlobCIDs(in record: PublicRecord) -> [CID] {
        var byString: [String: CID] = [:]

        func visit(_ value: PublicRecordValue) {
            switch value {
            case let .link(cid) where cid.codec == .raw:
                byString[cid.string] = cid
            case let .array(values):
                for value in values { visit(value) }
            case let .object(fields):
                for value in fields.values { visit(value) }
            default:
                break
            }
        }

        visit(.object(record.fields))
        return byString.keys.sorted().compactMap { byString[$0] }
    }

    private static func encodeObject(
        _ object: [String: PublicRecordValue],
        depth: Int,
        maximumDepth: Int
    ) throws -> OrderedCBORMap {
        guard depth <= maximumDepth else {
            throw PublicRepositoryDomainError.recordNestingTooDeep
        }
        return try OrderedCBORMap(entries: object.map { key, value in
            (key: key, value: try encode(value, depth: depth, maximumDepth: maximumDepth))
        })
    }

    private static func encode(
        _ value: PublicRecordValue,
        depth: Int,
        maximumDepth: Int
    ) throws -> Any {
        switch value {
        case .null:
            return NSNull()
        case let .bool(value):
            return value
        case let .integer(value):
            guard (minimumSafeInteger...maximumSafeInteger).contains(value) else {
                throw PublicRepositoryDomainError.invalidRecordInteger
            }
            return value
        case let .string(value):
            return value
        case let .bytes(value):
            return value
        case let .link(cid):
            let cidBytes = cid.bytes
            guard cidBytes.count == 36,
                  cidBytes[cidBytes.startIndex] == 0x01,
                  cidBytes[cidBytes.startIndex + 1] == cid.codec.rawValue,
                  (cid.codec == .raw || cid.codec == .dagCBOR),
                  cid.multihash.algorithm == Multihash.sha256Code,
                  cid.multihash.length == Multihash.sha256Length,
                  cid.multihash.digest.count == 32 else {
                throw PublicRepositoryDomainError.invalidRecordLink
            }
            return ATProtoLink(cid: cid)
        case let .array(values):
            guard depth < maximumDepth else {
                throw PublicRepositoryDomainError.recordNestingTooDeep
            }
            return try values.map { try encode($0, depth: depth + 1, maximumDepth: maximumDepth) }
        case let .object(object):
            return try encodeObject(object, depth: depth + 1, maximumDepth: maximumDepth)
        }
    }
}
