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
