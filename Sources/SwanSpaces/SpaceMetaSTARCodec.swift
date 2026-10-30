import Foundation
import Petrel
import PetrelCrypto
import SwanCore

/// One member of a memberspace, as a space meta archive carries it.
public struct SpaceMetaMember: Sendable, Equatable {
    public let did: String
    public let read: Bool
    public let write: Bool

    public init(did: String, read: Bool, write: Bool) throws {
        guard SpaceURI.isValidDID(did) else { throw SpaceMetaArchiveError.invalidArchive }
        self.did = did
        self.read = read
        self.write = write
    }
}

/// One entry of a space's writer set, as `listRepos` reports it: the repo's
/// latest accepted `rev` and `data`, and the space revision the host gave it.
public struct SpaceMetaWriter: Sendable, Equatable {
    public let did: String
    public let rev: String
    public let data: Data
    public let spaceRev: String

    public init(did: String, rev: String, data: Data, spaceRev: String) throws {
        guard SpaceURI.isValidDID(did), data.count == 32,
              (try? TID(tidString: rev)) != nil,
              (try? TID(tidString: spaceRev)) != nil else {
            throw SpaceMetaArchiveError.invalidArchive
        }
        self.did = did
        self.rev = rev
        self.data = data
        self.spaceRev = spaceRev
    }
}

/// A space authority's host-side state for one space: its policy, the
/// policy's state (a memberspace's member list), and its writer set. It moves
/// between hosts with the authority's account (October 29 section 5b).
public struct SpaceMetaArchive: Sendable, Equatable {
    public let space: SpaceURI
    public let policy: SpacePolicy
    public let members: [SpaceMetaMember]
    public let writers: [SpaceMetaWriter]

    public init(
        space: SpaceURI,
        policy: SpacePolicy,
        members: [SpaceMetaMember],
        writers: [SpaceMetaWriter]
    ) throws {
        guard members.isEmpty || { if case .member = policy { true } else { false } }() else {
            throw SpaceMetaArchiveError.invalidArchive
        }
        self.space = space
        self.policy = policy
        self.members = members
        self.writers = writers
    }
}

/// Any malformed archive. The HTTP boundary answers it with `InvalidRequest`;
/// an unknown policy `$type` is ``SpacePolicyError/unsupportedPolicy`` instead.
public enum SpaceMetaArchiveError: Error, Sendable, Equatable {
    case invalidArchive
}

/// The `atproto-space-meta` STAR profile. It is framed like `getRepo`'s
/// archive: magic, a DRISL metadata frame, then key/value frames in three
/// sections in this order, each in strict bytewise key order:
///
/// 1. `policy`: the policy object.
/// 2. Policy state, keyed like record paths. Of the baseline policies only
///    memberspace has any: `com.atproto.memberspace.member/<did as rkey>`.
/// 3. `writer/<did>` → `{ rev, data, spaceRev }`.
///
/// The reader refuses a missing `policy`, a section or key out of order, a
/// duplicate key, and any policy-state key the policy does not define. It
/// never drops access state.
public enum SpaceMetaSTARCodec {
    public static let metadataType = "atproto-space-meta"
    public static let policyKey = "policy"
    public static let writerKeyPrefix = "writer/"
    public static let memberKeyPrefix = SpacePolicy.memberRecordCollection + "/"
    /// The import body bound. A member or writer entry is a few hundred
    /// bytes, so this admits several hundred thousand of each.
    public static let maximumArchiveBytes = 64 * 1_024 * 1_024
    static let maximumKeyBytes = 4_096
    static let maximumValueBytes = 65_536

    public static func encode(_ archive: SpaceMetaArchive) throws -> Data {
        var output = SpaceSTARCodec.magic
        SpaceSTARCodec.appendFrame(try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: metadataType),
            (key: "ver", value: 1),
            (key: "space", value: archive.space.rawValue),
        ])), to: &output)
        var pairs: [(key: Data, value: Data)] = [
            (Data(policyKey.utf8), try DAGCBOR.encodeValue(archive.policy.cborValue)),
        ]
        var memberPairs: [(key: Data, value: Data)] = []
        for member in archive.members {
            memberPairs.append((
                Data((memberKeyPrefix + SpacePolicy.memberRecordKey(for: member.did)).utf8),
                try SpacePolicy.memberRecordValue(read: member.read, write: member.write)
            ))
        }
        var writerPairs: [(key: Data, value: Data)] = []
        for writer in archive.writers {
            writerPairs.append((
                Data((writerKeyPrefix + writer.did).utf8),
                try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                    (key: "rev", value: writer.rev),
                    (key: "data", value: writer.data),
                    (key: "spaceRev", value: writer.spaceRev),
                ]))
            ))
        }
        for section in [memberPairs, writerPairs] {
            let sorted = section.sorted { $0.key.lexicographicallyPrecedes($1.key) }
            for index in sorted.indices.dropFirst() where sorted[index - 1].key == sorted[index].key {
                throw SpaceMetaArchiveError.invalidArchive
            }
            pairs += sorted
        }
        for pair in pairs {
            SpaceSTARCodec.appendFrame(pair.key, to: &output)
            SpaceSTARCodec.appendFrame(pair.value, to: &output)
        }
        guard output.count <= maximumArchiveBytes else { throw SpaceMetaArchiveError.invalidArchive }
        return output
    }

    private enum Section: Int, Comparable {
        case policy, policyState, writers
        static func < (left: Section, right: Section) -> Bool { left.rawValue < right.rawValue }
    }

    public static func decode(_ bytes: Data) throws -> SpaceMetaArchive {
        do {
            return try decodeArchive(bytes)
        } catch SpacePolicyError.unsupportedPolicy {
            throw SpacePolicyError.unsupportedPolicy
        } catch {
            throw SpaceMetaArchiveError.invalidArchive
        }
    }

    private static func decodeArchive(_ bytes: Data) throws -> SpaceMetaArchive {
        guard bytes.count <= maximumArchiveBytes else { throw SpaceMetaArchiveError.invalidArchive }
        var reader = STARBufferReader(bytes: Data(bytes))
        guard try reader.readExactly(SpaceSTARCodec.magic.count) == SpaceSTARCodec.magic else {
            throw SpaceMetaArchiveError.invalidArchive
        }
        let metadataBytes = try reader.frame(maximum: SpaceSTARLimits.maximumMetadataBytes)
        let metadata = try decodeDRISLMap(metadataBytes)
        guard metadata["$type"] as? String == metadataType,
              let ver = metadata["ver"] as? UInt64, ver == 1,
              let rawSpace = metadata["space"] as? String else {
            throw SpaceMetaArchiveError.invalidArchive
        }
        let space = try SpaceURI(rawSpace)

        var policy: SpacePolicy?
        var memberValues: [(did: String, value: [String: Any])] = []
        var writers: [SpaceMetaWriter] = []
        var section: Section?
        var previousKey: Data?
        while !reader.isAtEnd {
            let keyBytes = try reader.frame(maximum: maximumKeyBytes)
            let valueBytes = try reader.frame(maximum: maximumValueBytes)
            guard let key = String(data: keyBytes, encoding: .utf8), Data(key.utf8) == keyBytes else {
                throw SpaceMetaArchiveError.invalidArchive
            }
            let keySection: Section = if key == policyKey {
                .policy
            } else if key.hasPrefix(writerKeyPrefix) {
                .writers
            } else {
                .policyState
            }
            if keySection != section {
                if let section, keySection < section { throw SpaceMetaArchiveError.invalidArchive }
                section = keySection
                previousKey = nil
            }
            if let previousKey, !previousKey.lexicographicallyPrecedes(keyBytes) {
                throw SpaceMetaArchiveError.invalidArchive
            }
            previousKey = keyBytes
            let value = try decodeDRISLMap(valueBytes)
            switch keySection {
            case .policy:
                guard policy == nil else { throw SpaceMetaArchiveError.invalidArchive }
                policy = try SpacePolicy.normalized(jsonObject: value)
            case .policyState:
                // Parsed after the loop: the policy that defines the state
                // always precedes it, but a missing policy is reported as such.
                guard key.hasPrefix(memberKeyPrefix),
                      let did = SpacePolicy.memberDID(fromRecordKey: String(key.dropFirst(memberKeyPrefix.count))),
                      SpaceURI.isValidDID(did),
                      memberKeyPrefix + SpacePolicy.memberRecordKey(for: did) == key else {
                    throw SpaceMetaArchiveError.invalidArchive
                }
                memberValues.append((did, value))
            case .writers:
                let did = String(key.dropFirst(writerKeyPrefix.count))
                guard let rev = value["rev"] as? String,
                      let data = value["data"] as? Data,
                      let spaceRev = value["spaceRev"] as? String else {
                    throw SpaceMetaArchiveError.invalidArchive
                }
                writers.append(try SpaceMetaWriter(did: did, rev: rev, data: data, spaceRev: spaceRev))
            }
        }
        guard let policy else { throw SpaceMetaArchiveError.invalidArchive }
        guard memberValues.isEmpty || { if case .member = policy { true } else { false } }() else {
            throw SpaceMetaArchiveError.invalidArchive
        }
        var seen = Set<String>()
        let members = try memberValues.map { entry -> SpaceMetaMember in
            guard seen.insert(entry.did).inserted,
                  entry.value["$type"].map({ $0 as? String == SpacePolicy.memberRecordCollection }) ?? true,
                  let read = entry.value["read"], SpacePolicy.isJSONBoolean(read), let readFlag = read as? Bool,
                  let write = entry.value["write"], SpacePolicy.isJSONBoolean(write),
                  let writeFlag = write as? Bool else {
                throw SpaceMetaArchiveError.invalidArchive
            }
            return try SpaceMetaMember(did: entry.did, read: readFlag, write: writeFlag)
        }
        return try SpaceMetaArchive(space: space, policy: policy, members: members, writers: writers)
    }

    /// Decodes one canonical DRISL map through Petrel's generic block decoder
    /// (exposed only via `CARReader`), after the strict canonical check.
    static func decodeDRISLMap(_ bytes: Data) throws -> [String: Any] {
        try CanonicalSpaceRecordValidator.validate(bytes)
        let cid = CID.fromDAGCBOR(bytes)
        let header = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: cid)]), (key: "version", value: 1),
        ]))
        var car = Data()
        SpaceSTARCodec.appendFrame(header, to: &car)
        SpaceSTARCodec.appendFrame(cid.bytes + bytes, to: &car)
        let reader = try CARReader(data: car)
        guard let map = try reader.decodeBlock(for: CARReader.cidHex(from: cid)) as? [String: Any] else {
            throw SpaceMetaArchiveError.invalidArchive
        }
        return map
    }
}
