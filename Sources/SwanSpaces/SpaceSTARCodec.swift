import Foundation
import Petrel
import PetrelCrypto
import SwanCore

/// The current Spaces commit. Historical signed CAR backup envelopes remain
/// separate: this value is authenticated by a per-request HTTP response MAC.
public struct SpaceRepositoryCommit: Sendable, Equatable, Codable {
    public let ver: Int
    public let repo: String
    public let space: SpaceURI
    public let rev: String
    public let data: Data

    public init(ver: Int = 1, repo: String, space: SpaceURI, rev: String, data: Data) throws {
        guard ver == 1, data.count == 32,
              (try? SpaceRecordURI(space: space, author: repo, collection: "app.bsky.feed.post", rkey: "validation")) != nil,
              (try? TID(tidString: rev)) != nil else { throw SpaceSTARError.invalidCommit }
        self.ver = ver
        self.repo = repo
        self.space = space
        self.rev = rev
        self.data = data
    }

    public func mac(sharedSecret: Data) throws -> Data {
        try SpaceMAC.commit(sharedSecret: sharedSecret, space: space.rawValue, repo: repo, rev: rev, data: data)
    }

    private enum CodingKeys: String, CodingKey { case ver, repo, space, rev, data }
    private enum BytesKey: String, CodingKey { case bytes = "$bytes" }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let encodedBytes = try values.nestedContainer(keyedBy: BytesKey.self, forKey: .data)
            .decode(String.self, forKey: .bytes)
        guard let data = Data(base64Encoded: encodedBytes + String(repeating: "=", count: (4 - encodedBytes.utf8.count % 4) % 4)) else { throw SpaceSTARError.invalidCommit }
        try self.init(
            ver: values.decode(Int.self, forKey: .ver),
            repo: values.decode(String.self, forKey: .repo),
            space: SpaceURI(values.decode(String.self, forKey: .space)),
            rev: values.decode(String.self, forKey: .rev), data: data
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(ver, forKey: .ver)
        try values.encode(repo, forKey: .repo)
        try values.encode(space.rawValue, forKey: .space)
        try values.encode(rev, forKey: .rev)
        var bytes = values.nestedContainer(keyedBy: BytesKey.self, forKey: .data)
        try bytes.encode(data.base64EncodedString().replacingOccurrences(of: "=", with: ""), forKey: .bytes)
    }
}

public enum SpaceSTARError: Error, Sendable, Equatable {
    case invalidMagic, invalidCommit, invalidMetadata, invalidVarint
    case truncated, limitExceeded, invalidRecord, invalidOrder
    case wrongRepository, badMAC, digestMismatch, invalidSource
}

public struct SpaceSTARLimits: Sendable, Equatable {
    public static let maximumRecordBytes = 1_048_576
    public static let maximumMetadataBytes = 65_536
    public static let maximumPathBytes = 830
    public static let maximumChunkBytes = 65_536
    public let maximumArchiveBytes: Int
    public let maximumRecordCount: Int

    public static let standard = Self(validatedBytes: 256 * 1_024 * 1_024, count: 100_000)

    public init(maximumArchiveBytes: Int = 256 * 1_024 * 1_024, maximumRecordCount: Int = 100_000) throws {
        guard (1...256 * 1_024 * 1_024).contains(maximumArchiveBytes),
              (0...100_000).contains(maximumRecordCount) else { throw SpaceSTARError.limitExceeded }
        self.init(validatedBytes: maximumArchiveBytes, count: maximumRecordCount)
    }

    private init(validatedBytes: Int, count: Int) {
        self.maximumArchiveBytes = validatedBytes
        self.maximumRecordCount = count
    }
}

public struct VerifiedSpaceSTARRecovery: Sendable, Equatable {
    public let commit: SpaceRepositoryCommit
    public let records: [SpaceRecord]
    public let ltHash: Data
}

public struct VerifiedStreamingSpaceSTARRecovery: Sendable, Equatable {
    public let commit: SpaceRepositoryCommit
    public let recordCount: Int
    public let ltHash: Data
    public let receivedByteCount: Int
}

/// A consumer must stage these records outside the visible repository. Only a
/// successful verified result authorizes an atomic replacement (including
/// removal of old records absent from this archive). On any error, the verifier
/// discards staging. The callback never signifies that the whole repo passed.
public protocol SpaceSTARRecoverySink: Sendable {
    func stage(record: SpaceRecord) async throws
    func discard() async
}

public enum SpaceSTARCodec {
    public static let magic = Data([0x2a, 0x6c, 0x01, 0x00])
    public static let mediaType = "application/octet-stream"
    public static let metadataType = "atproto-space-repo"

    /// Input order is part of the producer contract. This intentionally rejects
    /// unsorted input, rather than buffering/sorting a repository in memory.
    public static func encode(
        commit: SpaceRepositoryCommit, records: [SpaceRecord], limits: SpaceSTARLimits = .standard
    ) throws -> Data {
        guard records.count <= limits.maximumRecordCount else { throw SpaceSTARError.limitExceeded }
        var result = try prefix(commit: commit)
        guard result.count <= limits.maximumArchiveBytes else { throw SpaceSTARError.limitExceeded }
        var previous: Data?
        var setHash = LtHash()
        for record in records {
            guard record.uri.space == commit.space, record.uri.author == commit.repo else {
                throw SpaceSTARError.wrongRepository
            }
            let path = recordPath(record)
            try checkOrder(path, previous: &previous)
            let frame = try recordFrame(record)
            guard frame.count <= limits.maximumArchiveBytes - result.count else { throw SpaceSTARError.limitExceeded }
            result.append(frame)
            setHash.add(element: "\(path)/\(CID.fromDAGCBOR(record.value).string)")
        }
        guard commitmentMatches(setHash.commitment, commit.data) else { throw SpaceSTARError.digestMismatch }
        return result
    }

    /// Prefix for bounded spool writers; their record iterator must enforce
    /// strict bytewise path order and compare its final LtHash to commit.data.
    public static func prefix(commit: SpaceRepositoryCommit) throws -> Data {
        let metadata = try encodeMetadata(commit)
        guard metadata.count <= SpaceSTARLimits.maximumMetadataBytes else { throw SpaceSTARError.limitExceeded }
        var output = magic
        appendFrame(metadata, to: &output)
        return output
    }

    /// Prefix preceding the streamed record value in a STAR pair. The caller
    /// validates canonical record bytes and CID while copying its bounded chunks.
    public static func framePrefix(path: String, valueByteCount: Int) throws -> Data {
        try validatePath(path)
        guard (1...SpaceSTARLimits.maximumRecordBytes).contains(valueByteCount) else {
            throw SpaceSTARError.limitExceeded
        }
        var output = Data()
        appendFrame(Data(path.utf8), to: &output)
        appendLength(valueByteCount, to: &output)
        return output
    }

    public static func recordFrame(_ record: SpaceRecord) throws -> Data {
        let path = recordPath(record)
        try validatePath(path)
        try validateRecord(record.value)
        guard record.cid == CID.fromDAGCBOR(record.value).string else { throw SpaceSTARError.invalidRecord }
        var output = Data()
        appendFrame(Data(path.utf8), to: &output)
        appendFrame(record.value, to: &output)
        return output
    }

    /// Parses only the bounded archive prefix so transports can authenticate
    /// metadata before selecting a retry. This is not a complete-repo proof.
    public static func decodeMetadataPrefix(_ bytes: Data, space: SpaceURI, author: String) throws -> SpaceRepositoryCommit {
        var reader = STARBufferReader(bytes: Data(bytes))
        guard try reader.readExactly(magic.count) == magic else { throw SpaceSTARError.invalidMagic }
        return try decodeMetadata(reader.frame(maximum: SpaceSTARLimits.maximumMetadataBytes), space: space, author: author)
    }

    public static func decode(
        _ bytes: Data, space: SpaceURI, author: String, limits: SpaceSTARLimits = .standard,
        commitVerifier: (SpaceRepositoryCommit) throws -> Bool
    ) throws -> VerifiedSpaceSTARRecovery {
        guard bytes.count <= limits.maximumArchiveBytes else { throw SpaceSTARError.limitExceeded }
        var reader = STARBufferReader(bytes: Data(bytes))
        guard try reader.readExactly(magic.count) == magic else { throw SpaceSTARError.invalidMagic }
        let metadata = try reader.frame(maximum: SpaceSTARLimits.maximumMetadataBytes)
        let commit = try decodeMetadata(metadata, space: space, author: author)
        guard try commitVerifier(commit) else { throw SpaceSTARError.badMAC }
        var previous: Data?
        var setHash = LtHash()
        var records: [SpaceRecord] = []
        while !reader.isAtEnd {
            guard records.count < limits.maximumRecordCount else { throw SpaceSTARError.limitExceeded }
            let key = try reader.frame(maximum: SpaceSTARLimits.maximumPathBytes)
            let value = try reader.frame(maximum: SpaceSTARLimits.maximumRecordBytes)
            let record = try parseRecord(key: key, value: value, commit: commit, previous: &previous)
            setHash.add(element: "\(recordPath(record))/\(record.cid)")
            records.append(record)
        }
        guard commitmentMatches(setHash.commitment, commit.data) else { throw SpaceSTARError.digestMismatch }
        return VerifiedSpaceSTARRecovery(commit: commit, records: records, ltHash: setHash.serialized)
    }

    /// Pulls at most 64 KiB per source read and retains only one <=1 MiB record.
    /// Reuses the existing bounded source protocol; no CAR framing is involved.
    public static func verifyStreaming(
        source: any SpaceCARRecoveryByteSource,
        sink: any SpaceSTARRecoverySink,
        space: SpaceURI, author: String, limits: SpaceSTARLimits = .standard,
        commitVerifier: @Sendable (SpaceRepositoryCommit) throws -> Bool
    ) async throws -> VerifiedStreamingSpaceSTARRecovery {
        let reader = STARStreamingReader(source: source, maximumBytes: limits.maximumArchiveBytes)
        do {
            guard try await reader.readExactly(magic.count) == magic else { throw SpaceSTARError.invalidMagic }
            guard let metadata = try await reader.frame(maximum: SpaceSTARLimits.maximumMetadataBytes) else {
                throw SpaceSTARError.truncated
            }
            let commit = try decodeMetadata(metadata, space: space, author: author)
            guard try commitVerifier(commit) else { throw SpaceSTARError.badMAC }
            var previous: Data?
            var setHash = LtHash()
            var count = 0
            while let key = try await reader.frame(maximum: SpaceSTARLimits.maximumPathBytes) {
                guard count < limits.maximumRecordCount else { throw SpaceSTARError.limitExceeded }
                guard let value = try await reader.frame(maximum: SpaceSTARLimits.maximumRecordBytes) else {
                    throw SpaceSTARError.truncated
                }
                let record = try parseRecord(key: key, value: value, commit: commit, previous: &previous)
                setHash.add(element: "\(recordPath(record))/\(record.cid)")
                try await sink.stage(record: record)
                count += 1
            }
            guard commitmentMatches(setHash.commitment, commit.data) else { throw SpaceSTARError.digestMismatch }
            return VerifiedStreamingSpaceSTARRecovery(
                commit: commit, recordCount: count, ltHash: setHash.serialized,
                receivedByteCount: reader.receivedBytes
            )
        } catch {
            await sink.discard()
            throw error
        }
    }

    public static func encodeMetadata(_ commit: SpaceRepositoryCommit) throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: metadataType), (key: "ver", value: commit.ver),
            (key: "repo", value: commit.repo), (key: "space", value: commit.space.rawValue),
            (key: "rev", value: commit.rev), (key: "data", value: commit.data),
        ]))
    }

    /// `com.atproto.space.importRepo`: an account's own archive, read
    /// without a MAC (section 5d). The records must still fold to the
    /// commit's `data`; the caller checks that `repo` is the caller.
    public static func decodeImport(
        _ bytes: Data, limits: SpaceSTARLimits = .standard
    ) throws -> VerifiedSpaceSTARRecovery {
        var reader = STARBufferReader(bytes: Data(bytes))
        guard try reader.readExactly(magic.count) == magic else { throw SpaceSTARError.invalidMagic }
        let commit = try decodeMetadataUnchecked(reader.frame(maximum: SpaceSTARLimits.maximumMetadataBytes))
        return try decode(bytes, space: commit.space, author: commit.repo, limits: limits) { _ in true }
    }

    public static func decodeMetadata(_ bytes: Data, space: SpaceURI, author: String) throws -> SpaceRepositoryCommit {
        let commit = try decodeMetadataUnchecked(bytes)
        guard commit.space == space, commit.repo == author else { throw SpaceSTARError.wrongRepository }
        return commit
    }

    private static func decodeMetadataUnchecked(_ bytes: Data) throws -> SpaceRepositoryCommit {
        // Petrel's public generic DRISL decoder is exposed through CARReader.
        // This bounded one-block envelope stays internal and does not alter
        // the STAR bytes, which are compared with canonical encoding below.
        let commit: SpaceRepositoryCommit
        do {
            try CanonicalSpaceRecordValidator.validate(bytes)
            let cid = CID.fromDAGCBOR(bytes)
            let header = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "roots", value: [ATProtoLink(cid: cid)]), (key: "version", value: 1),
            ]))
            var car = Data()
            appendFrame(header, to: &car)
            appendFrame(cid.bytes + bytes, to: &car)
            let reader = try CARReader(data: car)
            guard let map = try reader.decodeBlock(for: CARReader.cidHex(from: cid)) as? [String: Any],
                  map["$type"] as? String == metadataType,
                  let ver = map["ver"] as? UInt64, ver == 1,
                  let repo = map["repo"] as? String,
                  let rawSpace = map["space"] as? String,
                  let rev = map["rev"] as? String,
                  let data = map["data"] as? Data else { throw SpaceSTARError.invalidMetadata }
            commit = try SpaceRepositoryCommit(repo: repo, space: SpaceURI(rawSpace), rev: rev, data: data)
            guard try encodeMetadata(commit) == bytes else { throw SpaceSTARError.invalidMetadata }
        } catch { throw SpaceSTARError.invalidMetadata }
        return commit
    }

    private static func parseRecord(
        key: Data, value: Data, commit: SpaceRepositoryCommit, previous: inout Data?
    ) throws -> SpaceRecord {
        guard let path = String(data: key, encoding: .utf8), Data(path.utf8) == key else {
            throw SpaceSTARError.invalidRecord
        }
        try validatePath(path)
        try checkOrder(path, previous: &previous)
        try validateRecord(value)
        let components = path.split(separator: "/")
        let uri = try SpaceRecordURI(
            space: commit.space, author: commit.repo,
            collection: String(components[0]), rkey: String(components[1])
        )
        return SpaceRecord(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string, revision: 0)
    }

    private static func validatePath(_ path: String) throws {
        guard path.utf8.count <= SpaceSTARLimits.maximumPathBytes, SpaceCARCodec.isRecordPath(path) else {
            throw SpaceSTARError.invalidRecord
        }
    }

    private static func validateRecord(_ value: Data) throws {
        guard !value.isEmpty, value.count <= SpaceSTARLimits.maximumRecordBytes else { throw SpaceSTARError.limitExceeded }
        do { try CanonicalSpaceRecordValidator.validate(value) }
        catch { throw SpaceSTARError.invalidRecord }
    }

    private static func checkOrder(_ path: String, previous: inout Data?) throws {
        let key = Data(path.utf8)
        if let previous, !previous.lexicographicallyPrecedes(key) { throw SpaceSTARError.invalidOrder }
        previous = key
    }

    private static func commitmentMatches(_ actual: Data, _ expected: Data) -> Bool {
        guard actual.count == 32, expected.count == 32 else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(actual, expected) { difference |= left ^ right }
        return difference == 0
    }

    private static func recordPath(_ record: SpaceRecord) -> String { "\(record.uri.collection)/\(record.uri.rkey)" }

    static func appendFrame(_ value: Data, to output: inout Data) {
        appendLength(value.count, to: &output)
        output.append(value)
    }

    private static func appendLength(_ count: Int, to output: inout Data) {
        var remaining = UInt64(count)
        repeat {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            output.append(byte)
        } while remaining != 0
    }
}

struct STARBufferReader {
    let bytes: Data
    var offset = 0
    var isAtEnd: Bool { offset == bytes.count }

    mutating func readExactly(_ count: Int) throws -> Data {
        guard count <= bytes.count - offset else { throw SpaceSTARError.truncated }
        defer { offset += count }
        return Data(bytes[offset..<offset + count])
    }

    mutating func frame(maximum: Int) throws -> Data {
        var value: UInt64 = 0
        for index in 0..<6 {
            guard !isAtEnd else { throw SpaceSTARError.truncated }
            let byte = bytes[offset]
            offset += 1
            value |= UInt64(byte & 0x7f) << (7 * index)
            if byte < 0x80 {
                guard index == 0 || byte != 0 else { throw SpaceSTARError.invalidVarint }
                guard value <= UInt64(maximum) else { throw SpaceSTARError.limitExceeded }
                return try readExactly(Int(value))
            }
        }
        throw SpaceSTARError.invalidVarint
    }
}

private final class STARStreamingReader {
    let source: any SpaceCARRecoveryByteSource
    let maximumBytes: Int
    private var buffered = Data()
    private var offset = 0
    private(set) var receivedBytes = 0
    private var eof = false

    init(source: any SpaceCARRecoveryByteSource, maximumBytes: Int) {
        self.source = source
        self.maximumBytes = maximumBytes
    }

    private func fill() async throws -> Bool {
        try Task.checkCancellation()
        if offset < buffered.count { return true }
        if eof { return false }
        // One extra byte beyond the archive limit is sufficient to reject it.
        let requested = min(SpaceSTARLimits.maximumChunkBytes, maximumBytes - receivedBytes + 1)
        guard let next = try await source.read(maximumBytes: requested) else {
            eof = true
            return false
        }
        guard !next.isEmpty, next.count <= requested else { throw SpaceSTARError.invalidSource }
        guard next.count <= maximumBytes - receivedBytes else { throw SpaceSTARError.limitExceeded }
        receivedBytes += next.count
        buffered = Data(next)
        offset = 0
        return true
    }

    func readExactly(_ count: Int) async throws -> Data {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            guard try await fill() else { throw SpaceSTARError.truncated }
            let available = min(count - result.count, buffered.count - offset)
            result.append(buffered[offset..<offset + available])
            offset += available
        }
        return result
    }

    func frame(maximum: Int) async throws -> Data? {
        var value: UInt64 = 0
        for index in 0..<6 {
            guard try await fill() else {
                if index == 0 { return nil }
                throw SpaceSTARError.truncated
            }
            let byte = buffered[offset]
            offset += 1
            value |= UInt64(byte & 0x7f) << (7 * index)
            if byte < 0x80 {
                guard index == 0 || byte != 0 else { throw SpaceSTARError.invalidVarint }
                guard value <= UInt64(maximum) else { throw SpaceSTARError.limitExceeded }
                return try await readExactly(Int(value))
            }
        }
        throw SpaceSTARError.invalidVarint
    }
}
