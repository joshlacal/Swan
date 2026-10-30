import Foundation
import Petrel
import PetrelCrypto
import SwanCore
@testable import SwanSpaces
import XCTest

final class SpaceSTARCodecTests: XCTestCase {
    private let author = "did:plc:alice"
    private let secret = Data(repeating: 0x42, count: 32)
    private var space: SpaceURI { get throws { try SpaceURI("at://did:plc:alice/space/app.bsky.bookmarks/self") } }

    private func records() throws -> [SpaceRecord] {
        try ["aa", "b"].map { key in
            let bytes = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "$type", value: "app.bsky.feed.post"), (key: "text", value: key),
            ]))
            return SpaceRecord(
                uri: try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: key),
                value: bytes, cid: CID.fromDAGCBOR(bytes).string, revision: 0
            )
        }
    }

    private func commit(_ records: [SpaceRecord]) throws -> SpaceRepositoryCommit {
        var hash = LtHash()
        for record in records { hash.add(element: "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)") }
        return try SpaceRepositoryCommit(repo: author, space: space, rev: "2222222222222", data: hash.commitment)
    }

    private func verify(_ bytes: Data, commit: SpaceRepositoryCommit) throws -> VerifiedSpaceSTARRecovery {
        let mac = try commit.mac(sharedSecret: secret)
        return try SpaceSTARCodec.decode(bytes, space: space, author: author) {
            try SpaceMAC.verify(mac: mac, expected: $0.mac(sharedSecret: self.secret))
            return true
        }
    }

    func testRoundTripUsesStrictBytewisePathsInsteadOfCARKeyLengthOrder() throws {
        let records = try records()
        let commit = try commit(records)
        let archive = try SpaceSTARCodec.encode(commit: commit, records: records)
        let restored = try verify(archive, commit: commit)
        XCTAssertEqual(restored.commit, commit)
        XCTAssertEqual(restored.records, records)
        XCTAssertThrowsError(try SpaceSTARCodec.encode(commit: commit, records: Array(records.reversed())))
    }

    func testEmptyArchiveMatchesIndependentFramingAndCBORVector() throws {
        // Encoded independently with a minimal Python standard-library CBOR
        // encoder and SHA256(bytes(2048)); this does not call Swan's writer.
        let vector = "2a6c0100a301a6637265766d32323232323232323232323232637665720164646174615820e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad647265706f6d6469643a706c633a616c69636565247479706572617470726f746f2d73706163652d7265706f657370616365783061743a2f2f6469643a706c633a616c6963652f73706163652f6170702e62736b792e626f6f6b6d61726b732f73656c66"
        let commit = try commit([])
        let archive = try SpaceSTARCodec.encode(commit: commit, records: [])
        XCTAssertEqual(Hex.encode(archive), vector)
        XCTAssertEqual(try verify(archive, commit: commit).records, [])
    }

    func testCommitJSONUsesDataBytesAndNoLegacyEnvelopeFields() throws {
        let commit = try commit([])
        let bytes = try JSONEncoder().encode(commit)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(Set(json.keys), Set(["ver", "repo", "space", "rev", "data"]))
        XCTAssertEqual(json["space"] as? String, try space.rawValue)
        XCTAssertEqual((json["data"] as? [String: String])?["$bytes"], commit.data.base64EncodedString().replacingOccurrences(of: "=", with: ""))
        XCTAssertEqual(try JSONDecoder().decode(SpaceRepositoryCommit.self, from: bytes), commit)
        XCTAssertThrowsError(try SpaceRepositoryCommit(ver: 2, repo: author, space: space, rev: "2222222222222", data: commit.data))
        XCTAssertThrowsError(try SpaceRepositoryCommit(repo: author, space: space, rev: "not-a-tid", data: commit.data))
    }

    func testRejectsEveryTruncationUntilFinalRecordBoundary() throws {
        let records = try records()
        let commit = try commit(records)
        let archive = try SpaceSTARCodec.encode(commit: commit, records: records)
        for count in 0..<archive.count {
            XCTAssertThrowsError(try verify(Data(archive.prefix(count)), commit: commit), "prefix \(count)")
        }
    }

    func testRejectsDuplicateAndOutOfOrderRecords() throws {
        let records = try records()
        let commit = try commit(records)
        let prefix = try SpaceSTARCodec.prefix(commit: commit)
        let aa = try SpaceSTARCodec.recordFrame(records[0])
        let b = try SpaceSTARCodec.recordFrame(records[1])
        XCTAssertThrowsError(try verify(prefix + aa + aa, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidOrder) }
        XCTAssertThrowsError(try verify(prefix + b + aa, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidOrder) }
    }

    func testRejectsNonminimalAndExcessiveVarints() throws {
        let commit = try commit([])
        let metadata = try SpaceSTARCodec.encodeMetadata(commit)
        // 163 is normally a3 01; a3 81 00 is the same integer with padding.
        let nonminimal = SpaceSTARCodec.magic + Data([0xa3, 0x81, 0]) + metadata
        XCTAssertThrowsError(try verify(nonminimal, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidVarint) }
        let excessive = SpaceSTARCodec.magic + Data(repeating: 0x80, count: 6)
        XCTAssertThrowsError(try verify(excessive, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidVarint) }
    }

    func testRejectsNoncanonicalMetadataAndUnknownMetadataFields() throws {
        let commit = try commit([])
        let archive = try SpaceSTARCodec.encode(commit: commit, records: [])
        var noncanonical = archive
        // After the two-byte frame length, the map header a6 must be minimal.
        noncanonical.replaceSubrange(6..<7, with: Data([0xb8, 6]))
        noncanonical[4] += 1
        XCTAssertThrowsError(try verify(noncanonical, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidMetadata) }
        let metadata = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: SpaceSTARCodec.metadataType), (key: "ver", value: 1),
            (key: "repo", value: author), (key: "space", value: try space.rawValue),
            (key: "rev", value: commit.rev), (key: "data", value: commit.data),
            (key: "sig", value: Data(repeating: 1, count: 64)),
        ]))
        XCTAssertThrowsError(try verify(SpaceSTARCodec.magic + frame(metadata), commit: commit))
    }

    func testRejectsWrongRepositoryBadMACAndDigestMismatch() throws {
        let records = try records()
        let commit = try commit(records)
        let archive = try SpaceSTARCodec.encode(commit: commit, records: records)
        XCTAssertThrowsError(try SpaceSTARCodec.decode(archive, space: space, author: "did:plc:bob") { _ in true }) {
            XCTAssertEqual($0 as? SpaceSTARError, .wrongRepository)
        }
        XCTAssertThrowsError(try SpaceSTARCodec.decode(archive, space: space, author: author) { _ in false }) {
            XCTAssertEqual($0 as? SpaceSTARError, .badMAC)
        }
        let wrongDigest = try SpaceRepositoryCommit(repo: author, space: space, rev: commit.rev, data: Data(repeating: 1, count: 32))
        let tampered = try SpaceSTARCodec.prefix(commit: wrongDigest) + records.reduce(into: Data()) { $0.append(try SpaceSTARCodec.recordFrame($1)) }
        XCTAssertThrowsError(try verify(tampered, commit: wrongDigest)) { XCTAssertEqual($0 as? SpaceSTARError, .digestMismatch) }
    }

    func testRejectsOversizedFramesBeforeReadingValuesAndMalformedPaths() throws {
        let commit = try commit([])
        let prefix = try SpaceSTARCodec.prefix(commit: commit)
        let path = Data("app.bsky.feed.post/a".utf8)
        // Declares 1 MiB + 1; the payload is absent and the size error wins.
        let oversized = prefix + frame(path) + Data([0x81, 0x80, 0x40])
        XCTAssertThrowsError(try verify(oversized, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .limitExceeded) }
        let malformed = prefix + frame(Data([0xff])) + frame(Data([0xa0]))
        XCTAssertThrowsError(try verify(malformed, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidRecord) }
        let invalidValue = prefix + frame(path) + frame(Data([0xa1, 0x61, 0x61, 0x18, 0]))
        XCTAssertThrowsError(try verify(invalidValue, commit: commit)) { XCTAssertEqual($0 as? SpaceSTARError, .invalidRecord) }
    }

    func testStreamingHandlesEveryByteBoundaryAndDiscardsFailedRecovery() async throws {
        let records = try records()
        let commit = try commit(records)
        let archive = try SpaceSTARCodec.encode(commit: commit, records: records)
        let sink = TestSTARSink()
        let source = TestSTARSource(bytes: archive, chunkSize: 1)
        let result = try await SpaceSTARCodec.verifyStreaming(source: source, sink: sink, space: space, author: author) { $0 == commit }
        XCTAssertEqual(result.recordCount, records.count)
        XCTAssertEqual(result.receivedByteCount, archive.count)
        let staged = await sink.records
        XCTAssertEqual(staged, records)
        let wasDiscarded = await sink.wasDiscarded
        XCTAssertFalse(wasDiscarded)
        let failedSink = TestSTARSink()
        let corrupt = archive + frame(Data("app.bsky.feed.post/c".utf8)) + frame(Data([0xa0]))
        do {
            _ = try await SpaceSTARCodec.verifyStreaming(source: TestSTARSource(bytes: corrupt, chunkSize: 7), sink: failedSink, space: space, author: author) { $0 == commit }
            XCTFail("digest mismatch must fail")
        } catch { XCTAssertEqual(error as? SpaceSTARError, .digestMismatch) }
        let failedDiscarded = await failedSink.wasDiscarded
        let remainingCount = await failedSink.records.count
        XCTAssertTrue(failedDiscarded)
        XCTAssertEqual(remainingCount, 0)
    }

    func testStreamingRejectsSourceContractViolationsAndArchiveBudget() async throws {
        let commit = try commit([])
        let archive = try SpaceSTARCodec.encode(commit: commit, records: [])
        let source = TestSTARSource(bytes: archive, chunkSize: 9)
        let sink = TestSTARSink()
        do {
            _ = try await SpaceSTARCodec.verifyStreaming(source: source, sink: sink, space: space, author: author, limits: SpaceSTARLimits(maximumArchiveBytes: archive.count - 1)) { _ in true }
            XCTFail("archive budget must fail")
        } catch { XCTAssertEqual(error as? SpaceSTARError, .limitExceeded) }
        let invalidSink = TestSTARSink()
        do {
            _ = try await SpaceSTARCodec.verifyStreaming(source: EmptySTARSource(), sink: invalidSink, space: space, author: author) { _ in true }
            XCTFail("empty non-EOF chunk must fail")
        } catch { XCTAssertEqual(error as? SpaceSTARError, .invalidSource) }
        let invalidDiscarded = await invalidSink.wasDiscarded
        XCTAssertTrue(invalidDiscarded)
    }

    private func frame(_ bytes: Data) -> Data {
        var remaining = bytes.count
        var result = Data()
        repeat {
            var byte = UInt8(remaining & 127)
            remaining >>= 7
            if remaining != 0 { byte |= 128 }
            result.append(byte)
        } while remaining != 0
        result.append(bytes)
        return result
    }
}

private actor TestSTARSource: SpaceCARRecoveryByteSource {
    let bytes: Data
    let chunkSize: Int
    var offset = 0
    init(bytes: Data, chunkSize: Int) { self.bytes = bytes; self.chunkSize = chunkSize }
    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < bytes.count else { return nil }
        let count = min(chunkSize, maximumBytes, bytes.count - offset)
        defer { offset += count }
        return Data(bytes[offset..<offset + count])
    }
}

private struct EmptySTARSource: SpaceCARRecoveryByteSource {
    func read(maximumBytes: Int) async throws -> Data? { Data() }
}

private actor TestSTARSink: SpaceSTARRecoverySink {
    private(set) var records: [SpaceRecord] = []
    private(set) var wasDiscarded = false
    func stage(record: SpaceRecord) async throws { records.append(record) }
    func discard() async { records = []; wasDiscarded = true }
}
