import Crypto
import Foundation
import Petrel
import SwanSpaces
import XCTest
@testable import SwanInterop

final class FullCARWitnessStreamingTests: XCTestCase {
    func testFixtureUsesOwnerOnlyDirectoryAndCARPermissions() throws {
        let fixture = try FullCARWitnessFixture()
        defer { fixture.remove() }

        XCTAssertEqual(try fullCARPermissions(at: fixture.root), 0o700)
        XCTAssertEqual(try fullCARPermissions(at: fixture.carURL), 0o600)
    }

    func testStreamingConsumerVerifiesExactExpectedPathAndCID() async throws {
        let fixture = try FullCARWitnessFixture()
        defer { fixture.remove() }

        let summary = try await fixture.consumer.verifyStreaming(
            fileURL: fixture.carURL,
            space: fixture.space,
            author: fixture.author,
            publicKey: fixture.key.publicKey,
            expectedEntries: [
                SpaceCARRecoveryIndexEntry(
                    path: fixture.path,
                    cid: fixture.cid
                ),
            ]
        )

        XCTAssertEqual(summary.verifiedExpectedWitnessCount, 1)
    }

    func testStreamingConsumerRejectsExpectedPathMismatch() async throws {
        let fixture = try FullCARWitnessFixture()
        defer { fixture.remove() }

        do {
            _ = try await fixture.consumer.verifyStreaming(
                fileURL: fixture.carURL,
                space: fixture.space,
                author: fixture.author,
                publicKey: fixture.key.publicKey,
                expectedEntries: [
                    SpaceCARRecoveryIndexEntry(
                        path: "app.bsky.feed.post/other",
                        cid: fixture.cid
                    ),
                ]
            )
            XCTFail("a CAR without the expected record path was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .expectedWitnessMismatch)
        }
    }

    func testStreamingConsumerRejectsExpectedCIDMismatch() async throws {
        let fixture = try FullCARWitnessFixture()
        defer { fixture.remove() }
        let otherCID = CID.fromDAGCBOR(Data([0xa1, 0x61, 0x78, 0x02]))

        do {
            _ = try await fixture.consumer.verifyStreaming(
                fileURL: fixture.carURL,
                space: fixture.space,
                author: fixture.author,
                publicKey: fixture.key.publicKey,
                expectedEntries: [
                    SpaceCARRecoveryIndexEntry(
                        path: fixture.path,
                        cid: otherCID
                    ),
                ]
            )
            XCTFail("a CAR with the wrong expected record CID was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .expectedWitnessMismatch)
        }
    }
}

private struct FullCARWitnessFixture {
    let author = "did:plc:alice"
    let path = "app.bsky.feed.post/r1"
    let space: SpaceURI
    let key: P256.Signing.PrivateKey
    let cid: CID
    let root: URL
    let carURL: URL
    let consumer: SwanCARConsumer

    init() throws {
        space = try SpaceURI(
            authority: author,
            spaceType: "app.swan.interop",
            skey: "witness"
        )
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "r1"
        )
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        cid = CID.fromDAGCBOR(value)
        var ltHash = LtHash()
        ltHash.add(element: "\(path)/\(cid.string)")
        key = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: author,
                rev: "222222222222a",
                ikm: Data(repeating: 0x42, count: 32)
            ),
            commitment: ltHash.commitment,
            key: key
        )
        let car = try SpaceCARCodec.encode(
            commit: commit,
            records: [
                SpaceRecord(
                    uri: uri,
                    value: value,
                    cid: cid.string,
                    revision: 1
                ),
            ]
        )
        root = FileManager.default.temporaryDirectory.appending(
            path: "swan-full-car-witness-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        try fullCARCreateOwnerOnlyDirectory(at: root)
        carURL = root.appending(path: "recovery.car")
        try fullCARWriteOwnerOnlyFile(car.data, to: carURL)
        consumer = try SwanCARConsumer(
            maximumBytes: car.data.count,
            stagingDirectory: root
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

private func fullCARCreateOwnerOnlyDirectory(at url: URL) throws {
    try FileManager.default.createDirectory(
        at: url,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: NSNumber(value: 0o700)]
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: NSNumber(value: 0o700)],
        ofItemAtPath: url.path
    )
}

private func fullCARWriteOwnerOnlyFile(_ data: Data, to url: URL) throws {
    guard FileManager.default.createFile(
        atPath: url.path,
        contents: nil,
        attributes: [.posixPermissions: NSNumber(value: 0o600)]
    ) else {
        throw CocoaError(.fileWriteFileExists)
    }
    var succeeded = false
    defer {
        if !succeeded {
            try? FileManager.default.removeItem(at: url)
        }
    }
    try FileManager.default.setAttributes(
        [.posixPermissions: NSNumber(value: 0o600)],
        ofItemAtPath: url.path
    )
    let handle = try FileHandle(forWritingTo: url)
    do {
        try handle.write(contentsOf: data)
        try handle.close()
        succeeded = true
    } catch {
        try? handle.close()
        throw error
    }
}

private func fullCARPermissions(at url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(
        atPath: url.path
    )
    guard let permissions = attributes[.posixPermissions] as? NSNumber else {
        throw CocoaError(.fileReadUnknown)
    }
    return permissions.intValue & 0o777
}
