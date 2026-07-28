import Crypto
import Foundation
import Petrel
@testable import SwanPublicRepository
import XCTest

final class PublicRepositoryCARTests: XCTestCase {
    private let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
    private let revision = "3jzfcijpj2z2a"

    func testCanonicalUnsignedVarintBoundaries() throws {
        let vectors: [(UInt64, [UInt8])] = [
            (0, [0x00]),
            (1, [0x01]),
            (127, [0x7f]),
            (128, [0x80, 0x01]),
            (16_383, [0xff, 0x7f]),
            (16_384, [0x80, 0x80, 0x01]),
            (UInt64.max, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
        ]

        for (value, bytes) in vectors {
            XCTAssertEqual(PublicRepositoryCAR.canonicalUnsignedVarint(value), Data(bytes))
        }
    }

    func testImportParserCoversEveryUInt64VarintTransitionAndOverlongForm() async {
        let transitions: [UInt64] = [
            0,
            (1 << 7) - 1, 1 << 7,
            (1 << 14) - 1, 1 << 14,
            (1 << 21) - 1, 1 << 21,
            (1 << 28) - 1, 1 << 28,
            (1 << 35) - 1, 1 << 35,
            (1 << 42) - 1, 1 << 42,
            (1 << 49) - 1, 1 << 49,
            (1 << 56) - 1, 1 << 56,
            (1 << 63) - 1, 1 << 63,
            UInt64.max,
        ]

        for value in transitions {
            let encoded = PublicRepositoryCAR.canonicalUnsignedVarint(value)
            let expected: PublicRepositoryCARError =
                value == 0 ? .invalidRootCount
                : value <= 1_024 ? .malformedFrame
                : .malformedHeader
            await assertImportError(expected, encoded)

            if encoded.count < 10 {
                var overlong = encoded
                overlong[overlong.count - 1] |= 0x80
                overlong.append(0)
                await assertImportError(.nonCanonicalVarint, overlong)
            }
        }
    }

    func testImportParserRejectsMalformedTenthByteAndTenByteOverlongForms() async {
        let cases: [(Data, PublicRepositoryCARError)] = [
            (Data(repeating: 0x80, count: 9) + Data([0x02]), .malformedVarint),
            (Data(repeating: 0x80, count: 10), .malformedVarint),
            (Data(repeating: 0xff, count: 9) + Data([0x81]), .malformedVarint),
            (Data(repeating: 0x80, count: 9) + Data([0x00]), .nonCanonicalVarint),
            (Data(repeating: 0x80, count: 9) + Data([0x01]), .malformedHeader),
            (Data(repeating: 0xff, count: 9) + Data([0x01]), .malformedHeader),
        ]
        for (encoded, expected) in cases {
            await assertImportError(expected, encoded)
        }
    }

    func testWriterEmitsCanonicalHeaderAndSeparateBoundedChunks() async throws {
        let blockBytes = Data([0xa1, 0x61, 0x78, 0x01])
        let blockCID = CID.fromDAGCBOR(blockBytes)
        let sink = RecordingCARSink()
        let stream = ArrayCARBlockStream([
            PublicRepositoryBlock(cid: blockCID, bytes: blockBytes),
        ])

        let result = try await PublicRepositoryCAR.write(
            rootCID: blockCID,
            blocks: stream,
            to: sink,
            maximumChunkBytes: 3
        )

        let writes = await sink.writes
        XCTAssertFalse(writes.isEmpty)
        XCTAssertLessThanOrEqual(writes.map(\.count).max() ?? 0, 3)
        XCTAssertEqual(result.blockCount, 1)
        XCTAssertEqual(result.byteCount, writes.reduce(0) { $0 + $1.count })

        let expectedHeader = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: blockCID)]),
            (key: "version", value: 1),
        ]))
        let expected = PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(expectedHeader.count))
            + expectedHeader
            + PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(blockCID.bytes.count + blockBytes.count))
            + blockCID.bytes
            + blockBytes
        XCTAssertEqual(writes.reduce(into: Data(), { $0.append($1) }), expected)
    }

    func testFullExportUsesPinnedCommitBreadthFirstMSTThenStableRecordsOrder() async throws {
        let fixture = try await makeRepositoryFixture()
        let sink = RecordingCARSink()

        let result = try await PublicRepositoryCAR.export(
            signedCommit: fixture.commit,
            blocks: fixture.blocks,
            to: sink,
            maximumChunkBytes: 17
        )
        let car = await sink.data
        let parsedCIDs = try framedBlockCIDs(car)
        let expected = try await pinnedOrder(
            commitCID: fixture.commit.commitCID,
            rootCID: fixture.commit.descriptor.dataCID,
            blocks: fixture.blocks
        )

        XCTAssertEqual(parsedCIDs, expected)
        XCTAssertEqual(result.blockCount, expected.count)
        XCTAssertEqual(result.byteCount, car.count)
    }

    func testImportAcceptsArbitraryOrderIdenticalDuplicatesAndExtrasButProjectsReachableOnly() async throws {
        let fixture = try await makeRepositoryFixture()
        let expected = try await pinnedBlocks(
            commit: fixture.commit,
            blocks: fixture.blocks
        )
        let extraBytes = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: "com.example.extra"),
        ]))
        let extra = PublicRepositoryBlock(cid: CID.fromDAGCBOR(extraBytes), bytes: extraBytes)
        let shuffled = Array(expected.reversed()) + [expected[1], extra]
        let car = try await carData(root: fixture.commit.commitCID, blocks: shuffled)
        let imported = try await PublicRepositoryCAR.importRepository(
            from: ChunkedCARSource(car, chunkSizes: [1, 2, 5, 3, 13]),
            verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey)
        )

        XCTAssertEqual(imported.state.did, did)
        XCTAssertEqual(imported.state.revision, revision)
        XCTAssertEqual(imported.state.commitCID, fixture.commit.commitCID)
        XCTAssertEqual(imported.state.dataCID, fixture.commit.descriptor.dataCID)
        XCTAssertEqual(imported.repository.leaves.count, 5)
        XCTAssertEqual(imported.reachableBlocks.cids, Set(expected.map(\.cid)))
        let projectedExtra = try await imported.reachableBlocks.block(for: extra.cid)
        XCTAssertNil(projectedExtra)
        let validatedAgain = try await RepositoryMSTValidation.validate(
            rootCID: imported.state.dataCID,
            blocks: imported.reachableBlocks
        )
        XCTAssertEqual(validatedAgain.leaves, imported.repository.leaves)

        let reexportSink = RecordingCARSink()
        _ = try await PublicRepositoryCAR.export(
            signedCommit: imported.signedCommit,
            blocks: imported.reachableBlocks,
            to: reexportSink
        )
        let reexported = await reexportSink.data
        let reimported = try await PublicRepositoryCAR.importRepository(
            from: ChunkedCARSource(reexported, chunkSizes: [7, 1, 64]),
            verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey)
        )
        XCTAssertEqual(reimported.state, imported.state)
        XCTAssertEqual(reimported.reachableBlocks.cids, imported.reachableBlocks.cids)
    }

    func testImportRejectsNonCanonicalFramingHeaderRootAndCorruptionMatrix() async throws {
        let fixture = try await makeRepositoryFixture()
        let blocks = try await pinnedBlocks(commit: fixture.commit, blocks: fixture.blocks)
        let valid = try await carData(root: fixture.commit.commitCID, blocks: blocks)

        var nonCanonicalHeaderLength = Data([valid[0] | 0x80, 0x00])
        nonCanonicalHeaderLength.append(valid.dropFirst())
        let headerLength = Int(valid[0])
        let headerAndPrefix = Data(valid.prefix(1 + headerLength))
        let nonCanonicalFrameLength = headerAndPrefix + Data([0x80, 0x00])
        let unterminatedFrameLength = headerAndPrefix + Data([0x80])
        let overflowingFrameLength = headerAndPrefix
            + Data([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02])

        var truncated = valid
        truncated.removeLast()

        var trailingFrame = valid
        trailingFrame.append(0)

        let wrongRoot = CID.fromDAGCBOR(Data("wrong-root".utf8))
        let wrongRootCAR = try await carData(root: wrongRoot, blocks: blocks)

        let missingCommitCAR = try await carData(
            root: fixture.commit.commitCID,
            blocks: Array(blocks.dropFirst())
        )

        var mismatchBlocks = blocks
        mismatchBlocks[1] = PublicRepositoryBlock(
            cid: mismatchBlocks[1].cid,
            bytes: Data("wrong".utf8)
        )
        let mismatchCAR = try await uncheckedCARData(
            root: fixture.commit.commitCID,
            blocks: mismatchBlocks
        )

        var conflictBlocks = blocks
        conflictBlocks.append(.init(cid: blocks[1].cid, bytes: Data("conflict".utf8)))
        let conflictCAR = try await uncheckedCARData(
            root: fixture.commit.commitCID,
            blocks: conflictBlocks
        )

        let badVersionHeader = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: fixture.commit.commitCID)]),
            (key: "version", value: 2),
        ]))
        let badVersion = replaceHeader(in: valid, with: badVersionHeader)

        let noRootsHeader = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink]()),
            (key: "version", value: 1),
        ]))
        let noRoots = replaceHeader(in: valid, with: noRootsHeader)

        let rawBody = Data("unsupported".utf8)
        let rawCID = CID.fromBlob(rawBody)
        let unsupportedCIDCAR = try await uncheckedCARData(
            root: fixture.commit.commitCID,
            blocks: blocks + [.init(cid: rawCID, bytes: rawBody)]
        )

        for candidate in [
            nonCanonicalHeaderLength, nonCanonicalFrameLength,
            unterminatedFrameLength, overflowingFrameLength,
            truncated, trailingFrame, wrongRootCAR, missingCommitCAR,
            mismatchCAR, conflictCAR, badVersion, noRoots, unsupportedCIDCAR,
        ] {
            await assertImportRejected(candidate, key: fixture.key)
        }
    }

    func testWriterEnforcesBodyTotalAndBlockLimitsBeforeWritingTheOffendingBody() async throws {
        let bytes = Data(repeating: 0x61, count: 1_001)
        let block = PublicRepositoryBlock(cid: CID.fromDAGCBOR(bytes), bytes: bytes)
        let smallPolicy = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: 1,
            maximumMSTNodes: 1,
            maximumMSTEntriesPerNode: 1,
            maximumCBORNestingDepth: 3
        )
        let sink = RecordingCARSink()
        do {
            _ = try await PublicRepositoryCAR.write(
                rootCID: block.cid,
                blocks: ArrayCARBlockStream([block]),
                to: sink,
                limits: smallPolicy
            )
            XCTFail("expected body limit")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, .blockBodyLimitExceeded)
        }
        let bytesWritten = await sink.byteCount
        XCTAssertLessThan(bytesWritten, bytes.count)
    }

    func testWriterIndependentlyEnforcesTotalByteAndBlockCountLimits() async throws {
        let oneMiB = Data(repeating: 0x31, count: 1_000_000)
        let large = PublicRepositoryBlock(cid: CID.fromDAGCBOR(oneMiB), bytes: oneMiB)
        let totalLimited = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000_000,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: 1_000,
            maximumMSTNodes: 500,
            maximumMSTEntriesPerNode: 100,
            maximumCBORNestingDepth: 16
        )
        do {
            _ = try await PublicRepositoryCAR.write(
                rootCID: large.cid,
                blocks: RepeatingCARBlockStream(block: large, count: 269),
                to: CountingCARSink(),
                limits: totalLimited
            )
            XCTFail("expected total byte limit")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, .byteLimitExceeded)
        }

        let smallBytes = Data([0xa1, 0x61, 0x78, 0x01])
        let small = PublicRepositoryBlock(cid: CID.fromDAGCBOR(smallBytes), bytes: smallBytes)
        let blockLimited = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: 1,
            maximumMSTNodes: 1,
            maximumMSTEntriesPerNode: 10,
            maximumCBORNestingDepth: 8
        )
        do {
            _ = try await PublicRepositoryCAR.write(
                rootCID: small.cid,
                blocks: RepeatingCARBlockStream(block: small, count: 2),
                to: CountingCARSink(),
                limits: blockLimited
            )
            XCTFail("expected block count limit")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, .blockLimitExceeded)
        }
    }

    func testImportIndependentlyRejectsDeclaredBodyCapAndMultipleRoots() async throws {
        let root = CID.fromDAGCBOR(Data([0xa0]))
        let header = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: root)]),
            (key: "version", value: 1),
        ]))
        let declaredOversize = PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(header.count))
            + header
            + PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(36 + 1_001))
        let limits = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: 10,
            maximumMSTNodes: 10,
            maximumMSTEntriesPerNode: 10,
            maximumCBORNestingDepth: 8
        )
        await assertImportError(.blockBodyLimitExceeded, declaredOversize, limits: limits)

        let other = CID.fromDAGCBOR(Data([0xa1, 0x61, 0x78, 0x01]))
        let multipleRootsHeader = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: root), ATProtoLink(cid: other)]),
            (key: "version", value: 1),
        ]))
        let multipleRoots =
            PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(multipleRootsHeader.count))
            + multipleRootsHeader
        await assertImportError(.invalidRootCount, multipleRoots)
    }

    func testLargeWriterUsesBoundedChunksAndPropagatesSinkFailure() async throws {
        let oneMiB = Data(repeating: 0x7a, count: 1_000_000)
        let block = PublicRepositoryBlock(cid: CID.fromDAGCBOR(oneMiB), bytes: oneMiB)
        let repetitions = 269
        let sink = CountingCARSink()
        let result = try await PublicRepositoryCAR.write(
            rootCID: block.cid,
            blocks: RepeatingCARBlockStream(block: block, count: repetitions),
            to: sink,
            maximumChunkBytes: 32 * 1_024
        )

        XCTAssertGreaterThanOrEqual(result.byteCount, 256 * 1_024 * 1_024)
        let maximumWrite = await sink.maximumWrite
        XCTAssertLessThanOrEqual(maximumWrite, 32 * 1_024)
        XCTAssertEqual(result.blockCount, repetitions)

        let failing = FailingCARSink(failAfterWrites: 2)
        do {
            _ = try await PublicRepositoryCAR.write(
                rootCID: block.cid,
                blocks: RepeatingCARBlockStream(block: block, count: 10),
                to: failing,
                maximumChunkBytes: 32 * 1_024
            )
            XCTFail("expected sink failure")
        } catch {
            XCTAssertTrue(error is TestSinkError)
        }
        let consumed = await failing.writeCount
        XCTAssertEqual(consumed, 2)
    }

    func testCancellationStopsWriterWithoutSuccessfulCompletion() async throws {
        let bytes = Data(repeating: 0x44, count: 1_000_000)
        let block = PublicRepositoryBlock(cid: CID.fromDAGCBOR(bytes), bytes: bytes)
        let sink = SlowCountingCARSink()
        let task = Task {
            try await PublicRepositoryCAR.write(
                rootCID: block.cid,
                blocks: RepeatingCARBlockStream(block: block, count: 100),
                to: sink,
                maximumChunkBytes: 1_024
            )
        }
        try await Task.sleep(for: .milliseconds(5))
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        let written = await sink.byteCount
        XCTAssertLessThan(written, 100_000_000)
    }

    func testImportEnforcesConfiguredBlockCountBeforeParsingExtraBody() async throws {
        let fixture = try await makeRepositoryFixture()
        let car = try await carData(
            root: fixture.commit.commitCID,
            blocks: try await pinnedBlocks(commit: fixture.commit, blocks: fixture.blocks)
        )
        let limits = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000_000,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: 2,
            maximumMSTNodes: 2,
            maximumMSTEntriesPerNode: 100,
            maximumCBORNestingDepth: 16
        )
        do {
            _ = try await PublicRepositoryCAR.importRepository(
                from: ChunkedCARSource(car, chunkSizes: [1, 2, 3]),
                verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
                limits: limits
            )
            XCTFail("expected block limit")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, .blockLimitExceeded)
        }
    }

    func testValidationRejectsOneRecordCIDReferencedAcrossMismatchedCollectionsWithoutRetainingBodies() async throws {
        let first = try depthZeroPath(collection: "app.bsky.feed.post")
        let second = try depthZeroPath(collection: "app.bsky.feed.like")
        let prepared = try PublicRepositoryRecordCodec.prepare(
            PublicRecord(["$type": .string(first.collection)]),
            for: first
        )
        let leaves = [
            RepositoryMSTLeaf(path: first, recordCID: prepared.cid),
            RepositoryMSTLeaf(path: second, recordCID: prepared.cid),
        ].sorted { $0.path.mstKey < $1.path.mstKey }
        let nodeBytes = try RepositoryMSTCodec.encode(
            RepositoryMSTCodec.node(leaves: leaves)
        )
        let nodeCID = CID.fromDAGCBOR(nodeBytes)
        do {
            _ = try await RepositoryMSTValidation.validate(
                rootCID: nodeCID,
                blocks: TestBlockSource([
                    nodeCID: nodeBytes,
                    prepared.cid: prepared.bytes,
                ])
            )
            XCTFail("expected collection mismatch")
        } catch {
            XCTAssertEqual(error as? RepositoryMSTValidationError, .invalidRecordBlock)
        }
    }

    func testImportAcceptsExactTotalByteLimitAndRejectsOneByteOver() async throws {
        let fixture = try await makeRepositoryFixture()
        let base = try await carData(
            root: fixture.commit.commitCID,
            blocks: try await pinnedBlocks(commit: fixture.commit, blocks: fixture.blocks)
        )
        let exactSegments = try exactLengthCARSegments(
            base: base,
            target: PublicRepositoryLimits.requiredStreamingCARBytes
        )
        let exact = try await PublicRepositoryCAR.importRepository(
            from: SegmentedCARSource(exactSegments),
            verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
            limits: try PublicRepositoryLimits(
                maximumRecordBlockBytes: 1_000_000,
                maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
                maximumCARBlocks: 1_000,
                maximumMSTNodes: 500,
                maximumMSTEntriesPerNode: 100,
                maximumCBORNestingDepth: 16
            )
        )
        XCTAssertEqual(exact.state.commitCID, fixture.commit.commitCID)

        let oneByteOver = exactSegments + [Data([0])]
        do {
            _ = try await PublicRepositoryCAR.importRepository(
                from: SegmentedCARSource(oneByteOver),
                verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
                limits: try PublicRepositoryLimits(
                    maximumRecordBlockBytes: 1_000_000,
                    maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
                    maximumCARBlocks: 1_000,
                    maximumMSTNodes: 500,
                    maximumMSTEntriesPerNode: 100,
                    maximumCBORNestingDepth: 16
                )
            )
            XCTFail("expected one-byte overflow")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, .byteLimitExceeded)
        }
    }

    func testPinnedTypeScriptNonEmptyCARImportsAndReexportsByteForByte() async throws {
        let fixture = try PinnedNonEmptyCARFixture.load()
        let car = try XCTUnwrap(Data(base64Encoded: fixture.carBase64))
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        let imported = try await PublicRepositoryCAR.importRepository(
            from: ChunkedCARSource(car, chunkSizes: [1, 7, 64, 3]),
            verifier: P256PublicRepositoryCommitVerifier(publicKey: key.publicKey)
        )
        XCTAssertEqual(imported.state.commitCID.string, fixture.commitCID)
        XCTAssertEqual(imported.state.did, fixture.did)
        XCTAssertEqual(imported.state.revision, fixture.revision)
        XCTAssertEqual(imported.repository.leaves.map(\.path.mstKey), [
            "\(fixture.record.collection)/\(fixture.record.rkey)",
        ])

        let sink = RecordingCARSink()
        _ = try await PublicRepositoryCAR.export(
            signedCommit: imported.signedCommit,
            blocks: imported.reachableBlocks,
            to: sink
        )
        let reexported = await sink.data
        XCTAssertEqual(reexported, car)

        let swiftCAR = try XCTUnwrap(Data(base64Encoded: fixture.swift.carBase64))
        let importedSwift = try await PublicRepositoryCAR.importRepository(
            from: ChunkedCARSource(swiftCAR, chunkSizes: [2, 31, 1]),
            verifier: P256PublicRepositoryCommitVerifier(publicKey: key.publicKey)
        )
        XCTAssertEqual(importedSwift.state.commitCID.string, fixture.swift.commitCID)
        XCTAssertEqual(importedSwift.repository.leaves.map(\.path), imported.repository.leaves.map(\.path))
    }

    func testPinnedTypeScriptMultiLayerCARHasExactIndependentBlockOrderAndRecords() async throws {
        let fixture = try PinnedNonEmptyCARFixture.load()
        let vector = fixture.multiLayer
        let car = try XCTUnwrap(Data(base64Encoded: vector.carBase64))
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        let imported = try await PublicRepositoryCAR.importRepository(
            from: ChunkedCARSource(car, chunkSizes: [1, 5, 2, 31, 3]),
            verifier: P256PublicRepositoryCommitVerifier(publicKey: key.publicKey)
        )

        XCTAssertEqual(imported.state.commitCID.string, vector.commitCID)
        XCTAssertEqual(imported.state.dataCID.string, vector.dataCID)
        let actualOrder = try framedBlockCIDs(car).map(\.string)
        XCTAssertEqual(actualOrder, vector.blockOrder)
        XCTAssertGreaterThan(Set(imported.repository.leaves.map {
            RepositoryMSTCodec.keyDepth(for: $0.path)
        }).count, 1)
        XCTAssertEqual(
            imported.repository.leaves.map(\.path.mstKey),
            vector.records.map { "\($0.collection)/\($0.rkey)" }.sorted()
        )

        let sink = RecordingCARSink()
        _ = try await PublicRepositoryCAR.export(
            signedCommit: imported.signedCommit,
            blocks: imported.reachableBlocks,
            to: sink
        )
        let reexported = await sink.dataValue()
        XCTAssertEqual(reexported, car)
    }

    private func makeRepositoryFixture() async throws -> (
        key: P256.Signing.PrivateKey,
        commit: PreparedPublicRepositorySignedCommit,
        blocks: TestBlockSource
    ) {
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        let paths = try ["0", "2", "18", "54", "90"].map {
            try PublicRepositoryPath(collection: "app.bsky.feed.post", recordKey: $0)
        }
        var tree = try RepositoryMST.empty()
        var storage: [CID: Data] = [:]
        for path in paths {
            let record = PublicRecord([
                "$type": .string(path.collection),
                "text": .string(path.recordKey),
            ])
            let prepared = try PublicRepositoryRecordCodec.prepare(record, for: path)
            storage[prepared.cid] = prepared.bytes
            tree = try await tree.adding(path: path, recordCID: prepared.cid)
        }
        let materialized = try await tree.materialized()
        for cid in materialized.newBlocks.cids {
            storage[cid] = try await materialized.newBlocks.block(for: cid)
        }
        let commit = try await PublicRepositoryCommitCodec.prepare(
            did: did,
            revision: revision,
            dataCID: materialized.rootCID,
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        storage[commit.commitCID] = commit.signedCommitBytes
        return (key, commit, TestBlockSource(storage))
    }

    private func depthZeroPath(collection: String) throws -> PublicRepositoryPath {
        for index in 0 ..< 10_000 {
            let path = try PublicRepositoryPath(collection: collection, recordKey: "k\(index)")
            if RepositoryMSTCodec.keyDepth(for: path) == 0 {
                return path
            }
        }
        throw PublicRepositoryCARError.repository(.invalidLayer)
    }

    private func pinnedBlocks(
        commit: PreparedPublicRepositorySignedCommit,
        blocks: TestBlockSource
    ) async throws -> [PublicRepositoryBlock] {
        let cids = try await pinnedOrder(
            commitCID: commit.commitCID,
            rootCID: commit.descriptor.dataCID,
            blocks: blocks
        )
        return try await cids.mapAsync { cid in
            let candidate = try await blocks.block(for: cid)
            return PublicRepositoryBlock(cid: cid, bytes: try XCTUnwrap(candidate))
        }
    }

    private func pinnedOrder(
        commitCID: CID,
        rootCID: CID,
        blocks: TestBlockSource
    ) async throws -> [CID] {
        var result = [commitCID]
        var queue = [rootCID]
        var records: [CID] = []
        var seenRecords = Set<CID>()
        while !queue.isEmpty {
            let layer = queue
            queue.removeAll()
            for cid in layer {
                result.append(cid)
                let candidate = try await blocks.block(for: cid)
                let bytes = try XCTUnwrap(candidate)
                let node = try RepositoryMSTCodec.decode(bytes)
                let leaves = try RepositoryMSTCodec.reconstructedLeaves(from: node)
                if let left = node.leftTreeCID { queue.append(left) }
                for leaf in leaves {
                    if seenRecords.insert(leaf.recordCID).inserted {
                        records.append(leaf.recordCID)
                    }
                    if let right = leaf.rightTreeCID { queue.append(right) }
                }
            }
        }
        return result + records
    }

    private func carData(root: CID, blocks: [PublicRepositoryBlock]) async throws -> Data {
        let sink = RecordingCARSink()
        _ = try await PublicRepositoryCAR.write(
            rootCID: root,
            blocks: ArrayCARBlockStream(blocks),
            to: sink
        )
        return await sink.data
    }

    private func uncheckedCARData(root: CID, blocks: [PublicRepositoryBlock]) async throws -> Data {
        let header = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: root)]),
            (key: "version", value: 1),
        ]))
        var result = PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(header.count)) + header
        for block in blocks {
            result += PublicRepositoryCAR.canonicalUnsignedVarint(
                UInt64(block.cid.bytes.count + block.bytes.count)
            )
            result += block.cid.bytes
            result += block.bytes
        }
        return result
    }

    private func replaceHeader(in car: Data, with header: Data) -> Data {
        let oldLength = Int(car[0])
        return PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(header.count))
            + header
            + car.dropFirst(1 + oldLength)
    }

    private func exactLengthCARSegments(base: Data, target: Int) throws -> [Data] {
        precondition(base.count < target)
        let maximumFrame = try uncheckedFrame(body: Data(repeating: 0xab, count: 1_000_000))
        var segments = [base]
        var remaining = target - base.count
        while remaining > 0 {
            if remaining >= maximumFrame.count + 38 {
                segments.append(maximumFrame)
                remaining -= maximumFrame.count
                continue
            }
            if remaining > maximumFrame.count {
                let minimumFrame = try frameWithExactTotalByteCount(38)
                segments.append(minimumFrame)
                remaining -= minimumFrame.count
                continue
            }
            let frame = try frameWithExactTotalByteCount(remaining)
            segments.append(frame)
            remaining -= frame.count
        }
        XCTAssertEqual(segments.reduce(0) { $0 + $1.count }, target)
        return segments
    }

    private func frameWithExactTotalByteCount(_ total: Int) throws -> Data {
        guard total >= 38 else { throw PublicRepositoryCARError.malformedFrame }
        for varintBytes in 1 ... 3 {
            let bodyCount = total - 36 - varintBytes
            guard bodyCount > 0, bodyCount <= 1_000_000 else { continue }
            let frameLength = 36 + bodyCount
            if PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(frameLength)).count == varintBytes {
                let body = Data(repeating: UInt8(truncatingIfNeeded: bodyCount), count: bodyCount)
                return try uncheckedFrame(body: body)
            }
        }
        throw PublicRepositoryCARError.malformedFrame
    }

    private func uncheckedFrame(body: Data) throws -> Data {
        let cid = CID.fromDAGCBOR(body)
        return PublicRepositoryCAR.canonicalUnsignedVarint(UInt64(36 + body.count))
            + cid.bytes
            + body
    }

    private func framedBlockCIDs(_ car: Data) throws -> [CID] {
        var offset = 0
        let headerLength = try testReadVarint(car, offset: &offset)
        offset += headerLength
        var result: [CID] = []
        while offset < car.count {
            let frameLength = try testReadVarint(car, offset: &offset)
            let end = offset + frameLength
            result.append(try CID(bytes: Data(car[offset ..< offset + 36])))
            offset = end
        }
        return result
    }

    private func testReadVarint(_ bytes: Data, offset: inout Int) throws -> Int {
        var result = 0
        var shift = 0
        while offset < bytes.count {
            let byte = Int(bytes[offset])
            offset += 1
            result |= (byte & 0x7f) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }
        throw PublicRepositoryCARError.malformedVarint
    }

    private func assertImportRejected(
        _ car: Data,
        key: P256.Signing.PrivateKey,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await PublicRepositoryCAR.importRepository(
                from: ChunkedCARSource(car, chunkSizes: [1, 3, 2]),
                verifier: P256PublicRepositoryCommitVerifier(publicKey: key.publicKey)
            )
            XCTFail("expected rejection", file: file, line: line)
        } catch {
            XCTAssertTrue(error is PublicRepositoryCARError, "\(error)", file: file, line: line)
        }
    }

    private func assertImportError(
        _ expected: PublicRepositoryCARError,
        _ car: Data,
        limits: PublicRepositoryLimits = .standard,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
            _ = try await PublicRepositoryCAR.importRepository(
                from: ChunkedCARSource(car, chunkSizes: [1, 2, 3]),
                verifier: P256PublicRepositoryCommitVerifier(publicKey: key.publicKey),
                limits: limits
            )
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, expected, file: file, line: line)
        }
    }
}

private actor RecordingCARSink: PublicRepositoryCARByteSink {
    private(set) var writes: [Data] = []

    func write(_ bytes: Data) async throws {
        writes.append(bytes)
    }

    var data: Data { writes.reduce(into: Data(), { $0.append($1) }) }
    var byteCount: Int { writes.reduce(0) { $0 + $1.count } }
    func dataValue() -> Data { data }
}

private actor ArrayCARBlockStream: PublicRepositoryCARBlockStream {
    private var blocks: [PublicRepositoryBlock]

    init(_ blocks: [PublicRepositoryBlock]) {
        self.blocks = blocks
    }

    func nextBlock() async throws -> PublicRepositoryBlock? {
        blocks.isEmpty ? nil : blocks.removeFirst()
    }
}

private actor ChunkedCARSource: PublicRepositoryCARByteSource {
    private let bytes: Data
    private let chunkSizes: [Int]
    private var offset = 0
    private var chunkIndex = 0

    init(_ bytes: Data, chunkSizes: [Int]) {
        self.bytes = bytes
        self.chunkSizes = chunkSizes
    }

    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < bytes.count else { return nil }
        let preferred = chunkSizes[chunkIndex % chunkSizes.count]
        chunkIndex += 1
        let count = min(maximumBytes, preferred, bytes.count - offset)
        defer { offset += count }
        return Data(bytes[offset ..< offset + count])
    }
}

private actor SegmentedCARSource: PublicRepositoryCARByteSource {
    private let segments: [Data]
    private var segmentIndex = 0
    private var segmentOffset = 0

    init(_ segments: [Data]) {
        self.segments = segments
    }

    func read(maximumBytes: Int) async throws -> Data? {
        while segmentIndex < segments.count,
              segmentOffset == segments[segmentIndex].count {
            segmentIndex += 1
            segmentOffset = 0
        }
        guard segmentIndex < segments.count else { return nil }
        let segment = segments[segmentIndex]
        let count = min(maximumBytes, segment.count - segmentOffset)
        defer { segmentOffset += count }
        return Data(segment[segmentOffset ..< segmentOffset + count])
    }
}

private struct TestBlockSource: PublicRepositoryBlockSource {
    let storage: [CID: Data]

    init(_ storage: [CID: Data]) {
        self.storage = storage
    }

    func block(for cid: CID) async throws -> Data? {
        storage[cid]
    }
}

private actor CountingCARSink: PublicRepositoryCARByteSink {
    private(set) var maximumWrite = 0
    private(set) var byteCount = 0

    func write(_ bytes: Data) async throws {
        maximumWrite = max(maximumWrite, bytes.count)
        byteCount += bytes.count
    }
}

private actor SlowCountingCARSink: PublicRepositoryCARByteSink {
    private(set) var byteCount = 0

    func write(_ bytes: Data) async throws {
        try await Task.sleep(for: .milliseconds(1))
        byteCount += bytes.count
    }
}

private actor RepeatingCARBlockStream: PublicRepositoryCARBlockStream {
    private let block: PublicRepositoryBlock
    private var remaining: Int

    init(block: PublicRepositoryBlock, count: Int) {
        self.block = block
        remaining = count
    }

    func nextBlock() async throws -> PublicRepositoryBlock? {
        guard remaining > 0 else { return nil }
        remaining -= 1
        return block
    }
}

private enum TestSinkError: Error {
    case failed
}

private actor FailingCARSink: PublicRepositoryCARByteSink {
    private let failAfterWrites: Int
    private(set) var writeCount = 0

    init(failAfterWrites: Int) {
        self.failAfterWrites = failAfterWrites
    }

    func write(_ bytes: Data) async throws {
        guard writeCount < failAfterWrites else { throw TestSinkError.failed }
        writeCount += 1
    }
}

private extension Array {
    func mapAsync<T: Sendable>(
        _ transform: (Element) async throws -> T
    ) async rethrows -> [T] {
        var result: [T] = []
        result.reserveCapacity(count)
        for element in self {
            result.append(try await transform(element))
        }
        return result
    }
}

private struct PinnedNonEmptyCARFixture: Decodable {
    struct CAR: Decodable {
        let commitCID: String
        let carBase64: String
    }

    struct Record: Decodable {
        let collection: String
        let rkey: String
        let text: String
    }

    struct MultiLayer: Decodable {
        let commitCID: String
        let dataCID: String
        let carBase64: String
        let blockOrder: [String]
        let records: [Record]
    }

    let did: String
    let revision: String
    let commitCID: String
    let carBase64: String
    let record: Record
    let swift: CAR
    let multiLayer: MultiLayer

    static func load() throws -> Self {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let url = packageRoot.appending(
            path: "fixtures/permissioned-data-0016-2026-07-03/public-repository-nonempty-car.json"
        )
        return try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }
}
