import Crypto
import Foundation
import Petrel
import XCTest
@testable import SwanSpaces

final class StreamingSpaceCARRecoveryTests: XCTestCase {
    func testStreamingRecoveryReturnsBoundedSummaryAndRequestsAtMost64KiB() async throws {
        let fixture = try StreamingRecoveryFixture(recordByteCount: 4)
        let source = InstrumentedSpaceCARSource(bytes: fixture.car.data, chunkByteCount: 7)
        let index = InMemorySpaceRecoveryIndex()

        let summary = try await SpaceCARCodec.verifyStreamingRecovery(
            from: source,
            space: fixture.space,
            author: fixture.author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature(
                    $0,
                    publicKey: fixture.signingKey.publicKey
                )
            },
            index: index,
            expectedEntries: [
                SpaceCARRecoveryIndexEntry(
                    path: "app.bsky.feed.post/only",
                    cid: fixture.recordCID
                ),
            ],
            limits: try SpaceCARRecoveryLimits(
                maximumCARBytes: fixture.car.data.count,
                maximumRecordBytes: 1 * 1_024 * 1_024
            )
        )

        XCTAssertEqual(summary.wireRevision.toString(), fixture.revision)
        XCTAssertEqual(summary.recordCount, 1)
        XCTAssertEqual(summary.verifiedExpectedWitnessCount, 1)
        XCTAssertEqual(summary.ltHash, fixture.ltHash.serialized)
        XCTAssertEqual(summary.commitment, fixture.ltHash.commitment)
        let largestRequestedChunk = await source.largestRequestedChunk
        let unconsumedCount = await index.unconsumedCount
        XCTAssertLessThanOrEqual(
            largestRequestedChunk,
            SpaceCARRecoveryLimits.maximumChunkBytes
        )
        XCTAssertEqual(unconsumedCount, 0)
    }

    func testStreamingRecoveryRejectsCorruptRecordWithoutAcceptingTheIndex() async throws {
        let fixture = try StreamingRecoveryFixture(recordByteCount: 4)
        var corrupt = fixture.car.data
        corrupt[corrupt.index(before: corrupt.endIndex)] ^= 0x01
        let index = InMemorySpaceRecoveryIndex()

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(bytes: corrupt, chunkByteCount: 3),
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: fixture.signingKey.publicKey
                    )
                },
                index: index,
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: corrupt.count,
                    maximumRecordBytes: 1 * 1_024 * 1_024
                )
            )
            XCTFail("a record body whose digest does not match its CID was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .blockCIDMismatch)
        }
    }

    func testStreamingRecoveryRejectsRecordLargerThanOneMiBBeforeReadingItsBody() async throws {
        let fixture = try StreamingRecoveryFixture(recordByteCount: 1 * 1_024 * 1_024 + 1)
        let source = InstrumentedSpaceCARSource(
            bytes: fixture.car.data,
            chunkByteCount: SpaceCARRecoveryLimits.maximumChunkBytes
        )

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: source,
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: fixture.signingKey.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: fixture.car.data.count,
                    maximumRecordBytes: 1 * 1_024 * 1_024
                )
            )
            XCTFail("a record body over the configured one-MiB ceiling was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .recordBodyLimitExceeded)
        }
        let deliveredByteCount = await source.deliveredByteCount
        XCTAssertLessThan(deliveredByteCount, fixture.car.data.count)
    }

    func testStreamingRecoveryRejectsNonCanonicalDAGCBOREvenWhenItsCIDAndCommitmentMatch() async throws {
        let fixture = try StreamingRecoveryFixture(
            recordValue: Data([0xa1, 0x61, 0x78, 0x18, 0x01])
        )

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(
                    bytes: fixture.car.data,
                    chunkByteCount: 11
                ),
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: fixture.signingKey.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: fixture.car.data.count
                )
            )
            XCTFail("non-canonical DAG-CBOR with internally consistent CIDs was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .invalidRecordValue)
        }
    }

    func testStreamingRecoveryAcceptsCanonicalSharedCIDFramesAndCountsEveryIndexedPath() async throws {
        let author = "did:plc:alice"
        let space = try SpaceURI(
            authority: author,
            spaceType: "app.swan.streaming",
            skey: "shared-cid"
        )
        let sharedValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "text", value: "same value"),
        ]))
        let distinctValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "text", value: "distinct value"),
        ]))
        let sharedCID = CID.fromDAGCBOR(sharedValue)
        let distinctCID = CID.fromDAGCBOR(distinctValue)
        // Both index and record blocks use length-then-bytes (`b`, `z`,
        // `aa`). The shared CID appears in both `z` and `aa` frames while
        // staging and the unique-block limit count it only once.
        let values = [
            (rkey: "aa", value: sharedValue),
            (rkey: "b", value: distinctValue),
            (rkey: "z", value: sharedValue),
        ]
        let records = try values.map { item in
            SpaceRecord(
                uri: try SpaceRecordURI(
                    space: space,
                    author: author,
                    collection: "app.bsky.feed.post",
                    rkey: item.rkey
                ),
                value: item.value,
                cid: CID.fromDAGCBOR(item.value).string,
                revision: 1
            )
        }
        var ltHash = LtHash()
        ltHash.add(element: "app.bsky.feed.post/aa/\(sharedCID.string)")
        ltHash.add(element: "app.bsky.feed.post/b/\(distinctCID.string)")
        ltHash.add(element: "app.bsky.feed.post/z/\(sharedCID.string)")
        let key = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: author,
                rev: "222222222222a",
                ikm: Data(repeating: 0x31, count: 32)
            ),
            commitment: ltHash.commitment,
            key: key
        )
        let encoded = try SpaceCARCodec.encode(commit: commit, records: records)
        let frames = try testCARFrameRanges(encoded.data)
        XCTAssertEqual(
            frames.count,
            5,
            "commit, DRISL index, and one record frame per path must be emitted"
        )
        var expectedDistinctFrame = try SpaceCARCodec.streamingBlockPrefix(
            cid: distinctCID, dataLength: distinctValue.count
        )
        expectedDistinctFrame.append(distinctValue)
        var expectedSharedFrame = try SpaceCARCodec.streamingBlockPrefix(
            cid: sharedCID, dataLength: sharedValue.count
        )
        expectedSharedFrame.append(sharedValue)
        XCTAssertEqual(Data(encoded.data[frames[2]]), expectedDistinctFrame)
        XCTAssertEqual(Data(encoded.data[frames[3]]), expectedSharedFrame)
        XCTAssertEqual(Data(encoded.data[frames[4]]), expectedSharedFrame)

        // The former lexical order (`aa`, `b`) has the same valid blocks and
        // commitment but violates the updated proposal's record block order.
        var lexicalCAR = Data(encoded.data[..<frames[2].lowerBound])
        lexicalCAR.append(encoded.data[frames[3]])
        lexicalCAR.append(encoded.data[frames[2]])
        lexicalCAR.append(encoded.data[frames[4]])
        XCTAssertThrowsError(try SpaceCARCodec.verify(
            lexicalCAR, space: space, author: author, publicKey: key.publicKey
        ))
        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(bytes: lexicalCAR, chunkByteCount: 19),
                space: space,
                author: author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature($0, publicKey: key.publicKey)
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(maximumCARBytes: lexicalCAR.count)
            )
            XCTFail("lexical record block order was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .invalidRecordOrder)
        }
        var corruptRepeatedFrame = encoded.data
        corruptRepeatedFrame[frames[4].upperBound - 1] ^= 1
        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(bytes: corruptRepeatedFrame, chunkByteCount: 19),
                space: space, author: author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature($0, publicKey: key.publicKey)
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(maximumCARBytes: corruptRepeatedFrame.count)
            )
            XCTFail("a corrupt repeated CID frame was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .blockCIDMismatch)
        }
        let compactCAR = Data(encoded.data[..<frames[4].lowerBound])
        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(bytes: compactCAR, chunkByteCount: 19),
                space: space, author: author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature($0, publicKey: key.publicKey)
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(maximumCARBytes: compactCAR.count)
            )
            XCTFail("a compact CAR missing an indexed shared-CID frame was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .unindexedBlocks)
        }
        let overlayShapedCAR = encoded.data
        let summary = try await SpaceCARCodec.verifyStreamingRecovery(
            from: InstrumentedSpaceCARSource(
                bytes: overlayShapedCAR,
                chunkByteCount: 19
            ),
            space: space,
            author: author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature(
                    $0,
                    publicKey: key.publicKey
                )
            },
            index: InMemorySpaceRecoveryIndex(),
            limits: try SpaceCARRecoveryLimits(
                maximumCARBytes: overlayShapedCAR.count
            )
        )
        XCTAssertEqual(summary.recordCount, 3)
        XCTAssertEqual(summary.uniqueBlockCount, 2)
        XCTAssertEqual(summary.commitment, ltHash.commitment)
        let materialized = try SpaceCARCodec.verify(
            overlayShapedCAR,
            space: space,
            author: author,
            publicKey: key.publicKey
        )
        XCTAssertEqual(materialized.count, 3)
        XCTAssertEqual(
            materialized["app.bsky.feed.post/aa"],
            sharedValue
        )
        XCTAssertEqual(
            materialized["app.bsky.feed.post/b"],
            distinctValue
        )
        XCTAssertEqual(
            materialized["app.bsky.feed.post/z"],
            sharedValue
        )
    }

    func testStreamingRecoveryRejectsSharedCIDFrameWithoutAnIndexEntry() async throws {
        let author = "did:plc:alice"
        let space = try SpaceURI(
            authority: author,
            spaceType: "app.swan.streaming",
            skey: "duplicate-shared-cid"
        )
        let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "text", value: "same value"),
        ]))
        let cid = CID.fromDAGCBOR(value)
        let records = try ["first", "second"].map { rkey in
            SpaceRecord(
                uri: try SpaceRecordURI(
                    space: space,
                    author: author,
                    collection: "app.bsky.feed.post",
                    rkey: rkey
                ),
                value: value,
                cid: cid.string,
                revision: 1
            )
        }
        var ltHash = LtHash()
        ltHash.add(element: "app.bsky.feed.post/first/\(cid.string)")
        ltHash.add(element: "app.bsky.feed.post/second/\(cid.string)")
        let key = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: author,
                rev: "222222222222a",
                ikm: Data(repeating: 0x32, count: 32)
            ),
            commitment: ltHash.commitment,
            key: key
        )
        let encoded = try SpaceCARCodec.encode(commit: commit, records: records)
        let frames = try testCARFrameRanges(encoded.data)
        let firstRecordFrame = frames[2]
        var repeatedCIDCAR = encoded.data
        repeatedCIDCAR.append(encoded.data[firstRecordFrame])

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(
                    bytes: repeatedCIDCAR,
                    chunkByteCount: 23
                ),
                space: space,
                author: author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: key.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: repeatedCIDCAR.count
                )
            )
            XCTFail("a shared CID frame without a corresponding index entry was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .invalidRecordOrder)
        }
        do {
            _ = try SpaceCARCodec.verify(
                repeatedCIDCAR,
                space: space,
                author: author,
                publicKey: key.publicKey
            )
            XCTFail(
                "the materializing verifier accepted a repeated record block"
            )
        } catch {}
    }

    func testStreamingRecoveryRejectsMissingIndexedBlock() async throws {
        let fixture = try StreamingRecoveryFixture(recordByteCount: 8)
        let frames = try testCARFrameRanges(fixture.car.data)
        let missingRecordCAR = Data(
            fixture.car.data[..<frames[1].upperBound]
        )

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(
                    bytes: missingRecordCAR,
                    chunkByteCount: 17
                ),
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: fixture.signingKey.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: missingRecordCAR.count
                )
            )
            XCTFail("an indexed record with no CAR block was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .unindexedBlocks)
        }
    }

    func testStreamingRecoveryRejectsExtraUnindexedBlock() async throws {
        let fixture = try StreamingRecoveryFixture(recordByteCount: 8)
        let extraBody = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [
                (key: "extra", value: true),
            ])
        )
        let extraCID = CID.fromDAGCBOR(extraBody)
        var extraBlockCAR = fixture.car.data
        extraBlockCAR.append(
            testCanonicalVarint(extraCID.bytes.count + extraBody.count)
        )
        extraBlockCAR.append(extraCID.bytes)
        extraBlockCAR.append(extraBody)

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(
                    bytes: extraBlockCAR,
                    chunkByteCount: 29
                ),
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: fixture.signingKey.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: extraBlockCAR.count
                )
            )
            XCTFail("an unindexed trailing CAR block was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .invalidRecordOrder)
        }
    }

    func testStreamingRecoveryRejectsNonCanonicalCommitEncodingWithValidSignatureAndMAC() async throws {
        let fixture = try StreamingRecoveryFixture(recordByteCount: 4)
        let canonicalCommit = try SpaceCARCodec.encodeCommit(fixture.commit)
        let versionField = Data([0x63, 0x76, 0x65, 0x72, 0x01])
        let versionRange = try XCTUnwrap(canonicalCommit.range(of: versionField))
        var nonCanonicalCommit = canonicalCommit
        nonCanonicalCommit.replaceSubrange(
            nonCanonicalCommit.index(before: versionRange.upperBound)
                ..< versionRange.upperBound,
            with: [0x18, 0x01]
        )
        let commitCID = CID.fromDAGCBOR(nonCanonicalCommit)
        let header = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "roots", value: [
                ATProtoLink(cid: commitCID),
                ATProtoLink(cid: fixture.car.indexCID),
            ]),
            (key: "version", value: 1),
        ]))
        var malformedCAR = testCanonicalVarint(header.count)
        malformedCAR.append(header)
        malformedCAR.append(
            testCanonicalVarint(commitCID.bytes.count + nonCanonicalCommit.count)
        )
        malformedCAR.append(commitCID.bytes)
        malformedCAR.append(nonCanonicalCommit)

        var suffixOffset = 0
        let oldHeaderLength = try testReadCanonicalVarint(
            fixture.car.data,
            offset: &suffixOffset
        )
        suffixOffset += oldHeaderLength
        let oldCommitFrameLength = try testReadCanonicalVarint(
            fixture.car.data,
            offset: &suffixOffset
        )
        suffixOffset += oldCommitFrameLength
        malformedCAR.append(fixture.car.data[suffixOffset...])

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(
                    bytes: malformedCAR,
                    chunkByteCount: 13
                ),
                space: fixture.space,
                author: fixture.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: fixture.signingKey.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: malformedCAR.count
                )
            )
            XCTFail("a non-canonical signed-commit block was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .malformedFrame)
        }
    }

    // MARK: - F02: delegated exact-content integrity

    /// This test pins a DELIBERATELY ACCEPTED behaviour. Do not "fix" it.
    ///
    /// The pinned proposal-0016 commit envelope signs only the tuple
    /// `(space, author, rev, ikm)`; the content commitment is outside
    /// `SpaceCommitCodec.contextSigningBytes`. The commitment is bound only by
    /// the deniable HMAC content binding, whose key is derived from the IKM —
    /// and the IKM travels in the clear as the `ikm` field of the wire commit
    /// block. So any party that can serve or relay that block can swap the
    /// commitment, recompute the MAC, and leave the author's signature bytes
    /// untouched, and `verifyStreamingRecovery` will accept the result.
    ///
    /// Exact-content integrity for permissioned content is therefore delegated
    /// to the pinned HTTPS source origin. Changing that is an upstream
    /// amendment plus a coordinated re-pin, not a Swan-side patch. If this
    /// test ever starts failing because the verifier rejects the substitution,
    /// the trust model changed and `docs/threat-boundaries.md` needs updating
    /// with it.
    func testStreamingRecoveryAcceptsCommitmentSubstitutionUnderTheOriginalAuthorSignature() async throws {
        let honest = try StreamingRecoveryFixture(recordByteCount: 4)
        let substituted = try SubstitutedCommitmentFixture(honest: honest)

        // Nothing the author produced was re-signed: the signature bytes are
        // byte-identical to the honest envelope's, and the private key is
        // never used to build the forgery.
        XCTAssertEqual(
            substituted.envelope.contextSignature,
            honest.commit.contextSignature
        )
        XCTAssertNotEqual(
            substituted.envelope.commitment,
            honest.commit.commitment
        )
        XCTAssertNotEqual(
            substituted.envelope.contentBinding,
            honest.commit.contentBinding
        )
        XCTAssertTrue(try SpaceCommitCodec.verifyContextSignature(
            substituted.envelope,
            publicKey: honest.signingKey.publicKey
        ))
        XCTAssertTrue(
            SpaceCommitCodec.verifyContentBinding(substituted.envelope)
        )

        let index = InMemorySpaceRecoveryIndex()
        let summary = try await SpaceCARCodec.verifyStreamingRecovery(
            from: InstrumentedSpaceCARSource(
                bytes: substituted.car.data,
                chunkByteCount: 17
            ),
            space: honest.space,
            author: honest.author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature(
                    $0,
                    publicKey: honest.signingKey.publicKey
                )
            },
            index: index,
            limits: try SpaceCARRecoveryLimits(
                maximumCARBytes: substituted.car.data.count
            )
        )

        // Accepted, with the substituted content, at the author's original
        // wire revision.
        XCTAssertEqual(summary.recordCount, 1)
        XCTAssertEqual(summary.wireRevision.toString(), honest.revision)
        XCTAssertEqual(summary.commitment, substituted.ltHash.commitment)
        XCTAssertNotEqual(summary.commitment, honest.ltHash.commitment)
        XCTAssertEqual(summary.ltHash, substituted.ltHash.serialized)
        let unconsumedCount = await index.unconsumedCount
        XCTAssertEqual(unconsumedCount, 0)

        // The pair the publish path actually adjudicates: an unchanged wire
        // revision carrying a different commitment. That is exactly the
        // `wireRevision == highWater && commitment != highWaterCommitment`
        // branch in
        // `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift`
        // (`requireRemoteReplicaHighWater`, lines 1541-1548), which throws
        // `PermissionedRemoteReplicaRecoveryError.equivocation` and leaves the
        // installed head untouched. That rejection is proved end-to-end by
        // `PermissionedRemoteReplicaRecoverySQLiteTests`
        // (`same-tid-equivocation`), which owns the SQLite harness; this test
        // owns only the verifier-level property.
        XCTAssertEqual(summary.wireRevision.toString(), honest.revision)
        XCTAssertNotEqual(summary.commitment, honest.ltHash.commitment)
    }

    /// The one thing that does catch the substitution inside the verifier: an
    /// expected path/CID witness obtained out of band, from somewhere other
    /// than the origin serving the CAR. Documented so the mitigation is not
    /// mistaken for a property of the commit envelope.
    func testStreamingRecoveryRejectsCommitmentSubstitutionWhenAnOutOfBandWitnessIsSupplied() async throws {
        let honest = try StreamingRecoveryFixture(recordByteCount: 4)
        let substituted = try SubstitutedCommitmentFixture(honest: honest)

        do {
            _ = try await SpaceCARCodec.verifyStreamingRecovery(
                from: InstrumentedSpaceCARSource(
                    bytes: substituted.car.data,
                    chunkByteCount: 17
                ),
                space: honest.space,
                author: honest.author,
                contextSignatureVerifier: {
                    try SpaceCommitCodec.verifyContextSignature(
                        $0,
                        publicKey: honest.signingKey.publicKey
                    )
                },
                index: InMemorySpaceRecoveryIndex(),
                expectedEntries: [
                    SpaceCARRecoveryIndexEntry(
                        path: "app.bsky.feed.post/only",
                        cid: honest.recordCID
                    ),
                ],
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: substituted.car.data.count
                )
            )
            XCTFail("substituted content passed an out-of-band CID witness")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .expectedWitnessMismatch)
        }
    }
}

/// Builds the commitment-substituted envelope for the F02 tests using only
/// material a CAR-serving origin already possesses: the honest envelope's
/// verbatim signature bytes and the cleartext IKM from the same commit block.
/// The author's private key is deliberately not used.
private struct SubstitutedCommitmentFixture {
    let recordValue: Data
    let recordCID: CID
    let ltHash: LtHash
    let envelope: SpaceCommitEnvelope
    let car: SpaceCAR

    init(honest: StreamingRecoveryFixture) throws {
        recordValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "data", value: Data("substituted by the CAR origin".utf8)),
        ]))
        recordCID = CID.fromDAGCBOR(recordValue)
        var calculated = LtHash()
        calculated.add(element: "app.bsky.feed.post/only/\(recordCID.string)")
        ltHash = calculated

        let context = honest.commit.context
        envelope = SpaceCommitEnvelope(
            context: context,
            contextSignature: honest.commit.contextSignature,
            contentBinding: Self.recomputedContentBinding(
                context: try SpaceCommitCodec.contextSigningBytes(context),
                ikm: context.ikm,
                commitment: calculated.commitment
            ),
            commitment: calculated.commitment
        )
        car = try SpaceCARCodec.encode(
            commit: envelope,
            records: [
                SpaceRecord(
                    uri: try SpaceRecordURI(
                        space: honest.space,
                        author: honest.author,
                        collection: "app.bsky.feed.post",
                        rkey: "only"
                    ),
                    value: recordValue,
                    cid: recordCID.string,
                    revision: 1
                ),
            ]
        )
    }

    /// The pinned one-block HKDF-Expand construction from RFC 5869, restated
    /// here rather than called through production code: the point of the test
    /// is that an outsider can reproduce it from the public envelope alone.
    private static func recomputedContentBinding(
        context: Data,
        ikm: Data,
        commitment: Data
    ) -> Data {
        var expandInput = context
        expandInput.append(0x01)
        let derived = SymmetricKey(data: Data(
            HMAC<SHA256>.authenticationCode(
                for: expandInput,
                using: SymmetricKey(data: ikm)
            )
        ))
        return Data(HMAC<SHA256>.authenticationCode(
            for: commitment,
            using: derived
        ))
    }
}

private struct StreamingRecoveryFixture {
    let author = "did:plc:alice"
    let revision = "222222222222a"
    let space: SpaceURI
    let signingKey: P256.Signing.PrivateKey
    let ltHash: LtHash
    let commit: SpaceCommitEnvelope
    let car: SpaceCAR
    let recordCID: CID

    init(recordByteCount: Int) throws {
        try self.init(
            recordValue: DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "data", value: Data(repeating: 0x2a, count: recordByteCount)),
            ]))
        )
    }

    init(recordValue value: Data) throws {
        space = try SpaceURI(
            authority: author,
            spaceType: "app.swan.streaming",
            skey: "recovery"
        )
        signingKey = P256.Signing.PrivateKey()
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "only"
        )
        let cid = CID.fromDAGCBOR(value)
        recordCID = cid
        var calculated = LtHash()
        calculated.add(element: "app.bsky.feed.post/only/\(cid.string)")
        ltHash = calculated
        commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: author,
                rev: revision,
                ikm: Data(repeating: 0x21, count: 32)
            ),
            commitment: calculated.commitment,
            key: signingKey
        )
        car = try SpaceCARCodec.encode(
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
    }
}

private func testCanonicalVarint(_ value: Int) -> Data {
    precondition(value >= 0)
    var remaining = UInt64(value)
    var output = Data()
    repeat {
        var byte = UInt8(remaining & 0x7f)
        remaining >>= 7
        if remaining != 0 { byte |= 0x80 }
        output.append(byte)
    } while remaining != 0
    return output
}

private func testReadCanonicalVarint(
    _ data: Data,
    offset: inout Int
) throws -> Int {
    var value: UInt64 = 0
    var shift: UInt64 = 0
    var encoded = Data()
    while offset < data.count {
        let byte = data[offset]
        offset += 1
        encoded.append(byte)
        value |= UInt64(byte & 0x7f) << shift
        if byte & 0x80 == 0 {
            guard value <= UInt64(Int.max) else {
                throw SpaceCARStreamingError.malformedVarint
            }
            guard testCanonicalVarint(Int(value)) == encoded else {
                throw SpaceCARStreamingError.nonCanonicalVarint
            }
            return Int(value)
        }
        shift += 7
        guard shift < 64 else {
            throw SpaceCARStreamingError.malformedVarint
        }
    }
    throw SpaceCARStreamingError.malformedVarint
}

private func testCARFrameRanges(_ data: Data) throws -> [Range<Int>] {
    var offset = 0
    let headerLength = try testReadCanonicalVarint(data, offset: &offset)
    guard headerLength <= data.count - offset else {
        throw SpaceCARStreamingError.malformedHeader
    }
    offset += headerLength
    var frames: [Range<Int>] = []
    while offset < data.count {
        let frameStart = offset
        let frameLength = try testReadCanonicalVarint(data, offset: &offset)
        guard frameLength <= data.count - offset else {
            throw SpaceCARStreamingError.malformedFrame
        }
        offset += frameLength
        frames.append(frameStart..<offset)
    }
    return frames
}

private actor InstrumentedSpaceCARSource: SpaceCARRecoveryByteSource {
    private let bytes: Data
    private let chunkByteCount: Int
    private var offset = 0
    private(set) var largestRequestedChunk = 0
    private(set) var deliveredByteCount = 0

    init(bytes: Data, chunkByteCount: Int) {
        self.bytes = bytes
        self.chunkByteCount = chunkByteCount
    }

    func read(maximumBytes: Int) throws -> Data? {
        largestRequestedChunk = max(largestRequestedChunk, maximumBytes)
        guard offset < bytes.count else { return nil }
        let end = min(bytes.count, offset + min(chunkByteCount, maximumBytes))
        let chunk = Data(bytes[offset ..< end])
        offset = end
        deliveredByteCount += chunk.count
        return chunk
    }
}

private actor InMemorySpaceRecoveryIndex: SpaceCARRecoveryIndex {
    private var entries: [SpaceCARRecoveryIndexEntry] = []
    private var consumedPaths = Set<String>()

    var unconsumedCount: Int {
        entries.count - consumedPaths.count
    }

    func insert(_ entry: SpaceCARRecoveryIndexEntry) throws {
        guard !entries.contains(where: { $0.path == entry.path }) else {
            throw SpaceCARStreamingError.duplicateIndexEntry
        }
        entries.append(entry)
    }

    func nextUnconsumedCanonicalEntry() -> SpaceCARRecoveryIndexEntry? {
        entries
            .filter { !consumedPaths.contains($0.path) }
            .min { SpaceCARCodec.canonicalRecordPathPrecedes($0.path, $1.path) }
    }

    func hasConsumedCID(_ cid: CID) -> Bool {
        entries.contains { $0.cid == cid && consumedPaths.contains($0.path) }
    }

    func consumeEntry(_ entry: SpaceCARRecoveryIndexEntry) throws {
        guard nextUnconsumedCanonicalEntry() == entry,
              consumedPaths.insert(entry.path).inserted else {
            throw SpaceCARStreamingError.invalidRecordOrder
        }
    }

}
