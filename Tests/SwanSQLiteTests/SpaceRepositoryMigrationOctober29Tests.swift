import Crypto
import Foundation
import NIOCore
import Petrel
import PetrelCrypto
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
@testable import SwanSpaces
import SwanStorage
import XCTest

/// October 29 sections 4 and 5 in SQLite: clearRecords, importRepo,
/// exportSpaceMeta / importSpaceMeta, and blob permanence on a later upload.
final class SpaceRepositoryMigrationOctober29Tests: XCTestCase {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let carol = "did:plc:cdefghijklmnopqrstuvwxyz"
    private static let emptyDigest = "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"

    private var oldHost: URL!
    private var newHost: URL!
    private let owner = AuthorizationContext.accountOAuthForTesting(
        subject: SpaceRepositoryMigrationOctober29Tests.alice,
        scopes: ["atproto"]
    )

    override func setUpWithError() throws {
        let base = FileManager.default.temporaryDirectory
            .appending(path: "SpaceRepositoryMigrationOctober29Tests-\(UUID().uuidString)")
        oldHost = base.appending(path: "old")
        newHost = base.appending(path: "new")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: oldHost.deletingLastPathComponent())
    }

    private func withDatabase(
        _ root: URL,
        _ body: (SQLiteAccountDatabase) async throws -> Void
    ) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: Self.alice)
        do {
            try await body(database)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func value(_ text: String, type: String = "app.bsky.feed.post") throws -> Data {
        try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: type), (key: "text", value: text),
        ]))
    }

    @discardableResult
    private func write(
        _ database: SQLiteAccountDatabase,
        space: SpaceURI,
        _ entries: [(collection: String, rkey: String, value: Data)]
    ) async throws -> PersistedRepositoryCommit {
        let state = try await database.repositoryState(space: space, author: Self.alice)
        let wire = try TID(tidString: try SpaceRevisionSequence.next(
            after: state?.wireRevision.toString(), now: Date()
        ))
        return try await database.apply(
            space: space, author: Self.alice,
            expectedRevision: state?.revision ?? 0, requestID: UUID(), wireRevision: wire,
            writes: try entries.map {
                .create(
                    uri: try SpaceRecordURI(space: space, author: Self.alice, collection: $0.collection, rkey: $0.rkey),
                    value: $0.value, cid: CID.fromDAGCBOR($0.value).string
                )
            }
        )
    }

    private func paths(_ database: SQLiteAccountDatabase, _ space: SpaceURI) async throws -> [String] {
        let rows = try await database.connection.query(
            """
            SELECT collection, rkey FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ? ORDER BY collection, rkey
            """,
            [.text(space.rawValue), .text(Self.alice)]
        )
        return rows.map { "\($0.column("collection")?.string ?? "")/\($0.column("rkey")?.string ?? "")" }
    }

    private func count(_ database: SQLiteAccountDatabase, _ sql: String, _ space: SpaceURI) async throws -> Int {
        try await database.connection.query(sql, [.text(space.rawValue)]).first?.column("count")?.integer ?? -1
    }

    /// The archive `getRepo` would serve for the account's repo.
    private func archive(_ database: SQLiteAccountDatabase, _ space: SpaceURI) async throws -> Data {
        let maybeState = try await database.repositoryState(space: space, author: Self.alice)
        let state = try XCTUnwrap(maybeState)
        let rows = try await database.connection.query(
            """
            SELECT collection, rkey, value, cid FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ? ORDER BY collection, rkey
            """,
            [.text(space.rawValue), .text(Self.alice)]
        )
        let records = try rows.map { row -> SpaceRecord in
            let value = try XCTUnwrap(row.column("value").flatMap { Data(sqliteData: $0) })
            return SpaceRecord(
                uri: try SpaceRecordURI(
                    space: space, author: Self.alice,
                    collection: row.column("collection")?.string ?? "", rkey: row.column("rkey")?.string ?? ""
                ),
                value: value, cid: row.column("cid")?.string ?? "", revision: 0
            )
        }
        let commit = try SpaceRepositoryCommit(
            repo: Self.alice, space: space, rev: state.wireRevision.toString(), data: state.commitment
        )
        return try SpaceSTARCodec.encode(commit: commit, records: records)
    }

    // MARK: clearRecords

    func testClearRecordsReachesTheEmptyDigestAndIsANoOpWhenEmpty() async throws {
        let space = try SpaceURI(authority: Self.carol, spaceType: "app.bsky.bookmarks", skey: "shared")
        try await withDatabase(oldHost) { database in
            let never = try await database.clearSpaceRepository(space: space, author: Self.alice, keepCollections: [])
            XCTAssertNil(never, "a repo never written is a no-op")

            let first = try await write(database, space: space, [
                ("app.bsky.feed.post", "a", try value("a")),
                ("app.bsky.feed.like", "b", try value("b", type: "app.bsky.feed.like")),
            ])
            let collections = try await database.spaceRepositoryCollections(space: space, author: Self.alice, excluding: [])
            XCTAssertEqual(collections, ["app.bsky.feed.like", "app.bsky.feed.post"])

            let maybeCleared = try await database.clearSpaceRepository(
                space: space, author: Self.alice, keepCollections: []
            )
            let cleared = try XCTUnwrap(maybeCleared)
            XCTAssertEqual(Hex.encode(cleared.state.commitment), Self.emptyDigest)
            XCTAssertGreaterThan(cleared.state.wireRevision, first.state.wireRevision)
            XCTAssertEqual(cleared.state.revision, first.state.revision + 1)
            XCTAssertTrue(cleared.entries.isEmpty)
            let remaining = try await paths(database, space)
            XCTAssertTrue(remaining.isEmpty)
            let oplog = try await count(
                database, "SELECT COUNT(*) AS count FROM permissioned_space_oplog WHERE space_uri = ?", space
            )
            XCTAssertEqual(oplog, 0)
            // The write notification is queued like any write's.
            let outbox = try await database.connection.query(
                "SELECT revision FROM permissioned_space_outbox WHERE id = ?",
                [.text(cleared.outbox.id.uuidString)]
            )
            XCTAssertEqual(outbox.first?.column("revision")?.integer, Int(cleared.state.revision))

            // A syncer at the old rev gets the new commit and no ops; its
            // running hash no longer matches, which is its resync signal.
            let page = try await database.wireOplog(
                space: space, author: Self.alice, since: first.state.wireRevision, limit: 100, includeValues: false
            )
            guard case let .incremental(state, entries) = page else {
                return XCTFail("expected an incremental page, got \(page)")
            }
            XCTAssertTrue(entries.isEmpty)
            XCTAssertEqual(state?.wireRevision, cleared.state.wireRevision)

            // Clearing an empty repo again is a no-op: no new rev.
            let again = try await database.clearSpaceRepository(space: space, author: Self.alice, keepCollections: [])
            XCTAssertNil(again)
            let state2 = try await database.repositoryState(space: space, author: Self.alice)
            XCTAssertEqual(state2?.wireRevision, cleared.state.wireRevision)

            // A later write repopulates the repo; an old cursor still sees it.
            let next = try await write(database, space: space, [("app.bsky.feed.post", "c", try value("c"))])
            let later = try await database.wireOplog(
                space: space, author: Self.alice, since: first.state.wireRevision, limit: 100, includeValues: false
            )
            guard case let .incremental(laterState, laterEntries) = later else {
                return XCTFail("expected an incremental page, got \(later)")
            }
            XCTAssertEqual(laterEntries.map(\.uri.rkey), ["c"])
            XCTAssertEqual(laterState?.wireRevision, next.state.wireRevision)
        }
    }

    func testAuthorityClearKeepsPublishedRecordsAndTheirDigest() async throws {
        let space = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "mine")
        try await withDatabase(oldHost) { database in
            let policy = SpacePolicy.member(try MemberSpacePolicy(publishPolicy: true, publishMembers: true))
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: policy), authorization: owner
            )
            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.bob, read: true, write: true, authorization: owner
            )
            try await write(database, space: space, [("app.bsky.feed.post", "a", try value("a"))])
            let keep = SpacePolicy.publishedCollections
            let collections = try await database.spaceRepositoryCollections(
                space: space, author: Self.alice, excluding: keep
            )
            XCTAssertEqual(collections, ["app.bsky.feed.post"], "kept collections need no delete grant")

            let maybeCleared = try await database.clearSpaceRepository(
                space: space, author: Self.alice, keepCollections: keep
            )
            let cleared = try XCTUnwrap(maybeCleared)
            let remaining = try await paths(database, space)
            XCTAssertEqual(remaining, [
                "com.atproto.memberspace.member/\(Self.bob)",
                "com.atproto.space.policy/self",
            ])
            var expected = LtHash()
            expected.add(element: "com.atproto.memberspace.member/\(Self.bob)/\(CID.fromDAGCBOR(try SpacePolicy.memberRecordValue(read: true, write: true)).string)")
            expected.add(element: "com.atproto.space.policy/self/\(CID.fromDAGCBOR(try policy.policyRecordValue()).string)")
            XCTAssertEqual(cleared.state.commitment, expected.commitment)
            // The authority's clear updates its own writer entry.
            let writer = try await database.connection.query(
                "SELECT wire_revision, commitment FROM permissioned_space_writers WHERE space_uri = ? AND repo_did = ?",
                [.text(space.rawValue), .text(Self.alice)]
            )
            XCTAssertEqual(writer.first?.column("wire_revision")?.string, cleared.state.wireRevision.toString())
            XCTAssertEqual(
                writer.first?.column("commitment").flatMap { Data(sqliteData: $0) },
                cleared.state.commitment
            )
            // Only published records left: nothing more to clear.
            let again = try await database.clearSpaceRepository(space: space, author: Self.alice, keepCollections: keep)
            XCTAssertNil(again)
        }
    }

    // MARK: importRepo

    func testImportRepoTakesANewRevWithTheSameDataAndCanBeRetried() async throws {
        let space = try SpaceURI(authority: Self.carol, spaceType: "app.bsky.bookmarks", skey: "shared")
        var star = Data()
        var oldState: PersistedRepositoryState?
        try await withDatabase(oldHost) { database in
            try await write(database, space: space, [
                ("app.bsky.feed.post", "a", try value("a")),
                ("app.bsky.feed.post", "b", try value("b")),
            ])
            star = try await archive(database, space)
            oldState = try await database.repositoryState(space: space, author: Self.alice)
        }
        let old = try XCTUnwrap(oldState)
        let verified = try SpaceSTARCodec.decodeImport(star)
        XCTAssertEqual(verified.commit.repo, Self.alice)
        XCTAssertEqual(verified.commit.space, space)

        try await withDatabase(newHost) { database in
            // Something already here is replaced.
            try await write(database, space: space, [("app.bsky.feed.like", "z", try value("z", type: "app.bsky.feed.like"))])
            let imported = try await database.importSpaceRepository(
                space: space, author: Self.alice, records: verified.records, ltHash: verified.ltHash
            )
            XCTAssertEqual(imported.commitment, old.commitment)
            XCTAssertGreaterThan(imported.wireRevision, old.wireRevision)
            let importedPaths = try await paths(database, space)
            XCTAssertEqual(importedPaths, ["app.bsky.feed.post/a", "app.bsky.feed.post/b"])
            let oplog = try await count(
                database, "SELECT COUNT(*) AS count FROM permissioned_space_oplog WHERE space_uri = ?", space
            )
            XCTAssertEqual(oplog, 0)
            // A syncer at the old host's rev: no ops, and `data` still matches.
            let page = try await database.wireOplog(
                space: space, author: Self.alice, since: old.wireRevision, limit: 100, includeValues: false
            )
            guard case let .incremental(state, entries) = page else {
                return XCTFail("expected an incremental page, got \(page)")
            }
            XCTAssertTrue(entries.isEmpty)
            XCTAssertEqual(state?.commitment, old.commitment)

            // Retrying replaces again at a newer rev.
            let retried = try await database.importSpaceRepository(
                space: space, author: Self.alice, records: verified.records, ltHash: verified.ltHash
            )
            XCTAssertEqual(retried.commitment, old.commitment)
            XCTAssertGreaterThan(retried.wireRevision, imported.wireRevision)

            // Records that do not fold to the digest are refused.
            do {
                _ = try await database.importSpaceRepository(
                    space: space, author: Self.alice, records: Array(verified.records.prefix(1)), ltHash: verified.ltHash
                )
                XCTFail("a partial archive must not import")
            } catch SwanError.malformed {}
        }
    }

    func testImportRepoIntoTheAuthoritysOwnSpaceNeedsTheSpaceFirst() async throws {
        let space = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "mine")
        var star = Data()
        var meta = Data()
        try await withDatabase(oldHost) { database in
            let policy = SpacePolicy.member(try MemberSpacePolicy(publishPolicy: true))
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: policy), authorization: owner
            )
            try await write(database, space: space, [("app.bsky.feed.post", "a", try value("a"))])
            star = try await archive(database, space)
            meta = try SpaceMetaSTARCodec.encode(try await database.exportSpaceMeta(space: space, authorization: owner))
        }
        let verified = try SpaceSTARCodec.decodeImport(star)
        try await withDatabase(newHost) { database in
            do {
                _ = try await database.importSpaceRepository(
                    space: space, author: Self.alice, records: verified.records, ltHash: verified.ltHash
                )
                XCTFail("importRepo before importSpaceMeta must be SpaceNotFound")
            } catch AuthorizedSimpleSpaceLifecycleError.notFound {}

            try await database.importSpaceMeta(try SpaceMetaSTARCodec.decode(meta), authorization: owner)
            // importSpaceMeta publishes nothing; the records arrive with the repo.
            let beforeRepo = try await paths(database, space)
            XCTAssertTrue(beforeRepo.isEmpty)
            let imported = try await database.importSpaceRepository(
                space: space, author: Self.alice, records: verified.records, ltHash: verified.ltHash
            )
            XCTAssertEqual(imported.commitment, verified.commit.data)
            let afterRepo = try await paths(database, space)
            XCTAssertEqual(afterRepo, ["app.bsky.feed.post/a", "com.atproto.space.policy/self"])
        }
    }

    func testBlobUploadedAfterImportBecomesPermanent() async throws {
        let space = try SpaceURI(authority: Self.carol, spaceType: "app.bsky.bookmarks", skey: "shared")
        let bytes = Data("blob bytes".utf8)
        let cid = CID(
            codec: .raw,
            multihash: Multihash(
                algorithm: Multihash.sha256Code, length: Multihash.sha256Length,
                digest: Data(SHA256.hash(data: bytes))
            )
        )
        let record = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: "app.bsky.feed.post"),
            (key: "image", value: OrderedCBORMap(entries: [
                (key: "$type", value: "blob"), (key: "ref", value: ATProtoLink(cid: cid)),
                (key: "mimeType", value: "image/png"), (key: "size", value: bytes.count),
            ])),
        ]))
        var check = LtHash()
        check.add(element: "app.bsky.feed.post/a/\(CID.fromDAGCBOR(record).string)")
        let records = [SpaceRecord(
            uri: try SpaceRecordURI(space: space, author: Self.alice, collection: "app.bsky.feed.post", rkey: "a"),
            value: record, cid: CID.fromDAGCBOR(record).string, revision: 0
        )]
        try await withDatabase(newHost) { database in
            _ = try await database.importSpaceRepository(
                space: space, author: Self.alice, records: records, ltHash: check.serialized
            )
            let edges = try await database.connection.query(
                "SELECT namespace_kind, space_uri FROM blob_namespace_references WHERE cid = ?",
                [.text(cid.string)]
            )
            XCTAssertTrue(edges.isEmpty, "the blob has not been uploaded yet")
            let association = try await count(
                database, "SELECT COUNT(*) AS count FROM permissioned_space_record_blobs WHERE space_uri = ?", space
            )
            XCTAssertEqual(association, 1)

            let reference = try await database.putStreaming(
                namespace: .staged, mimeType: "image/png", maximumBytes: 1_024
            ) { sink in
                try await sink(bytes)
            }
            XCTAssertEqual(reference.cid, cid.string)
            let after = try await database.connection.query(
                "SELECT namespace_kind, space_uri FROM blob_namespace_references WHERE cid = ? ORDER BY namespace_kind",
                [.text(cid.string)]
            )
            XCTAssertEqual(after.map { $0.column("namespace_kind")?.string }, ["space"])
            XCTAssertEqual(after.first?.column("space_uri")?.string, space.rawValue)
        }
    }

    // MARK: exportSpaceMeta / importSpaceMeta

    func testSpaceMetaRoundTripKeepsPolicyMembersAndWriterSpaceRevs() async throws {
        let space = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "mine")
        let policy = SpacePolicy.member(try MemberSpacePolicy(
            publicRead: true, allowedApps: ["https://app.example/client.json"], publishMembers: true
        ))
        var bytes = Data()
        try await withDatabase(oldHost) { database in
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: policy), authorization: owner
            )
            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.bob, read: true, write: false, authorization: owner
            )
            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.carol, read: true, write: true, authorization: owner
            )
            for (did, spaceRev) in [(Self.bob, "3mzzzzzzzzzy2"), (Self.carol, "3mzzzzzzzzzz2")] {
                _ = try await database.connection.query(
                    """
                    INSERT OR REPLACE INTO permissioned_space_writers(
                        space_uri, repo_did, wire_revision, commitment, updated_at, space_rev
                    ) VALUES (?, ?, '3m2aaaaaaaaa2', ?, 1, ?)
                    """,
                    [
                        .text(space.rawValue), .text(did),
                        .blob(ByteBuffer(bytes: [UInt8](repeating: 9, count: 32))), .text(spaceRev),
                    ]
                )
            }
            let readOnly = AuthorizationContext.accountOAuthForTesting(
                subject: Self.alice,
                scopes: ["space:app.bsky.bookmarks?authority=\(Self.alice)&skey=mine&action=read_self"]
            )
            bytes = try SpaceMetaSTARCodec.encode(try await database.exportSpaceMeta(space: space, authorization: readOnly))
        }
        let archive = try SpaceMetaSTARCodec.decode(bytes)
        XCTAssertEqual(archive.policy, policy)
        XCTAssertEqual(archive.members, [
            try SpaceMetaMember(did: Self.bob, read: true, write: false),
            try SpaceMetaMember(did: Self.carol, read: true, write: true),
        ], "the owner row Swan keeps is not exported")
        // The owner's own writer entry (from publishing the policy) travels too.
        XCTAssertEqual(archive.writers.map(\.did), [Self.alice, Self.bob, Self.carol])
        XCTAssertEqual(archive.writers.suffix(2).map(\.spaceRev), ["3mzzzzzzzzzy2", "3mzzzzzzzzzz2"])

        try await withDatabase(newHost) { database in
            // manage=update alone is not enough: importing also creates.
            let updateOnly = AuthorizationContext.accountOAuthForTesting(
                subject: Self.alice, scopes: ["space:*?authority=*&skey=*&manage=update"]
            )
            do {
                try await database.importSpaceMeta(archive, authorization: updateOnly)
                XCTFail("importSpaceMeta needs manage=create and manage=update")
            } catch SwanError.unauthorized {}

            try await database.importSpaceMeta(archive, authorization: owner)
            let stored = try await database.requiredSimpleSpace(space).state.space
            XCTAssertEqual(stored.configuration.policy, policy)
            XCTAssertEqual(stored.members[Self.bob], SimpleSpaceMember(did: Self.bob, read: true, write: false))
            XCTAssertEqual(stored.members[Self.carol], SimpleSpaceMember(did: Self.carol, read: true, write: true))
            XCTAssertNotNil(stored.members[Self.alice])
            let published = try await paths(database, space)
            XCTAssertTrue(published.isEmpty, "importSpaceMeta does not republish")

            // Re-export on the new host reproduces the archive byte for byte.
            let again = try SpaceMetaSTARCodec.encode(try await database.exportSpaceMeta(space: space, authorization: owner))
            XCTAssertEqual(again, bytes)

            // The next accepted write continues after the imported space revs.
            let sequence = try await database.withConnectionGate {
                try await database.transaction {
                    try await database.advanceWriterHighWaterWithoutGate(
                        space: space, repository: Self.bob, wireRevision: "3m2aaaaaaaac2",
                        commitment: Data(repeating: 1, count: 32), updatedAt: 2
                    )
                }
            }
            XCTAssertEqual(sequence?.previousSpaceRevision, "3mzzzzzzzzzz2")
            XCTAssertGreaterThan(try XCTUnwrap(sequence?.spaceRevision), "3mzzzzzzzzzz2")
        }
    }
}
