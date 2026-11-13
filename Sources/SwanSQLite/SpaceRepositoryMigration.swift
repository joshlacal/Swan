import Foundation
import Petrel
import PetrelCrypto
import PetrelRepo
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage

/// October 29 sections 4 and 5: clearing a space repo, moving one between
/// hosts with `importRepo`, and moving an authority's space state with
/// `exportSpaceMeta` / `importSpaceMeta`. Each mutation is one SQLite
/// transaction with no network I/O.
extension SQLiteAccountDatabase {
    // MARK: clearRecords

    /// Deletes every record of `author`'s repo in `space` outside
    /// `keepCollections`, with its blob associations and the whole operation
    /// log, and advances the repo to a new rev (the reference's
    /// `TID.nextStr(rev)`) at the digest of what is left. Returns `nil`, writing nothing, when there is nothing to delete.
    /// A real clear queues the usual write notification, and an authority's
    /// clear of its own repo updates its writer set like any authority write.
    public func clearSpaceRepository(
        space: SpaceURI,
        author: String,
        keepCollections: Set<String>,
        eventID: UUID = UUID(),
        now: Date = Date()
    ) async throws -> PersistedRepositoryCommit? {
        try requireAccount(author)
        return try await withConnectionGate {
            try await transaction {
                try await clearSpaceRepositoryWithoutGate(
                    space: space,
                    author: author,
                    keepCollections: keepCollections,
                    eventID: eventID,
                    now: now
                )
            }
        }
    }

    /// The collections that hold records `clearSpaceRepository` would delete,
    /// so the caller can require a `delete` grant for each before clearing.
    public func spaceRepositoryCollections(
        space: SpaceURI,
        author: String,
        excluding keepCollections: Set<String>
    ) async throws -> [String] {
        try requireAccount(author)
        let keep = keepCollections.sorted()
        let rows = try await withConnectionGate {
            try await connection.query(
                """
                SELECT DISTINCT collection FROM permissioned_space_records
                WHERE space_uri = ? AND author_did = ?\(Self.excludingCollections(keep.count))
                ORDER BY collection
                """,
                [.text(space.rawValue), .text(author)] + keep.map(SQLiteData.text)
            )
        }
        return try rows.map { try migrationText($0, "collection") }
    }

    private func clearSpaceRepositoryWithoutGate(
        space: SpaceURI,
        author: String,
        keepCollections: Set<String>,
        eventID: UUID,
        now: Date
    ) async throws -> PersistedRepositoryCommit? {
        try await requireLocalRepositorySpaceOpen(space)
        guard let loaded = try await loadStateWithCounts(space: space, author: author) else {
            return nil
        }
        let current = loaded.state
        let keep = keepCollections.sorted()
        let filter = Self.excludingCollections(keep.count)
        let arguments: [SQLiteData] = [.text(space.rawValue), .text(author)] + keep.map(SQLiteData.text)
        let counted = try await connection.query(
            """
            SELECT COUNT(*) AS count FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?\(filter)
            """,
            arguments
        )
        guard let first = counted.first, try requiredNonnegativeInteger(first, "count") > 0 else {
            return nil
        }
        let wireRevision = try TID(tidString: try SpaceRevisionSequence.next(
            after: current.wireRevision.toString(),
            now: now
        ))
        guard current.revision < UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(current.revision)
        }
        for table in ["permissioned_space_record_blobs", "permissioned_space_records"] {
            _ = try await connection.query(
                "DELETE FROM \(table) WHERE space_uri = ? AND author_did = ?\(filter)",
                arguments
            )
        }
        _ = try await connection.query(
            "DELETE FROM permissioned_space_oplog WHERE space_uri = ? AND author_did = ?",
            [.text(space.rawValue), .text(author)]
        )
        try await markRepositoryHistoryResetWithoutGate(space: space, author: author)
        var ltHash = LtHash()
        for row in try await connection.query(
            """
            SELECT collection, rkey, cid FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        ) {
            ltHash.add(element: "\(try migrationText(row, "collection"))/\(try migrationText(row, "rkey"))/\(try migrationText(row, "cid"))")
        }

        let revision = current.revision + 1
        let storedRevision = try sqliteRevision(revision)
        let marker = try repositoryStateMarker(
            space: space, author: author, revision: revision,
            wireRevision: wireRevision, commitment: ltHash.commitment
        )
        let createdAt = Int(Date().timeIntervalSince1970 * 1_000_000)
        try await coalesceSupersededOutboxRowsWithoutGate(space: space, author: author, now: createdAt)
        let payload = opaqueNotificationPayload(eventID: eventID)
        _ = try await connection.query(
            """
            INSERT INTO permissioned_space_outbox(
                id, space_uri, author_did, revision,
                payload, attempts, created_at, available_at,
                lease_token, lease_expires_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
            """,
            [
                .text(eventID.uuidString), .text(space.rawValue), .text(author),
                .integer(storedRevision), blob(payload),
                .integer(createdAt), .integer(createdAt),
            ]
        )
        // As in `applyWithoutGate`: an authority's own write is a space-host
        // update, recorded and forwarded in the same transaction.
        if space.authority == accountDID,
           try await isActiveSimpleSpaceWithoutGate(space),
           let sequence = try await advanceWriterHighWaterWithoutGate(
               space: space,
               repository: author,
               wireRevision: wireRevision.toString(),
               commitment: ltHash.commitment,
               updatedAt: Int64(createdAt)
           ) {
            try await enqueueWriteForwardsWithoutGate(
                space: space,
                sourceEventID: eventID.uuidString.lowercased(),
                repository: author,
                wireRevision: wireRevision.toString(),
                commitment: ltHash.commitment,
                sequence: sequence,
                timestamp: createdAt
            )
        }
        try await writeRepositoryStateWithoutGate(
            space: space, author: author, storedRevision: storedRevision,
            wireRevision: wireRevision, ltHash: ltHash, marker: marker,
            requestEntryCount: loaded.requestEntryCount
        )
        return PersistedRepositoryCommit(
            state: PersistedRepositoryState(
                space: space, author: author, revision: revision,
                wireRevision: wireRevision, ltHash: ltHash.serialized, commit: marker
            ),
            entries: [],
            outbox: PersistedOutboxEvent(
                id: eventID, space: space, author: author,
                revision: revision, payload: payload, attempts: 0
            )
        )
    }

    // MARK: importRepo

    /// Replaces `author`'s repo in `space` with verified archive `records`
    /// (whose set hash is `ltHash`) at a new rev: prior records,
    /// blob associations and operation log go, and the repo's history starts
    /// here. Records are taken as they are, including the published policy
    /// and member records. A blob already on this host is attached now; one
    /// uploaded later is attached when it arrives. Nothing is notified, as in
    /// the reference. The authority's own spaces must already exist here.
    public func importSpaceRepository(
        space: SpaceURI,
        author: String,
        records: [SpaceRecord],
        ltHash serializedLtHash: Data,
        now: Date = Date()
    ) async throws -> PersistedRepositoryState {
        try requireAccount(author)
        var ltHash = try LtHash(serialized: serializedLtHash)
        var check = LtHash()
        var totalBytes = 0
        var blobCIDs: [SpaceRecordURI: [String]] = [:]
        for record in records {
            guard record.uri.space == space, record.uri.author == author else {
                throw SwanError.malformed("record belongs to another repository")
            }
            do {
                try SpaceCARCodec.validateCanonicalRecord(record.value, expectedCID: record.cid)
                blobCIDs[record.uri] = try rawBlobCIDs(in: record.value)
            } catch {
                throw SwanError.malformed("record must be canonical DAG-CBOR with its exact CID")
            }
            totalBytes += record.value.count
            check.add(element: "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)")
        }
        guard check.serialized == ltHash.serialized else {
            throw SwanError.malformed("records do not fold to the archive digest")
        }
        guard records.count <= SpaceCARProductionLimits.maximumRecordCount,
              totalBytes <= SpaceCARRecoveryLimits.absoluteMaximumLogicalRestoredBytes else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        ltHash = check
        return try await withConnectionGate {
            try await transaction {
                if space.authority == accountDID {
                    let rows = try await connection.query(
                        """
                        SELECT 1 FROM permissioned_simple_space_authorities
                        WHERE space_uri = ? AND owner_did = ? AND is_deleted = 0
                        UNION ALL
                        SELECT 1 FROM conversation_space_authorities
                        WHERE space_uri = ? AND authority_did = ? AND state = 'active'
                        LIMIT 1
                        """,
                        [.text(space.rawValue), .text(accountDID), .text(space.rawValue), .text(accountDID)]
                    )
                    guard !rows.isEmpty else { throw AuthorizedSimpleSpaceLifecycleError.notFound }
                }
                try await requireLocalRepositorySpaceOpen(space)
                let loaded = try await loadStateWithCounts(space: space, author: author)
                let wireRevision = try TID(tidString: try SpaceRevisionSequence.next(
                    after: loaded?.state.wireRevision.toString(),
                    now: now
                ))
                let revision = (loaded?.state.revision ?? 0) + 1
                guard revision < UInt64(Int.max) else {
                    throw SQLiteRepositoryError.revisionOutOfRange(revision)
                }
                let storedRevision = try sqliteRevision(revision)
                let repositoryValues: [SQLiteData] = [.text(space.rawValue), .text(author)]
                for table in [
                    "permissioned_space_record_blobs",
                    "permissioned_space_records",
                    "permissioned_space_oplog",
                ] {
                    _ = try await connection.query(
                        "DELETE FROM \(table) WHERE space_uri = ? AND author_did = ?",
                        repositoryValues
                    )
                }
                try await markRepositoryHistoryResetWithoutGate(space: space, author: author)
                var available: [String] = []
                for record in records {
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_records(
                            space_uri, author_did, collection, rkey, value, cid, revision
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        repositoryValues + [
                            .text(record.uri.collection), .text(record.uri.rkey),
                            blob(record.value), .text(record.cid), .integer(storedRevision),
                        ]
                    )
                    let cids = blobCIDs[record.uri] ?? []
                    try await replacePermissionedRecordBlobEdges(
                        space: space, author: author,
                        collection: record.uri.collection, rkey: record.uri.rkey,
                        blobCIDs: cids, wireRevision: wireRevision
                    )
                    available += cids
                }
                let present = try await uploadedBlobCIDsWithoutGate(Set(available))
                try await promotePermissionedBlobReferences(present.sorted(), space: space)
                let marker = try repositoryStateMarker(
                    space: space, author: author, revision: revision,
                    wireRevision: wireRevision, commitment: ltHash.commitment
                )
                try await writeRepositoryStateWithoutGate(
                    space: space, author: author, storedRevision: storedRevision,
                    wireRevision: wireRevision, ltHash: ltHash, marker: marker,
                    requestEntryCount: loaded?.requestEntryCount ?? 0
                )
                return PersistedRepositoryState(
                    space: space, author: author, revision: revision,
                    wireRevision: wireRevision, ltHash: ltHash.serialized, commit: marker
                )
            }
        }
    }

    /// Attaches a just-uploaded blob to every space whose imported records
    /// reference it (October 29 section 5a: blobs are copied after
    /// `importRepo`). A blob no imported record references stays staged.
    func promoteImportedSpaceBlobReferences(cid: String) async throws {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT DISTINCT space_uri FROM permissioned_space_record_blobs
                    WHERE blob_cid = ? AND author_did = ?
                    ORDER BY space_uri
                    """,
                    [.text(cid), .text(accountDID)]
                )
                for row in rows {
                    let space = try SpaceURI(try migrationText(row, "space_uri"))
                    try await promotePermissionedBlobReferences([cid], space: space)
                }
            }
        }
    }

    private func uploadedBlobCIDsWithoutGate(_ cids: Set<String>) async throws -> Set<String> {
        var present = Set<String>()
        for cid in cids.sorted() {
            let rows = try await connection.query(
                "SELECT 1 FROM blob_payloads WHERE cid = ? AND storage_kind = 'cas-v1' LIMIT 1",
                [.text(cid)]
            )
            if !rows.isEmpty { present.insert(cid) }
        }
        return present
    }

    // MARK: Shared repository state

    private func writeRepositoryStateWithoutGate(
        space: SpaceURI,
        author: String,
        storedRevision: Int,
        wireRevision: TID,
        ltHash: LtHash,
        marker: Data,
        requestEntryCount: Int
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_state(
                space_uri, author_did, revision, wire_revision,
                lthash, current_commit, oplog_entry_count, request_entry_count
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(space_uri, author_did) DO UPDATE SET
                revision = excluded.revision,
                wire_revision = excluded.wire_revision,
                lthash = excluded.lthash,
                current_commit = excluded.current_commit,
                oplog_entry_count = 0,
                request_entry_count = excluded.request_entry_count
            """,
            [
                .text(space.rawValue), .text(author), .integer(storedRevision),
                .text(wireRevision.toString()), blob(ltHash.serialized), blob(marker),
                .integer(requestEntryCount),
            ]
        )
    }

    private func markRepositoryHistoryResetWithoutGate(space: SpaceURI, author: String) async throws {
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_history_resets(space_uri, author_did)
            VALUES (?, ?) ON CONFLICT DO NOTHING
            """,
            [.text(space.rawValue), .text(author)]
        )
    }

    /// Retention pruning deleted retained history: older cursors need a full
    /// recovery again.
    func dropRepositoryHistoryResetWithoutGate(space: SpaceURI, author: String) async throws {
        _ = try await connection.query(
            "DELETE FROM permissioned_repository_history_resets WHERE space_uri = ? AND author_did = ?",
            [.text(space.rawValue), .text(author)]
        )
    }

    private static func excludingCollections(_ count: Int) -> String {
        guard count > 0 else { return "" }
        return " AND collection NOT IN (" + Array(repeating: "?", count: count).joined(separator: ", ") + ")"
    }

    // MARK: exportSpaceMeta / importSpaceMeta

    /// The authority's state for one live space: its policy, a memberspace's
    /// member list (Swan's own owner row excluded, as in published member
    /// records), and the writer set with each entry's space revision.
    public func exportSpaceMeta(
        space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> SpaceMetaArchive {
        try requireAuthorityAccount(space: space)
        try SpaceAuthorizationPolicy.requireSpaceDescriptionRead(space: space, authorization: authorization)
        return try await withConnectionGate {
            try await transaction {
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                let simpleSpace = stored.state.space
                let policy = simpleSpace.configuration.policy
                var members: [SpaceMetaMember] = []
                if case .member = policy {
                    for member in simpleSpace.members.values.sorted(by: { $0.did < $1.did })
                        where member.did != simpleSpace.owner {
                        members.append(try SpaceMetaMember(did: member.did, read: member.read, write: member.write))
                    }
                }
                var writers: [SpaceMetaWriter] = []
                for row in try await connection.query(
                    """
                    SELECT repo_did, wire_revision, commitment, space_rev
                    FROM permissioned_space_writers
                    WHERE space_uri = ? ORDER BY repo_did
                    """,
                    [.text(space.rawValue)]
                ) {
                    guard let spaceRev = row.column("space_rev")?.string else {
                        throw SQLiteRepositoryError.corruptDatabase("writer has no space revision")
                    }
                    writers.append(try SpaceMetaWriter(
                        did: try migrationText(row, "repo_did"),
                        repoRev: try migrationText(row, "wire_revision"),
                        data: try requiredBlob(row, "commitment"),
                        spaceRev: spaceRev
                    ))
                }
                return try SpaceMetaArchive(space: space, policy: policy, members: members, writers: writers)
            }
        }
    }

    /// Creates or replaces the authority's space from an archive its
    /// previous host exported: the policy wholesale, the member list, and the
    /// writer set with its space revisions, so `listRepos` cursors stay
    /// valid. A tombstoned space is revived as `createSpace` revives one.
    /// Nothing is published: the published records arrive with the
    /// authority's repo through `importRepo`.
    public func importSpaceMeta(
        _ archive: SpaceMetaArchive,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws {
        let space = archive.space
        try requireAuthorityAccount(space: space, owner: space.authority)
        try requireAuthorityManagement(space: space, authorization: authorization, operation: .create)
        try requireAuthorityManagement(space: space, authorization: authorization, operation: .update)
        guard archive.members.filter({ $0.did != space.authority }).count + 1
            <= SimpleSpaceLimits.maximumMembersPerSpace else {
            throw SwanError.malformed("space meta archive has too many members")
        }
        let configuration = SimpleSpaceConfiguration(policy: archive.policy)
        try validateSimpleSpaceConfiguration(configuration)
        let timestamp = try simpleSpaceTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query(
                    "SELECT owner_did, is_deleted, revision FROM permissioned_simple_space_authorities WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
                if let row = existing.first {
                    guard row.column("owner_did")?.string == space.authority else {
                        throw SQLiteRepositoryError.corruptDatabase("space owner does not match its URI")
                    }
                    if (row.column("is_deleted")?.integer ?? 0) != 0 {
                        // As createSpace: a revived space starts fresh.
                        try await deleteAuthorityRepositoryWithoutGate(space: space)
                        for table in [
                            "permissioned_space_notification_fanout",
                            "permissioned_space_notification_registrations",
                        ] {
                            _ = try await connection.query(
                                "DELETE FROM \(table) WHERE space_uri = ?",
                                [.text(space.rawValue)]
                            )
                        }
                    }
                    let nextRevision = try nextSimpleSpaceRevision(try requiredRevision(row, "revision"))
                    _ = try await connection.query(
                        """
                        UPDATE permissioned_simple_space_authorities
                        SET is_deleted = 0, revision = ?,
                            read_policy = ?, read_managing_app = ?,
                            write_policy = ?, write_managing_app = ?,
                            app_access = ?, policy_type = ?,
                            publish_policy = ?, publish_members = ?,
                            updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
                        WHERE space_uri = ?
                        """,
                        [.integer(try sqliteRevision(nextRevision))]
                            + simpleSpacePolicyColumnBindings(configuration)
                            + [.integer(timestamp), .integer(timestamp), .text(space.rawValue)]
                    )
                } else {
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_simple_space_authorities(
                            space_uri, owner_did, read_policy, read_managing_app,
                            write_policy, write_managing_app, app_access,
                            policy_type, publish_policy, publish_members,
                            is_deleted, revision, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?)
                        """,
                        [.text(space.rawValue), .text(space.authority)]
                            + simpleSpacePolicyColumnBindings(configuration)
                            + [.integer(timestamp), .integer(timestamp)]
                    )
                }
                _ = try await connection.query(
                    "DELETE FROM permissioned_simple_space_members WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_simple_space_members(space_uri, member_did, can_read, can_write)
                    VALUES (?, ?, 1, 1)
                    """,
                    [.text(space.rawValue), .text(space.authority)]
                )
                for member in archive.members where member.did != space.authority {
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_simple_space_members(space_uri, member_did, can_read, can_write)
                        VALUES (?, ?, ?, ?)
                        """,
                        [
                            .text(space.rawValue), .text(member.did),
                            .integer(member.read ? 1 : 0), .integer(member.write ? 1 : 0),
                        ]
                    )
                }
                try await replaceSimpleSpaceClients(space: space, appAccess: configuration.appAccess)
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_writers WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
                let updatedAt = Int(now.timeIntervalSince1970 * 1_000_000)
                for writer in archive.writers {
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_writers(
                            space_uri, repo_did, wire_revision, commitment, updated_at, space_rev
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        [
                            .text(space.rawValue), .text(writer.did), .text(writer.repoRev),
                            blob(writer.data), .integer(updatedAt), .text(writer.spaceRev),
                        ]
                    )
                }
                // Fail closed on a state the authority reader would refuse.
                _ = try await requiredSimpleSpace(space)
            }
        }
    }

    private func migrationText(_ row: SQLiteRow, _ column: String) throws -> String {
        guard let value = row.column(column)?.string else {
            throw SQLiteRepositoryError.corruptDatabase("invalid \(column)")
        }
        return value
    }
}
