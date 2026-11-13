import Foundation
import Petrel
import PetrelRepo
import SQLiteNIO
import SwanCore
import SwanSpaces

/// October 29 policy persistence helpers: the column bindings of a
/// ``SpacePolicy``, publication of `com.atproto.space.policy` and
/// `com.atproto.memberspace.member` records, and writer-set removal.
extension SQLiteAccountDatabase {
    /// `read_policy, read_managing_app, write_policy, write_managing_app,
    /// app_access, policy_type, publish_policy, publish_members`, in order.
    func simpleSpacePolicyColumnBindings(
        _ configuration: SimpleSpaceConfiguration
    ) -> [SQLiteData] {
        let policyType: String = switch configuration.policy {
        case .personal: "personalspace"
        case .member: "memberspace"
        case .managed: "managedspace"
        }
        let publishMembers = configuration.policy.publishesMembers
        return [
            .text(configuration.readPolicy.rawValue),
            configuration.readManagingApp.map(SQLiteData.text) ?? .null,
            .text(configuration.writePolicy.rawValue),
            configuration.writeManagingApp.map(SQLiteData.text) ?? .null,
            .text(simpleSpaceAppAccessName(configuration.appAccess)),
            .text(policyType),
            .integer(configuration.policy.publishesPolicy ? 1 : 0),
            .integer(publishMembers ? 1 : 0),
        ]
    }

    /// Brings the records the authority publishes in its own repository in
    /// `space` in line with the stored configuration: the policy record when
    /// `publishPolicy` is set, one member record per member (Swan's owner row
    /// excluded) when `publishMembers` is set, and nothing otherwise. Records
    /// that are already correct are left alone, so an unchanged configuration
    /// writes nothing. The caller holds the connection gate and the write
    /// transaction; the publication commits with the configuration change and
    /// is notified like any other authority write.
    func reconcilePublishedSpaceRecordsWithoutGate(
        space: SpaceURI,
        now: Date = Date()
    ) async throws {
        guard space.authority == accountDID,
              let stored = try await loadSimpleSpace(space),
              !stored.state.space.isDeleted else {
            return
        }
        let simpleSpace = stored.state.space
        let policy = simpleSpace.configuration.policy
        var desired: [String: Data] = [:]
        if policy.publishesPolicy {
            desired["\(SpacePolicy.policyRecordCollection)/\(SpacePolicy.policyRecordKey)"] =
                try policy.policyRecordValue()
        }
        if policy.publishesMembers {
            for member in simpleSpace.members.values where member.did != simpleSpace.owner {
                let key = "\(SpacePolicy.memberRecordCollection)/\(SpacePolicy.memberRecordKey(for: member.did))"
                desired[key] = try SpacePolicy.memberRecordValue(
                    read: member.read,
                    write: member.write
                )
            }
        }
        let existingRows = try await connection.query(
            """
            SELECT collection, rkey, cid
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ? AND collection IN (?, ?)
            """,
            [
                .text(space.rawValue), .text(accountDID),
                .text(SpacePolicy.policyRecordCollection),
                .text(SpacePolicy.memberRecordCollection),
            ]
        )
        var existing: [String: String] = [:]
        for row in existingRows {
            guard let collection = row.column("collection")?.string,
                  let rkey = row.column("rkey")?.string,
                  let cid = row.column("cid")?.string else {
                throw SQLiteRepositoryError.corruptDatabase("invalid published record row")
            }
            existing["\(collection)/\(rkey)"] = cid
        }
        var writes: [SQLiteSpaceWrite] = []
        for (path, value) in desired.sorted(by: { $0.key < $1.key }) {
            let cid = CID.fromDAGCBOR(value).string
            guard existing[path] != cid else { continue }
            writes.append(.put(uri: try publishedRecordURI(space: space, path: path), value: value, cid: cid))
        }
        for path in existing.keys.sorted() where desired[path] == nil {
            writes.append(.delete(uri: try publishedRecordURI(space: space, path: path)))
        }
        guard !writes.isEmpty else { return }
        var offset = 0
        while offset < writes.count {
            let chunk = Array(writes[offset ..< min(writes.count, offset + SpaceWriteLimits.maximumOperations)])
            offset += chunk.count
            let current = try await loadStateWithCounts(space: space, author: accountDID)
            let wireRevision = try TID(tidString: try SpaceRevisionSequence.next(
                after: current?.state.wireRevision.toString(),
                now: now
            ))
            _ = try await applyWithoutGate(
                space: space,
                author: accountDID,
                expectedRevision: current?.state.revision ?? 0,
                requestID: UUID(),
                wireRevision: wireRevision,
                writes: chunk,
                eventID: UUID(),
                permissionedBlobCIDs: []
            )
        }
    }

    private func publishedRecordURI(space: SpaceURI, path: String) throws -> SpaceRecordURI {
        let parts = path.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2 else {
            throw SQLiteRepositoryError.corruptDatabase("invalid published record path")
        }
        return try SpaceRecordURI(
            space: space,
            author: accountDID,
            collection: parts[0],
            rkey: parts[1]
        )
    }

    /// Tombstones one account in a space's writer set. Caller holds the gate
    /// and transaction. Absent/already-removed rows are idempotent; an active
    /// row consumes the next space revision exactly like an accepted write.
    @discardableResult
    func removeSpaceWriterWithoutGate(
        space: SpaceURI,
        writer: String,
        now: Date = Date()
    ) async throws -> SpaceWriterSequence? {
        let rows = try await connection.query(
            """
            SELECT removed_at
            FROM permissioned_space_writers
            WHERE space_uri = ? AND repo_did = ?
            """,
            [.text(space.rawValue), .text(writer)]
        )
        guard let row = rows.first,
              row.column("removed_at")?.isNull == true else {
            return nil
        }
        let previousSpaceRevision = try await latestSpaceRevisionWithoutGate(space: space)
        let spaceRevision = try SpaceRevisionSequence.next(
            after: previousSpaceRevision,
            now: now
        )
        _ = try await connection.query(
            """
            UPDATE permissioned_space_writers
            SET removed_at = ?, space_rev = ?
            WHERE space_uri = ? AND repo_did = ? AND removed_at IS NULL
            """,
            [
                .integer(Int(now.timeIntervalSince1970 * 1_000_000)),
                .text(spaceRevision),
                .text(space.rawValue),
                .text(writer),
            ]
        )
        return SpaceWriterSequence(
            spaceRevision: spaceRevision,
            previousSpaceRevision: previousSpaceRevision
        )
    }

    /// `com.atproto.space.removeWriter`: the authority (with `manage=update`)
    /// drops `writer` from the space's writer set. Idempotent; the account is
    /// tracked again after its next authorized write is notified.
    public func removeSpaceWriter(
        space: SpaceURI,
        writer: String,
        authorization: AuthorizationContext
    ) async throws {
        guard isValidSimpleSpaceDID(writer) else {
            throw SwanError.invalidIdentifier(writer)
        }
        try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                try await removeSpaceWriterWithoutGate(space: space, writer: writer)
            }
        }
    }
}
