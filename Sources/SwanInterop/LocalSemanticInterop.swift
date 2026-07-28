import Crypto
import Foundation
import Petrel
import SwanCore
import SwanSQLite
import SwanStorage
import SwanSpaces

/// A sanitized result from the local semantic interoperability laboratory.
///
/// This runner deliberately uses two independent SQLite account roots and the
/// same durable repository facade on each side.  It is useful on a machine
/// without Docker because it exercises the transaction, replay, retention,
/// CAR, authorization, and namespace boundaries without pretending that a
/// TypeScript PDS participated in the run.
public struct LocalSemanticInteropCheck: Codable, Sendable, Equatable {
    public let name: String
    public let passed: Bool

    public init(name: String, passed: Bool) {
        self.name = name
        self.passed = passed
    }
}

public struct LocalSemanticInteropArtifact: Codable, Sendable, Equatable {
    public let scenario: String
    public let implementation: String
    public let profileID: String
    public let status: String
    public let checks: [LocalSemanticInteropCheck]
    public let operationCount: Int
    public let recordCount: Int
    public let sourceCommitment: String?
    public let consumerCommitment: String?
    public let fullRecoveryCommitment: String?
    public let carDigest: String?
    public let fixturePolicy: String
    public let errorCode: String?

    public init(
        scenario: String,
        implementation: String = "swan-durable-to-swan-durable",
        profileID: String = OfflineProtocolProfileVerifier.stableProfileID,
        status: String,
        checks: [LocalSemanticInteropCheck],
        operationCount: Int,
        recordCount: Int,
        sourceCommitment: String?,
        consumerCommitment: String?,
        fullRecoveryCommitment: String?,
        carDigest: String?,
        errorCode: String?
    ) {
        self.scenario = scenario
        self.implementation = implementation
        self.profileID = profileID
        self.status = status
        self.checks = checks
        self.operationCount = operationCount
        self.recordCount = recordCount
        self.sourceCommitment = sourceCommitment
        self.consumerCommitment = consumerCommitment
        self.fullRecoveryCommitment = fullRecoveryCommitment
        self.carDigest = carDigest
        self.fixturePolicy = "semantic-summary-only; counts, commitments, and digests; no credentials, tokens, keys, or record values"
        self.errorCode = errorCode
    }
}

/// Executes a deterministic, offline semantic run against two independent
/// durable Swan repository hosts.
public enum LocalSemanticInteropRunner {
    private struct Failure: Error {}

    private struct Batch {
        let revision: UInt64
        let wireRevision: TID
        let writes: [SpaceWrite]
        let requestID: UUID
    }

    private static let author = "did:plc:alice"
    private static let reader = "did:plc:reader"

    public static func execute(
        scenario: String = "swan-swan-semantic"
    ) async -> LocalSemanticInteropArtifact {
        var checks: [LocalSemanticInteropCheck] = []
        var operationCount = 0
        var recordCount = 0
        var sourceCommitment: String?
        var consumerCommitment: String?
        var fullRecoveryCommitment: String?
        var carDigest: String?
        var databases: [SQLiteAccountDatabase] = []
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-semantic-\(UUID().uuidString)", directoryHint: .isDirectory)

        func check(_ name: String, _ condition: Bool) throws {
            let passed = condition
            checks.append(LocalSemanticInteropCheck(name: name, passed: passed))
            guard passed else { throw Failure() }
        }

        do {
            let space = try SpaceURI(
                authority: author,
                spaceType: "app.bsky.bookmarks",
                skey: "self"
            )
            let first = try SpaceRecordURI(
                space: space,
                author: author,
                collection: "app.bsky.feed.post",
                rkey: "first"
            )
            let second = try SpaceRecordURI(
                space: space,
                author: author,
                collection: "app.bsky.feed.post",
                rkey: "second"
            )
            let stale = try SpaceRecordURI(
                space: space,
                author: author,
                collection: "app.bsky.feed.post",
                rkey: "stale"
            )
            let firstValue = canonicalRecord(text: "first")
            let secondValue = canonicalRecord(text: "second")
            let updatedFirstValue = canonicalRecord(text: "updated")
            let authorized = AuthorizationContext.accountOAuth(
                subject: author,
                scopes: ["atproto"]
            )

            let sourceRoot = root.appending(path: "source", directoryHint: .isDirectory)
            let consumerRoot = root.appending(path: "consumer", directoryHint: .isDirectory)
            let source = try await SQLiteAccountDatabase(
                dataDirectory: sourceRoot,
                did: author,
                oplogRetention: 10
            )
            let consumer = try await SQLiteAccountDatabase(
                dataDirectory: consumerRoot,
                did: author,
                oplogRetention: 10
            )
            databases += [source, consumer]
            let sourceRepository = try DurableSpaceRepository(
                database: source,
                space: space,
                author: author
            )
            let consumerRepository = try DurableSpaceRepository(
                database: consumer,
                space: space,
                author: author
            )

            let firstRequestID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
            let secondRequestID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
            let firstEntries = try await sourceRepository.applyAtomically(
                [
                    .put(uri: first, value: firstValue),
                    .put(uri: second, value: secondValue),
                ],
                expectedRevision: 0,
                requestID: firstRequestID,
                wireRevision: try tid(0),
                authorization: authorized
            )
            let secondEntries = try await sourceRepository.applyAtomically(
                [
                    .put(uri: first, value: updatedFirstValue),
                    .delete(uri: second),
                ],
                expectedRevision: 1,
                requestID: secondRequestID,
                wireRevision: try tid(1),
                authorization: authorized
            )
            let sourceEntries = firstEntries + secondEntries
            operationCount = sourceEntries.count
            let sourceState = try await sourceRepository.currentState(authorization: authorized)
            sourceCommitment = Hex.encode(sourceState.commitment)
            try check("source_commitment_is_nonempty", !sourceState.commitment.isEmpty)

            guard case let .incremental(incrementalEntries) = try await sourceRepository.sync(
                since: 0,
                authorization: authorized
            ) else {
                throw Failure()
            }
            try check("incremental_sync_retains_ordered_operations", incrementalEntries == sourceEntries)

            let batches = makeBatches(from: sourceEntries)
            var consumerRevision: UInt64 = 0
            for batch in batches {
                _ = try await consumerRepository.applyAtomically(
                    batch.writes,
                    expectedRevision: consumerRevision,
                    requestID: batch.requestID,
                    wireRevision: batch.wireRevision,
                    authorization: authorized
                )
                consumerRevision += 1
            }
            let consumerState = try await consumerRepository.currentState(authorization: authorized)
            consumerCommitment = Hex.encode(consumerState.commitment)
            try check("ordered_replica_converges_on_commitment", consumerState.commitment == sourceState.commitment)
            let consumerRecords = try await consumerRepository.snapshot(authorization: authorized)
            let sourceRecords = try await sourceStateRecords(
                repository: sourceRepository,
                authorization: authorized
            )
            try check("ordered_replica_converges_on_records", consumerRecords == sourceRecords)

            // The first delivery was already committed. A duplicated delivery
            // with the same replay identity is rejected before it can touch
            // the durable state.
            let duplicateWrite = try sqliteWrite(from: firstEntries[0])
            var duplicateRejected = false
            do {
                _ = try await consumer.apply(
                    space: space,
                    author: author,
                    expectedRevision: 0,
                    requestID: firstRequestID,
                    wireRevision: try tid(0),
                    writes: [duplicateWrite]
                )
            } catch let error as SQLiteRepositoryError {
                duplicateRejected = error == .duplicateRequest(firstRequestID)
            }
            try check("duplicate_delivery_is_rejected_by_replay_identity", duplicateRejected)
            let stateAfterDuplicate = try await consumerRepository.currentState(authorization: authorized)
            try check("duplicate_delivery_does_not_change_commitment", stateAfterDuplicate.commitment == consumerState.commitment)

            // A receiver may get notifications out of order. The durable
            // cursor is the ordering authority; an unordered input is not
            // applied, then the same input sorted by cursor converges.
            let reordered = sourceEntries.reversed()
            let reorderRoot = root.appending(path: "reordered", directoryHint: .isDirectory)
            let reorderDatabase = try await SQLiteAccountDatabase(
                dataDirectory: reorderRoot,
                did: author,
                oplogRetention: 10
            )
            databases.append(reorderDatabase)
            let reorderRepository = try DurableSpaceRepository(
                database: reorderDatabase,
                space: space,
                author: author
            )
            var reorderedRejected = false
            do {
                _ = try await applyBatches(
                    makeBatches(from: Array(reordered)),
                    to: reorderRepository,
                    authorization: authorized
                )
            } catch {
                reorderedRejected = true
            }
            try check("reordered_delivery_is_not_applied_as_a_new_order", reorderedRejected)
            let orderedRoot = root.appending(path: "ordered", directoryHint: .isDirectory)
            let orderedDatabase = try await SQLiteAccountDatabase(
                dataDirectory: orderedRoot,
                did: author,
                oplogRetention: 10
            )
            databases.append(orderedDatabase)
            let orderedRepository = try DurableSpaceRepository(
                database: orderedDatabase,
                space: space,
                author: author
            )
            _ = try await applyBatches(
                makeBatches(from: sourceEntries.sorted { $0.cursor < $1.cursor }),
                to: orderedRepository,
                authorization: authorized
            )
            let orderedState = try await orderedRepository.currentState(authorization: authorized)
            try check("reordered_delivery_converges_after_cursor_ordering", orderedState.commitment == sourceState.commitment)

            // Force a retention gap and authenticate the complete two-root
            // recovery CAR before replacing the stale consumer state.
            let recoveryRoot = root.appending(path: "recovery-source", directoryHint: .isDirectory)
            let recoveryDatabase = try await SQLiteAccountDatabase(
                dataDirectory: recoveryRoot,
                did: author,
                oplogRetention: 1
            )
            databases.append(recoveryDatabase)
            let recoverySource = try DurableSpaceRepository(
                database: recoveryDatabase,
                space: space,
                author: author
            )
            _ = try await recoverySource.applyAtomically(
                [
                    .put(uri: first, value: firstValue),
                    .put(uri: second, value: secondValue),
                ],
                expectedRevision: 0,
                requestID: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
                wireRevision: try tid(0),
                authorization: authorized
            )
            _ = try await recoverySource.applyAtomically(
                [
                    .put(uri: first, value: updatedFirstValue),
                    .delete(uri: second),
                ],
                expectedRevision: 1,
                requestID: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
                wireRevision: try tid(1),
                authorization: authorized
            )
            guard case let .fullSnapshot(_, recoveryRecords, recoveryCommitment) = try await recoverySource.sync(
                since: 0,
                authorization: authorized
            ) else {
                throw Failure()
            }
            let recoveryState = try await recoverySource.currentState(authorization: authorized)
            fullRecoveryCommitment = Hex.encode(recoveryCommitment)
            try check("retention_gap_selects_full_snapshot", recoveryRecords.count == 1 && recoveryCommitment == recoveryState.commitment)

            let signingKey = P256.Signing.PrivateKey()
            let car = try await recoverySource.exportCAR(
                rev: recoveryState.wireRevision?.toString() ?? "2222222222222",
                signingKey: signingKey,
                authorization: authorized
            )
            carDigest = Hex.encode(SHA256.hash(data: car.data))
            let verifiedRecovery = try SpaceCARCodec.verifyRecovery(
                car.data,
                space: space,
                author: author,
                publicKey: signingKey.publicKey
            )
            try check("full_recovery_car_authenticates_two_roots", verifiedRecovery.commitment == recoveryCommitment)
            try check(
                "full_recovery_car_preserves_records",
                sameRecordFacts(verifiedRecovery.records, recoveryRecords)
            )

            let staleDatabase = try await SQLiteAccountDatabase(
                dataDirectory: root.appending(path: "stale", directoryHint: .isDirectory),
                did: author,
                oplogRetention: 10
            )
            databases.append(staleDatabase)
            let staleRepository = try DurableSpaceRepository(
                database: staleDatabase,
                space: space,
                author: author
            )
            _ = try await staleRepository.apply(
                .put(uri: stale, value: canonicalRecord(text: "stale")),
                expectedRevision: 0,
                requestID: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
                wireRevision: try tid(0),
                authorization: authorized
            )
            let staleSnapshot = try await staleRepository.snapshot(authorization: authorized)
            let replacementWrites = fullRecoveryWrites(
                current: staleSnapshot,
                target: verifiedRecovery.records
            )
            _ = try await staleRepository.applyAtomically(
                replacementWrites,
                expectedRevision: 1,
                requestID: UUID(uuidString: "66666666-6666-6666-6666-666666666666")!,
                wireRevision: try tid(1),
                authorization: authorized
            )
            let replacedState = try await staleRepository.currentState(authorization: authorized)
            try check("full_recovery_replaces_stale_records", replacedState.commitment == verifiedRecovery.commitment)

            var corruptedCAR = car.data
            corruptedCAR[corruptedCAR.index(before: corruptedCAR.endIndex)] ^= 1
            var corruptedRejected = false
            do {
                _ = try SpaceCARCodec.verifyRecovery(
                    corruptedCAR,
                    space: space,
                    author: author,
                    publicKey: signingKey.publicKey
                )
            } catch {
                corruptedRejected = true
            }
            try check("corrupted_car_is_rejected", corruptedRejected)
            let stateAfterCorruptCAR = try await staleRepository.currentState(authorization: authorized)
            try check("corrupted_car_does_not_change_last_valid_state", stateAfterCorruptCAR.commitment == verifiedRecovery.commitment)

            let grant = SpaceGrant(
                subject: reader,
                space: space,
                permissions: [.read],
                expiresAt: .distantFuture
            )
            _ = try await consumerRepository.record(first, authorization: .spaceCredential(grant))
            try check("space_credential_can_read_bound_repository", true)
            var publicReadDenied = false
            do {
                _ = try await consumerRepository.record(first, authorization: .public)
            } catch {
                publicReadDenied = true
            }
            try check("public_context_cannot_read_permissioned_repository", publicReadDenied)

            let blobStore = try FileBlobStore(
                root: root.appending(path: "blobs", directoryHint: .isDirectory)
            )
            let privateBlob = try await blobStore.put(
                Data("private".utf8),
                namespace: .space(space)
            )
            let publicBlob = try await blobStore.put(
                Data("public".utf8),
                namespace: .public
            )
            let privatePublicData = try await blobStore.publicData(cid: privateBlob.cid)
            let publicPublicData = try await blobStore.publicData(cid: publicBlob.cid)
            try check("private_blob_is_not_publicly_reachable", privatePublicData == nil)
            try check("public_blob_remains_publicly_reachable", publicPublicData == Data("public".utf8))
            recordCount = verifiedRecovery.records.count

            for database in databases { try await database.close() }
            try? FileManager.default.removeItem(at: root)
            return LocalSemanticInteropArtifact(
                scenario: scenario,
                status: "passed",
                checks: checks,
                operationCount: operationCount,
                recordCount: recordCount,
                sourceCommitment: sourceCommitment,
                consumerCommitment: consumerCommitment,
                fullRecoveryCommitment: fullRecoveryCommitment,
                carDigest: carDigest,
                errorCode: nil
            )
        } catch {
            for database in databases { try? await database.close() }
            try? FileManager.default.removeItem(at: root)
            return LocalSemanticInteropArtifact(
                scenario: scenario,
                status: "failed",
                checks: checks,
                operationCount: operationCount,
                recordCount: recordCount,
                sourceCommitment: sourceCommitment,
                consumerCommitment: consumerCommitment,
                fullRecoveryCommitment: fullRecoveryCommitment,
                carDigest: carDigest,
                errorCode: "semantic_check_failed"
            )
        }
    }

    private static func tid(_ index: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        guard alphabet.indices.contains(index) else { throw Failure() }
        return try TID(tidString: "222222222222\(alphabet[index])")
    }

    private static func canonicalRecord(text: String) -> Data {
        // DAG-CBOR for {"text": <string>}; the fixed fixture values keep this
        // local semantic run deterministic without a JSON conversion path.
        let bytes = Array(text.utf8)
        var output = Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74])
        output.append(UInt8(0x60 + bytes.count))
        output.append(contentsOf: bytes)
        return output
    }

    private static func makeBatches(from entries: [DurableSpaceOplogEntry]) -> [Batch] {
        let ordered = entries
        var batches: [Batch] = []
        for entry in ordered {
            if let index = batches.indices.last, batches[index].revision == entry.revision {
                let current = batches[index]
                batches[index] = Batch(
                    revision: current.revision,
                    wireRevision: current.wireRevision,
                    writes: current.writes + [entry.write],
                    requestID: current.requestID
                )
            } else {
                batches.append(
                    Batch(
                        revision: entry.revision,
                        wireRevision: entry.wireRevision,
                        writes: [entry.write],
                        requestID: requestID(for: entry.revision)
                    )
                )
            }
        }
        return batches
    }

    private static func requestID(for revision: UInt64) -> UUID {
        switch revision {
        case 1: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        default: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        }
    }

    private static func applyBatches(
        _ batches: [Batch],
        to repository: DurableSpaceRepository,
        authorization: AuthorizationContext
    ) async throws -> [DurableSpaceOplogEntry] {
        var revision: UInt64 = 0
        var entries: [DurableSpaceOplogEntry] = []
        for batch in batches {
            entries += try await repository.applyAtomically(
                batch.writes,
                expectedRevision: revision,
                requestID: batch.requestID,
                wireRevision: batch.wireRevision,
                authorization: authorization
            )
            revision += 1
        }
        return entries
    }

    private static func sourceStateRecords(
        repository: DurableSpaceRepository,
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord] {
        try await repository.snapshot(authorization: authorization)
    }

    private static func sqliteWrite(from entry: DurableSpaceOplogEntry) throws -> SQLiteSpaceWrite {
        switch entry.action {
        case .create:
            guard case let .put(uri, value) = entry.write, let cid = entry.cid else { throw Failure() }
            return .create(uri: uri, value: value, cid: cid)
        case .update:
            guard case let .put(uri, value) = entry.write, let cid = entry.cid else { throw Failure() }
            return .update(uri: uri, value: value, cid: cid)
        case .delete:
            guard case let .delete(uri) = entry.write else { throw Failure() }
            return .delete(uri: uri)
        }
    }

    private static func fullRecoveryWrites(
        current: [SpaceRecord],
        target: [SpaceRecord]
    ) -> [SpaceWrite] {
        let currentByURI = Dictionary(uniqueKeysWithValues: current.map { ($0.uri, $0) })
        let targetByURI = Dictionary(uniqueKeysWithValues: target.map { ($0.uri, $0) })
        var writes: [SpaceWrite] = []
        for record in current.sorted(by: { $0.uri.rawValue < $1.uri.rawValue }) where targetByURI[record.uri] == nil {
            writes.append(.delete(uri: record.uri))
        }
        for record in target.sorted(by: { $0.uri.rawValue < $1.uri.rawValue }) {
            guard let old = currentByURI[record.uri], old.cid == record.cid, old.value == record.value else {
                writes.append(.put(uri: record.uri, value: record.value))
                continue
            }
        }
        return writes
    }

    private static func sameRecordFacts(
        _ lhs: [SpaceRecord],
        _ rhs: [SpaceRecord]
    ) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(
            lhs.sorted { $0.uri.rawValue < $1.uri.rawValue },
            rhs.sorted { $0.uri.rawValue < $1.uri.rawValue }
        ).allSatisfy { left, right in
            left.uri == right.uri && left.value == right.value && left.cid == right.cid
        }
    }
}
