import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanStorage

/// One row of `oauth_lexicon_documents` — upstream's `LexiconData`
/// (`oauth-provider/src/lexicon/lexicon-data.ts:5-11`).
///
/// `document`, `sourceURI` and `verifiedCID` are nullable **together**: a row
/// where they are all `nil` is the negative-cache entry upstream writes on a
/// `LexResolverError` (`lexicon-getter.ts:19-40`), not a missing row. Reading it
/// yields `invalid_scope` / `invalid_request` per §5.7.5 **without a network
/// round trip**, which is the entire reason the column is nullable.
public struct OAuthLexiconDocumentRow: Sendable, Equatable {
    public let nsid: String
    /// The canonical DAG-CBOR record bytes that were proved, or `nil` for a
    /// negative-cache row. See the schema comment for why these are the record
    /// bytes rather than re-serialised JSON.
    public let document: Data?
    public let sourceURI: String?
    public let verifiedCID: String?
    public let createdAt: Date
    /// Always bumped, success or failure. `isStale` is measured from here.
    public let updatedAt: Date
    /// Preserved across failures (`lexicon-getter.ts:36-38`). Swan's 24 h hard
    /// expiry is measured from **here**, not from `updatedAt`.
    public let lastSucceededAt: Date?

    public init(
        nsid: String,
        document: Data?,
        sourceURI: String?,
        verifiedCID: String?,
        createdAt: Date,
        updatedAt: Date,
        lastSucceededAt: Date?
    ) {
        self.nsid = nsid
        self.document = document
        self.sourceURI = sourceURI
        self.verifiedCID = verifiedCID
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.lastSucceededAt = lastSucceededAt
    }

    /// `LEXICON_REFRESH_FREQUENCY = 5 * MINUTE`
    /// (`oauth-provider/oauth-constants.ts:84`). Stale triggers a refetch; it
    /// does not invalidate.
    public func isStale(now: Date) -> Bool {
        now.timeIntervalSince(updatedAt)
            >= SwanLexiconResolutionBudget.refreshThresholdSeconds
    }

    /// Swan's 24 h hard expiry. Upstream serves stale forever; past this, a
    /// cached document is treated as unresolved (§5.7.4).
    public func isHardExpired(now: Date) -> Bool {
        guard let lastSucceededAt else { return true }
        return now.timeIntervalSince(lastSucceededAt)
            >= SwanLexiconResolutionBudget.hardExpirySeconds
    }
}

/// The three-method interface at
/// `oauth-provider/src/lexicon/lexicon-store.ts` — `findLexicon` /
/// `storeLexicon` / `deleteLexicon`.
///
/// It is a protocol rather than a bare concrete type because the resolver lives
/// in SwanInterop and must not carry a hard dependency on one storage engine to
/// be testable; `SQLiteControlDatabase` is the production conformer.
public protocol OAuthLexiconDocumentStore: Sendable {
    func findLexicon(nsid: String) async throws -> OAuthLexiconDocumentRow?
    func storeLexicon(_ row: OAuthLexiconDocumentRow) async throws
    func deleteLexicon(nsid: String) async throws
}

/// Durable resolved-lexicon cache in `control.sqlite`.
///
/// **Two caches, not one.** This is the document-keyed cache covering §5.7.4
/// steps 7-15. Steps 1-6 (DNS authority + DID document) are cached separately
/// and keyed by **domain**, not by NSID, so four includes under one authority
/// share one DNS + DID resolution — and because upstream's own seam is two
/// hooks at two different stages (`onResolveAuthority` at `:116`, `onFetch` at
/// `:140`). That cache lives with the resolver; it caches the *DID document*,
/// never the proof result, because the proof must be re-verified against
/// whatever key the document currently names.
extension SQLiteControlDatabase: OAuthLexiconDocumentStore {
    /// A row per distinct NSID ever resolved. The population is bounded in
    /// practice by the 4-include / 8-space-type per-request caps, but nothing
    /// bounds the number of *distinct* NSIDs across requests, and a negative row
    /// is written for every NSID that fails — including ones an attacker
    /// chooses. The ceiling keeps that unbounded in requests rather than in
    /// disk.
    static let lexiconDocumentRowCapacity = 8_192
    static let lexiconDocumentNegativeRowCapacity = 4_096
    static let lexiconDocumentNegativeEvictionAgeMicroseconds: Int = 3_600 * 1_000_000
    static let lexiconDocumentNegativeEvictionBatchSize = 512

    public func findLexicon(nsid: String) async throws -> OAuthLexiconDocumentRow? {
        guard Self.validLexiconNSID(nsid) else {
            throw OAuthControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT nsid, document, source_uri, verified_cid,
                       created_at, updated_at, last_succeeded_at
                FROM oauth_lexicon_documents
                WHERE nsid = ?
                """,
                [.text(nsid)]
            )
            guard let row = rows.first else { return nil }
            return try Self.decodeLexiconRow(row)
        }
    }

    public func storeLexicon(_ row: OAuthLexiconDocumentRow) async throws {
        guard Self.validLexiconNSID(row.nsid) else {
            throw OAuthControlStoreError.invalidInput
        }
        // The all-or-nothing invariant the schema CHECKs, enforced here too so a
        // malformed row is rejected by the type's own store rather than only by
        // SQLite — the SQL error would surface as an opaque driver failure.
        guard (row.document == nil) == (row.verifiedCID == nil),
              (row.document == nil) == (row.sourceURI == nil),
              row.document == nil || row.lastSucceededAt != nil else {
            throw OAuthControlStoreError.invalidInput
        }
        if let document = row.document {
            // Bounded by the same 256 KiB the CAR fetch is bounded by: a proved
            // record cannot be larger than the CAR that carried it.
            guard !document.isEmpty,
                  document.count <= SwanLexiconResolutionBudget.maximumCARBytes else {
                throw OAuthControlStoreError.invalidInput
            }
        }
        let createdAt = try Self.lexiconTimestamp(row.createdAt)
        let updatedAt = try Self.lexiconTimestamp(row.updatedAt)
        let lastSucceededAt = try row.lastSucceededAt.map(Self.lexiconTimestamp)
        try await withConnectionGate {
            try await transaction {
                let negativeEvictionThreshold = max(0, updatedAt - Self.lexiconDocumentNegativeEvictionAgeMicroseconds)
                _ = try await connection.query(
                    """
                    DELETE FROM oauth_lexicon_documents
                    WHERE nsid IN (
                        SELECT nsid FROM oauth_lexicon_documents
                        WHERE document IS NULL AND updated_at < ?
                        ORDER BY updated_at ASC
                        LIMIT ?
                    )
                    """,
                    [.integer(negativeEvictionThreshold), .integer(Self.lexiconDocumentNegativeEvictionBatchSize)]
                )
                if row.document == nil {
                    let existingNegative = try await connection.query(
                        "SELECT 1 FROM oauth_lexicon_documents WHERE nsid = ? AND document IS NULL LIMIT 1",
                        [.text(row.nsid)]
                    )
                    if existingNegative.isEmpty {
                        let countRows = try await connection.query(
                            "SELECT COUNT(*) AS count FROM oauth_lexicon_documents WHERE document IS NULL"
                        )
                        guard let countRow = countRows.first,
                              case let .integer(negCount) = countRow.column("count"),
                              negCount >= 0 else {
                            throw OAuthControlStoreError.malformedRecord
                        }
                        guard negCount < Self.lexiconDocumentNegativeRowCapacity else {
                            throw SwanError.unavailable(
                                "OAuth lexicon negative cache capacity is exhausted"
                            )
                        }
                    }
                }
                try await requireInsertionCapacity(
                    table: "oauth_lexicon_documents",
                    keyColumn: "nsid",
                    key: .text(row.nsid),
                    maximumRows: Self.lexiconDocumentRowCapacity
                )
                _ = try await connection.query(
                    """
                    INSERT INTO oauth_lexicon_documents(
                        nsid, document, source_uri, verified_cid,
                        created_at, updated_at, last_succeeded_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(nsid) DO UPDATE SET
                        document = excluded.document,
                        source_uri = excluded.source_uri,
                        verified_cid = excluded.verified_cid,
                        -- `created_at` is deliberately NOT updated:
                        -- `lexicon-getter.ts:32` keeps the original.
                        updated_at = excluded.updated_at,
                        last_succeeded_at = excluded.last_succeeded_at
                    """,
                    [
                        .text(row.nsid),
                        row.document.map { $0.sqliteData! } ?? .null,
                        row.sourceURI.map(SQLiteData.text) ?? .null,
                        row.verifiedCID.map(SQLiteData.text) ?? .null,
                        .integer(createdAt),
                        .integer(updatedAt),
                        lastSucceededAt.map(SQLiteData.integer) ?? .null,
                    ]
                )
            }
        }
    }

    public func deleteLexicon(nsid: String) async throws {
        guard Self.validLexiconNSID(nsid) else {
            throw OAuthControlStoreError.invalidInput
        }
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "DELETE FROM oauth_lexicon_documents WHERE nsid = ?",
                    [.text(nsid)]
                )
            }
        }
    }

    // MARK: - Row coding

    private static func decodeLexiconRow(
        _ row: SQLiteRow
    ) throws -> OAuthLexiconDocumentRow {
        guard case let .text(nsid) = row.column("nsid"),
              case let .integer(createdAt) = row.column("created_at"),
              case let .integer(updatedAt) = row.column("updated_at"),
              createdAt >= 0, updatedAt >= 0 else {
            throw OAuthControlStoreError.malformedRecord
        }
        let document: Data?
        switch row.column("document") {
        case let .blob(buffer):
            document = Data(buffer: buffer)
        case .null, .none:
            document = nil
        default:
            throw OAuthControlStoreError.malformedRecord
        }
        let sourceURI = try optionalLexiconText(row.column("source_uri"))
        let verifiedCID = try optionalLexiconText(row.column("verified_cid"))
        let lastSucceededAt: Int?
        switch row.column("last_succeeded_at") {
        case let .integer(value):
            guard value >= 0 else { throw OAuthControlStoreError.malformedRecord }
            lastSucceededAt = value
        case .null, .none:
            lastSucceededAt = nil
        default:
            throw OAuthControlStoreError.malformedRecord
        }
        // The schema CHECKs this, but a database restored from an older or
        // hand-edited file has not necessarily been through those CHECKs, and a
        // half-populated positive row would read back as a document with no CID
        // vouching for it.
        guard (document == nil) == (verifiedCID == nil),
              (document == nil) == (sourceURI == nil),
              document == nil || lastSucceededAt != nil else {
            throw OAuthControlStoreError.malformedRecord
        }
        return OAuthLexiconDocumentRow(
            nsid: nsid,
            document: document,
            sourceURI: sourceURI,
            verifiedCID: verifiedCID,
            createdAt: lexiconDate(createdAt),
            updatedAt: lexiconDate(updatedAt),
            lastSucceededAt: lastSucceededAt.map(lexiconDate)
        )
    }

    private static func optionalLexiconText(_ value: SQLiteData?) throws -> String? {
        switch value {
        case let .text(text):
            guard validLexiconText(text) else {
                throw OAuthControlStoreError.malformedRecord
            }
            return text
        case .null, .none:
            return nil
        default:
            throw OAuthControlStoreError.malformedRecord
        }
    }

    /// Whole microseconds since the epoch, matching every other timestamp in
    /// `control.sqlite`.
    private static func lexiconTimestamp(_ date: Date) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else {
            throw OAuthControlStoreError.invalidInput
        }
        let value = seconds * 1_000_000
        guard value.isFinite, value <= Double(Int.max) else {
            throw OAuthControlStoreError.invalidInput
        }
        return Int(value.rounded(.down))
    }

    private static func lexiconDate(_ microseconds: Int) -> Date {
        Date(timeIntervalSince1970: Double(microseconds) / 1_000_000)
    }

    private static func validLexiconText(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 && !value.utf8.contains(0)
    }

    /// The NSID is a primary key reachable with unvalidated input, so it is
    /// bounded here as well as by the resolver's own syntax check. 317 is
    /// `PublicRepositoryPath.maximumCollectionCharacters`, the same NSID ceiling
    /// the repository layer applies.
    private static func validLexiconNSID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 317 && !value.utf8.contains(0)
    }
}
