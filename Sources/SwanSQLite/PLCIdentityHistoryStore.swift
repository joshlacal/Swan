import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage

extension SQLiteAccountDatabase: PublicPLCIdentityHistoryStore {
    public func installPublicPLCOperation(
        _ entry: PublicPLCOperationHistoryEntry
    ) async throws -> PublicPLCOperationHistoryEntry {
        let timestamp = try plcIdentityHistoryTimestamp(entry.createdAt)
        return try await withConnectionGate {
            try await transaction {
                let existingRows = try await connection.query(
                    """
                    SELECT sequence, cid, previous_cid, canonical_json, created_at,
                           signing_key_generation, rotation_key_generation
                    FROM plc_identity_operations
                    WHERE cid = ?
                    """,
                    [.text(entry.cid)]
                )
                guard existingRows.count <= 1 else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "duplicate PLC identity operation"
                    )
                }
                if let existing = existingRows.first {
                    let decoded = try decodePLCIdentityHistoryRow(existing)
                    // CID and the authenticated operation body are the
                    // idempotency key. `createdAt` is local retention
                    // metadata, so a replay after a restart may carry a new
                    // wall-clock value without becoming a conflicting PLC
                    // operation. Key generations remain part of the
                    // durable binding and therefore must still match.
                    guard decoded.cid == entry.cid,
                          decoded.previousCID == entry.previousCID,
                          decoded.canonicalJSON == entry.canonicalJSON,
                          decoded.signingKeyGeneration == entry.signingKeyGeneration,
                          decoded.rotationKeyGeneration == entry.rotationKeyGeneration else {
                        throw SwanError.conflict(expected: 0, actual: 1)
                    }
                    return decoded
                }

                let latestRows = try await connection.query(
                    """
                    SELECT sequence, cid
                    FROM plc_identity_operations
                    ORDER BY sequence DESC
                    LIMIT 1
                    """
                )
                guard latestRows.count <= 1 else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "duplicate PLC identity history head"
                    )
                }
                let nextSequence: Int
                if let latest = latestRows.first {
                    guard let sequence = latest.column("sequence")?.integer,
                          sequence > 0,
                          let latestCID = latest.column("cid")?.string,
                          entry.previousCID == latestCID else {
                        throw SwanError.conflict(expected: 0, actual: 1)
                    }
                    guard sequence < Int.max else {
                        throw SwanError.unavailable("PLC identity history is exhausted")
                    }
                    nextSequence = sequence + 1
                } else {
                    guard entry.previousCID == nil else {
                        throw SwanError.conflict(expected: 0, actual: 1)
                    }
                    nextSequence = 1
                }

                _ = try await connection.query(
                    """
                    INSERT INTO plc_identity_operations(
                        sequence, cid, previous_cid, canonical_json, created_at,
                        signing_key_generation, rotation_key_generation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        .integer(nextSequence),
                        .text(entry.cid),
                        entry.previousCID.map(SQLiteData.text) ?? .null,
                        entry.canonicalJSON.sqliteData!,
                        .integer(timestamp),
                        .integer(try plcIdentityHistoryGeneration(entry.signingKeyGeneration)),
                        .integer(try plcIdentityHistoryGeneration(entry.rotationKeyGeneration)),
                    ]
                )
                return entry
            }
        }
    }

    public func publicPLCOperationHistory() async throws
        -> [PublicPLCOperationHistoryEntry]
    {
        try await withConnectionGate {
            try await publicPLCOperationHistoryWithoutGate()
        }
    }

    /// Read helper for account-database transactions that already hold the
    /// connection gate. It is internal so public repository identity reads
    /// can authenticate the history in the same SQLite snapshot.
    func publicPLCOperationHistoryWithoutGate()
        async throws -> [PublicPLCOperationHistoryEntry]
    {
        let rows = try await connection.query(
            """
            SELECT sequence, cid, previous_cid, canonical_json, created_at,
                   signing_key_generation, rotation_key_generation
            FROM plc_identity_operations
            ORDER BY sequence ASC
            """
        )
        return try rows.map(decodePLCIdentityHistoryRow)
    }

    private func decodePLCIdentityHistoryRow(
        _ row: SQLiteRow
    ) throws -> PublicPLCOperationHistoryEntry {
        guard let value = row.column("canonical_json"),
              let json = Data(sqliteData: value),
              let createdAtRaw = row.column("created_at")?.integer,
              let signingGeneration = row.column("signing_key_generation")?.integer,
              let rotationGeneration = row.column("rotation_key_generation")?.integer,
              createdAtRaw >= 0,
              signingGeneration > 0,
              rotationGeneration > 0,
              signingGeneration <= Int64.max,
              rotationGeneration <= Int64.max else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid PLC identity operation row"
            )
        }
        return try PublicPLCOperationHistoryEntry(
            cid: try requiredPLCIdentityText(row, "cid"),
            previousCID: row.column("previous_cid")?.string,
            canonicalJSON: json,
            createdAt: Date(timeIntervalSince1970: Double(createdAtRaw) / 1_000_000),
            signingKeyGeneration: UInt64(signingGeneration),
            rotationKeyGeneration: UInt64(rotationGeneration)
        )
    }
}

private func plcIdentityHistoryTimestamp(_ date: Date) throws -> Int {
    let value = date.timeIntervalSince1970 * 1_000_000
    guard value.isFinite, value >= 0, value <= Double(Int.max) else {
        throw SwanError.malformed("PLC identity operation timestamp is invalid")
    }
    return Int(value.rounded(.down))
}

private func plcIdentityHistoryGeneration(_ generation: UInt64) throws -> Int {
    guard generation > 0, generation <= UInt64(Int.max) else {
        throw SwanError.malformed("PLC identity key generation is invalid")
    }
    return Int(generation)
}

private func requiredPLCIdentityText(
    _ row: SQLiteRow,
    _ column: String
) throws -> String {
    guard let value = row.column(column)?.string, !value.isEmpty else {
        throw SQLiteRepositoryError.corruptDatabase(
            "missing PLC identity operation text"
        )
    }
    return value
}
