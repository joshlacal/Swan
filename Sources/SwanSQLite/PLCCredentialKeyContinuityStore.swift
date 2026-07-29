import SQLiteNIO
import SwanStorage

extension SQLiteControlDatabase: PLCCredentialKeyContinuityStore {
    /// Installs or advances one authenticated PLC terminal inside a single
    /// `BEGIN IMMEDIATE` transaction. The audit was fetched and verified by
    /// the resolver before this call; this transaction performs bounded local
    /// comparisons only.
    public func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint {
        try await withConnectionGate {
            try await transaction {
                let existing = try await plcCredentialKeyContinuityCheckpointLocked(
                    for: advance.checkpoint.issuer
                )
                if let existing {
                    if existing.terminalCID == advance.checkpoint.terminalCID {
                        return existing
                    }
                    guard advance.auditCIDs.contains(existing.terminalCID) else {
                        throw PLCCredentialKeyContinuityStoreError.continuityViolation
                    }
                }

                _ = try await connection.query(
                    """
                    INSERT INTO plc_credential_key_continuity(issuer, terminal_cid)
                    VALUES (?, ?)
                    ON CONFLICT(issuer) DO UPDATE SET
                        terminal_cid = excluded.terminal_cid
                    """,
                    [
                        .text(advance.checkpoint.issuer),
                        .text(advance.checkpoint.terminalCID),
                    ]
                )
                guard try await plcCredentialKeyContinuityCheckpointLocked(
                    for: advance.checkpoint.issuer
                ) == advance.checkpoint else {
                    throw PLCCredentialKeyContinuityStoreError.malformedRecord
                }
                return advance.checkpoint
            }
        }
    }

    public func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        guard issuer.hasPrefix("did:plc:"),
              AccountControlIdentifiers.isDID(issuer) else {
            throw PLCCredentialKeyContinuityStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await plcCredentialKeyContinuityCheckpointLocked(for: issuer)
        }
    }

    /// Bounded canonical inventory used only by authenticated operator backup.
    /// The `LIMIT + 1` prevents a corrupted database from forcing an unbounded
    /// materialization before the domain limit is enforced.
    public func plcCredentialKeyContinuityInventory()
        async throws -> PLCCredentialKeyContinuityInventory
    {
        try await withConnectionGate {
            try await plcCredentialKeyContinuityInventoryLocked()
        }
    }

    func plcCredentialKeyContinuityInventoryLocked()
        async throws -> PLCCredentialKeyContinuityInventory
    {
        let rows = try await connection.query(
            """
            SELECT issuer, terminal_cid
            FROM plc_credential_key_continuity
            ORDER BY issuer
            LIMIT ?
            """,
            [
                .integer(
                    PLCCredentialKeyContinuityInventory.maximumCheckpointCount
                        + 1
                ),
            ]
        )
        guard
            rows.count <=
                PLCCredentialKeyContinuityInventory.maximumCheckpointCount
        else {
            throw PLCCredentialKeyContinuityStoreError.malformedRecord
        }
        do {
            let checkpoints = try rows.map { row in
                guard case let .text(issuer) = row.column("issuer"),
                      case let .text(terminalCID) =
                          row.column("terminal_cid") else {
                    throw PLCCredentialKeyContinuityStoreError.malformedRecord
                }
                return try PLCCredentialKeyContinuityCheckpoint(
                    issuer: issuer,
                    terminalCID: terminalCID
                )
            }
            let inventory = try PLCCredentialKeyContinuityInventory(
                checkpoints: checkpoints
            )
            guard inventory.checkpoints == checkpoints else {
                throw PLCCredentialKeyContinuityStoreError.malformedRecord
            }
            return inventory
        } catch let error as PLCCredentialKeyContinuityStoreError {
            guard error == .malformedRecord else {
                throw PLCCredentialKeyContinuityStoreError.malformedRecord
            }
            throw error
        } catch {
            throw PLCCredentialKeyContinuityStoreError.malformedRecord
        }
    }

    func installPLCCredentialKeyContinuityInventoryLocked(
        _ inventory: PLCCredentialKeyContinuityInventory
    ) async throws {
        for checkpoint in inventory.checkpoints {
            let existing = try await plcCredentialKeyContinuityCheckpointLocked(
                for: checkpoint.issuer
            )
            if let existing {
                guard existing == checkpoint else {
                    throw PLCCredentialKeyContinuityStoreError.continuityViolation
                }
                continue
            }
            _ = try await connection.query(
                """
                INSERT INTO plc_credential_key_continuity(issuer, terminal_cid)
                VALUES (?, ?)
                """,
                [.text(checkpoint.issuer), .text(checkpoint.terminalCID)]
            )
        }
        let stored = try await plcCredentialKeyContinuityInventoryLocked()
        for checkpoint in inventory.checkpoints {
            guard stored.checkpoints.contains(checkpoint) else {
                throw PLCCredentialKeyContinuityStoreError.malformedRecord
            }
        }
    }

    func plcCredentialKeyContinuityCheckpointLocked(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        let rows = try await connection.query(
            """
            SELECT issuer, terminal_cid
            FROM plc_credential_key_continuity
            WHERE issuer = ?
            """,
            [.text(issuer)]
        )
        guard rows.count <= 1 else {
            throw PLCCredentialKeyContinuityStoreError.malformedRecord
        }
        guard let row = rows.first else { return nil }
        guard case let .text(storedIssuer) = row.column("issuer"),
              case let .text(terminalCID) = row.column("terminal_cid") else {
            throw PLCCredentialKeyContinuityStoreError.malformedRecord
        }
        do {
            return try PLCCredentialKeyContinuityCheckpoint(
                issuer: storedIssuer,
                terminalCID: terminalCID
            )
        } catch {
            throw PLCCredentialKeyContinuityStoreError.malformedRecord
        }
    }
}

extension SQLiteAccountDatabase {
    /// Reads the companion control database fail-closed. A production operator
    /// backup cannot silently downgrade a missing or unreadable continuity
    /// database to an empty first-use trust state.
    public func operatorBackupPLCCredentialKeyContinuityInventory()
        async throws -> PLCCredentialKeyContinuityInventory
    {
        let control = try await SQLiteControlDatabase(
            dataDirectory: dataDirectory,
            openMode: .existingPortableExportSource
        )
        do {
            let inventory =
                try await control.plcCredentialKeyContinuityInventory()
            try await control.close()
            return inventory
        } catch {
            try? await control.close()
            throw error
        }
    }
}
