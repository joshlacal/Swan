import Foundation
import SQLiteNIO
import SwanStorage

extension SQLiteControlDatabase {
    // MARK: Account control schema

    /// Evolves the alpha `accounts` registry in place. Legacy accounts retain
    /// a NULL verifier, which decodes only as `.missing`; migration never
    /// fabricates a usable credential from an absent column.
    func migrateAccountControlSchema() async throws {
        try await addColumnIfMissing(
            table: "accounts",
            column: "updated_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "password_verifier",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "signing_key_generation",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "signing_key_reference",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "rotation_key_generation",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "rotation_key_reference",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "public_genesis_commit_cid",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "tombstone_declared_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "tombstone_reason",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "export_declared_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "export_reference",
            definition: "TEXT"
        )

        _ = try await connection.query(
            "UPDATE accounts SET updated_at = created_at WHERE updated_at IS NULL"
        )

        // The first alpha table had a binary unique `handle` column but no
        // canonical-case guarantee. Reject a legacy ambiguity rather than
        // allowing two spellings of a canonical handle to become usable.
        let collisions = try await connection.query(
            """
            SELECT lower(handle) AS canonical_handle
            FROM accounts
            GROUP BY lower(handle)
            HAVING COUNT(*) > 1
            """
        )
        guard collisions.isEmpty else { throw AccountControlStoreError.malformedRecord }
        _ = try await connection.query(
            "UPDATE accounts SET handle = lower(handle) WHERE handle != lower(handle)"
        )
        _ = try await connection.query(
            "CREATE UNIQUE INDEX IF NOT EXISTS accounts_canonical_handle_unique ON accounts(lower(handle))"
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_status_valid_insert
            BEFORE INSERT ON accounts
            WHEN NEW.status = ''
              OR length(NEW.status) > 64
              OR substr(NEW.status, 1, 1) NOT GLOB '[a-z]'
              OR NEW.status GLOB '*[^a-z0-9_-]*'
            BEGIN
                SELECT RAISE(ABORT, 'invalid account status');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_status_valid_update
            BEFORE UPDATE OF status ON accounts
            WHEN NEW.status = ''
              OR length(NEW.status) > 64
              OR substr(NEW.status, 1, 1) NOT GLOB '[a-z]'
              OR NEW.status GLOB '*[^a-z0-9_-]*'
            BEGIN
                SELECT RAISE(ABORT, 'invalid account status');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_handle_canonical_insert
            BEFORE INSERT ON accounts
            WHEN NEW.handle != lower(NEW.handle)
            BEGIN
                SELECT RAISE(ABORT, 'account handle must be canonical');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_handle_canonical_update
            BEFORE UPDATE OF handle ON accounts
            WHEN NEW.handle != lower(NEW.handle)
            BEGIN
                SELECT RAISE(ABORT, 'account handle must be canonical');
            END
            """
        )
    }

    // MARK: AccountControlStore

    /// Offline-restore invariant: exactly one selected account exists and no
    /// OAuth, replay, client-metadata, or PLC-preparation control state was
    /// fabricated. Kept behind SPI so request-time modules cannot treat it as
    /// a general control-plane inspection API.
    @_spi(PortableRestore)
    public func validateOperatorRestoreOnlyAccount(did: String) async throws {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        try await withConnectionGate {
            let accounts = try await connection.query(
                "SELECT did FROM accounts ORDER BY did"
            )
            guard accounts.count == 1,
                  try requiredText(accounts[0], "did") == did else {
                throw AccountControlStoreError.malformedRecord
            }
            for table in [
                "oauth_tokens",
                "oauth_client_metadata",
                "oauth_control_client_metadata",
                "oauth_control_token_families",
                "oauth_control_par_requests",
                "oauth_control_par_state_replays",
                "oauth_control_authorization_codes",
                "oauth_control_access_tokens",
                "oauth_control_refresh_tokens",
                "oauth_control_dpop_replays",
                "oauth_control_client_assertion_replays",
                "permissioned_space_delegation_replays",
                "permissioned_space_client_attestation_replays",
                "plc_account_preparation_intents",
            ] {
                let rows = try await connection.query(
                    "SELECT 1 FROM \(table) LIMIT 1"
                )
                guard rows.isEmpty else {
                    throw AccountControlStoreError.malformedRecord
                }
            }
        }
    }

    public func createAccount(
        _ registration: AccountControlRegistration
    ) async throws -> AccountControlAccount {
        try validate(registration: registration)
        return try await withConnectionGate {
            try await transaction {
                let didRows = try await connection.query(
                    "SELECT did FROM accounts WHERE did = ?",
                    [.text(registration.did)]
                )
                guard didRows.isEmpty else { throw AccountControlStoreError.duplicateDID }
                let handleRows = try await connection.query(
                    "SELECT did FROM accounts WHERE handle = ?",
                    [.text(registration.canonicalHandle)]
                )
                guard handleRows.isEmpty else { throw AccountControlStoreError.duplicateHandle }

                let createdAt = try controlTimestamp(registration.createdAt)
                _ = try await connection.query(
                    """
                    INSERT INTO accounts(
                        did, handle, status, created_at, updated_at,
                        password_verifier,
                        signing_key_generation, signing_key_reference,
                        rotation_key_generation, rotation_key_reference,
                        public_genesis_commit_cid,
                        tombstone_declared_at, tombstone_reason,
                        export_declared_at, export_reference
                    ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
                    """,
                    [
                        .text(registration.did), .text(registration.canonicalHandle),
                        .integer(createdAt), .integer(createdAt),
                        .text(registration.passwordVerifier),
                        .integer(try controlGeneration(registration.signingKey.generation)),
                        .text(registration.signingKey.reference),
                        .integer(try controlGeneration(registration.rotationKey.generation)),
                        .text(registration.rotationKey.reference),
                        optionalText(registration.publicGenesisCommitCID),
                    ]
                )
                return try await requiredAccount(did: registration.did)
            }
        }
    }

    public func rotateAccountKeys(
        did: String,
        request: AccountControlKeyRotationRequest,
        now: Date
    ) async throws -> AccountControlAccount {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let account = try await requiredAccount(did: did)
                guard account.status.authorizesAccount else {
                    throw AccountControlStoreError.invalidTransition
                }
                guard let signing = account.signingKey,
                      let rotation = account.rotationKey,
                      signing.generation == request.expectedGeneration,
                      rotation.generation == request.expectedGeneration,
                      signing.purpose == .signing,
                      rotation.purpose == .rotation else {
                    throw AccountControlStoreError.invalidTransition
                }
                _ = try await connection.query(
                    """
                    UPDATE accounts
                    SET signing_key_generation = ?, signing_key_reference = ?,
                        rotation_key_generation = ?, rotation_key_reference = ?,
                        updated_at = ?
                    WHERE did = ?
                      AND signing_key_generation = ?
                      AND rotation_key_generation = ?
                    """,
                    [
                        .integer(try controlGeneration(request.signingKey.generation)),
                        .text(request.signingKey.reference),
                        .integer(try controlGeneration(request.rotationKey.generation)),
                        .text(request.rotationKey.reference),
                        .integer(timestamp), .text(did),
                        .integer(try controlGeneration(request.expectedGeneration)),
                        .integer(try controlGeneration(request.expectedGeneration)),
                    ]
                )
                let updated = try await requiredAccount(did: did)
                guard updated.signingKey == request.signingKey,
                      updated.rotationKey == request.rotationKey else {
                    throw AccountControlStoreError.invalidTransition
                }
                return updated
            }
        }
    }

    public func account(did: String) async throws -> AccountControlAccount? {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query(
                accountSelectSQL + " WHERE did = ?",
                [.text(did)]
            )
            guard let row = rows.first else { return nil }
            return try decodeAccount(row)
        }
    }

    public func account(canonicalHandle: String) async throws -> AccountControlAccount? {
        guard AccountControlIdentifiers.isCanonicalHandle(canonicalHandle) else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                accountSelectSQL + " WHERE handle = ?",
                [.text(canonicalHandle)]
            )
            guard let row = rows.first else { return nil }
            return try decodeAccount(row)
        }
    }

    /// A startup-only inventory for services that must preopen known account
    /// databases. Keep this status-only: control credentials, handles, keys,
    /// exports, and repository metadata must not cross this boundary.
    public func activeAccountDIDs() async throws -> [String] {
        try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT did, status FROM accounts WHERE status = 'active' ORDER BY did"
            )
            var result: [String] = []
            var previous: String?
            for row in rows {
                let did = try requiredText(row, "did")
                let status = try AccountControlStatus(rawValue: requiredText(row, "status"))
                guard AccountControlIdentifiers.isDID(did),
                      status == .active,
                      status.isCanonicalValue,
                      previous.map({ $0 < did }) ?? true else {
                    throw AccountControlStoreError.malformedRecord
                }
                result.append(did)
                previous = did
            }
            return result
        }
    }

    public func credential(did: String) async throws -> AccountControlCredential? {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT password_verifier, updated_at FROM accounts WHERE did = ?",
                [.text(did)]
            )
            guard let row = rows.first else { return nil }
            guard let verifier = try optionalText(row, "password_verifier") else { return nil }
            guard validVerifier(verifier) else { throw AccountControlStoreError.malformedRecord }
            return try AccountControlCredential(
                did: did,
                verifier: verifier,
                updatedAt: try requiredDate(row, "updated_at")
            )
        }
    }

    public func replaceCredential(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String,
        now: Date
    ) async throws -> AccountCredentialReplacement {
        guard AccountControlIdentifiers.isDID(did), validVerifier(expectedVerifier), validVerifier(replacementVerifier) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    "SELECT password_verifier FROM accounts WHERE did = ?",
                    [.text(did)]
                )
                guard let row = rows.first else { throw AccountControlStoreError.notFound }
                guard try optionalText(row, "password_verifier") == expectedVerifier else {
                    return .unchanged
                }
                _ = try await connection.query(
                    """
                    UPDATE accounts
                    SET password_verifier = ?, updated_at = ?
                    WHERE did = ? AND password_verifier = ?
                    """,
                    [
                        .text(replacementVerifier), .integer(timestamp), .text(did),
                        .text(expectedVerifier),
                    ]
                )
                return .replaced
            }
        }
    }

    /// The final account authorization decision is made in one SQLite write
    /// transaction. A password that was verified against a stale credential,
    /// or an account suspended/deleted while Argon2 was running, cannot cross
    /// this boundary as a successful authentication.
    public func finalizeAuthentication(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String?,
        now: Date
    ) async throws -> AccountAuthenticationFinalization? {
        guard AccountControlIdentifiers.isDID(did), validVerifier(expectedVerifier),
              replacementVerifier.map(validVerifier) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    accountSelectSQL + " WHERE did = ?",
                    [.text(did)]
                )
                guard let row = rows.first else { return nil }
                let account = try decodeAccount(row)
                guard account.status.authorizesAccount,
                      try optionalText(row, "password_verifier") == expectedVerifier else {
                    return nil
                }

                let credentialWasReplaced: Bool
                if let replacementVerifier, replacementVerifier != expectedVerifier {
                    _ = try await connection.query(
                        """
                        UPDATE accounts
                        SET password_verifier = ?, updated_at = ?
                        WHERE did = ? AND password_verifier = ? AND status = 'active'
                        """,
                        [
                            .text(replacementVerifier), .integer(timestamp), .text(did),
                            .text(expectedVerifier),
                        ]
                    )
                    credentialWasReplaced = true
                } else {
                    credentialWasReplaced = false
                }
                let finalized = try await requiredAccount(did: did)
                guard finalized.status.authorizesAccount else {
                    throw AccountControlStoreError.malformedRecord
                }
                return AccountAuthenticationFinalization(
                    account: finalized,
                    credentialWasReplaced: credentialWasReplaced
                )
            }
        }
    }

    public func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountControlAccount {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        guard status.isCanonicalValue else { throw AccountControlStoreError.invalidStatus }
        guard status == .deleted || declaration.tombstone == nil else {
            throw AccountControlStoreError.invalidInput
        }
        // Lifecycle metadata can arrive through a Codable or other opaque
        // boundary. Revalidate it immediately before persistence so only
        // bounded operator text and digest-only export references enter the
        // control database.
        guard declaration.tombstone?.isCanonicalValue ?? true,
              declaration.export?.isCanonicalValue ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let account = try await requiredAccount(did: did)
                try AccountStatusTransitionPolicy.standard.validate(
                    from: account.status,
                    to: status
                )
                let tombstoneTimestamp = try declaration.tombstone.map {
                    try controlTimestamp($0.declaredAt)
                }
                let exportTimestamp = try declaration.export.map {
                    try controlTimestamp($0.declaredAt)
                }
                _ = try await connection.query(
                    """
                    UPDATE accounts
                    SET status = ?, updated_at = ?,
                        tombstone_declared_at = COALESCE(?, tombstone_declared_at),
                        tombstone_reason = COALESCE(?, tombstone_reason),
                        export_declared_at = COALESCE(?, export_declared_at),
                        export_reference = COALESCE(?, export_reference)
                    WHERE did = ?
                    """,
                    [
                        .text(status.rawValue), .integer(timestamp),
                        optionalInteger(tombstoneTimestamp), optionalText(declaration.tombstone?.reason),
                        optionalInteger(exportTimestamp), optionalText(declaration.export?.reference),
                        .text(did),
                    ]
                )
                return try await requiredAccount(did: did)
            }
        }
    }

    // MARK: Decoding and validation

    private var accountSelectSQL: String {
        """
        SELECT did, handle, status, created_at, updated_at, password_verifier,
               signing_key_generation, signing_key_reference,
               rotation_key_generation, rotation_key_reference,
               public_genesis_commit_cid,
               tombstone_declared_at, tombstone_reason,
               export_declared_at, export_reference
        FROM accounts
        """
    }

    private func requiredAccount(did: String) async throws -> AccountControlAccount {
        let rows = try await connection.query(
            accountSelectSQL + " WHERE did = ?",
            [.text(did)]
        )
        guard let row = rows.first else { throw AccountControlStoreError.notFound }
        return try decodeAccount(row)
    }

    private func decodeAccount(_ row: SQLiteRow) throws -> AccountControlAccount {
        let did = try requiredText(row, "did")
        let handle = try requiredText(row, "handle")
        guard AccountControlIdentifiers.isDID(did),
              AccountControlIdentifiers.isCanonicalHandle(handle) else {
            throw AccountControlStoreError.malformedRecord
        }
        let status = try AccountControlStatus(rawValue: try requiredText(row, "status"))
        let signingKey = try decodeKeyReference(
            row,
            generationColumn: "signing_key_generation",
            referenceColumn: "signing_key_reference",
            purpose: .signing
        )
        let rotationKey = try decodeKeyReference(
            row,
            generationColumn: "rotation_key_generation",
            referenceColumn: "rotation_key_reference",
            purpose: .rotation
        )
        let publicGenesisCommitCID = try optionalText(row, "public_genesis_commit_cid")
        let tombstone = try decodeTombstone(row)
        let export = try decodeExport(row)
        let credentialState: AccountCredentialState
        if let verifier = try optionalText(row, "password_verifier") {
            guard validVerifier(verifier) else { throw AccountControlStoreError.malformedRecord }
            credentialState = .configured
        } else {
            credentialState = .missing
        }
        do {
            return try AccountControlAccount(
                did: did,
                canonicalHandle: handle,
                status: status,
                createdAt: try requiredDate(row, "created_at"),
                updatedAt: try requiredDate(row, "updated_at"),
                credentialState: credentialState,
                signingKey: signingKey,
                rotationKey: rotationKey,
                publicGenesisCommitCID: publicGenesisCommitCID,
                tombstone: tombstone,
                export: export
            )
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func decodeKeyReference(
        _ row: SQLiteRow,
        generationColumn: String,
        referenceColumn: String,
        purpose: AccountControlKeyReference.Purpose
    ) throws -> AccountControlKeyReference? {
        let generation = try optionalInteger(row, generationColumn)
        let reference = try optionalText(row, referenceColumn)
        guard generation != nil || reference != nil else { return nil }
        guard let generation, let reference, generation > 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        do {
            return try AccountControlKeyReference(
                purpose: purpose,
                generation: UInt64(generation),
                reference: reference
            )
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func decodeTombstone(_ row: SQLiteRow) throws -> AccountTombstoneMetadata? {
        let timestamp = try optionalDate(row, "tombstone_declared_at")
        let reason = try optionalText(row, "tombstone_reason")
        guard timestamp != nil || reason != nil else { return nil }
        guard let timestamp else { throw AccountControlStoreError.malformedRecord }
        do {
            return try AccountTombstoneMetadata(declaredAt: timestamp, reason: reason)
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func decodeExport(_ row: SQLiteRow) throws -> AccountExportMetadata? {
        let timestamp = try optionalDate(row, "export_declared_at")
        let reference = try optionalText(row, "export_reference")
        guard timestamp != nil || reference != nil else { return nil }
        guard let timestamp, let reference else { throw AccountControlStoreError.malformedRecord }
        do {
            // Legacy/corrupted rows are not grandfathered: only the public
            // digest constructor may decode an export declaration.
            return try AccountExportMetadata(declaredAt: timestamp, reference: reference)
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func validate(registration: AccountControlRegistration) throws {
        guard AccountControlIdentifiers.isDID(registration.did),
              AccountControlIdentifiers.isCanonicalHandle(registration.canonicalHandle),
              validVerifier(registration.passwordVerifier),
              registration.signingKey.isCanonicalValue,
              registration.rotationKey.isCanonicalValue,
              registration.signingKey.generation == registration.rotationKey.generation,
              registration.signingKey.purpose == .signing,
              registration.rotationKey.purpose == .rotation,
              registration.publicGenesisCommitCID.map(AccountControlIdentifiers.isPublicGenesisCommitCID) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        _ = try controlTimestamp(registration.createdAt)
    }

    private func controlTimestamp(_ date: Date) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else { throw AccountControlStoreError.invalidInput }
        let value = seconds * 1_000_000
        guard value.isFinite, value <= Double(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        return Int(value.rounded(.down))
    }

    private func controlGeneration(_ generation: UInt64) throws -> Int {
        guard generation > 0, generation <= UInt64(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        return Int(generation)
    }

    private func requiredDate(_ row: SQLiteRow, _ column: String) throws -> Date {
        guard case let .integer(value) = row.column(column), value >= 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        return Date(timeIntervalSince1970: Double(value) / 1_000_000)
    }

    private func optionalDate(_ row: SQLiteRow, _ column: String) throws -> Date? {
        guard let value = row.column(column) else { throw AccountControlStoreError.malformedRecord }
        if value.isNull { return nil }
        guard case let .integer(raw) = value, raw >= 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
    }

    private func requiredText(_ row: SQLiteRow, _ column: String) throws -> String {
        guard case let .text(value) = row.column(column), validIdentifier(value) else {
            throw AccountControlStoreError.malformedRecord
        }
        return value
    }

    private func optionalText(_ row: SQLiteRow, _ column: String) throws -> String? {
        guard let value = row.column(column) else { throw AccountControlStoreError.malformedRecord }
        if value.isNull { return nil }
        guard case let .text(text) = value, !text.utf8.contains(0) else {
            throw AccountControlStoreError.malformedRecord
        }
        return text
    }

    private func optionalInteger(_ row: SQLiteRow, _ column: String) throws -> Int? {
        guard let value = row.column(column) else { throw AccountControlStoreError.malformedRecord }
        if value.isNull { return nil }
        guard case let .integer(integer) = value else {
            throw AccountControlStoreError.malformedRecord
        }
        return integer
    }

    private func optionalText(_ value: String?) -> SQLiteData {
        value.map(SQLiteData.text) ?? .null
    }

    private func optionalInteger(_ value: Int?) -> SQLiteData {
        value.map(SQLiteData.integer) ?? .null
    }

    private func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 2_048 &&
            value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }

    private func validVerifier(_ value: String) -> Bool {
        value.hasPrefix("$argon2id$v=19$") && value.utf8.count <= 1_024 &&
            value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }
}
