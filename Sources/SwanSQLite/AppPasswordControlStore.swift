import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage
import SwanAccounts

/// App-password rows, in the control database beside `accounts`.
///
/// This layer never sees a password — only the opaque digest
/// `SwanAccounts.AppPasswordCredentials` produces. Lookup is by digest
/// equality, which is what makes a login one indexed probe rather than a verify
/// loop over every row the account owns; see that type for why the digest can
/// safely be deterministic.
extension SQLiteControlDatabase: AppPasswordStore {
    public func createAppPassword(
        did: String,
        name: String,
        scopes: String,
        digest: Data,
        now: Date = Date()
    ) async throws -> AppPasswordRecord {
        let identifier = UUID().uuidString.lowercased()
        let createdAt = try appPasswordTimestamp(now)

        return try await withConnectionGate {
            try await transaction {
                // The account must exist AND be usable. The foreign key would
                // catch a missing row but not an inactive one, and a caller
                // must never be handed a working credential for an account that
                // cannot use it.
                let accounts = try await connection.query(
                    "SELECT status FROM accounts WHERE did = ?",
                    [.text(did)]
                )
                guard let account = accounts.first,
                      case let .text(status) = account.column("status"),
                      let parsed = try? AccountControlStatus(rawValue: status),
                      parsed.authorizesAccount else {
                    throw AppPasswordStoreError.unknownAccount
                }

                let existing = try await connection.query(
                    "SELECT COUNT(*) AS total FROM account_app_passwords WHERE did = ?",
                    [.text(did)]
                )
                guard let row = existing.first,
                      case let .integer(total) = row.column("total"),
                      total < AppPasswordStorePolicy.maximumPerAccount else {
                    throw AppPasswordStoreError.limitReached
                }

                // Checked explicitly rather than by catching the INSERT's
                // failure. Both run inside this transaction, so the check is not
                // racy — and mapping every write error to `duplicateName` would
                // report a full disk, a corrupt page, or a schema drift as the
                // caller's naming mistake. The UNIQUE constraint remains as the
                // storage-level backstop; it is simply not the thing that
                // produces this diagnosis.
                let duplicates = try await connection.query(
                    "SELECT 1 FROM account_app_passwords WHERE did = ? AND name = ? LIMIT 1",
                    [.text(did), .text(name)]
                )
                guard duplicates.isEmpty else {
                    throw AppPasswordStoreError.duplicateName
                }

                _ = try await connection.query(
                    """
                    INSERT INTO account_app_passwords
                        (id, did, name, digest, scopes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        .text(identifier),
                        .text(did),
                        .text(name),
                        .blob(ByteBuffer(data: digest)),
                        .text(scopes),
                        .integer(createdAt),
                    ]
                )

                return AppPasswordRecord(
                    id: identifier,
                    did: did,
                    name: name,
                    scopes: scopes,
                    createdAt: now
                )
            }
        }
    }

    public func listAppPasswords(did: String) async throws -> [AppPasswordRecord] {
        try await withConnectionGate {
            // `digest` is deliberately absent from the projection.
            let rows = try await connection.query(
                """
                SELECT id, name, scopes, created_at
                FROM account_app_passwords
                WHERE did = ?
                ORDER BY created_at ASC, id ASC
                """,
                [.text(did)]
            )
            return try rows.map { try appPasswordRecord($0, did: did) }
        }
    }

    public func revokeAppPassword(did: String, name: String) async throws {
        _ = try await withConnectionGate {
            // The canonical main schema cascades deletion through the legacy
            // family and token rows. This keeps revocation account-bound and
            // atomic without introducing a second session authority.
            try await transaction {
                _ = try await connection.query(
                    "DELETE FROM account_app_passwords WHERE did = ? AND name = ?",
                    [.text(did), .text(name)]
                )
            }
        }
    }

    public func appPassword(did: String, digest: Data) async throws -> AppPasswordRecord? {
        try await withConnectionGate { () -> AppPasswordRecord? in
            let rows = try await connection.query(
                """
                SELECT id, name, scopes, created_at
                FROM account_app_passwords
                WHERE digest = ? AND did = ?
                """,
                [digest.sqliteData!, .text(did)]
            )
            guard let row = rows.first else { return nil }
            return try appPasswordRecord(row, did: did)
        }
    }

    private func appPasswordRecord(_ row: SQLiteRow, did: String) throws -> AppPasswordRecord {
        guard case let .text(identifier) = row.column("id"),
              case let .text(name) = row.column("name"),
              case let .text(scopes) = row.column("scopes"),
              case let .integer(createdAt) = row.column("created_at") else {
            throw AccountControlStoreError.malformedRecord
        }
        return AppPasswordRecord(
            id: identifier,
            did: did,
            name: name,
            scopes: scopes,
            createdAt: Date(timeIntervalSince1970: Double(createdAt) / 1_000_000)
        )
    }

    private func appPasswordTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max) else {
            throw SwanError.malformed("app password timestamp is out of range")
        }
        return Int(microseconds.rounded(.down))
    }
}
