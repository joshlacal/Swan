import Foundation
import SQLiteNIO
import SwanAccounts
import SwanStorage

/// Task 4's additive schema is intentionally not called from the shared
/// migration spine. The integration owner invokes this hook after reviewing
/// the reserved migration number and ordering.
extension SQLiteControlDatabase: SignupAuthorizationStore {
    public func migrateTask4OnboardingSchema() async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("""
                CREATE TABLE IF NOT EXISTS signup_invites (
                    digest BLOB PRIMARY KEY CHECK(length(digest) = 32),
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    reserved_by TEXT,
                    reserved_until INTEGER,
                    redeemed_at INTEGER,
                    redemption_account_did TEXT
                )
                """)
                _ = try await connection.query("CREATE INDEX IF NOT EXISTS signup_invites_due ON signup_invites(expires_at, redeemed_at, reserved_until)")
                _ = try await connection.query("""
                CREATE TABLE IF NOT EXISTS signup_email_proofs (
                    digest BLOB PRIMARY KEY CHECK(length(digest) = 32),
                    email TEXT NOT NULL,
                    handle TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    reserved_by TEXT,
                    reserved_until INTEGER,
                    consumed_at INTEGER
                )
                """)
                _ = try await connection.query("CREATE INDEX IF NOT EXISTS signup_email_proofs_due ON signup_email_proofs(expires_at, consumed_at, reserved_until)")
                _ = try await connection.query("""
                CREATE TABLE IF NOT EXISTS signup_authorizations (
                    id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    policy TEXT NOT NULL,
                    account_did TEXT,
                    handle TEXT NOT NULL,
                    email TEXT,
                    identity_did TEXT,
                    email_proof_digest BLOB,
                    invite_digest BLOB,
                    client_ip_digest BLOB NOT NULL CHECK(length(client_ip_digest) = 32),
                    state TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    lease_expires_at INTEGER,
                    result_session_id TEXT,
                    committed_at INTEGER
                )
                """)
                _ = try await connection.query("CREATE INDEX IF NOT EXISTS signup_authorizations_expiry ON signup_authorizations(expires_at, state)")
            }
        }
    }

    public func insertSignupInvite(_ invite: SignupInvite) async throws {
        let issued = try task4Timestamp(invite.issuedAt)
        let expiry = try invite.expiresAt.map(task4Timestamp)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("INSERT INTO signup_invites(digest, issued_at, expires_at) VALUES (?, ?, ?)", [task4Blob(invite.digest), .integer(issued), expiry.map(SQLiteData.integer) ?? .null])
        } }
    }

    public func insertSignupEmailProof(digest: Data, email: AccountEmailAddress, handle: String, issuedAt: Date, expiresAt: Date) async throws {
        guard digest.count == 32, AccountControlIdentifiers.isCanonicalHandle(handle), expiresAt > issuedAt else { throw AccountControlStoreError.invalidInput }
        let issued = try task4Timestamp(issuedAt), expiry = try task4Timestamp(expiresAt)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("INSERT INTO signup_email_proofs(digest, email, handle, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)", [task4Blob(digest), .text(email.value), .text(handle), .integer(issued), .integer(expiry)])
        } }
    }

    public func reserve(_ authorization: SignupAuthorization, now: Date) async throws {
        let issued = try task4Timestamp(authorization.issuedAt), expiry = try task4Timestamp(authorization.expiresAt), current = try task4Timestamp(now)
        guard expiry > current else { throw SwanError.expired }
        let lease = try authorization.leaseExpiresAt.map(task4Timestamp)
        try await withConnectionGate { try await transaction {
            let existing = try await connection.query("SELECT request_id, state FROM signup_authorizations WHERE id = ? OR request_id = ?", [.text(authorization.id.rawValue), .text(authorization.requestID)])
            if let row = existing.first {
                guard task4Text(row, "request_id") == authorization.requestID else { throw AccountControlStoreError.duplicateDID }
                return
            }
            if let digest = authorization.inviteDigest {
                let changed = try await connection.query("UPDATE signup_invites SET reserved_by = ?, reserved_until = ? WHERE digest = ? AND redeemed_at IS NULL AND (expires_at IS NULL OR expires_at > ?) AND (reserved_until IS NULL OR reserved_until <= ?) RETURNING digest", [.text(authorization.id.rawValue), .integer(lease ?? expiry), task4Blob(digest), .integer(current), .integer(current)])
                guard changed.count == 1 else { throw SwanError.invalidIdentifier("signup invite") }
            }
            if let digest = authorization.emailProofDigest {
                let changed = try await connection.query("UPDATE signup_email_proofs SET reserved_by = ?, reserved_until = ? WHERE digest = ? AND consumed_at IS NULL AND expires_at > ? AND (reserved_until IS NULL OR reserved_until <= ?) RETURNING digest", [.text(authorization.id.rawValue), .integer(lease ?? expiry), task4Blob(digest), .integer(current), .integer(current)])
                guard changed.count == 1 else { throw SwanError.invalidIdentifier("signup proof") }
            }
            _ = try await connection.query("INSERT INTO signup_authorizations(id, request_id, policy, account_did, handle, email, identity_did, email_proof_digest, invite_digest, client_ip_digest, state, issued_at, expires_at, lease_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [.text(authorization.id.rawValue), .text(authorization.requestID), .text(authorization.policy.rawValue), authorization.accountDID.map(SQLiteData.text) ?? .null, .text(authorization.handle), authorization.email.map(SQLiteData.text) ?? .null, authorization.identityDID.map(SQLiteData.text) ?? .null, authorization.emailProofDigest.map(task4Blob) ?? .null, authorization.inviteDigest.map(task4Blob) ?? .null, task4Blob(authorization.clientIPBucketDigest), .text(authorization.state.rawValue), .integer(issued), .integer(expiry), lease.map(SQLiteData.integer) ?? .null])
        } }
    }

    public func authorization(id: SignupAuthorizationID, now: Date) async throws -> SignupAuthorization? {
        let current = try task4Timestamp(now)
        return try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM signup_authorizations WHERE id = ?", [.text(id.rawValue)])
            guard let row = rows.first else { return nil }
            return try task4DecodeAuthorization(row, now: current)
        }
    }

    public func fail(id: SignupAuthorizationID, now: Date) async throws {
        let current = try task4Timestamp(now)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("UPDATE signup_authorizations SET state = 'failed', lease_expires_at = NULL WHERE id = ? AND state NOT IN ('committed', 'failed')", [.text(id.rawValue)])
            _ = try await connection.query("UPDATE signup_invites SET reserved_by = NULL, reserved_until = NULL WHERE reserved_by = ? AND redeemed_at IS NULL", [.text(id.rawValue)])
            _ = try await connection.query("UPDATE signup_email_proofs SET reserved_by = NULL, reserved_until = NULL WHERE reserved_by = ? AND consumed_at IS NULL AND expires_at > ?", [.text(id.rawValue), .integer(current)])
        } }
    }

    public func finalize(_ request: SignupFinalizationRequest, now: Date) async throws -> SignupFinalizationResult {
        let current = try task4Timestamp(now)
        return try await withConnectionGate { try await transaction {
            let rows = try await connection.query("SELECT state, account_did, result_session_id, committed_at, expires_at, invite_digest, email_proof_digest FROM signup_authorizations WHERE id = ? AND request_id = ?", [.text(request.authorizationID.rawValue), .text(request.idempotencyKey)])
            guard let row = rows.first else { throw AccountControlStoreError.notFound }
            if task4Text(row, "state") == "committed", let session = task4Text(row, "result_session_id"), let committed = task4Integer(row, "committed_at") {
                return try SignupFinalizationResult(accountDID: request.accountDID, managementSessionID: ManagementSessionID(rawValue: session), idempotencyKey: request.idempotencyKey, committedAt: Date(timeIntervalSince1970: Double(committed) / 1_000_000))
            }
            guard task4Text(row, "state") == "issued" || task4Text(row, "state") == "failed", task4Integer(row, "expires_at") ?? 0 > Int64(current) else { throw SwanError.expired }
            guard task4BlobValue(row, "invite_digest") == request.inviteDigest,
                  task4BlobValue(row, "email_proof_digest") == request.emailProofDigest
            else {
                throw AccountControlStoreError.invalidInput
            }
            let updated = try await connection.query("UPDATE signup_authorizations SET state = 'committed', account_did = ?, result_session_id = ?, committed_at = ?, lease_expires_at = NULL WHERE id = ? AND request_id = ? AND state IN ('issued', 'failed') RETURNING id", [.text(request.accountDID), .text(request.managementSession.sessionID.rawValue), .integer(current), .text(request.authorizationID.rawValue), .text(request.idempotencyKey)])
            guard updated.count == 1 else { throw AccountControlStoreError.unavailable }
            if let digest = request.inviteDigest {
                let consumed = try await connection.query("UPDATE signup_invites SET redeemed_at = ?, redemption_account_did = ?, reserved_by = NULL, reserved_until = NULL WHERE digest = ? AND redeemed_at IS NULL RETURNING digest", [.integer(current), .text(request.accountDID), task4Blob(digest)])
                guard consumed.count == 1 else { throw AccountControlStoreError.invalidInput }
            }
            if let digest = request.emailProofDigest {
                let consumed = try await connection.query("UPDATE signup_email_proofs SET consumed_at = ?, reserved_by = NULL, reserved_until = NULL WHERE digest = ? AND consumed_at IS NULL RETURNING digest", [.integer(current), task4Blob(digest)])
                guard consumed.count == 1 else { throw AccountControlStoreError.invalidInput }
            }
            return try SignupFinalizationResult(accountDID: request.accountDID, managementSessionID: request.managementSession.sessionID, idempotencyKey: request.idempotencyKey, committedAt: now)
        } }
    }

    public func purgeExpiredSignupState(now: Date) async throws {
        let current = try task4Timestamp(now)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("UPDATE signup_invites SET reserved_by = NULL, reserved_until = NULL WHERE reserved_until IS NOT NULL AND reserved_until <= ? AND redeemed_at IS NULL", [.integer(current)])
            _ = try await connection.query("UPDATE signup_email_proofs SET reserved_by = NULL, reserved_until = NULL WHERE reserved_until IS NOT NULL AND reserved_until <= ? AND consumed_at IS NULL", [.integer(current)])
            _ = try await connection.query("DELETE FROM signup_authorizations WHERE expires_at <= ? AND state != 'committed'", [.integer(current)])
            _ = try await connection.query("DELETE FROM signup_email_proofs WHERE expires_at <= ? AND consumed_at IS NULL AND reserved_by IS NULL", [.integer(current)])
            _ = try await connection.query("DELETE FROM signup_invites WHERE expires_at IS NOT NULL AND expires_at <= ? AND redeemed_at IS NULL AND reserved_by IS NULL", [.integer(current)])
        } }
    }
}

private func task4Timestamp(_ date: Date) throws -> Int {
    let value = date.timeIntervalSince1970 * 1_000_000
    guard value.isFinite, value >= 0, value <= Double(Int.max) else { throw AccountControlStoreError.invalidInput }
    return Int(value.rounded(.down))
}

private func task4Blob(_ data: Data) -> SQLiteData {
    data.sqliteData!
}

private func task4DecodeAuthorization(_ row: SQLiteRow, now _: Int) throws -> SignupAuthorization {
    guard let id = task4Text(row, "id"), let request = task4Text(row, "request_id"), let policy = task4Text(row, "policy"), let handle = task4Text(row, "handle"), let state = task4Text(row, "state"), let issued = task4Integer(row, "issued_at"), let expiry = task4Integer(row, "expires_at"), let ip = task4BlobValue(row, "client_ip_digest"), ip.count == 32 else { throw AccountControlStoreError.malformedRecord }
    func blob(_ name: String) -> Data? {
        task4BlobValue(row, name)
    }
    func text(_ name: String) -> String? {
        task4Text(row, name)
    }
    let idValue = try SignupAuthorizationID(rawValue: id)
    return try SignupAuthorization(id: idValue, requestID: request, policy: SignupPolicy(rawValue: policy) ?? .closed, accountDID: text("account_did"), handle: handle, email: text("email"), identityDID: text("identity_did"), emailProofDigest: blob("email_proof_digest"), inviteDigest: blob("invite_digest"), clientIPBucketDigest: ip, state: SignupAuthorizationState(rawValue: state) ?? .failed, issuedAt: Date(timeIntervalSince1970: Double(issued) / 1_000_000), expiresAt: Date(timeIntervalSince1970: Double(expiry) / 1_000_000), leaseExpiresAt: task4Integer(row, "lease_expires_at").map { Date(timeIntervalSince1970: Double($0) / 1_000_000) })
}

private func task4Text(_ row: SQLiteRow, _ name: String) -> String? {
    guard case let .text(value) = row.column(name) else { return nil }
    return value
}

private func task4Integer(_ row: SQLiteRow, _ name: String) -> Int64? {
    guard case let .integer(value) = row.column(name) else { return nil }
    return Int64(value)
}

private func task4BlobValue(_ row: SQLiteRow, _ name: String) -> Data? {
    guard case let .blob(value) = row.column(name) else { return nil }
    return Data(value.readableBytesView)
}
