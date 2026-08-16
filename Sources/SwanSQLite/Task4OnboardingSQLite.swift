import Crypto
import Foundation
import SQLiteNIO
import SwanAccounts
import SwanStorage

/// Task 4 consumes foundation-owned signup tables. It adds only lane-owned
/// reservation, proof, and result tables; shared tables are never redefined.
extension SQLiteControlDatabase: SignupAuthorizationStore {
    public func migrateTask4OnboardingSchema() async throws {
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("""
            CREATE TABLE IF NOT EXISTS signup_invite_reservations(
                invite_digest BLOB PRIMARY KEY CHECK(length(invite_digest)=32),
                authorization_id TEXT NOT NULL, reserved_until INTEGER NOT NULL)
            """)
            _ = try await connection.query("""
            CREATE TABLE IF NOT EXISTS signup_email_proofs(
                proof_digest BLOB PRIMARY KEY CHECK(length(proof_digest)=32),
                email TEXT NOT NULL, handle TEXT NOT NULL, issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, consumed_at INTEGER)
            """)
            _ = try await connection.query("""
            CREATE TABLE IF NOT EXISTS signup_email_proof_reservations(
                proof_digest BLOB PRIMARY KEY CHECK(length(proof_digest)=32),
                authorization_id TEXT NOT NULL, reserved_until INTEGER NOT NULL)
            """)
            _ = try await connection.query("""
            CREATE TABLE IF NOT EXISTS signup_authorization_reservations(
                authorization_id TEXT PRIMARY KEY, input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
                reserved_until INTEGER NOT NULL)
            """)
            _ = try await connection.query("""
            CREATE TABLE IF NOT EXISTS signup_authorization_results(
                authorization_id TEXT PRIMARY KEY, input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
                account_did TEXT NOT NULL, session_id TEXT NOT NULL, committed_at INTEGER NOT NULL)
            """)
        } }
    }

    public func insertSignupInvite(_ invite: SignupInvite) async throws {
        let issued = try task4Timestamp(invite.issuedAt), expiry = try invite.expiresAt.map(task4Timestamp)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("INSERT INTO signup_invites(invite_digest,issued_at,expires_at) VALUES(?,?,?)", [task4Blob(invite.digest), .integer(issued), expiry.map(SQLiteData.integer) ?? .null])
        } }
    }

    public func insertSignupEmailProof(digest: Data, email: AccountEmailAddress, handle: String, issuedAt: Date, expiresAt: Date) async throws {
        guard digest.count == 32, AccountControlIdentifiers.isCanonicalHandle(handle), expiresAt > issuedAt else { throw AccountControlStoreError.invalidInput }
        let issued = try task4Timestamp(issuedAt), expiry = try task4Timestamp(expiresAt)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("INSERT INTO signup_email_proofs(proof_digest,email,handle,issued_at,expires_at) VALUES(?,?,?,?,?)", [task4Blob(digest), .text(email.value), .text(handle), .integer(issued), .integer(expiry)])
        } }
    }

    public func reserve(_ authorization: SignupAuthorization, now: Date) async throws {
        let issued = try task4Timestamp(authorization.issuedAt), expiry = try task4Timestamp(authorization.expiresAt), current = try task4Timestamp(now)
        guard expiry > current else { throw SwanError.expired }
        let lease = try authorization.leaseExpiresAt.map(task4Timestamp) ?? expiry
        let inputDigest = task4AuthorizationDigest(authorization)
        try await withConnectionGate { try await transaction {
            let existing = try await connection.query("SELECT authorization_id,request_id FROM signup_authorizations WHERE authorization_id=? OR request_id=?", [.text(authorization.id.rawValue), .text(authorization.requestID)])
            if let row = existing.first {
                guard task4Text(row, "request_id") == authorization.requestID else { throw AccountControlStoreError.duplicateDID }
                let stored = try await connection.query("SELECT input_digest FROM signup_authorization_reservations WHERE authorization_id=?", [.text(authorization.id.rawValue)])
                guard task4BlobValue(stored.first, "input_digest") == inputDigest else { throw AccountControlStoreError.duplicateDID }
                return
            }
            if let digest = authorization.inviteDigest {
                let available = try await connection.query("SELECT invite_digest FROM signup_invites WHERE invite_digest=? AND redeemed_at IS NULL AND (expires_at IS NULL OR expires_at>?)", [task4Blob(digest), .integer(current)])
                guard !available.isEmpty else { throw SwanError.invalidIdentifier("signup invite") }
                let claimed = try await connection.query("INSERT INTO signup_invite_reservations(invite_digest,authorization_id,reserved_until) VALUES(?,?,?) ON CONFLICT(invite_digest) DO UPDATE SET authorization_id=excluded.authorization_id,reserved_until=excluded.reserved_until WHERE signup_invite_reservations.reserved_until<=? RETURNING invite_digest", [task4Blob(digest), .text(authorization.id.rawValue), .integer(lease), .integer(current)])
                guard claimed.count == 1 else { throw SwanError.invalidIdentifier("signup invite") }
            }
            if let digest = authorization.emailProofDigest {
                let available = try await connection.query("SELECT proof_digest FROM signup_email_proofs WHERE proof_digest=? AND consumed_at IS NULL AND expires_at>?", [task4Blob(digest), .integer(current)])
                guard !available.isEmpty else { throw SwanError.invalidIdentifier("signup proof") }
                let claimed = try await connection.query("INSERT INTO signup_email_proof_reservations(proof_digest,authorization_id,reserved_until) VALUES(?,?,?) ON CONFLICT(proof_digest) DO UPDATE SET authorization_id=excluded.authorization_id,reserved_until=excluded.reserved_until WHERE signup_email_proof_reservations.reserved_until<=? RETURNING proof_digest", [task4Blob(digest), .text(authorization.id.rawValue), .integer(lease), .integer(current)])
                guard claimed.count == 1 else { throw SwanError.invalidIdentifier("signup proof") }
            }
            _ = try await connection.query("INSERT INTO signup_authorizations(authorization_id,request_id,account_did,policy,handle,email,identity_did,email_proof_digest,invite_digest,client_ip_bucket_digest,state,issued_at,expires_at,lease_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [.text(authorization.id.rawValue), .text(authorization.requestID), authorization.accountDID.map(SQLiteData.text) ?? .null, .text(authorization.policy.rawValue), .text(authorization.handle), authorization.email.map(SQLiteData.text) ?? .null, authorization.identityDID.map(SQLiteData.text) ?? .null, authorization.emailProofDigest.map(task4Blob) ?? .null, authorization.inviteDigest.map(task4Blob) ?? .null, task4Blob(authorization.clientIPBucketDigest), .text(authorization.state.rawValue), .integer(issued), .integer(expiry), .integer(lease)])
            _ = try await connection.query("INSERT INTO signup_authorization_reservations(authorization_id,input_digest,reserved_until) VALUES(?,?,?)", [.text(authorization.id.rawValue), task4Blob(inputDigest), .integer(lease)])
        } }
    }

    public func authorization(id: SignupAuthorizationID, now: Date) async throws -> SignupAuthorization? {
        _ = try task4Timestamp(now)
        return try await withConnectionGate { let rows = try await connection.query("SELECT * FROM signup_authorizations WHERE authorization_id=?", [.text(id.rawValue)]); guard let row = rows.first else { return nil }; return try task4DecodeAuthorization(row) }
    }

    public func fail(id: SignupAuthorizationID, now: Date) async throws {
        let current = try task4Timestamp(now)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("UPDATE signup_authorizations SET state='failed',lease_expires_at=NULL WHERE authorization_id=? AND state NOT IN('committed','failed')", [.text(id.rawValue)])
            _ = try await connection.query("DELETE FROM signup_invite_reservations WHERE authorization_id=?", [.text(id.rawValue)])
            _ = try await connection.query("DELETE FROM signup_email_proof_reservations WHERE authorization_id=?", [.text(id.rawValue)])
            _ = try await connection.query("DELETE FROM signup_authorization_reservations WHERE authorization_id=? OR reserved_until<=?", [.text(id.rawValue), .integer(current)])
        } }
    }

    /// The committing CAS is the durable linearization point. Proof/invite
    /// consumption and the persisted idempotent result share this transaction.
    public func finalize(_ request: SignupFinalizationRequest, now: Date) async throws -> SignupFinalizationResult {
        let current = try task4Timestamp(now)
        return try await withConnectionGate { try await transaction {
            let authRows = try await connection.query("SELECT * FROM signup_authorizations WHERE authorization_id=? AND request_id=?", [.text(request.authorizationID.rawValue), .text(request.idempotencyKey)])
            guard let auth = authRows.first else { throw AccountControlStoreError.notFound }
            let digest = task4FinalizationDigest(request)
            if let result = try await connection.query("SELECT input_digest,account_did,session_id,committed_at FROM signup_authorization_results WHERE authorization_id=?", [.text(request.authorizationID.rawValue)]).first {
                guard task4BlobValue(result, "input_digest") == digest, let did = task4Text(result, "account_did"), let session = task4Text(result, "session_id"), let committed = task4Integer(result, "committed_at") else { throw AccountControlStoreError.invalidInput }
                return try SignupFinalizationResult(accountDID: did, managementSessionID: ManagementSessionID(rawValue: session), idempotencyKey: request.idempotencyKey, committedAt: Date(timeIntervalSince1970: Double(committed) / 1_000_000))
            }
            guard task4Integer(auth, "expires_at") ?? 0 > Int64(current), task4Text(auth, "state") == "issued" || task4Text(auth, "state") == "failed" else { throw SwanError.expired }
            guard task4BlobValue(auth, "invite_digest") == request.inviteDigest, task4BlobValue(auth, "email_proof_digest") == request.emailProofDigest else { throw AccountControlStoreError.invalidInput }
            let committing = try await connection.query("UPDATE signup_authorizations SET state='committing',account_did=? WHERE authorization_id=? AND request_id=? AND state IN('issued','failed') RETURNING authorization_id", [.text(request.accountDID), .text(request.authorizationID.rawValue), .text(request.idempotencyKey)])
            guard committing.count == 1 else { throw AccountControlStoreError.unavailable }
            if let invite = request.inviteDigest { let consumed = try await connection.query("UPDATE signup_invites SET redeemed_at=?,redemption_account_did=? WHERE invite_digest=? AND redeemed_at IS NULL RETURNING invite_digest", [.integer(current), .text(request.accountDID), task4Blob(invite)]); guard consumed.count == 1 else { throw AccountControlStoreError.invalidInput } }
            if let proof = request.emailProofDigest { let consumed = try await connection.query("UPDATE signup_email_proofs SET consumed_at=? WHERE proof_digest=? AND consumed_at IS NULL RETURNING proof_digest", [.integer(current), task4Blob(proof)]); guard consumed.count == 1 else { throw AccountControlStoreError.invalidInput } }
            _ = try await connection.query("DELETE FROM signup_invite_reservations WHERE authorization_id=?", [.text(request.authorizationID.rawValue)])
            _ = try await connection.query("DELETE FROM signup_email_proof_reservations WHERE authorization_id=?", [.text(request.authorizationID.rawValue)])
            _ = try await connection.query("INSERT INTO signup_authorization_results(authorization_id,input_digest,account_did,session_id,committed_at) VALUES(?,?,?,?,?)", [.text(request.authorizationID.rawValue), task4Blob(digest), .text(request.accountDID), .text(request.managementSession.sessionID.rawValue), .integer(current)])
            _ = try await connection.query("UPDATE signup_authorizations SET state='committed',lease_expires_at=NULL WHERE authorization_id=? AND state='committing'", [.text(request.authorizationID.rawValue)])
            return try SignupFinalizationResult(accountDID: request.accountDID, managementSessionID: request.managementSession.sessionID, idempotencyKey: request.idempotencyKey, committedAt: now)
        } }
    }

    public func purgeExpiredSignupState(now: Date) async throws {
        let current = try task4Timestamp(now)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("DELETE FROM signup_invite_reservations WHERE reserved_until<=?", [.integer(current)])
            _ = try await connection.query("DELETE FROM signup_email_proof_reservations WHERE reserved_until<=?", [.integer(current)])
            _ = try await connection.query("DELETE FROM signup_authorization_reservations WHERE reserved_until<=?", [.integer(current)])
            _ = try await connection.query("DELETE FROM signup_email_proofs WHERE expires_at<=? AND consumed_at IS NULL", [.integer(current)])
        } }
    }
}

private func task4Timestamp(_ date: Date) throws -> Int {
    let value = date.timeIntervalSince1970 * 1_000_000; guard value.isFinite, value >= 0, value <= Double(Int.max) else { throw AccountControlStoreError.invalidInput }; return Int(value.rounded(.down))
}

private func task4Blob(_ data: Data) -> SQLiteData {
    data.sqliteData!
}

private func task4Text(_ row: SQLiteRow?, _ name: String) -> String? {
    guard case let .text(value) = row?.column(name) else { return nil }; return value
}

private func task4Integer(_ row: SQLiteRow?, _ name: String) -> Int64? {
    guard case let .integer(value) = row?.column(name) else { return nil }; return Int64(value)
}

private func task4BlobValue(_ row: SQLiteRow?, _ name: String) -> Data? {
    guard case let .blob(value) = row?.column(name) else { return nil }; return Data(value.readableBytesView)
}

private func task4DecodeAuthorization(_ row: SQLiteRow) throws -> SignupAuthorization {
    guard let id = task4Text(row, "authorization_id"), let request = task4Text(row, "request_id"), let policy = task4Text(row, "policy"), let handle = task4Text(row, "handle"), let state = task4Text(row, "state"), let issued = task4Integer(row, "issued_at"), let expiry = task4Integer(row, "expires_at"), let ip = task4BlobValue(row, "client_ip_bucket_digest") else { throw AccountControlStoreError.malformedRecord }
    return try SignupAuthorization(id: SignupAuthorizationID(rawValue: id), requestID: request, policy: SignupPolicy(rawValue: policy) ?? .closed, accountDID: task4Text(row, "account_did"), handle: handle, email: task4Text(row, "email"), identityDID: task4Text(row, "identity_did"), emailProofDigest: task4BlobValue(row, "email_proof_digest"), inviteDigest: task4BlobValue(row, "invite_digest"), clientIPBucketDigest: ip, state: SignupAuthorizationState(rawValue: state) ?? .failed, issuedAt: Date(timeIntervalSince1970: Double(issued) / 1_000_000), expiresAt: Date(timeIntervalSince1970: Double(expiry) / 1_000_000), leaseExpiresAt: task4Integer(row, "lease_expires_at").map { Date(timeIntervalSince1970: Double($0) / 1_000_000) })
}

private func task4AuthorizationDigest(_ value: SignupAuthorization) -> Data {
    Data(SHA256.hash(data: Data("\(value.requestID)\0\(value.policy.rawValue)\0\(value.handle)\0\(value.email ?? "")\0\(value.identityDID ?? "")\0\(value.emailProofDigest?.base64EncodedString() ?? "")\0\(value.inviteDigest?.base64EncodedString() ?? "")\0\(value.clientIPBucketDigest.base64EncodedString())".utf8)))
}

private func task4FinalizationDigest(_ value: SignupFinalizationRequest) -> Data {
    Data(SHA256.hash(data: Data("\(value.idempotencyKey)\0\(value.accountDID)\0\(value.handle)\0\(value.identityDID)\0\(value.reservedKeyID ?? "")\0\(value.emailProofDigest?.base64EncodedString() ?? "")\0\(value.inviteDigest?.base64EncodedString() ?? "")".utf8)))
}
