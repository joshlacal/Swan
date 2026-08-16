import Crypto
import Foundation
import SQLiteNIO
import SwanAccounts
import SwanStorage

/// Task 4 consumes foundation-owned signup tables. It adds only lane-owned
/// reservation, proof, and result tables; shared tables are never redefined.
public struct SQLiteSignupFinalizationTransaction: SignupFinalizationTransaction {
    private let store: SQLiteControlDatabase
    private let request: SignupFinalizationRequest
    private let now: Date
    fileprivate init(store: SQLiteControlDatabase, request: SignupFinalizationRequest, now: Date) {
        self.store = store; self.request = request; self.now = now
    }

    public func commit() async throws -> SignupFinalizationResult {
        try await store.finalize(request, now: now)
    }
}

public struct SignupEmailOutboxMessage: Sendable, Equatable {
    public let deliveryID: String
    public let email: String
    public let protectedEnvelope: Data
    public init(deliveryID: String, email: String, protectedEnvelope: Data) {
        self.deliveryID = deliveryID; self.email = email; self.protectedEnvelope = protectedEnvelope
    }
}

/// Concrete integration seam: the writer is an object (not an escaping
/// callback) and all of its account/identity/session writes run under this
/// connection's transaction. Until the foundation supplies this writer, the
/// signup service fails closed rather than pretending its side effects are
/// atomic.
public protocol SignupTransactionScopedFoundationWriter: Sendable {
    func write(_ context: SQLiteSignupTransactionContext, request: SignupFinalizationRequest) async throws
}

public struct SQLiteSignupTransactionContext: Sendable {
    fileprivate let executeSQL: @Sendable (String, [SQLiteData]) async throws -> Void
    public func execute(_ sql: String, _ binds: [SQLiteData] = []) async throws {
        try await executeSQL(sql, binds)
    }
}

public struct SQLiteSignupTransactionCoordinator: Sendable {
    private let database: SQLiteControlDatabase
    public init(database: SQLiteControlDatabase) {
        self.database = database
    }

    public func run(_ request: SignupFinalizationRequest, writer: any SignupTransactionScopedFoundationWriter) async throws {
        try await database.withConnectionGate { try await database.transaction {
            let context = SQLiteSignupTransactionContext { sql, binds in _ = try await database.connection.query(sql, binds) }
            try await writer.write(context, request: request)
        } }
    }
}

extension SQLiteControlDatabase: SignupAtomicFinalizationStore, SignupEmailRequestStore {
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
            _ = try await connection.query("""
            CREATE TABLE IF NOT EXISTS signup_email_request_outbox(
                proof_digest BLOB PRIMARY KEY CHECK(length(proof_digest)=32),
                delivery_id TEXT NOT NULL UNIQUE, email TEXT NOT NULL, handle TEXT NOT NULL,
                protected_envelope BLOB NOT NULL, issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                lease_expires_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0, delivered_at INTEGER)
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

    public func persistSignupEmailRequest(email: AccountEmailAddress, handle: String, proofDigest: Data, protectedEnvelope: Data, issuedAt: Date, expiresAt: Date) async throws {
        guard proofDigest.count == 32, !protectedEnvelope.isEmpty, protectedEnvelope.count <= 16384, AccountControlIdentifiers.isCanonicalHandle(handle), expiresAt > issuedAt else { throw AccountControlStoreError.invalidInput }
        let issued = try task4Timestamp(issuedAt), expiry = try task4Timestamp(expiresAt)
        let deliveryID = "signup-" + proofDigest.map { String(format: "%02x", $0) }.joined()
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("INSERT INTO signup_email_proofs(proof_digest,email,handle,issued_at,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(proof_digest) DO NOTHING", [task4Blob(proofDigest), .text(email.value), .text(handle), .integer(issued), .integer(expiry)])
            _ = try await connection.query("INSERT INTO signup_email_request_outbox(proof_digest,delivery_id,email,handle,protected_envelope,issued_at,expires_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(proof_digest) DO NOTHING", [task4Blob(proofDigest), .text(deliveryID), .text(email.value), .text(handle), task4Blob(protectedEnvelope), .integer(issued), .integer(expiry)])
        } }
    }

    public func claimSignupEmailOutbox(now: Date = Date(), lease: TimeInterval = 60) async throws -> SignupEmailOutboxMessage? {
        let current = try task4Timestamp(now), until = try task4Timestamp(now.addingTimeInterval(lease))
        guard until > current else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate { try await transaction {
            let rows = try await connection.query("UPDATE signup_email_request_outbox SET state='sending',lease_expires_at=?,attempts=attempts+1 WHERE rowid=(SELECT rowid FROM signup_email_request_outbox WHERE expires_at>? AND (state='pending' OR (state='sending' AND lease_expires_at<=?)) ORDER BY issued_at LIMIT 1) RETURNING delivery_id,email,protected_envelope", [.integer(until), .integer(current), .integer(current)])
            guard let row = rows.first, let deliveryID = task4Text(row, "delivery_id"), let email = task4Text(row, "email"), let envelope = task4BlobValue(row, "protected_envelope") else { return nil }
            return SignupEmailOutboxMessage(deliveryID: deliveryID, email: email, protectedEnvelope: envelope)
        } }
    }

    public func markSignupEmailOutboxDelivered(deliveryID: String, now: Date = Date()) async throws {
        let current = try task4Timestamp(now)
        try await withConnectionGate { try await transaction {
            _ = try await connection.query("UPDATE signup_email_request_outbox SET state='delivered',delivered_at=?,lease_expires_at=NULL WHERE delivery_id=? AND state='sending'", [.integer(current), .text(deliveryID)])
        } }
    }

    public func reserve(_ authorization: SignupAuthorization, now: Date) async throws {
        let issued = try task4Timestamp(authorization.issuedAt), expiry = try task4Timestamp(authorization.expiresAt), current = try task4Timestamp(now)
        guard issued <= current, expiry > current else { throw SwanError.expired }
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
                let available = try await connection.query("SELECT proof_digest FROM signup_email_proofs WHERE proof_digest=? AND email=? AND handle=? AND consumed_at IS NULL AND expires_at>?", [task4Blob(digest), authorization.email.map(SQLiteData.text) ?? .null, .text(authorization.handle), .integer(current)])
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

    public func makeFinalizationTransaction(_ request: SignupFinalizationRequest, now: Date) async throws -> any SignupFinalizationTransaction {
        SQLiteSignupFinalizationTransaction(store: self, request: request, now: now)
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
            guard task4Integer(auth, "expires_at") ?? 0 > Int64(current),
                  task4Integer(auth, "lease_expires_at") ?? 0 > Int64(current),
                  task4Text(auth, "state") == "issued" || task4Text(auth, "state") == "failed" else { throw SwanError.expired }
            guard task4BlobValue(auth, "invite_digest") == request.inviteDigest, task4BlobValue(auth, "email_proof_digest") == request.emailProofDigest else { throw AccountControlStoreError.invalidInput }
            if let proof = request.emailProofDigest {
                let proofRows = try await connection.query("SELECT email,handle,expires_at,consumed_at FROM signup_email_proofs WHERE proof_digest=?", [task4Blob(proof)])
                guard let proofRow = proofRows.first, task4Text(proofRow, "email") == task4Text(auth, "email"), task4Text(proofRow, "handle") == task4Text(auth, "handle"), (task4Integer(proofRow, "expires_at") ?? 0) > Int64(current), task4Integer(proofRow, "consumed_at") == nil else { throw AccountControlStoreError.invalidInput }
            }
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
    task4CanonicalDigest([
        value.requestID, value.policy.rawValue, value.handle, value.email ?? "", value.identityDID ?? "",
        value.emailProofDigest?.base64EncodedString() ?? "", value.inviteDigest?.base64EncodedString() ?? "",
        value.clientIPBucketDigest.base64EncodedString(),
    ])
}

private func task4FinalizationDigest(_ value: SignupFinalizationRequest) -> Data {
    let session = value.managementSession
    return task4CanonicalDigest([
        value.authorizationID.rawValue, value.idempotencyKey, value.accountDID,
        value.handle, value.identityDID, value.reservedKeyID ?? "",
        value.sessionDigest.base64EncodedString(), value.csrfDigest.base64EncodedString(),
        value.preAuthCSRFDigest.base64EncodedString(), value.emailProofDigest?.base64EncodedString() ?? "",
        value.inviteDigest?.base64EncodedString() ?? "", session.sessionID.rawValue, session.accountDID,
        String(session.issuedAt.timeIntervalSince1970), String(session.idleExpiresAt.timeIntervalSince1970),
        String(session.absoluteExpiresAt.timeIntervalSince1970), session.lastStepUpAt.map { String($0.timeIntervalSince1970) } ?? "",
        String(describing: session.strength), session.revokedAt.map { String($0.timeIntervalSince1970) } ?? "",
    ])
}

private func task4CanonicalDigest(_ fields: [String]) -> Data {
    var bytes = Data("swan.signup.digest.v2".utf8)
    for field in fields {
        var length = UInt64(field.utf8.count).bigEndian
        withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
        bytes.append(contentsOf: field.utf8)
    }
    return Data(SHA256.hash(data: bytes))
}
