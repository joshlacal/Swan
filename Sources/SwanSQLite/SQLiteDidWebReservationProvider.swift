import Crypto
import Foundation
import NIOCore
import SQLiteNIO
import SwanStorage

/// Migration SQL is returned to the root migration owner; this lane does not
/// edit migration ordering. The runtime provider below uses only this table.
public enum SQLiteDidWebReservationMigration {
    public static let createTableSQL = """
    CREATE TABLE IF NOT EXISTS did_web_signing_key_reservations (
      request_id TEXT PRIMARY KEY, account_did TEXT, target_did TEXT NOT NULL,
      handle TEXT NOT NULL, key_id TEXT NOT NULL, key_type TEXT NOT NULL,
      public_key BLOB NOT NULL, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL,
      claim_bytes BLOB NOT NULL, claim_receipt_digest BLOB NOT NULL, pds_url TEXT NOT NULL,
      claim_service_endpoint TEXT NOT NULL, state TEXT NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      UNIQUE(nonce)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS identity_did_web_active_identity_uq
      ON identity_bindings(identity_did) WHERE method='did-web' AND state != 'released';
    CREATE UNIQUE INDEX IF NOT EXISTS identity_did_web_active_handle_uq
      ON identity_bindings(handle) WHERE method='did-web' AND state != 'released';
    """
    public static let createStepUpReceiptTableSQL = """
    CREATE TABLE IF NOT EXISTS did_web_step_up_receipts (
      receipt_digest BLOB PRIMARY KEY, session_id TEXT NOT NULL,
      account_did TEXT NOT NULL, operation TEXT NOT NULL,
      mfa_strength TEXT NOT NULL, verified_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, consumed_at INTEGER
    );
    """
}

extension SQLiteControlDatabase: SwanDidWebReservationStore, SwanIdentityReservedMaterialStore, SwanIdentityStepUpReceiptStore {
    public func reserveDidWebSigningKey(requestID: String, accountDID: String?, targetDID: String,
                                        handle: String, expiresAt: Date, pdsURL: String,
                                        publicURL: String, signingKey: SwanSigningKeyMaterial) async throws -> SwanPersistedDidWebReservation {
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query("SELECT * FROM did_web_signing_key_reservations WHERE request_id = ?", [.text(requestID)])
                if let row = existing.first {
                    let prior = try decodeReservation(row)
                    guard prior.accountDID == accountDID, prior.targetDID == targetDID,
                          prior.handle == handle, prior.expiresAt == expiresAt,
                          prior.pdsURL == pdsURL, prior.keyID == signingKey.keyID,
                          prior.keyType == signingKey.keyType,
                          prior.publicKey == signingKey.publicKey,
                          prior.claimServiceEndpoint == "\(publicURL)/.well-known/swan/did-web-claim/\(prior.nonce.base64URLEncodedString())" else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    return prior
                }
                let key = signingKey.publicKey
                var generator = SystemRandomNumberGenerator()
                let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
                let endpoint = "\(publicURL)/.well-known/swan/did-web-claim/\(nonce.base64URLEncodedString())"
                let record = SwanPersistedDidWebReservation(requestID: requestID, accountDID: accountDID,
                    targetDID: targetDID, handle: handle, keyID: signingKey.keyID, keyType: signingKey.keyType,
                    publicKey: key, nonce: nonce, expiresAt: expiresAt, claimBytes: Data(),
                    claimReceiptDigest: Data(), pdsURL: pdsURL, claimServiceEndpoint: endpoint)
                _ = try await connection.query("""
                    INSERT INTO did_web_signing_key_reservations
                    (request_id,account_did,target_did,handle,key_id,key_type,public_key,nonce,expires_at,claim_bytes,claim_receipt_digest,pds_url,claim_service_endpoint,state,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'issued',?,?)
                    """, [.text(requestID), accountDID.map(SQLiteData.text) ?? .null, .text(targetDID), .text(handle), .text(record.keyID), .text(record.keyType), .blob(ByteBuffer(data: key)), .blob(ByteBuffer(data: nonce)), .integer(timestamp(expiresAt)), .blob(ByteBuffer(data: Data())), .blob(ByteBuffer(data: Data())), .text(pdsURL), .text(endpoint), .integer(timestamp(Date())), .integer(timestamp(Date()))])
                return record
            }
        }
    }

    public func persistDidWebSigningReservation(_ reservation: SwanPersistedDidWebReservation) async throws {
        try await withConnectionGate {
            let rows = try await connection.query("""
                UPDATE did_web_signing_key_reservations SET claim_bytes=?, claim_receipt_digest=?, state=?, updated_at=?
                WHERE request_id=? AND state='issued' AND account_did IS ? AND target_did=? AND handle=?
                  AND key_id=? AND key_type=? AND public_key=? AND nonce=? AND expires_at=?
                  AND pds_url=? AND claim_service_endpoint=?
                RETURNING request_id
                """, [.blob(ByteBuffer(data: reservation.claimBytes)), .blob(ByteBuffer(data: reservation.claimReceiptDigest)), .text(reservation.state.rawValue), .integer(timestamp(Date())), .text(reservation.requestID), reservation.accountDID.map(SQLiteData.text) ?? .null, .text(reservation.targetDID), .text(reservation.handle), .text(reservation.keyID), .text(reservation.keyType), .blob(ByteBuffer(data: reservation.publicKey)), .blob(ByteBuffer(data: reservation.nonce)), .integer(timestamp(reservation.expiresAt)), .text(reservation.pdsURL), .text(reservation.claimServiceEndpoint)])
            guard rows.count == 1 else { throw AccountControlStoreError.malformedRecord }
        }
    }

    public func loadDidWebSigningReservation(requestID: String) async throws -> SwanPersistedDidWebReservation? {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM did_web_signing_key_reservations WHERE request_id = ?", [.text(requestID)])
            return try rows.first.map(decodeReservation)
        }
    }

    public func markDidWebSigningReservationCommitted(requestID: String) async throws { try await updateReservationState(requestID, state: .committed, allowCommitted: true) }
    public func repairDidWebSigningReservation(requestID: String) async throws { try await updateReservationState(requestID, state: .committed, allowCommitted: true) }
    public func releaseDidWebSigningReservation(requestID: String) async throws { try await updateReservationState(requestID, state: .released, allowCommitted: false) }

    public func purgeExpiredDidWebSigningReservations(now: Date) async throws -> [String] {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("SELECT request_id FROM did_web_signing_key_reservations WHERE expires_at <= ? AND state = 'issued'", [.integer(timestamp(now))])
                _ = try await connection.query("UPDATE did_web_signing_key_reservations SET state='released', updated_at=? WHERE expires_at <= ? AND state='issued'", [.integer(timestamp(now)), .integer(timestamp(now))])
                return rows.compactMap { $0.column("request_id")?.string }
            }
        }
    }

    public func committedDidWebSigningReservation(accountDID: String) async throws -> SwanPersistedDidWebReservation? {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM did_web_signing_key_reservations WHERE account_did = ? AND state = 'committed' ORDER BY updated_at DESC LIMIT 1", [.text(accountDID)])
            return try rows.first.map(decodeReservation)
        }
    }

    public func reservedMaterial(accountDID: String) async throws -> SwanPersistedDidWebReservation? {
        try await committedDidWebSigningReservation(accountDID: accountDID)
    }

    public func consumeIdentityStepUpReceipt(sessionID: String, accountDID: String,
                                              operation: String, mfaStrength: String,
                                              verifiedAt: Date, expiresAt: Date,
                                              receiptDigest: Data, now: Date) async throws {
        guard receiptDigest.count == 32, verifiedAt <= now, now < expiresAt else {
            throw AccountControlStoreError.malformedRecord
        }
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("""
                    UPDATE did_web_step_up_receipts SET consumed_at=?
                    WHERE receipt_digest=? AND session_id=? AND account_did=?
                      AND operation=? AND mfa_strength=? AND verified_at<=?
                      AND expires_at>? AND consumed_at IS NULL
                    RETURNING receipt_digest
                    """, [.integer(timestamp(now)), .blob(ByteBuffer(data: receiptDigest)),
                          .text(sessionID), .text(accountDID), .text(operation), .text(mfaStrength),
                          .integer(timestamp(verifiedAt)), .integer(timestamp(now))])
                guard rows.count == 1 else { throw AccountControlStoreError.malformedRecord }
            }
        }
    }

    private func updateReservationState(_ requestID: String, state: SwanPersistedDidWebReservation.State, allowCommitted: Bool) async throws {
        try await withConnectionGate {
            let predicate = allowCommitted ? "state != 'released'" : "state = 'issued'"
            _ = try await connection.query("UPDATE did_web_signing_key_reservations SET state=?, updated_at=? WHERE request_id=? AND \(predicate)", [.text(state.rawValue), .integer(timestamp(Date())), .text(requestID)])
        }
    }

    private func decodeReservation(_ row: SQLiteRow) throws -> SwanPersistedDidWebReservation {
        func data(_ name: String) -> Data? { row.column(name)?.blob.map { Data(buffer: $0) } }
        guard let requestID = row.column("request_id")?.string, let target = row.column("target_did")?.string,
              let handle = row.column("handle")?.string, let keyID = row.column("key_id")?.string,
              let keyType = row.column("key_type")?.string, let key = data("public_key"), let nonce = data("nonce"),
              let expires = row.column("expires_at")?.integer, let state = row.column("state")?.string.flatMap(SwanPersistedDidWebReservation.State.init(rawValue:)),
              let pds = row.column("pds_url")?.string, let endpoint = row.column("claim_service_endpoint")?.string else { throw AccountControlStoreError.malformedRecord }
        return SwanPersistedDidWebReservation(requestID: requestID, accountDID: row.column("account_did")?.string, targetDID: target, handle: handle, keyID: keyID, keyType: keyType, publicKey: key, nonce: nonce, expiresAt: Date(timeIntervalSince1970: Double(expires)/1_000_000), claimBytes: data("claim_bytes") ?? Data(), claimReceiptDigest: data("claim_receipt_digest") ?? Data(), pdsURL: pds, claimServiceEndpoint: endpoint, state: state)
    }
    private func timestamp(_ date: Date) -> Int { Int((date.timeIntervalSince1970 * 1_000_000).rounded(.down)) }
}

private extension Data {
    func base64URLEncodedString() -> String { base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
}
