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
    """
}

extension SQLiteControlDatabase: SwanDidWebReservationStore {
    public func reserveDidWebSigningKey(requestID: String, accountDID: String?, targetDID: String,
                                        handle: String, expiresAt: Date, pdsURL: String,
                                        publicURL: String) async throws -> SwanPersistedDidWebReservation {
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query("SELECT * FROM did_web_signing_key_reservations WHERE request_id = ?", [.text(requestID)])
                if let row = existing.first { return try decodeReservation(row) }
                let key = P256.Signing.PrivateKey().publicKey.rawRepresentation
                var generator = SystemRandomNumberGenerator()
                let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
                let endpoint = "\(publicURL)/.well-known/swan/did-web-claim/\(nonce.base64URLEncodedString())"
                let record = SwanPersistedDidWebReservation(requestID: requestID, accountDID: accountDID,
                    targetDID: targetDID, handle: handle, keyID: "#atproto", keyType: "Multikey",
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
            _ = try await connection.query("""
                UPDATE did_web_signing_key_reservations SET claim_bytes=?, claim_receipt_digest=?, state=?, updated_at=? WHERE request_id=? AND state != 'committed'
                """, [.blob(ByteBuffer(data: reservation.claimBytes)), .blob(ByteBuffer(data: reservation.claimReceiptDigest)), .text(reservation.state.rawValue), .integer(timestamp(Date())), .text(reservation.requestID)])
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
