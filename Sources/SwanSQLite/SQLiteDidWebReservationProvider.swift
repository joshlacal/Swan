import Foundation
import NIOCore
import SQLiteNIO

/// Durable provider record used by composition to bridge the identity
/// reservation protocol without adding a migration. It is stored in the
/// existing claim transaction's authenticated receipt column and is updated
/// transactionally with the claim state.
public struct SQLiteDidWebReservationRecord: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable { case issued, committed, released }
    public let requestID: String
    public let accountDID: String?
    public let targetDID: String
    public let handle: String
    public let keyID: String
    public let keyType: String
    public let publicKey: Data
    public let nonce: Data
    public let expiresAt: Date
    public let claimBytes: Data
    public let claimReceiptDigest: Data
    public let pdsURL: String
    public let state: State

    public init(requestID: String, accountDID: String?, targetDID: String, handle: String,
                keyID: String, keyType: String, publicKey: Data, nonce: Data,
                expiresAt: Date, claimBytes: Data, claimReceiptDigest: Data,
                pdsURL: String, state: State = .issued) {
        self.requestID = requestID; self.accountDID = accountDID; self.targetDID = targetDID
        self.handle = handle; self.keyID = keyID; self.keyType = keyType; self.publicKey = publicKey
        self.nonce = nonce; self.expiresAt = expiresAt; self.claimBytes = claimBytes
        self.claimReceiptDigest = claimReceiptDigest; self.pdsURL = pdsURL; self.state = state
    }
}

extension SQLiteControlDatabase {
    public func persistDidWebReservation(_ record: SQLiteDidWebReservationRecord) async throws {
        let bytes = try JSONEncoder().encode(record)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE did_web_claim_transactions SET step_up_receipt_digest = ? WHERE request_id = ?",
                    [.blob(ByteBuffer(data: bytes)), .text(record.requestID)])
            }
        }
    }

    public func didWebReservation(requestID: String) async throws -> SQLiteDidWebReservationRecord? {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT step_up_receipt_digest FROM did_web_claim_transactions WHERE request_id = ?", [.text(requestID)])
            guard let blob = rows.first?.column("step_up_receipt_digest")?.blob else { return nil }
            return try JSONDecoder().decode(SQLiteDidWebReservationRecord.self, from: Data(buffer: blob))
        }
    }

    public func releaseDidWebReservation(requestID: String) async throws {
        guard let current = try await didWebReservation(requestID: requestID) else { return }
        let released = SQLiteDidWebReservationRecord(requestID: current.requestID, accountDID: current.accountDID, targetDID: current.targetDID, handle: current.handle, keyID: current.keyID, keyType: current.keyType, publicKey: current.publicKey, nonce: current.nonce, expiresAt: current.expiresAt, claimBytes: current.claimBytes, claimReceiptDigest: current.claimReceiptDigest, pdsURL: current.pdsURL, state: .released)
        try await persistDidWebReservation(released)
    }

    public func repairDidWebReservation(requestID: String) async throws {
        guard let current = try await didWebReservation(requestID: requestID) else { return }
        let committed = SQLiteDidWebReservationRecord(requestID: current.requestID, accountDID: current.accountDID, targetDID: current.targetDID, handle: current.handle, keyID: current.keyID, keyType: current.keyType, publicKey: current.publicKey, nonce: current.nonce, expiresAt: current.expiresAt, claimBytes: current.claimBytes, claimReceiptDigest: current.claimReceiptDigest, pdsURL: current.pdsURL, state: .committed)
        try await persistDidWebReservation(committed)
    }
}
