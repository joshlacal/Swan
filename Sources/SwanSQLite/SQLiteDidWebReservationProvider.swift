import Foundation

/// The root integration lane owns migration ordering. This is the dedicated
/// table contract; identity code never overloads claim step-up/receipt bytes.
public enum SQLiteDidWebReservationMigration {
    public static let createTableSQL = """
    CREATE TABLE IF NOT EXISTS did_web_signing_key_reservations (
      request_id TEXT PRIMARY KEY,
      account_did TEXT,
      target_did TEXT NOT NULL,
      handle TEXT NOT NULL,
      key_id TEXT NOT NULL,
      key_type TEXT NOT NULL,
      public_key BLOB NOT NULL,
      nonce BLOB NOT NULL,
      expires_at INTEGER NOT NULL,
      claim_bytes BLOB NOT NULL,
      claim_receipt_digest BLOB NOT NULL,
      pds_url TEXT NOT NULL,
      claim_service_endpoint TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('issued','committed','released')),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS did_web_signing_key_reservations_nonce
      ON did_web_signing_key_reservations(nonce);
    """
}

/// Root composition supplies this table-backed implementation to the
/// Accounts service. Keeping the schema and adapter boundary here prevents a
/// second provider from silently falling back to process-local state.
public protocol SQLiteDidWebReservationTable: Sendable {
    func reserveDidWebSigningKey(requestID: String, accountDID: String?, targetDID: String,
                                 handle: String, expiresAt: Date, pdsURL: String) async throws
    func loadDidWebSigningReservation(requestID: String) async throws -> Data?
    func markDidWebSigningReservationCommitted(requestID: String) async throws
    func releaseDidWebSigningReservation(requestID: String) async throws
    func repairDidWebSigningReservation(requestID: String) async throws
    func purgeExpiredDidWebSigningReservations(now: Date) async throws -> [String]
}
