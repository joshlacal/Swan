import Foundation
import SQLiteNIO
import SwanCore

public struct AccountKEMBackfillClaim: Sendable, Equatable {
    public let did: String
    public let token: String
    public let requiresManualPublication: Bool
}

extension SQLiteControlDatabase {
    /// One account at a time under a durable lease. New accounts are admitted
    /// lazily; completed accounts never incur another PLC request on restart.
    public func claimAccountKEMBackfill(now: Int64, leaseSeconds: Int64 = 120) async throws -> AccountKEMBackfillClaim? {
        guard now >= 0, (30...600).contains(leaseSeconds) else { throw SwanError.malformed("invalid KEM lease") }
        return try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("""
                    INSERT OR IGNORE INTO account_kem_backfill(account_did, status)
                    SELECT did, 'pending' FROM accounts WHERE status = 'active'
                    """)
                let rows = try await connection.query("""
                    SELECT b.account_did, i.method FROM account_kem_backfill b
                    JOIN accounts a ON a.did = b.account_did
                    LEFT JOIN identity_bindings i ON i.account_did = a.did AND i.state = 'active'
                    WHERE a.status = 'active' AND b.status = 'pending' AND b.next_attempt_at <= ?
                      AND (b.lease_until IS NULL OR b.lease_until <= ?)
                    ORDER BY b.account_did LIMIT 1
                    """, [.integer(Int(now)), .integer(Int(now))])
                guard let row = rows.first, let did = row.column("account_did")?.string else { return nil }
                let token = UUID().uuidString.lowercased()
                _ = try await connection.query("""
                    UPDATE account_kem_backfill SET lease_token = ?, lease_until = ? WHERE account_did = ?
                    """, [.text(token), .integer(Int(now + leaseSeconds)), .text(did)])
                return AccountKEMBackfillClaim(did: did, token: token,
                    requiresManualPublication: !did.hasPrefix("did:plc:") || row.column("method")?.string == "did-web")
            }
        }
    }

    public func finishAccountKEMBackfill(_ claim: AccountKEMBackfillClaim, manual: Bool, now: Int64) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("""
                    UPDATE account_kem_backfill SET status = ?, completed_at = ?, lease_token = NULL, lease_until = NULL
                    WHERE account_did = ? AND status = 'pending' AND lease_token = ?
                    """, [.text(manual ? "manual" : "published"), .integer(Int(now)), .text(claim.did), .text(claim.token)])
            }
        }
    }

    public func retryAccountKEMBackfill(_ claim: AccountKEMBackfillClaim, now: Int64) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("""
                    UPDATE account_kem_backfill SET next_attempt_at = ?, lease_token = NULL, lease_until = NULL
                    WHERE account_did = ? AND status = 'pending' AND lease_token = ?
                    """, [.integer(Int(now + 60)), .text(claim.did), .text(claim.token)])
            }
        }
    }
}
