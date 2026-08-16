import Foundation
import NIOCore
import SQLiteNIO
import SwanCore
import SwanStorage

/// SQLite implementation of the reviewed method-neutral claim contract. The
/// claim, replacement history, and nonce consumption are committed under one
/// BEGIN IMMEDIATE transaction; no router or migration ownership is required.
extension SQLiteControlDatabase: SwanAtomicDidWebClaimStore, SwanAtomicIdentityContinuityStore, SwanExpiredIdentityClaimReleasingStore, SwanIdentityBindingEnumerating, SwanIdentityBindingHistoryStore {
    public func identityBinding(accountDID: String) async throws -> IdentityBinding? {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM identity_bindings WHERE account_did = ?", [.text(accountDID)])
            guard rows.count <= 1 else { throw AccountControlStoreError.malformedRecord }
            guard let row = rows.first else { return nil }
            return try decodeIdentityBinding(row)
        }
    }

    public func reserveDidWebClaim(_ claim: DidWebClaimTransaction, now: Date) async throws {
        guard now < claim.expiresAt else { throw SwanError.expired }
        try await withConnectionGate {
            try await self.transaction {
                let existing = try await connection.query("SELECT * FROM did_web_claim_transactions WHERE request_id = ?", [.text(claim.requestID)])
                if let row = existing.first {
                    guard try decodeClaim(row) == claim else { throw SwanError.conflict(expected: 0, actual: 1) }
                    return
                }
                let nonce = SQLiteData.blob(ByteBuffer(data: claim.claimNonceDigest))
                let document = claim.requestedDocumentDigest.map { SQLiteData.blob(ByteBuffer(data: $0)) } ?? .null
                let receipt = claim.claimReceiptDigest.map { SQLiteData.blob(ByteBuffer(data: $0)) } ?? .null
                _ = try await connection.query("""
                    INSERT INTO did_web_claim_transactions(request_id, account_did, target_did, handle, claim_nonce_digest, requested_document_digest, reserved_key_id, claim_receipt_digest, state, expires_at, step_up_receipt_digest)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, [.text(claim.requestID), claim.accountDID.map(SQLiteData.text) ?? .null, .text(claim.targetDID), .text(claim.handle), nonce, document, claim.reservedKeyID.map(SQLiteData.text) ?? .null, receipt, .text(claim.state.rawValue), .integer(timestamp(claim.expiresAt)), claim.stepUpReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null])
            }
        }
    }

    public func transitionDidWebClaim(_ claim: DidWebClaimTransaction, from expected: DidWebClaimTransactionState, now: Date) async throws {
        guard now < claim.expiresAt || claim.state == .expired else { throw SwanError.expired }
        try await withConnectionGate {
            try await self.transaction {
                let current = try await connection.query("""
                    SELECT request_id FROM did_web_claim_transactions
                    WHERE request_id = ? AND state = ?
                      AND account_did IS ? AND target_did = ? AND handle = ?
                      AND claim_nonce_digest = ?
                      AND (requested_document_digest IS ? OR requested_document_digest = ?)
                      AND (reserved_key_id IS ? OR reserved_key_id = ?)
                      AND (claim_receipt_digest IS ? OR claim_receipt_digest = ?)
                    """, [.text(claim.requestID), .text(expected.rawValue),
                          claim.accountDID.map(SQLiteData.text) ?? .null, .text(claim.targetDID), .text(claim.handle),
                          .blob(ByteBuffer(data: claim.claimNonceDigest)),
                          claim.requestedDocumentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          claim.requestedDocumentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          claim.reservedKeyID.map(SQLiteData.text) ?? .null,
                          claim.reservedKeyID.map(SQLiteData.text) ?? .null,
                          claim.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          claim.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null])
                guard current.count == 1 else { throw SwanError.conflict(expected: 0, actual: 1) }
                _ = try await connection.query("UPDATE did_web_claim_transactions SET state = ?, requested_document_digest = ?, reserved_key_id = ?, claim_receipt_digest = ? WHERE request_id = ? AND state = ?", [.text(claim.state.rawValue), claim.requestedDocumentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null, claim.reservedKeyID.map(SQLiteData.text) ?? .null, claim.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null, .text(claim.requestID), .text(expected.rawValue)])
            }
        }
    }

    public func commitDidWebClaim(_ request: DidWebClaimCommitRequest, history: IdentityBindingHistoryEntry?, now: Date) async throws {
        try await commitDidWebClaim(request, history: history, now: now, gracePeriod: 86_400)
    }

    public func commitDidWebClaim(_ request: DidWebClaimCommitRequest, history: IdentityBindingHistoryEntry?, now: Date, gracePeriod: TimeInterval) async throws {
        _ = try await commitDidWebClaimInternal(request, history: history, now: now, gracePeriod: gracePeriod, stepUpReceipt: nil)
    }

    public func commitDidWebClaimAtomically(_ request: DidWebClaimCommitRequest,
                                            history: IdentityBindingHistoryEntry?, now: Date,
                                            gracePeriod: TimeInterval,
                                            stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> Bool {
        try await commitDidWebClaimInternal(request, history: history, now: now, gracePeriod: gracePeriod, stepUpReceipt: stepUpReceipt)
    }

    private func commitDidWebClaimInternal(_ request: DidWebClaimCommitRequest, history: IdentityBindingHistoryEntry?, now: Date,
                                           gracePeriod: TimeInterval, stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> Bool {
        try await withConnectionGate {
            try await transaction {
                let nonce = SQLiteData.blob(ByteBuffer(data: request.claimNonceDigest))
                let committedNonce = try await connection.query("SELECT request_id FROM did_web_claim_transactions WHERE claim_nonce_digest = ? AND state = 'committed' AND request_id != ?", [nonce, .text(request.requestID)])
                guard committedNonce.isEmpty else { throw SwanError.conflict(expected: 0, actual: 1) }
                let current = try await connection.query("SELECT account_did, target_did, handle, claim_nonce_digest, reserved_key_id, claim_receipt_digest, state FROM did_web_claim_transactions WHERE request_id = ?", [.text(request.requestID)])
                guard current.count == 1,
                      current[0].column("state")?.string == DidWebClaimTransactionState.committing.rawValue,
                      current[0].column("account_did")?.string == request.accountDID,
                      current[0].column("target_did")?.string == request.targetDID,
                      current[0].column("handle")?.string == request.handle,
                      current[0].column("reserved_key_id")?.string == request.reservedKeyID,
                      current[0].column("claim_receipt_digest")?.blob.map({ Data(buffer: $0) }) == request.claimReceiptDigest,
                      current[0].column("claim_nonce_digest")?.blob.map({ Data(buffer: $0) }) == request.claimNonceDigest else { throw SwanError.conflict(expected: 0, actual: 1) }
                if let stepUpReceipt {
                    guard stepUpReceipt.accountDID == request.accountDID,
                          stepUpReceipt.operation == "replace" else {
                        throw SwanError.unauthorized("invalid identity replacement receipt")
                    }
                    try await consumeStepUpReceipt(stepUpReceipt, now: now)
                }
                var reservationFinalized = false
                if let reservation = request.reservation {
                    let finalized = try await connection.query("""
                        UPDATE did_web_signing_key_reservations
                        SET state='committed', updated_at=?
                        WHERE request_id=? AND state='issued'
                          AND account_did IS ? AND target_did=? AND handle=?
                          AND key_id=? AND key_type=? AND public_key=? AND nonce=?
                          AND expires_at=? AND claim_bytes=? AND claim_receipt_digest=?
                          AND pds_url=? AND claim_service_endpoint=?
                        RETURNING request_id
                        """, [.integer(timestamp(now)), .text(reservation.requestID),
                              reservation.accountDID.map(SQLiteData.text) ?? .null,
                              .text(reservation.targetDID), .text(reservation.handle),
                              .text(reservation.keyID), .text(reservation.keyType),
                              .blob(ByteBuffer(data: reservation.publicKey)),
                              .blob(ByteBuffer(data: reservation.nonce)),
                              .integer(timestamp(reservation.expiresAt)),
                              .blob(ByteBuffer(data: reservation.claimBytes)),
                              .blob(ByteBuffer(data: reservation.claimReceiptDigest)),
                              .text(reservation.pdsURL), .text(reservation.claimServiceEndpoint)])
                    guard finalized.count == 1 else {
                        throw SwanError.conflict(expected: 1, actual: 0)
                    }
                    reservationFinalized = true
                }
                if let history {
                    _ = try await connection.query("INSERT INTO identity_binding_history(account_did, replaced_at, identity_did, document_digest, claim_receipt_digest, reserved_key_id) VALUES (?, ?, ?, ?, ?, ?)", [.text(history.accountDID), .integer(timestamp(history.replacedAt)), .text(history.identityDID), history.documentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null, history.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null, history.reservedKeyID.map(SQLiteData.text) ?? .null])
                }
                let binding = request.identityBinding
                _ = try await connection.query("""
                    INSERT INTO identity_bindings(account_did, identity_did, method, handle, document_digest, claim_receipt_digest, reserved_key_id, last_validated_at, grace_expires_at, state)
                    VALUES (?, ?, 'did-web', ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(account_did) DO UPDATE SET identity_did = excluded.identity_did, method = excluded.method, handle = excluded.handle, document_digest = excluded.document_digest, claim_receipt_digest = excluded.claim_receipt_digest, reserved_key_id = excluded.reserved_key_id, last_validated_at = excluded.last_validated_at, grace_expires_at = excluded.grace_expires_at, state = excluded.state
                    """, [.text(binding.accountDID), .text(binding.identityDID), .text(binding.handle), .blob(ByteBuffer(data: binding.documentDigest!)), .blob(ByteBuffer(data: binding.claimReceiptDigest!)), .text(binding.reservedKeyID!), .integer(timestamp(now)), .integer(timestamp(now.addingTimeInterval(gracePeriod))), .text(binding.state.rawValue)])
                let committed = try await connection.query("UPDATE did_web_claim_transactions SET state = 'committed' WHERE request_id = ? AND state = 'committing' RETURNING request_id", [.text(request.requestID)])
                guard committed.count == 1 else { throw SwanError.conflict(expected: 0, actual: 1) }
                return reservationFinalized
            }
        }
    }

    public func purgeExpiredIdentityClaims(now: Date) async throws {
        _ = try await purgeExpiredIdentityClaimsReturningRequests(now: now)
    }

    public func purgeExpiredIdentityClaimsReturningRequests(now: Date) async throws -> [String] {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("SELECT request_id FROM did_web_claim_transactions WHERE expires_at < ? AND state != 'committed'", [.integer(timestamp(now))])
                _ = try await connection.query("DELETE FROM did_web_claim_transactions WHERE expires_at < ? AND state != 'committed'", [.integer(timestamp(now))])
                return rows.compactMap { $0.column("request_id")?.string }
            }
        }
    }

    public func persistIdentityContinuity(_ binding: IdentityBinding) async throws -> IdentityBinding {
        try await withConnectionGate {
            let rows = try await connection.query("""
                UPDATE identity_bindings SET identity_did = ?, method = ?, handle = ?,
                    document_digest = ?, claim_receipt_digest = ?, reserved_key_id = ?,
                    last_validated_at = ?, grace_expires_at = ?, state = ?
                WHERE account_did = ?
                """, [.text(binding.identityDID), .text(binding.method.rawValue), .text(binding.handle),
                      binding.documentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                      binding.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                      binding.reservedKeyID.map(SQLiteData.text) ?? .null,
                      binding.lastValidatedAt.map { .integer(timestamp($0)) } ?? .null,
                      binding.graceExpiresAt.map { .integer(timestamp($0)) } ?? .null,
                      .text(binding.state.rawValue), .text(binding.accountDID)])
            guard rows.count == 1 else { throw SwanError.conflict(expected: 0, actual: 1) }
            return binding
        }
    }

    public func compareAndPersistIdentityContinuity(expected: IdentityBinding, replacement: IdentityBinding) async throws -> IdentityBinding {
        try await withConnectionGate {
            let result = try await connection.query("""
                UPDATE identity_bindings SET identity_did = ?, method = ?, handle = ?,
                    document_digest = ?, claim_receipt_digest = ?, reserved_key_id = ?,
                    state = ?, last_validated_at = ?, grace_expires_at = ?
                WHERE account_did = ? AND identity_did = ? AND method = ? AND handle = ?
                  AND document_digest IS ? AND claim_receipt_digest IS ?
                  AND reserved_key_id IS ? AND state = ?
                RETURNING account_did
                """, [.text(replacement.identityDID), .text(replacement.method.rawValue), .text(replacement.handle),
                      replacement.documentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                      replacement.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                      replacement.reservedKeyID.map(SQLiteData.text) ?? .null, .text(replacement.state.rawValue),
                      replacement.lastValidatedAt.map { .integer(timestamp($0)) } ?? .null,
                      replacement.graceExpiresAt.map { .integer(timestamp($0)) } ?? .null,
                      .text(expected.accountDID), .text(expected.identityDID), .text(expected.method.rawValue),
                      .text(expected.handle), expected.documentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                      expected.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                      expected.reservedKeyID.map(SQLiteData.text) ?? .null, .text(expected.state.rawValue)])
            guard result.count == 1 else { throw SwanError.conflict(expected: 0, actual: 1) }
            return replacement
        }
    }

    public func compareAndPersistIdentityContinuityAtomically(expected: IdentityBinding,
                                                              replacement: IdentityBinding,
                                                              now: Date,
                                                              stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> IdentityBinding {
        try await withConnectionGate {
            try await transaction {
                if let stepUpReceipt {
                    guard stepUpReceipt.accountDID == expected.accountDID,
                          stepUpReceipt.operation == "remove" else {
                        throw SwanError.unauthorized("invalid identity removal receipt")
                    }
                    try await consumeStepUpReceipt(stepUpReceipt, now: now)
                }
                let result = try await connection.query("""
                    UPDATE identity_bindings SET identity_did = ?, method = ?, handle = ?,
                        document_digest = ?, claim_receipt_digest = ?, reserved_key_id = ?,
                        state = ?, last_validated_at = ?, grace_expires_at = ?
                    WHERE account_did = ? AND identity_did = ? AND method = ? AND handle = ?
                      AND document_digest IS ? AND claim_receipt_digest IS ?
                      AND reserved_key_id IS ? AND state = ?
                    RETURNING account_did
                    """, [.text(replacement.identityDID), .text(replacement.method.rawValue), .text(replacement.handle),
                          replacement.documentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          replacement.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          replacement.reservedKeyID.map(SQLiteData.text) ?? .null, .text(replacement.state.rawValue),
                          replacement.lastValidatedAt.map { .integer(timestamp($0)) } ?? .null,
                          replacement.graceExpiresAt.map { .integer(timestamp($0)) } ?? .null,
                          .text(expected.accountDID), .text(expected.identityDID), .text(expected.method.rawValue),
                          .text(expected.handle), expected.documentDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          expected.claimReceiptDigest.map { .blob(ByteBuffer(data: $0)) } ?? .null,
                          expected.reservedKeyID.map(SQLiteData.text) ?? .null, .text(expected.state.rawValue)])
                guard result.count == 1 else { throw SwanError.conflict(expected: 0, actual: 1) }
                return replacement
            }
        }
    }

    public func identityBindings(afterAccountDID: String?, limit: Int) async throws -> [IdentityBinding] {
        guard (1 ... 256).contains(limit) else { throw SwanError.invalidIdentifier("identity binding page size") }
        return try await withConnectionGate {
            let rows: [SQLiteRow]
            if let afterAccountDID {
                rows = try await connection.query("SELECT * FROM identity_bindings WHERE account_did > ? ORDER BY account_did ASC LIMIT ?", [.text(afterAccountDID), .integer(limit)])
            } else {
                rows = try await connection.query("SELECT * FROM identity_bindings ORDER BY account_did ASC LIMIT ?", [.integer(limit)])
            }
            return try rows.map(decodeIdentityBinding)
        }
    }

    public func identityBindingHistory(accountDID: String) async throws -> [IdentityBindingHistoryEntry] {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM identity_binding_history WHERE account_did = ? ORDER BY replaced_at ASC", [.text(accountDID)])
            return try rows.map(decodeIdentityBindingHistory)
        }
    }

    private func consumeStepUpReceipt(_ receipt: SwanIdentityStepUpReceipt, now: Date) async throws {
        guard receipt.verifiedAt <= now, now < receipt.expiresAt else {
            throw SwanError.unauthorized("expired identity step-up receipt")
        }
        let rows = try await connection.query("""
            UPDATE did_web_step_up_receipts SET consumed_at=?
            WHERE receipt_digest=? AND session_id=? AND account_did=?
              AND operation=? AND mfa_strength=? AND verified_at<=?
              AND expires_at>? AND consumed_at IS NULL
            RETURNING receipt_digest
            """, [.integer(timestamp(now)), .blob(ByteBuffer(data: receipt.receiptDigest)),
                  .text(receipt.sessionID), .text(receipt.accountDID), .text(receipt.operation),
                  .text(receipt.mfaStrength), .integer(timestamp(receipt.verifiedAt)),
                  .integer(timestamp(now))])
        guard rows.count == 1 else { throw SwanError.unauthorized("invalid or replayed identity step-up receipt") }
    }

    private func timestamp(_ value: Date) -> Int { Int((value.timeIntervalSince1970 * 1_000_000).rounded(.down)) }

    private func decodeClaim(_ row: SQLiteRow) throws -> DidWebClaimTransaction {
        func data(_ name: String) -> Data? { row.column(name)?.blob.map { Data(buffer: $0) } }
        guard let requestID = row.column("request_id")?.string, let target = row.column("target_did")?.string, let handle = row.column("handle")?.string, let nonce = data("claim_nonce_digest"), let state = row.column("state")?.string.flatMap(DidWebClaimTransactionState.init(rawValue:)), let expires = row.column("expires_at")?.integer else { throw AccountControlStoreError.malformedRecord }
        return try DidWebClaimTransaction(requestID: requestID, accountDID: row.column("account_did")?.string, targetDID: target, handle: handle, claimNonceDigest: nonce, requestedDocumentDigest: data("requested_document_digest"), state: state, expiresAt: Date(timeIntervalSince1970: Double(expires) / 1_000_000), stepUpReceiptDigest: data("step_up_receipt_digest"), reservedKeyID: row.column("reserved_key_id")?.string, claimReceiptDigest: data("claim_receipt_digest"))
    }

    private func decodeIdentityBinding(_ row: SQLiteRow) throws -> IdentityBinding {
        func data(_ name: String) -> Data? { row.column(name)?.blob.map { Data(buffer: $0) } }
        guard let account = row.column("account_did")?.string, let identity = row.column("identity_did")?.string, let method = row.column("method")?.string.flatMap(IdentityMethod.init(rawValue:)), let handle = row.column("handle")?.string, let state = row.column("state")?.string.flatMap(IdentityBindingState.init(rawValue:)) else { throw AccountControlStoreError.malformedRecord }
        let date: (String) -> Date? = { name in row.column(name)?.integer.map { Date(timeIntervalSince1970: Double($0) / 1_000_000) } }
        return try IdentityBinding(accountDID: account, identityDID: identity, method: method, handle: handle, documentDigest: data("document_digest"), claimReceiptDigest: data("claim_receipt_digest"), reservedKeyID: row.column("reserved_key_id")?.string, lastValidatedAt: date("last_validated_at"), graceExpiresAt: date("grace_expires_at"), state: state)
    }

    private func decodeIdentityBindingHistory(_ row: SQLiteRow) throws -> IdentityBindingHistoryEntry {
        func data(_ name: String) -> Data? { row.column(name)?.blob.map { Data(buffer: $0) } }
        guard let account = row.column("account_did")?.string,
              let identity = row.column("identity_did")?.string,
              let replaced = row.column("replaced_at")?.integer else {
            throw AccountControlStoreError.malformedRecord
        }
        return try IdentityBindingHistoryEntry(
            accountDID: account, identityDID: identity,
            documentDigest: data("document_digest"),
            claimReceiptDigest: data("claim_receipt_digest"),
            reservedKeyID: row.column("reserved_key_id")?.string,
            replacedAt: Date(timeIntervalSince1970: Double(replaced) / 1_000_000)
        )
    }
}
