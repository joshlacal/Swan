import Foundation
import SQLiteNIO
import SwanAccounts
import SwanCore
import SwanStorage

/// Connection-scoped foundation writer for the signup finalization
/// transaction. The provisioning pipeline supplies the password verifier and
/// the deterministic key references (provisioned against the external key
/// store before this transaction opens); this writer replicates the account,
/// identity binding, and management session row shapes of the shared control
/// store under the coordinator's single connection.
///
/// Every write goes through `context.execute` on the coordinator's current
/// connection, so a failure at any stage rolls back the account row, the
/// identity binding, the management session, and Task 4's proof/invite
/// consumption and persisted result together.
public struct SQLiteSignupFoundationWriter: SignupTransactionScopedFoundationWriter {
    /// The Argon2id verifier produced by the provisioning pipeline. Fail-closed
    /// validation mirrors `AccountControlMetadata.isVerifier`.
    private let passwordVerifier: String
    /// The signing key reference provisioned for this account (generation 1).
    private let signingReference: String
    /// The rotation key reference provisioned for this account (generation 1).
    private let rotationReference: String
    /// Test-only hook. When set, the writer invokes it with the named stage
    /// before performing that stage's write, so rollback tests can inject a
    /// failure at each stage in isolation.
    private let failureInjection: (@Sendable (String) async throws -> Void)?

    public init(
        passwordVerifier: String,
        signingReference: String,
        rotationReference: String,
        failureInjection: (@Sendable (String) async throws -> Void)? = nil
    ) throws {
        guard Self.isValidVerifier(passwordVerifier),
              !signingReference.isEmpty,
              !rotationReference.isEmpty else {
            throw AccountControlStoreError.invalidInput
        }
        self.passwordVerifier = passwordVerifier
        self.signingReference = signingReference
        self.rotationReference = rotationReference
        self.failureInjection = failureInjection
    }

    /// Tests construct the writer through the internal memberwise entry point
    /// so the rollback suite can inject a failure at each stage.
    init(
        verifier: String,
        signingReference: String,
        rotationReference: String,
        injecting failureInjection: (@Sendable (String) async throws -> Void)?
    ) {
        passwordVerifier = verifier
        self.signingReference = signingReference
        self.rotationReference = rotationReference
        self.failureInjection = failureInjection
    }

    public func write(
        _ context: SQLiteSignupTransactionContext,
        request: SignupFinalizationRequest
    ) async throws {
        let timestamp = try writerTimestamp(request.managementSession.issuedAt)
        try await stage("account") {
            try await context.execute(
                """
                INSERT INTO accounts(
                    did, handle, status, created_at, updated_at,
                    password_verifier,
                    signing_key_generation, signing_key_reference,
                    rotation_key_generation, rotation_key_reference,
                    public_genesis_commit_cid,
                    tombstone_declared_at, tombstone_reason,
                    export_declared_at, export_reference
                ) VALUES (?, ?, 'active', ?, ?, ?, 1, ?, 1, ?, NULL, NULL, NULL, NULL, NULL)
                """,
                [
                    .text(request.accountDID),
                    .text(request.handle),
                    .integer(timestamp),
                    .integer(timestamp),
                    .text(passwordVerifier),
                    .text(signingReference),
                    .text(rotationReference),
                ]
            )
        }
        try await stage("identity") {
            try await context.execute(
                """
                INSERT INTO identity_bindings(
                    account_did, identity_did, method, handle,
                    document_digest, claim_receipt_digest, reserved_key_id,
                    last_validated_at, grace_expires_at, state
                ) VALUES (?, ?, 'plc', ?, NULL, NULL, NULL, ?, NULL, 'active')
                """,
                [
                    .text(request.accountDID),
                    .text(request.identityDID),
                    .text(request.handle),
                    .integer(timestamp),
                ]
            )
        }
        try await stage("session") {
            try await context.execute(
                """
                INSERT INTO management_sessions(
                    session_digest, account_did, csrf_digest,
                    issued_at, idle_expires_at, absolute_expires_at,
                    last_step_up_at, strength, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                [
                    request.sessionDigest.sqliteData!,
                    .text(request.accountDID),
                    request.csrfDigest.sqliteData!,
                    .integer(timestamp),
                    .integer(try writerTimestamp(request.managementSession.idleExpiresAt)),
                    .integer(try writerTimestamp(request.managementSession.absoluteExpiresAt)),
                    request.managementSession.lastStepUpAt.map {
                        (try? writerTimestamp($0)).map(SQLiteData.integer) ?? .null
                    } ?? .null,
                    .text(writerStrengthName(request.managementSession.strength)),
                ]
            )
        }
    }

    private func stage(_ name: String, _ body: () async throws -> Void) async throws {
        if let failureInjection {
            try await failureInjection(name)
        }
        try await body()
    }

    private static func isValidVerifier(_ value: String) -> Bool {
        value.hasPrefix("$argon2id$v=19$") && value.utf8.count <= 1_024
            && value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }
}

private func writerTimestamp(_ date: Date) throws -> Int {
    let value = date.timeIntervalSince1970 * 1_000_000
    guard value.isFinite, value >= 0, value <= Double(Int.max) else {
        throw AccountControlStoreError.invalidInput
    }
    return Int(value.rounded(.down))
}

private func writerStrengthName(_ strength: AuthenticationStrength) -> String {
    switch strength {
    case .none: return "none"
    case .password: return "password"
    case .passwordPlusTOTP: return "passwordPlusTOTP"
    case .passwordPlusPasskey: return "passwordPlusPasskey"
    case .emailRecovery: return "emailRecovery"
    case .scopedAppPassword: return "scopedAppPassword"
    case .stepUpPassword: return "stepUpPassword"
    case let .stepUpMFA(base, _): return "stepUpMFA:\(base.rawValue)"
    }
}
