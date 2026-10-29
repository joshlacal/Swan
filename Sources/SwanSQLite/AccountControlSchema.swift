import Foundation

/// Reserved additive versions for the account-control migration spine. The
/// baseline is intentionally separate from public lifecycle markers.
public enum ControlSchemaMigrationVersion: Int, CaseIterable, Codable, Sendable {
    case baseline = 1
    case identity = 2
    case signup = 3
    case legacySessions = 4
    case managementSessions = 5
    case factors = 6
    case hardening = 7
    case accountProgramIntegration = 8
    /// The repo host's space-credential revocation list (atproto#5567).
    case spaceCredentialRevocations = 9
    /// The `account_kem_backfill` lease and completion table for the
    /// October 22 `#atproto_kem` backfill (Swan's counterpart to upstream's
    /// `kem_key_backfill_lease`).
    case accountKEMBackfill = 10
}
