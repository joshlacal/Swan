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
}
