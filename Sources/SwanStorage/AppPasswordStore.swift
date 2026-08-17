import Foundation
import SwanCore

/// Canonical app-password admission policy shared by the storage service and
/// SQLite's durable trigger. Keeping the boundary here prevents a service-side
/// limit from drifting above a schema-side limit and turning a typed refusal
/// into an opaque database error.
public enum AppPasswordStorePolicy {
    /// Current-main's canonical per-account ceiling. Keep this value shared
    /// with the SQLite admission trigger so populated databases can retain
    /// more than the old account-program alpha limit without a split-brain
    /// refusal between the service and storage layers.
    public static let maximumPerAccount = 100
}

/// One app password, as it is safe to show a caller.
///
/// Deliberately carries no credential material. The secret exists exactly once,
/// in the return value of the issuing call, and is never readable again — not
/// by `listAppPasswords`, not by an operator, not from a backup.
public struct AppPasswordRecord: Sendable, Equatable {
    /// Stable identifier, so a credential can be named without naming its
    /// secret.
    public let id: String
    public let did: String
    /// Client-supplied label. Unique per account so a user can tell two
    /// credentials apart when revoking one.
    public let name: String
    /// The effective scope string, space-separated and canonical.
    ///
    /// Stored verbatim as the scope evaluator's `rawScopes` source. Refresh
    /// re-derives from THIS row rather than from the session (§D5), so editing
    /// an app password narrows its live sessions and revoking it ends them.
    public let scopes: String
    public let createdAt: Date

    public init(id: String, did: String, name: String, scopes: String, createdAt: Date) {
        self.id = id
        self.did = did
        self.name = name
        self.scopes = scopes
        self.createdAt = createdAt
    }
}

public enum AppPasswordStoreError: Error, Sendable, Equatable {
    /// The account already has an app password with this name.
    case duplicateName
    /// The account is at its app-password ceiling.
    case limitReached
    /// No such account, or one whose status does not authorize it.
    case unknownAccount
}

/// Persistence for app passwords.
///
/// **This layer never sees a password.** It stores and matches an opaque
/// digest, computed by `SwanAccounts.AppPasswordCredentials`, which owns the
/// KDF and its policy. Keeping the secret out of the storage boundary means the
/// store can be exercised without libsodium, and that no query in this module
/// can accidentally log or project one.
public protocol AppPasswordStore: Sendable {
    /// Records one app password against a precomputed digest.
    ///
    /// `scopes` is stored verbatim; validation happens before this point (§D6 —
    /// an unparseable scope is REFUSED at creation rather than silently
    /// granting nothing).
    func createAppPassword(
        did: String,
        name: String,
        scopes: String,
        digest: Data,
        now: Date
    ) async throws -> AppPasswordRecord

    /// Never returns credential material.
    func listAppPasswords(did: String) async throws -> [AppPasswordRecord]

    /// Removes the row. A missing row is not an error — revocation is
    /// idempotent, and reporting "no such password" would let a caller probe
    /// which names an account holds.
    func revokeAppPassword(did: String, name: String) async throws

    /// Resolves a presented digest to its row, or `nil`.
    ///
    /// One indexed probe. Because the digest is deterministic for a given
    /// account and secret, this is never a scan that checks each row in turn —
    /// see `AppPasswordCredentials` for why that matters.
    func appPassword(did: String, digest: Data) async throws -> AppPasswordRecord?
}
