import Foundation

public struct SwanPersistedDidWebReservation: Codable, Sendable, Equatable {
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
    public let claimServiceEndpoint: String
    public let state: State

    public init(requestID: String, accountDID: String?, targetDID: String, handle: String,
                keyID: String, keyType: String, publicKey: Data, nonce: Data,
                expiresAt: Date, claimBytes: Data, claimReceiptDigest: Data,
                pdsURL: String, claimServiceEndpoint: String, state: State = .issued) {
        self.requestID = requestID; self.accountDID = accountDID; self.targetDID = targetDID
        self.handle = handle; self.keyID = keyID; self.keyType = keyType; self.publicKey = publicKey
        self.nonce = nonce; self.expiresAt = expiresAt; self.claimBytes = claimBytes
        self.claimReceiptDigest = claimReceiptDigest; self.pdsURL = pdsURL
        self.claimServiceEndpoint = claimServiceEndpoint; self.state = state
    }
}

public protocol SwanDidWebReservationStore: Sendable {
    func reserveDidWebSigningKey(requestID: String, accountDID: String?, targetDID: String,
                                 handle: String, expiresAt: Date, pdsURL: String,
                                 publicURL: String) async throws -> SwanPersistedDidWebReservation
    func persistDidWebSigningReservation(_ reservation: SwanPersistedDidWebReservation) async throws
    func loadDidWebSigningReservation(requestID: String) async throws -> SwanPersistedDidWebReservation?
    func markDidWebSigningReservationCommitted(requestID: String) async throws
    func releaseDidWebSigningReservation(requestID: String) async throws
    func repairDidWebSigningReservation(requestID: String) async throws
    func purgeExpiredDidWebSigningReservations(now: Date) async throws -> [String]
}

/// Optional identity-store capabilities layered over the reviewed base
/// contract. Keeping these in SwanStorage avoids a SwanSQLite -> SwanAccounts
/// dependency cycle while allowing configured-grace and durable revalidation.
public protocol SwanGraceAwareIdentityBindingStore: IdentityBindingStore {
    func commitDidWebClaim(_ request: DidWebClaimCommitRequest,
                           history: IdentityBindingHistoryEntry?, now: Date,
                           gracePeriod: TimeInterval) async throws
}

public protocol SwanIdentityContinuityStore: Sendable {
    func persistIdentityContinuity(_ binding: IdentityBinding) async throws -> IdentityBinding
}

public protocol SwanConditionalIdentityContinuityStore: SwanIdentityContinuityStore {
    func compareAndPersistIdentityContinuity(expected: IdentityBinding, replacement: IdentityBinding) async throws -> IdentityBinding
}

public protocol SwanExpiredIdentityClaimReleasingStore: IdentityBindingStore {
    func purgeExpiredIdentityClaimsReturningRequests(now: Date) async throws -> [String]
}
