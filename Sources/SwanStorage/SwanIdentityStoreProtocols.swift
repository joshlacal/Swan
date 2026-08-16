import Foundation

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
