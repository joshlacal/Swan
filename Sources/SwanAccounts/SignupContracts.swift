import Foundation
import SwanCore

/// Signup policy and its public advertisement are one value.  In particular,
/// invite advertisement can never be enabled independently of enforcement.
public enum SignupPolicy: String, Codable, CaseIterable, Sendable {
    case closed
    case inviteRequired
    case openProtected

    public var advertisesInviteCodeRequired: Bool { self == .inviteRequired }
    public var requiresTurnstile: Bool { self == .openProtected }
    public var permitsPublicSignup: Bool { self != .closed }
}

public enum SignupAuthorizationState: String, Codable, CaseIterable, Sendable {
    case issued
    case committing
    case committed
    case failed
}

public struct SignupAuthorizationID: Codable, Hashable, Sendable, Equatable {
    public let rawValue: String

    public init(rawValue: String) throws {
        guard (1 ... 128).contains(rawValue.utf8.count),
              rawValue.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (65 ... 90).contains($0)
                      || (97 ... 122).contains($0) || $0 == 45 || $0 == 95
              }) else {
            throw SwanError.invalidIdentifier("signup authorization")
        }
        self.rawValue = rawValue
    }
}

/// A durable two-phase signup authorization. Proofs and invite material are
/// represented by fixed-size keyed digests; no raw code can cross storage.
public struct SignupAuthorization: Codable, Sendable, Equatable {
    public let id: SignupAuthorizationID
    public let requestID: String
    public let policy: SignupPolicy
    public let handle: String
    public let email: String?
    public let identityDID: String?
    public let emailProofDigest: Data?
    public let inviteDigest: Data?
    public let clientIPBucketDigest: Data
    public let state: SignupAuthorizationState
    public let issuedAt: Date
    public let expiresAt: Date
    public let leaseExpiresAt: Date?

    public init(
        id: SignupAuthorizationID,
        requestID: String,
        policy: SignupPolicy,
        handle: String,
        email: String? = nil,
        identityDID: String? = nil,
        emailProofDigest: Data? = nil,
        inviteDigest: Data? = nil,
        clientIPBucketDigest: Data,
        state: SignupAuthorizationState = .issued,
        issuedAt: Date,
        expiresAt: Date,
        leaseExpiresAt: Date? = nil
    ) throws {
        guard !requestID.isEmpty, requestID.utf8.count <= 128,
              clientIPBucketDigest.count == 32,
              [emailProofDigest, inviteDigest].compactMap({ $0 }).allSatisfy({ $0.count == 32 }),
              expiresAt >= issuedAt,
              leaseExpiresAt.map({ $0 >= issuedAt && $0 <= expiresAt }) ?? true else {
            throw SwanError.invalidIdentifier("signup authorization")
        }
        self.id = id
        self.requestID = requestID
        self.policy = policy
        self.handle = handle
        self.email = email
        self.identityDID = identityDID
        self.emailProofDigest = emailProofDigest
        self.inviteDigest = inviteDigest
        self.clientIPBucketDigest = clientIPBucketDigest
        self.state = state
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.leaseExpiresAt = leaseExpiresAt
    }
}

public struct SignupInvite: Codable, Sendable, Equatable {
    public let digest: Data
    public let issuedAt: Date
    public let expiresAt: Date?
    public let redeemedAt: Date?
    public let redemptionAccountDID: String?

    public init(digest: Data, issuedAt: Date, expiresAt: Date? = nil, redeemedAt: Date? = nil, redemptionAccountDID: String? = nil) throws {
        guard digest.count == 32, expiresAt.map({ $0 >= issuedAt }) ?? true,
              redeemedAt.map({ $0 >= issuedAt }) ?? true else {
            throw SwanError.invalidIdentifier("signup invite digest")
        }
        self.digest = digest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.redeemedAt = redeemedAt
        self.redemptionAccountDID = redemptionAccountDID
    }
}

public protocol SignupAuthorizationStore: Sendable {
    func reserve(_ authorization: SignupAuthorization, now: Date) async throws
    func authorization(id: SignupAuthorizationID, now: Date) async throws -> SignupAuthorization?
    func commit(id: SignupAuthorizationID, accountDID: String, now: Date) async throws -> SignupAuthorization
    func fail(id: SignupAuthorizationID, now: Date) async throws
    func redeemInvite(digest: Data, accountDID: String, now: Date) async throws
    func purgeExpiredSignupState(now: Date) async throws
}
