import Foundation
import SwanCore
import SwanStorage

/// Signup policy and its public advertisement are one value.  In particular,
/// invite advertisement can never be enabled independently of enforcement.
public enum SignupPolicy: String, Codable, CaseIterable, Sendable {
    case closed
    case inviteRequired
    case openProtected

    public var advertisesInviteCodeRequired: Bool {
        self == .inviteRequired
    }

    public var requiresTurnstile: Bool {
        self == .openProtected
    }

    public var permitsPublicSignup: Bool {
        self != .closed
    }
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
              })
        else {
            throw SwanError.invalidIdentifier("signup authorization")
        }
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
}

/// A durable two-phase signup authorization. Proofs and invite material are
/// represented by fixed-size keyed digests; no raw code can cross storage.
public struct SignupAuthorization: Codable, Sendable, Equatable {
    public let id: SignupAuthorizationID
    public let requestID: String
    public let policy: SignupPolicy
    public let accountDID: String?
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
        accountDID: String? = nil,
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
              leaseExpiresAt.map({ $0 >= issuedAt && $0 <= expiresAt }) ?? true
        else {
            throw SwanError.invalidIdentifier("signup authorization")
        }
        self.id = id
        self.requestID = requestID
        self.policy = policy
        self.accountDID = accountDID
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

    private enum CodingKeys: String, CodingKey {
        case id, requestID, policy, accountDID, handle, email, identityDID, emailProofDigest,
             inviteDigest, clientIPBucketDigest, state, issuedAt, expiresAt, leaseExpiresAt
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: c.decode(SignupAuthorizationID.self, forKey: .id),
            requestID: c.decode(String.self, forKey: .requestID),
            policy: c.decode(SignupPolicy.self, forKey: .policy),
            accountDID: c.decodeIfPresent(String.self, forKey: .accountDID),
            handle: c.decode(String.self, forKey: .handle),
            email: c.decodeIfPresent(String.self, forKey: .email),
            identityDID: c.decodeIfPresent(String.self, forKey: .identityDID),
            emailProofDigest: c.decodeIfPresent(Data.self, forKey: .emailProofDigest),
            inviteDigest: c.decodeIfPresent(Data.self, forKey: .inviteDigest),
            clientIPBucketDigest: c.decode(Data.self, forKey: .clientIPBucketDigest),
            state: c.decode(SignupAuthorizationState.self, forKey: .state),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            expiresAt: c.decode(Date.self, forKey: .expiresAt),
            leaseExpiresAt: c.decodeIfPresent(Date.self, forKey: .leaseExpiresAt)
        )
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
              redeemedAt.map({ $0 >= issuedAt }) ?? true
        else {
            throw SwanError.invalidIdentifier("signup invite digest")
        }
        self.digest = digest
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.redeemedAt = redeemedAt
        self.redemptionAccountDID = redemptionAccountDID
    }

    private enum CodingKeys: String, CodingKey { case digest, issuedAt, expiresAt, redeemedAt, redemptionAccountDID }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            digest: c.decode(Data.self, forKey: .digest),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            expiresAt: c.decodeIfPresent(Date.self, forKey: .expiresAt),
            redeemedAt: c.decodeIfPresent(Date.self, forKey: .redeemedAt),
            redemptionAccountDID: c.decodeIfPresent(String.self, forKey: .redemptionAccountDID)
        )
    }
}

public struct SignupFinalizationRequest: Codable, Sendable, Equatable {
    public let authorizationID: SignupAuthorizationID
    public let accountDID: String
    public let handle: String
    public let identityDID: String
    public let reservedKeyID: String?
    public let managementSession: ManagementSessionMetadata
    public let sessionDigest: Data
    public let csrfDigest: Data
    public let emailProofDigest: Data?
    public let inviteDigest: Data?
    public let preAuthCSRFDigest: Data
    public let idempotencyKey: String

    public init(authorizationID: SignupAuthorizationID, accountDID: String, handle: String, identityDID: String, reservedKeyID: String?, managementSession: ManagementSessionMetadata, sessionDigest: Data, csrfDigest: Data, emailProofDigest: Data?, inviteDigest: Data?, preAuthCSRFDigest: Data, idempotencyKey: String) throws {
        guard !accountDID.isEmpty, !handle.isEmpty, !identityDID.isEmpty, !idempotencyKey.isEmpty,
              sessionDigest.count == 32, csrfDigest.count == 32, preAuthCSRFDigest.count == 32,
              [emailProofDigest, inviteDigest].compactMap({ $0 }).allSatisfy({ $0.count == 32 })
        else {
            throw SwanError.invalidIdentifier("signup finalization")
        }
        self.authorizationID = authorizationID
        self.accountDID = accountDID
        self.handle = handle
        self.identityDID = identityDID
        self.reservedKeyID = reservedKeyID
        self.managementSession = managementSession
        self.sessionDigest = sessionDigest
        self.csrfDigest = csrfDigest
        self.emailProofDigest = emailProofDigest
        self.inviteDigest = inviteDigest
        self.preAuthCSRFDigest = preAuthCSRFDigest
        self.idempotencyKey = idempotencyKey
    }

    private enum CodingKeys: String, CodingKey {
        case authorizationID, accountDID, handle, identityDID, reservedKeyID, managementSession,
             sessionDigest, csrfDigest, emailProofDigest, inviteDigest, preAuthCSRFDigest, idempotencyKey
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            authorizationID: c.decode(SignupAuthorizationID.self, forKey: .authorizationID),
            accountDID: c.decode(String.self, forKey: .accountDID),
            handle: c.decode(String.self, forKey: .handle),
            identityDID: c.decode(String.self, forKey: .identityDID),
            reservedKeyID: c.decodeIfPresent(String.self, forKey: .reservedKeyID),
            managementSession: c.decode(ManagementSessionMetadata.self, forKey: .managementSession),
            sessionDigest: c.decode(Data.self, forKey: .sessionDigest),
            csrfDigest: c.decode(Data.self, forKey: .csrfDigest),
            emailProofDigest: c.decodeIfPresent(Data.self, forKey: .emailProofDigest),
            inviteDigest: c.decodeIfPresent(Data.self, forKey: .inviteDigest),
            preAuthCSRFDigest: c.decode(Data.self, forKey: .preAuthCSRFDigest),
            idempotencyKey: c.decode(String.self, forKey: .idempotencyKey)
        )
    }
}

public struct SignupFinalizationResult: Codable, Sendable, Equatable {
    public let accountDID: String
    public let managementSessionID: ManagementSessionID
    public let idempotencyKey: String
    public let committedAt: Date

    public init(accountDID: String, managementSessionID: ManagementSessionID, idempotencyKey: String, committedAt: Date) throws {
        guard !accountDID.isEmpty, !idempotencyKey.isEmpty else { throw SwanError.invalidIdentifier("signup finalization result") }
        self.accountDID = accountDID
        self.managementSessionID = managementSessionID
        self.idempotencyKey = idempotencyKey
        self.committedAt = committedAt
    }

    private enum CodingKeys: String, CodingKey { case accountDID, managementSessionID, idempotencyKey, committedAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            accountDID: c.decode(String.self, forKey: .accountDID),
            managementSessionID: c.decode(ManagementSessionID.self, forKey: .managementSessionID),
            idempotencyKey: c.decode(String.self, forKey: .idempotencyKey),
            committedAt: c.decode(Date.self, forKey: .committedAt)
        )
    }
}

public protocol SignupAuthorizationStore: Sendable {
    func reserve(_ authorization: SignupAuthorization, now: Date) async throws
    func authorization(id: SignupAuthorizationID, now: Date) async throws -> SignupAuthorization?
    func finalize(_ request: SignupFinalizationRequest, now: Date) async throws -> SignupFinalizationResult
    func purgeExpiredSignupState(now: Date) async throws
}
