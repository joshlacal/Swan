import Foundation
import SwanCore

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

/// Public key material is supplied by the account/repository key provider.
/// Storage must never mint an identity key as a side effect of a reservation.
public struct SwanSigningKeyMaterial: Codable, Sendable, Equatable {
    public let keyID: String
    public let keyType: String
    public let publicKey: Data

    public init(keyID: String, keyType: String, publicKey: Data) throws {
        guard keyID == "#atproto", keyType == "Multikey",
              publicKey.count == 32 || publicKey.count == 33 else {
            throw AccountControlStoreError.malformedRecord
        }
        self.keyID = keyID
        self.keyType = keyType
        self.publicKey = publicKey
    }
}

public protocol SwanDidWebReservationStore: Sendable {
    func reserveDidWebSigningKey(requestID: String, accountDID: String?, targetDID: String,
                                 handle: String, expiresAt: Date, pdsURL: String,
                                 publicURL: String, signingKey: SwanSigningKeyMaterial) async throws -> SwanPersistedDidWebReservation
    func persistDidWebSigningReservation(_ reservation: SwanPersistedDidWebReservation) async throws
    func loadDidWebSigningReservation(requestID: String) async throws -> SwanPersistedDidWebReservation?
    func markDidWebSigningReservationCommitted(requestID: String) async throws
    func releaseDidWebSigningReservation(requestID: String) async throws
    func repairDidWebSigningReservation(requestID: String) async throws
    func purgeExpiredDidWebSigningReservations(now: Date) async throws -> [String]
    func committedDidWebSigningReservation(accountDID: String) async throws -> SwanPersistedDidWebReservation?
}

public protocol SwanIdentityReservedMaterialStore: Sendable {
    func reservedMaterial(accountDID: String) async throws -> SwanPersistedDidWebReservation?
}

/// Storage-side receipt consumption. The Accounts adapter turns the typed
/// operation into this dependency-neutral form so SQLite remains below the
/// account service target.
public protocol SwanIdentityStepUpReceiptStore: Sendable {
    func consumeIdentityStepUpReceipt(sessionID: String, accountDID: String,
                                      operation: String, mfaStrength: String,
                                      verifiedAt: Date, expiresAt: Date,
                                      receiptDigest: Data, now: Date) async throws
}

/// A receipt presented with an identity mutation. Implementations must consume
/// it in the same transaction as the mutation; this type deliberately carries
/// all of the predicates needed by the durable CAS.
public struct SwanIdentityStepUpReceipt: Sendable, Equatable {
    public let sessionID: String
    public let accountDID: String
    public let operation: String
    public let mfaStrength: String
    public let verifiedAt: Date
    public let expiresAt: Date
    public let receiptDigest: Data

    public init(sessionID: String, accountDID: String, operation: String,
                mfaStrength: String, verifiedAt: Date, expiresAt: Date,
                receiptDigest: Data) throws {
        guard !sessionID.isEmpty, !accountDID.isEmpty, !operation.isEmpty,
              !mfaStrength.isEmpty, verifiedAt <= expiresAt,
              receiptDigest.count == 32 else {
            throw SwanError.invalidIdentifier("identity step-up receipt")
        }
        self.sessionID = sessionID
        self.accountDID = accountDID
        self.operation = operation
        self.mfaStrength = mfaStrength
        self.verifiedAt = verifiedAt
        self.expiresAt = expiresAt
        self.receiptDigest = receiptDigest
    }
}

/// Transactional identity mutations. The receipt, when present, is consumed
/// before the mutation's CAS and rolls back with it on any failure.
public protocol SwanAtomicDidWebClaimStore: SwanGraceAwareIdentityBindingStore {
    func commitDidWebClaimAtomically(_ request: DidWebClaimCommitRequest,
                                     history: IdentityBindingHistoryEntry?, now: Date,
                                     gracePeriod: TimeInterval,
                                     stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> Bool
}

public protocol SwanIdentityBindingEnumerating: Sendable {
    func identityBindings(afterAccountDID: String?, limit: Int) async throws -> [IdentityBinding]
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

public protocol SwanAtomicIdentityContinuityStore: SwanConditionalIdentityContinuityStore {
    func compareAndPersistIdentityContinuityAtomically(expected: IdentityBinding,
                                                       replacement: IdentityBinding,
                                                       now: Date,
                                                       stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> IdentityBinding
}

public protocol SwanIdentityBindingHistoryStore: Sendable {
    func identityBindingHistory(accountDID: String) async throws -> [IdentityBindingHistoryEntry]
}

public protocol SwanExpiredIdentityClaimReleasingStore: IdentityBindingStore {
    func purgeExpiredIdentityClaimsReturningRequests(now: Date) async throws -> [String]
}
