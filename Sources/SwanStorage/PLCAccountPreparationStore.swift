import Foundation
import SwanPublicRepository

public enum PLCAccountPreparationStage: Int, Codable, Sendable, CaseIterable, Comparable {
    case keysStored = 1
    case repositoryInstalled = 2
    case submissionPending = 3
    case submitted = 4

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var isCanonicalValue: Bool {
        Self(rawValue: rawValue) == self
    }
}

public enum PLCAccountPreparationStoreError: Error, Sendable, Equatable {
    case invalidInput
    case conflict
    case notFound
    case invalidTransition
    case malformedRecord
    case unavailable
}

/// Public-only coordination state in `control.sqlite`. It deliberately cannot
/// represent a password, verifier, key byte, token, CAR, or account status.
public struct PLCAccountPreparationIntent: Sendable, Equatable {
    public let requestID: String
    public let did: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let repositoryRevision: String
    public let operationCID: String
    public let stage: PLCAccountPreparationStage

    public init(
        requestID: String,
        did: String,
        canonicalHandle: String,
        pdsOrigin: String,
        repositoryRevision: String,
        operationCID: String,
        stage: PLCAccountPreparationStage
    ) throws {
        guard PLCAccountPreparationValidation.isRequestID(requestID),
              PLCAccountPreparationValidation.isDID(did),
              PLCAccountPreparationValidation.isCanonicalHandle(canonicalHandle),
              PLCAccountPreparationValidation.isOrigin(pdsOrigin),
              PLCAccountPreparationValidation.isRevision(repositoryRevision),
              PLCAccountPreparationValidation.isCID(operationCID),
              stage.isCanonicalValue else {
            throw PLCAccountPreparationStoreError.invalidInput
        }
        self.requestID = requestID
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.repositoryRevision = repositoryRevision
        self.operationCID = operationCID
        self.stage = stage
    }

    public func advancing(to stage: PLCAccountPreparationStage) throws -> Self {
        guard stage > self.stage else {
            throw PLCAccountPreparationStoreError.invalidTransition
        }
        return try Self(
            requestID: requestID,
            did: did,
            canonicalHandle: canonicalHandle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: repositoryRevision,
            operationCID: operationCID,
            stage: stage
        )
    }
}

/// Public identity facts stored beside the repository truth for one DID. The
/// signed operation is bounded canonical JSON; the public repository remains
/// in its existing verified CAR table and is referenced only by commit CID.
public struct PLCAccountPreparationJournal: Sendable, Equatable {
    public let requestID: String
    public let did: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let repositoryRevision: String
    public let operationCID: String
    public let signedOperationJSON: Data
    public let signingKey: AccountControlKeyReference
    public let rotationKey: AccountControlKeyReference
    public let publicGenesisCommitCID: String?
    public let stage: PLCAccountPreparationStage

    public init(
        requestID: String,
        did: String,
        canonicalHandle: String,
        pdsOrigin: String,
        repositoryRevision: String,
        operationCID: String,
        signedOperationJSON: Data,
        signingKey: AccountControlKeyReference,
        rotationKey: AccountControlKeyReference,
        publicGenesisCommitCID: String?,
        stage: PLCAccountPreparationStage
    ) throws {
        guard PLCAccountPreparationValidation.isRequestID(requestID),
              PLCAccountPreparationValidation.isDID(did),
              PLCAccountPreparationValidation.isCanonicalHandle(canonicalHandle),
              PLCAccountPreparationValidation.isOrigin(pdsOrigin),
              PLCAccountPreparationValidation.isRevision(repositoryRevision),
              PLCAccountPreparationValidation.isCID(operationCID),
              !signedOperationJSON.isEmpty,
              signedOperationJSON.count <= 32 * 1_024,
              signingKey.isCanonicalValue,
              rotationKey.isCanonicalValue,
              signingKey.purpose == .signing,
              rotationKey.purpose == .rotation,
              signingKey.generation == 1,
              rotationKey.generation == 1,
              stage.isCanonicalValue,
              (stage == .keysStored) == (publicGenesisCommitCID == nil),
              publicGenesisCommitCID.map(PLCAccountPreparationValidation.isCID) ?? true else {
            throw PLCAccountPreparationStoreError.invalidInput
        }
        self.requestID = requestID
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.repositoryRevision = repositoryRevision
        self.operationCID = operationCID
        self.signedOperationJSON = signedOperationJSON
        self.signingKey = signingKey
        self.rotationKey = rotationKey
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.stage = stage
    }

    public func advancing(
        to stage: PLCAccountPreparationStage,
        publicGenesisCommitCID: String?
    ) throws -> Self {
        guard stage > self.stage else {
            throw PLCAccountPreparationStoreError.invalidTransition
        }
        let resolvedCommitCID = publicGenesisCommitCID ?? self.publicGenesisCommitCID
        return try Self(
            requestID: requestID,
            did: did,
            canonicalHandle: canonicalHandle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: repositoryRevision,
            operationCID: operationCID,
            signedOperationJSON: signedOperationJSON,
            signingKey: signingKey,
            rotationKey: rotationKey,
            publicGenesisCommitCID: resolvedCommitCID,
            stage: stage
        )
    }
}

public enum PLCAccountPreparationReservation: Sendable, Equatable {
    case created
    case existing(PLCAccountPreparationIntent)
}

public protocol PLCAccountPreparationIntentStore: Sendable {
    func reservePLCAccountPreparationIntent(
        _ intent: PLCAccountPreparationIntent
    ) async throws -> PLCAccountPreparationReservation

    func plcAccountPreparationIntent(
        requestID: String
    ) async throws -> PLCAccountPreparationIntent?

    func advancePLCAccountPreparationIntent(
        requestID: String,
        expectedStage: PLCAccountPreparationStage,
        to stage: PLCAccountPreparationStage
    ) async throws -> PLCAccountPreparationIntent
}

public protocol PLCAccountPreparationJournalStore: Sendable {
    func installPLCAccountPreparationJournal(
        _ journal: PLCAccountPreparationJournal
    ) async throws -> PLCAccountPreparationJournal

    func plcAccountPreparationJournal() async throws -> PLCAccountPreparationJournal?

    func advancePLCAccountPreparationJournal(
        requestID: String,
        expectedStage: PLCAccountPreparationStage,
        to stage: PLCAccountPreparationStage,
        publicGenesisCommitCID: String?
    ) async throws -> PLCAccountPreparationJournal
}

public protocol PLCAccountPreparationAccountStore:
    PLCAccountPreparationJournalStore,
    PublicRepositoryGenesisStore
{}

public protocol PLCAccountPreparationAccountStoreOpener: Sendable {
    func openPLCAccountPreparationStore(
        did: String
    ) async throws -> any PLCAccountPreparationAccountStore
}

enum PLCAccountPreparationValidation {
    static func isRequestID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
        }
    }

    static func isDID(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count == 3 && parts[0] == "did" && parts[1] == "plc"
            && parts[2].utf8.count == 24
            && parts[2].utf8.allSatisfy {
                ($0 >= 97 && $0 <= 122) || ($0 >= 50 && $0 <= 55)
            }
    }

    static func isCanonicalHandle(_ value: String) -> Bool {
        !value.isEmpty && value == value.lowercased() && value.utf8.count <= 253
            && value.contains(".")
    }

    static func isOrigin(_ value: String) -> Bool {
        guard value.utf8.count <= 2_048,
              let url = URL(string: value),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.path.isEmpty, let scheme = components.scheme,
              let host = components.host, !host.isEmpty else { return false }
        return scheme == "https" || (scheme == "http" && (host == "127.0.0.1" || host == "::1"))
    }

    static func isRevision(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 64
            && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }

    static func isCID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256
            && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }
}
