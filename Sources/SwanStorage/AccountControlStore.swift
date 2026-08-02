import Foundation

/// Durable lifecycle states for an account control plane. Only `active`
/// authorizes an account; every other known or future state fails closed.
public enum AccountControlStatus: Codable, Sendable, Equatable {
    case active
    case deactivated
    case deleting
    case deleted
    case takendown
    case suspended
    case desynchronized
    case throttled
    case unknown(String)

    public init(rawValue: String) throws {
        guard Self.isCanonicalToken(rawValue) else {
            throw AccountControlStoreError.invalidStatus
        }
        self = switch rawValue {
        case "active": .active
        case "deactivated": .deactivated
        case "deleting": .deleting
        case "deleted": .deleted
        case "takendown": .takendown
        case "suspended": .suspended
        case "desynchronized": .desynchronized
        case "throttled": .throttled
        default: .unknown(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .active: "active"
        case .deactivated: "deactivated"
        case .deleting: "deleting"
        case .deleted: "deleted"
        case .takendown: "takendown"
        case .suspended: "suspended"
        case .desynchronized: "desynchronized"
        case .throttled: "throttled"
        case let .unknown(value): value
        }
    }

    public var authorizesAccount: Bool { self == .active }

    /// A public enum case can be constructed directly, so a syntactically
    /// valid `.unknown("active")` must not be accepted as a distinct status
    /// which serializes to the authorizing `active` token. Every durable
    /// boundary requires this exact enum/raw-value round trip.
    public var isCanonicalValue: Bool {
        (try? AccountControlStatus(rawValue: rawValue)) == self
    }

    public init(from decoder: any Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else {
            throw AccountControlStoreError.invalidStatus
        }
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static func isCanonicalToken(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64,
              let first = value.utf8.first,
              (97 ... 122).contains(first) else {
            return false
        }
        return value.utf8.allSatisfy {
            (97 ... 122).contains($0)
                || (48 ... 57).contains($0)
                || $0 == 45
                || $0 == 95
        }
    }
}

/// The only legal account lifecycle edges. This policy is intentionally a
/// value, rather than allowing a storage caller to write arbitrary strings.
/// Operational moderation states remain fail-closed, but an operator may move
/// a non-deleted account to `active` or `deactivated` after remediation.
public struct AccountStatusTransitionPolicy: Sendable, Equatable {
    public static let standard = AccountStatusTransitionPolicy()

    public init() {}

    public func permits(from source: AccountControlStatus, to destination: AccountControlStatus) -> Bool {
        guard source.isCanonicalValue, destination.isCanonicalValue,
              source != .deleting, source != .deleted else { return false }
        if source == destination { return true }
        switch destination {
        case .active, .deactivated:
            return true
        case .deleting, .deleted:
            // Permanent deletion is a resumable, multi-resource workflow.
            // A generic lifecycle write cannot bypass its control scrub,
            // key destruction, repository/CAS erasure, or PLC tombstone.
            return false
        case .takendown, .suspended, .desynchronized, .throttled, .unknown:
            return true
        }
    }

    public func validate(from source: AccountControlStatus, to destination: AccountControlStatus) throws {
        guard source.isCanonicalValue, destination.isCanonicalValue else {
            throw AccountControlStoreError.invalidStatus
        }
        guard permits(from: source, to: destination) else {
            throw AccountControlStoreError.invalidTransition
        }
    }
}

/// A durable reference to key material that is held by an external key store.
/// It deliberately contains only a purpose, generation, and deterministic
/// identifier. Private key bytes and export envelopes are not representable.
public struct AccountControlKeyReference: Codable, Sendable, Equatable, Hashable {
    public enum Purpose: String, Codable, Sendable, CaseIterable {
        case signing = "account-signing"
        case rotation = "account-rotation"
    }

    public let purpose: Purpose
    public let generation: UInt64
    public let reference: String

    public init(purpose: Purpose, generation: UInt64, reference: String? = nil) throws {
        guard generation > 0, generation <= UInt64(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        let expected = "\(purpose.rawValue):\(generation)"
        guard reference == nil || reference == expected else {
            throw AccountControlStoreError.invalidInput
        }
        self.purpose = purpose
        self.generation = generation
        self.reference = expected
    }

    /// Codable synthesis would assign stored properties directly and bypass
    /// the deterministic-reference invariant in `init`. Keep it explicit so
    /// decoded input cannot smuggle arbitrary text (including key material)
    /// into a later control-store write.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            purpose: container.decode(Purpose.self, forKey: .purpose),
            generation: container.decode(UInt64.self, forKey: .generation),
            reference: container.decode(String.self, forKey: .reference)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else { throw AccountControlStoreError.invalidInput }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(generation, forKey: .generation)
        try container.encode(reference, forKey: .reference)
    }

    /// Mirrors the initializer check for callers receiving a value through an
    /// opaque boundary. This is repeated by registration and SQLite writes as
    /// defense in depth.
    public var isCanonicalValue: Bool {
        (try? AccountControlKeyReference(
            purpose: purpose,
            generation: generation,
            reference: reference
        )) == self
    }

    private enum CodingKeys: String, CodingKey {
        case purpose
        case generation
        case reference
    }
}

/// Optional operator-declared facts retained after a logical deletion. The
/// metadata is intentionally limited to a timestamp and bounded explanation;
/// data/key erasure is a separate explicit operation outside this control API.
public struct AccountTombstoneMetadata: Codable, Sendable, Equatable {
    public let declaredAt: Date
    public let reason: String?

    public init(declaredAt: Date = Date(), reason: String? = nil) throws {
        guard AccountControlMetadata.isControlDate(declaredAt),
              reason.map(AccountControlMetadata.isSafeText) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        self.declaredAt = declaredAt
        self.reason = reason
    }

    /// Codable synthesis would assign stored properties directly and bypass
    /// the bounded operator-text and timestamp boundary above.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            declaredAt: container.decode(Date.self, forKey: .declaredAt),
            reason: container.decodeIfPresent(String.self, forKey: .reason)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else { throw AccountControlStoreError.invalidInput }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(declaredAt, forKey: .declaredAt)
        try container.encodeIfPresent(reason, forKey: .reason)
    }

    /// Keeps decoded or opaque-boundary values within the same operator-text
    /// and timestamp constraints as the initializer.
    public var isCanonicalValue: Bool {
        AccountControlMetadata.isControlDate(declaredAt)
            && (reason.map(AccountControlMetadata.isSafeText) ?? true)
    }

    private enum CodingKeys: String, CodingKey {
        case declaredAt
        case reason
    }
}

/// A declaration that an export manifest was prepared elsewhere. `reference`
/// is a canonical SHA-256 digest of that manifest (`sha256:` followed by 64
/// lowercase hexadecimal characters), never an export payload, key, recovery
/// phrase, or repository data. This is the only export value permitted in
/// `control.sqlite`.
public struct AccountExportMetadata: Codable, Sendable, Equatable {
    public let declaredAt: Date
    public let reference: String

    public init(declaredAt: Date = Date(), reference: String) throws {
        guard AccountControlMetadata.isControlDate(declaredAt),
              Self.isCanonicalManifestDigestReference(reference) else {
            throw AccountControlStoreError.invalidInput
        }
        self.declaredAt = declaredAt
        self.reference = reference
    }

    /// Codable synthesis would otherwise permit an arbitrary export string to
    /// bypass the digest-only initializer and be written by a later lifecycle
    /// transition.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            declaredAt: container.decode(Date.self, forKey: .declaredAt),
            reference: container.decode(String.self, forKey: .reference)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else { throw AccountControlStoreError.invalidInput }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(declaredAt, forKey: .declaredAt)
        try container.encode(reference, forKey: .reference)
    }

    /// A nonrecoverable reference to an externally stored export manifest.
    /// This is deliberately stricter than general safe text so no secret-like
    /// payload can use an export declaration as a persistence channel.
    public static func isCanonicalManifestDigestReference(_ value: String) -> Bool {
        guard value.utf8.count == 71, value.hasPrefix("sha256:") else { return false }
        return value.utf8.dropFirst(7).allSatisfy {
            (48 ... 57).contains($0) || (97 ... 102).contains($0)
        }
    }

    /// Mirrors the initializer for values that crossed an opaque boundary.
    public var isCanonicalValue: Bool {
        AccountControlMetadata.isControlDate(declaredAt)
            && Self.isCanonicalManifestDigestReference(reference)
    }

    private enum CodingKeys: String, CodingKey {
        case declaredAt
        case reference
    }
}

/// A declaration applied alongside a lifecycle transition. Keeping it
/// explicit prevents status changes from being mistaken for physical deletion.
public struct AccountLifecycleDeclaration: Sendable, Equatable {
    public let tombstone: AccountTombstoneMetadata?
    public let export: AccountExportMetadata?

    public init(
        tombstone: AccountTombstoneMetadata? = nil,
        export: AccountExportMetadata? = nil
    ) {
        self.tombstone = tombstone
        self.export = export
    }
}

/// Durable permanent-deletion stages. Each transition represents an external
/// side effect which cannot be enclosed in the control.sqlite transaction.
/// Callers may advance only one stage at a time and finalization is legal only
/// after account data destruction.
public enum AccountDeletionStage: String, Codable, Sendable, CaseIterable {
    /// The account is non-authorizing and all control-plane trust is gone.
    case controlScrubbed = "control-scrubbed"
    /// The configured PLC directory accepted the account tombstone while the
    /// rotation key was still available.
    case plcTombstoned = "plc-tombstoned"
    /// Every DID-bound key envelope and authenticated matching staging file
    /// has been durably removed from the account key store.
    case keyMaterialDestroyed = "key-material-destroyed"
    /// The per-account SQLite database and private/public CAS ownership have
    /// been durably removed by the later deletion coordinator.
    case accountDataDestroyed = "account-data-destroyed"

    public var next: Self? {
        switch self {
        case .controlScrubbed: .plcTombstoned
        case .plcTombstoned: .keyMaterialDestroyed
        case .keyMaterialDestroyed: .accountDataDestroyed
        case .accountDataDestroyed: nil
        }
    }

    public var isFinalizable: Bool { self == .accountDataDestroyed }
}

/// The minimum authenticated inputs needed to locate a pre-DID PLC staging
/// envelope. These values are retained through PLC tombstoning so the key-store
/// erasure step can authenticate the exact file; advancing to
/// `keyMaterialDestroyed` removes them.
public struct AccountDeletionStagingKeyBinding:
    Codable, Sendable, Equatable, Hashable
{
    public let requestID: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let repositoryRevision: String

    public init(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: String,
        repositoryRevision: String
    ) throws {
        guard PLCAccountPreparationValidation.isRequestID(requestID),
              PLCAccountPreparationValidation.isCanonicalHandle(
                  canonicalHandle
              ),
              PLCAccountPreparationValidation.isOrigin(pdsOrigin),
              PLCAccountPreparationValidation.isRevision(
                  repositoryRevision
              ) else {
            throw AccountDeletionStoreError.invalidInput
        }
        self.requestID = requestID
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.repositoryRevision = repositoryRevision
    }

    public var isCanonicalValue: Bool {
        (try? Self(
            requestID: requestID,
            canonicalHandle: canonicalHandle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: repositoryRevision
        )) == self
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            requestID: container.decode(String.self, forKey: .requestID),
            canonicalHandle: container.decode(
                String.self,
                forKey: .canonicalHandle
            ),
            pdsOrigin: container.decode(String.self, forKey: .pdsOrigin),
            repositoryRevision: container.decode(
                String.self,
                forKey: .repositoryRevision
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else {
            throw AccountDeletionStoreError.invalidInput
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(requestID, forKey: .requestID)
        try container.encode(canonicalHandle, forKey: .canonicalHandle)
        try container.encode(pdsOrigin, forKey: .pdsOrigin)
        try container.encode(repositoryRevision, forKey: .repositoryRevision)
    }

    private enum CodingKeys: String, CodingKey {
        case requestID
        case canonicalHandle
        case pdsOrigin
        case repositoryRevision
    }
}

/// One bounded, resumable permanent-deletion job. It deliberately carries no
/// password verifier, private key bytes, public genesis CID, repository path,
/// CAR, token, or repository payload. Until key erasure it may retain one
/// authenticated PLC-staging AAD binding (including the former handle and PDS
/// origin) plus a deterministic, non-secret rotation reference. Both are
/// removed before the final tombstone is written.
public struct AccountDeletionJob: Sendable, Equatable {
    public static let maximumStagingKeyBindings = 1

    public let did: String
    public let stage: AccountDeletionStage
    public let revision: UInt64
    public let requestedAt: Date
    public let updatedAt: Date
    public let tombstone: AccountTombstoneMetadata
    public let export: AccountExportMetadata?
    /// Non-secret locator retained only until PLC tombstoning and physical
    /// key destruction complete. Legacy rows may not have one; the
    /// coordinator must then fail closed instead of guessing a generation.
    public let rotationKey: AccountControlKeyReference?
    public let stagingKeyBindings: [AccountDeletionStagingKeyBinding]

    public init(
        did: String,
        stage: AccountDeletionStage,
        revision: UInt64,
        requestedAt: Date,
        updatedAt: Date,
        tombstone: AccountTombstoneMetadata,
        export: AccountExportMetadata?,
        rotationKey: AccountControlKeyReference?,
        stagingKeyBindings: [AccountDeletionStagingKeyBinding]
    ) throws {
        guard AccountControlMetadata.isDID(did),
              revision > 0, revision <= UInt64(Int.max),
              AccountControlMetadata.isControlDate(requestedAt),
              AccountControlMetadata.isControlDate(updatedAt),
              updatedAt >= requestedAt,
              tombstone.isCanonicalValue,
              export?.isCanonicalValue ?? true,
              rotationKey?.isCanonicalValue ?? true,
              rotationKey?.purpose == .rotation || rotationKey == nil,
              stagingKeyBindings.count
                  <= Self.maximumStagingKeyBindings,
              Set(stagingKeyBindings).count
                  == stagingKeyBindings.count,
              stagingKeyBindings.allSatisfy(\.isCanonicalValue),
              stage == .controlScrubbed || stage == .plcTombstoned
                  || stagingKeyBindings.isEmpty,
              stage == .controlScrubbed || stage == .plcTombstoned
                  || rotationKey == nil else {
            throw AccountDeletionStoreError.invalidInput
        }
        self.did = did
        self.stage = stage
        self.revision = revision
        self.requestedAt = requestedAt
        self.updatedAt = updatedAt
        self.tombstone = tombstone
        self.export = export
        self.rotationKey = rotationKey
        self.stagingKeyBindings = stagingKeyBindings
    }
}

/// The only durable account record left after permanent deletion completes.
/// The shape cannot represent handles, credentials, keys, PLC genesis state,
/// sessions, repository contents, or blob ownership.
public struct AccountDeletionTombstone: Sendable, Equatable {
    public let did: String
    public let finalizedAt: Date
    public let revision: UInt64
    public let tombstone: AccountTombstoneMetadata
    public let export: AccountExportMetadata?

    public init(
        did: String,
        finalizedAt: Date,
        revision: UInt64,
        tombstone: AccountTombstoneMetadata,
        export: AccountExportMetadata?
    ) throws {
        guard AccountControlMetadata.isDID(did),
              AccountControlMetadata.isControlDate(finalizedAt),
              revision > 0, revision <= UInt64(Int.max),
              tombstone.isCanonicalValue,
              export?.isCanonicalValue ?? true else {
            throw AccountDeletionStoreError.invalidInput
        }
        self.did = did
        self.finalizedAt = finalizedAt
        self.revision = revision
        self.tombstone = tombstone
        self.export = export
    }
}

public enum AccountDeletionStoreError: Error, Sendable, Equatable {
    case invalidInput
    case notFound
    case conflict
    case invalidStage
    case malformedRecord
    case unavailable
}

/// Transactional control-plane half of permanent deletion. Network calls,
/// key-store operations, account database/CAS erasure, and PLC writes must
/// occur outside these methods; their completion is recorded by monotonic
/// compare-and-swap stage transitions.
public protocol AccountDeletionControlStore: Sendable {
    func beginDeletion(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionJob

    func deletionJob(did: String) async throws -> AccountDeletionJob?

    /// Bounded restart inventory in DID lexical order.
    func pendingDeletionJobs(
        afterDID: String?,
        limit: Int
    ) async throws -> [AccountDeletionJob]

    func advanceDeletion(
        did: String,
        expectedStage: AccountDeletionStage,
        expectedRevision: UInt64,
        to stage: AccountDeletionStage,
        now: Date
    ) async throws -> AccountDeletionJob

    func finalizeDeletion(
        did: String,
        expectedRevision: UInt64,
        now: Date
    ) async throws -> AccountDeletionTombstone

    func tombstone(did: String) async throws -> AccountDeletionTombstone?
}

public enum AccountCredentialState: String, Codable, Sendable, Equatable {
    case missing
    case configured
}

/// Registry/control information returned to ordinary callers. The password
/// verifier intentionally does not appear here; callers must use the narrow
/// credential method on `AccountControlStore` when authentication is needed.
public struct AccountControlAccount: Sendable, Equatable {
    public let did: String
    public let canonicalHandle: String
    public let status: AccountControlStatus
    public let createdAt: Date
    public let updatedAt: Date
    public let credentialState: AccountCredentialState
    public let signingKey: AccountControlKeyReference?
    public let rotationKey: AccountControlKeyReference?
    /// Immutable public commitment to the verified empty public repository
    /// genesis which authorized this local registration. Legacy rows may lack
    /// it; callers requiring local-install provenance must reject that case.
    public let publicGenesisCommitCID: String?
    public let tombstone: AccountTombstoneMetadata?
    public let export: AccountExportMetadata?

    public init(
        did: String,
        canonicalHandle: String,
        status: AccountControlStatus,
        createdAt: Date,
        updatedAt: Date,
        credentialState: AccountCredentialState,
        signingKey: AccountControlKeyReference?,
        rotationKey: AccountControlKeyReference?,
        publicGenesisCommitCID: String? = nil,
        tombstone: AccountTombstoneMetadata? = nil,
        export: AccountExportMetadata? = nil
    ) throws {
        switch (signingKey, rotationKey) {
        case (.none, .none):
            break
        case let (.some(signing), .some(rotation)) where signing.generation == rotation.generation:
            break
        default:
            throw AccountControlStoreError.invalidInput
        }
        guard status.isCanonicalValue else {
            throw AccountControlStoreError.invalidStatus
        }
        guard AccountControlMetadata.isDID(did),
              AccountControlMetadata.isCanonicalHandle(canonicalHandle),
              signingKey?.isCanonicalValue ?? true,
              rotationKey?.isCanonicalValue ?? true,
              signingKey?.purpose == .signing || signingKey == nil,
              rotationKey?.purpose == .rotation || rotationKey == nil,
              publicGenesisCommitCID.map(AccountControlMetadata.isPublicGenesisCommitCID) ?? true,
              tombstone?.isCanonicalValue ?? true,
              export?.isCanonicalValue ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.status = status
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.credentialState = credentialState
        self.signingKey = signingKey
        self.rotationKey = rotationKey
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.tombstone = tombstone
        self.export = export
    }
}

/// The exact atomic input for a new account. A verifier is stored atomically
/// with its registry entry, but it is only readable through `credential`.
public struct AccountControlRegistration: Sendable {
    public let did: String
    public let canonicalHandle: String
    public let passwordVerifier: String
    public let signingKey: AccountControlKeyReference
    public let rotationKey: AccountControlKeyReference
    /// Optional only to keep legacy non-local registration paths explicit.
    /// `LocalAccountProvisioner` always supplies this verified public CID.
    public let publicGenesisCommitCID: String?
    public let createdAt: Date

    public init(
        did: String,
        canonicalHandle: String,
        passwordVerifier: String,
        signingKey: AccountControlKeyReference,
        rotationKey: AccountControlKeyReference,
        publicGenesisCommitCID: String? = nil,
        createdAt: Date = Date()
    ) throws {
        guard signingKey.generation == rotationKey.generation,
              AccountControlMetadata.isDID(did),
              AccountControlMetadata.isCanonicalHandle(canonicalHandle),
              AccountControlMetadata.isVerifier(passwordVerifier),
              signingKey.isCanonicalValue,
              rotationKey.isCanonicalValue,
              signingKey.purpose == .signing,
              rotationKey.purpose == .rotation,
              publicGenesisCommitCID.map(AccountControlMetadata.isPublicGenesisCommitCID) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.passwordVerifier = passwordVerifier
        self.signingKey = signingKey
        self.rotationKey = rotationKey
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.createdAt = createdAt
    }
}

/// The only durable control-plane key transition permitted by the alpha.
/// Rotation is a compare-and-swap from one generation to the immediately
/// following generation; callers cannot move an account backwards or skip a
/// generation.
public struct AccountControlKeyRotationRequest: Sendable, Equatable {
    public let expectedGeneration: UInt64
    public let signingKey: AccountControlKeyReference
    public let rotationKey: AccountControlKeyReference

    public init(
        expectedGeneration: UInt64,
        signingKey: AccountControlKeyReference,
        rotationKey: AccountControlKeyReference
    ) throws {
        guard expectedGeneration > 0,
              expectedGeneration < UInt64.max,
              signingKey.purpose == .signing,
              rotationKey.purpose == .rotation,
              signingKey.generation == rotationKey.generation,
              signingKey.generation == expectedGeneration + 1,
              signingKey.isCanonicalValue,
              rotationKey.isCanonicalValue else {
            throw AccountControlStoreError.invalidInput
        }
        self.expectedGeneration = expectedGeneration
        self.signingKey = signingKey
        self.rotationKey = rotationKey
    }
}

/// Authentication-only credential material. It is deliberately separate from
/// `AccountControlAccount` so ordinary DID/handle lookups cannot leak it.
public struct AccountControlCredential: Sendable {
    public let did: String
    public let verifier: String
    public let updatedAt: Date

    public init(did: String, verifier: String, updatedAt: Date) throws {
        guard AccountControlMetadata.isDID(did),
              AccountControlMetadata.isVerifier(verifier) else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.verifier = verifier
        self.updatedAt = updatedAt
    }
}

public enum AccountCredentialReplacement: Sendable, Equatable {
    case replaced
    /// Another successful authentication already replaced this verifier. The
    /// caller must not overwrite it with a stale rehash result.
    case unchanged
}

/// Result of the storage transaction which is the linearization point between
/// a verified password and an account becoming authenticated. It intentionally
/// contains no verifier.
public struct AccountAuthenticationFinalization: Sendable, Equatable {
    public let account: AccountControlAccount
    public let credentialWasReplaced: Bool

    public init(account: AccountControlAccount, credentialWasReplaced: Bool) {
        self.account = account
        self.credentialWasReplaced = credentialWasReplaced
    }
}

public enum AccountControlStoreError: Error, Sendable, Equatable {
    case notFound
    case duplicateDID
    case duplicateHandle
    case invalidInput
    case invalidStatus
    case invalidTransition
    case malformedRecord
    case unavailable
}

/// The two user-facing email proofs deliberately share one keyed-digest-only
/// durable representation. Raw bearer proofs are delivery-only and never
/// enter the account registry, its logs, or a decoded storage value.
public enum AccountEmailTokenPurpose: String, Sendable, Equatable {
    case verifyEmail = "verify-email"
    case passwordRecovery = "password-recovery"
}

/// One canonical ASCII mailbox representation shared by association, lookup,
/// and SMTP delivery. Swan intentionally does not accept quoted local parts,
/// comments, Unicode, address literals, or other RFC mailbox forms which
/// cannot be safely and consistently normalized across those boundaries.
public struct AccountEmailAddress: Sendable, Equatable, Hashable {
    public let value: String

    public init(_ value: String) throws {
        let canonical = value.lowercased()
        guard Self.isCanonicalMailbox(canonical),
              value.utf8.allSatisfy({ $0 < 0x80 }) else {
            throw AccountControlStoreError.invalidInput
        }
        self.value = canonical
    }

    public static func isCanonicalMailbox(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (3 ... 254).contains(bytes.count),
              bytes.allSatisfy({ $0 < 0x80 }),
              value.filter({ $0 == "@" }).count == 1 else {
            return false
        }
        let parts = value.split(
            separator: "@",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )
        guard parts.count == 2 else { return false }
        let local = Array(parts[0].utf8)
        let allowedLocalPunctuation = Set("!#$%&'*+-/=?^_`{|}~.".utf8)
        guard (1 ... 64).contains(local.count),
              local.first != 46, local.last != 46,
              !parts[0].contains(".."),
              local.allSatisfy({
                  (48 ... 57).contains($0)
                      || (97 ... 122).contains($0)
                      || allowedLocalPunctuation.contains($0)
              }) else {
            return false
        }
        let domain = parts[1]
        guard (1 ... 253).contains(domain.utf8.count) else { return false }
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        return !labels.isEmpty && labels.allSatisfy { label in
            let labelBytes = Array(label.utf8)
            return (1 ... 63).contains(labelBytes.count)
                && labelBytes.first != 45 && labelBytes.last != 45
                && labelBytes.allSatisfy {
                    (48 ... 57).contains($0)
                        || (97 ... 122).contains($0)
                        || $0 == 45
                }
        }
    }
}

/// A random 256-bit identifier is the only durable seed from which the
/// email-delivery worker reconstructs a bearer proof. Its raw value is not
/// itself a proof.
public struct AccountEmailDeliveryID: Sendable, Equatable, Hashable {
    public let rawValue: String

    public init(rawValue: String) throws {
        guard rawValue.utf8.count == 43,
              rawValue.utf8.allSatisfy({
                  (48 ... 57).contains($0)
                      || (65 ... 90).contains($0)
                      || (97 ... 122).contains($0)
                      || $0 == 45 || $0 == 95
              }) else {
            throw AccountControlStoreError.invalidInput
        }
        self.rawValue = rawValue
    }
}

public enum AccountEmailDeliveryState: String, Sendable, Equatable {
    case pending
    case leased
    case sent
    case cancelled
}

/// Complete input for atomically replacing a proof and enqueueing its
/// delivery. `proofDigest` is a domain-separated HMAC, never a bare hash.
public struct AccountEmailProofDeliveryRequest: Sendable, Equatable {
    public let deliveryID: AccountEmailDeliveryID
    public let did: String
    public let email: AccountEmailAddress
    public let purpose: AccountEmailTokenPurpose
    public let proofDigest: Data
    public let expiresAt: Date
    public let createdAt: Date

    public init(
        deliveryID: AccountEmailDeliveryID,
        did: String,
        email: AccountEmailAddress,
        purpose: AccountEmailTokenPurpose,
        proofDigest: Data,
        expiresAt: Date,
        now: Date
    ) throws {
        guard AccountControlMetadata.isDID(did),
              (try? AccountEmailAddress(email.value)) == email,
              proofDigest.count == 32,
              AccountControlMetadata.isControlDate(expiresAt),
              AccountControlMetadata.isControlDate(now),
              expiresAt > now else {
            throw AccountControlStoreError.invalidInput
        }
        self.deliveryID = deliveryID
        self.did = did
        self.email = email
        self.purpose = purpose
        self.proofDigest = proofDigest
        self.expiresAt = expiresAt
        createdAt = now
    }
}

/// Enumeration-resistant password-recovery enqueue input. It deliberately has
/// no caller-supplied DID or plaintext mailbox. The request transaction stores
/// only a keyed marker
/// and an opaque, authenticated address envelope; a durable worker resolves
/// the envelope after the HTTP request has completed. This keeps known and
/// unknown addresses on the same request-time write path without retaining a
/// plaintext address in the marker table.
public struct AccountPasswordRecoveryDeliveryRequest: Sendable, Equatable {
    public let deliveryID: AccountEmailDeliveryID
    public let proofDigest: Data
    /// HMAC-derived canonical-address marker used only for blind recovery
    /// admission. It is not a bearer proof and is never exposed to callers.
    public let lookupDigest: Data
    /// Authenticated envelope for the canonical address. The storage layer
    /// treats this as opaque bytes and never attempts to decrypt it.
    public let emailEnvelope: Data
    public let expiresAt: Date
    public let createdAt: Date

    public init(
        deliveryID: AccountEmailDeliveryID,
        proofDigest: Data,
        lookupDigest: Data,
        emailEnvelope: Data,
        expiresAt: Date,
        now: Date
    ) throws {
        guard proofDigest.count == 32,
              lookupDigest.count == 32,
              (28 ... 4_096).contains(emailEnvelope.count),
              AccountControlMetadata.isControlDate(expiresAt),
              AccountControlMetadata.isControlDate(now),
              expiresAt > now else {
            throw AccountControlStoreError.invalidInput
        }
        self.deliveryID = deliveryID
        self.proofDigest = proofDigest
        self.lookupDigest = lookupDigest
        self.emailEnvelope = emailEnvelope
        self.expiresAt = expiresAt
        createdAt = now
    }
}

public enum AccountEmailEnqueueOutcome: Sendable, Equatable {
    case enqueued
    case accountNotFound
    case invalidEmail
}

public struct AccountEmailDeliveryLease: Sendable, Equatable {
    public let deliveryID: AccountEmailDeliveryID
    public let did: String
    public let email: AccountEmailAddress
    public let emailGeneration: UInt64
    public let purpose: AccountEmailTokenPurpose
    public let expiresAt: Date
    public let attempts: Int

    public init(
        deliveryID: AccountEmailDeliveryID,
        did: String,
        email: AccountEmailAddress,
        emailGeneration: UInt64,
        purpose: AccountEmailTokenPurpose,
        expiresAt: Date,
        attempts: Int
    ) throws {
        guard AccountControlMetadata.isDID(did),
              (try? AccountEmailAddress(email.value)) == email,
              emailGeneration > 0,
              AccountControlMetadata.isControlDate(expiresAt),
              (1 ... 64).contains(attempts) else {
            throw AccountControlStoreError.invalidInput
        }
        self.deliveryID = deliveryID
        self.did = did
        self.email = email
        self.emailGeneration = emailGeneration
        self.purpose = purpose
        self.expiresAt = expiresAt
        self.attempts = attempts
    }
}

/// A leased, account-free password-recovery request. The worker decrypts and
/// authenticates `emailEnvelope` before asking storage to materialize a real
/// account token/outbox row. Lease state is durable so a crash requeues work.
public struct AccountPasswordRecoveryWorkLease: Sendable, Equatable {
    public let deliveryID: AccountEmailDeliveryID
    public let lookupDigest: Data
    public let proofDigest: Data
    public let emailEnvelope: Data
    public let expiresAt: Date
    public let createdAt: Date
    public let attempts: Int

    public init(
        deliveryID: AccountEmailDeliveryID,
        lookupDigest: Data,
        proofDigest: Data,
        emailEnvelope: Data,
        expiresAt: Date,
        createdAt: Date,
        attempts: Int
    ) throws {
        guard lookupDigest.count == 32,
              proofDigest.count == 32,
              (28 ... 4_096).contains(emailEnvelope.count),
              AccountControlMetadata.isControlDate(expiresAt),
              AccountControlMetadata.isControlDate(createdAt),
              expiresAt > createdAt,
              (1 ... 64).contains(attempts) else {
            throw AccountControlStoreError.invalidInput
        }
        self.deliveryID = deliveryID
        self.lookupDigest = lookupDigest
        self.proofDigest = proofDigest
        self.emailEnvelope = emailEnvelope
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.attempts = attempts
    }
}

public enum AccountPasswordRecoveryWorkMaterialization: Sendable, Equatable {
    case enqueued
    case discarded
}

public struct AccountEmailRetryPolicy: Sendable, Equatable {
    public static let standard = try! AccountEmailRetryPolicy()

    public let maximumAttempts: Int
    public let initialDelay: TimeInterval
    public let maximumDelay: TimeInterval

    public init(
        maximumAttempts: Int = 8,
        initialDelay: TimeInterval = 1,
        maximumDelay: TimeInterval = 300
    ) throws {
        guard (1 ... 64).contains(maximumAttempts),
              initialDelay.isFinite, maximumDelay.isFinite,
              (0.01 ... 3_600).contains(initialDelay),
              initialDelay <= maximumDelay,
              maximumDelay <= 86_400 else {
            throw AccountControlStoreError.invalidInput
        }
        self.maximumAttempts = maximumAttempts
        self.initialDelay = initialDelay
        self.maximumDelay = maximumDelay
    }
}

public enum AccountEmailRetryDisposition: Sendable, Equatable {
    case scheduled(nextAttemptAt: Date)
    case expired
}

public enum AccountEmailConfirmationOutcome: Sendable, Equatable {
    case confirmed
    case accountNotFound
    case invalidEmail
    case expiredToken
    case invalidToken
}

public enum AccountPasswordRecoveryLookupOutcome: Sendable, Equatable {
    case ready(AccountPasswordRecoveryConfirmation)
    case expiredToken
    case invalidToken
}

public enum AccountPasswordResetOutcome: Sendable, Equatable {
    case completed
    case expiredToken
    case invalidToken
}

public enum AccountEmailRateLimitScope: String, Sendable, Equatable {
    case did
    case email
    case directPeer = "direct-peer"
}

/// The raw DID, email, or peer value is never persisted. Callers derive this
/// digest with the configured account-email HMAC key before storage.
public struct AccountEmailRateLimitKey: Sendable, Equatable {
    public let scope: AccountEmailRateLimitScope
    public let digest: Data

    public init(scope: AccountEmailRateLimitScope, digest: Data) throws {
        guard digest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        self.scope = scope
        self.digest = digest
    }
}

public struct AccountEmailRateLimitPolicy: Sendable, Equatable {
    public let maximumAttempts: Int
    public let window: TimeInterval

    public init(maximumAttempts: Int, window: TimeInterval) throws {
        guard (1 ... 10_000).contains(maximumAttempts),
              window.isFinite, (1 ... 86_400).contains(window) else {
            throw AccountControlStoreError.invalidInput
        }
        self.maximumAttempts = maximumAttempts
        self.window = window
    }
}

public enum AccountEmailRateLimitDecision: Sendable, Equatable {
    case allowed(remaining: Int)
    case limited(until: Date)
}

public enum AccountEmailStorageValidation {
    public static func isWorkerID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return (1 ... 128).contains(bytes.count)
            && bytes.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }
}

/// Exact binding required by authenticated email-confirmation surfaces. A
/// mismatched DID or address cannot consume a proof belonging to another
/// account before the caller learns that it selected the wrong identity.
public struct AccountEmailConfirmationRequest: Sendable, Equatable {
    public let did: String
    public let email: AccountEmailAddress
    public let proofDigest: Data

    public init(
        did: String,
        email: AccountEmailAddress,
        proofDigest: Data
    ) throws {
        guard AccountControlMetadata.isDID(did),
              (try? AccountEmailAddress(email.value)) == email,
              proofDigest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.email = email
        self.proofDigest = proofDigest
    }
}

/// Non-authorizing preflight facts selected by a live recovery-proof digest.
/// The completion transaction rechecks every field, so an address/lifecycle
/// change while Argon2id runs cannot turn this snapshot into authority.
public struct AccountPasswordRecoveryConfirmation: Sendable, Equatable {
    public let did: String
    public let email: AccountEmailAddress
    public let proofDigest: Data

    public init(
        did: String,
        email: AccountEmailAddress,
        proofDigest: Data
    ) throws {
        guard AccountControlMetadata.isDID(did),
              (try? AccountEmailAddress(email.value)) == email,
              proofDigest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.email = email
        self.proofDigest = proofDigest
    }
}

/// Hash-only, fully bound input for completing a password recovery. Argon2id
/// work happens before this value is constructed; the storage transaction
/// receives only the verifier it observed, the precomputed replacement, and a
/// keyed digest of the delivered proof.
public struct AccountPasswordRecoveryRequest: Sendable, Equatable {
    public let did: String
    public let email: AccountEmailAddress
    public let proofDigest: Data
    public let expectedVerifier: String
    public let replacementVerifier: String

    public init(
        did: String,
        email: AccountEmailAddress,
        proofDigest: Data,
        expectedVerifier: String,
        replacementVerifier: String
    ) throws {
        guard AccountControlMetadata.isDID(did),
              (try? AccountEmailAddress(email.value)) == email,
              proofDigest.count == 32,
              AccountControlMetadata.isVerifier(expectedVerifier),
              AccountControlMetadata.isVerifier(replacementVerifier),
              replacementVerifier != expectedVerifier else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.email = email
        self.proofDigest = proofDigest
        self.expectedVerifier = expectedVerifier
        self.replacementVerifier = replacementVerifier
    }

    public init(
        confirmation: AccountPasswordRecoveryConfirmation,
        expectedVerifier: String,
        replacementVerifier: String
    ) throws {
        try self.init(
            did: confirmation.did,
            email: confirmation.email,
            proofDigest: confirmation.proofDigest,
            expectedVerifier: expectedVerifier,
            replacementVerifier: replacementVerifier
        )
    }
}

/// A non-completing result deliberately does not reveal whether the account,
/// address, proof, lifecycle state, or expected verifier failed to match.
public enum AccountPasswordRecoveryResult: Sendable, Equatable {
    case completed
    case unchanged
}

/// Domain-shaped durable account-control storage. It contains registry,
/// lifecycle, verifier, key-reference, tombstone, and export-declaration
/// facts only. Repository contents and private key material belong elsewhere.
public protocol AccountControlStore: Sendable {
    func createAccount(_ registration: AccountControlRegistration) async throws -> AccountControlAccount
    func account(did: String) async throws -> AccountControlAccount?
    func account(canonicalHandle: String) async throws -> AccountControlAccount?
    /// Lists only canonical, active account DIDs in binary lexical order.
    ///
    /// This is a trusted startup inventory, not a request-time account
    /// discovery surface. Implementations must not load credential, key,
    /// handle, export, or repository fields to answer it.
    func activeAccountDIDs() async throws -> [String]
    func credential(did: String) async throws -> AccountControlCredential?
    func replaceCredential(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String,
        now: Date
    ) async throws -> AccountCredentialReplacement
    /// Atomically verifies that the account is still active and the verified
    /// credential remains current, optionally upgrades its verifier, and
    /// returns the active account snapshot. `nil` is a fail-closed result.
    func finalizeAuthentication(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String?,
        now: Date
    ) async throws -> AccountAuthenticationFinalization?
    func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountControlAccount
    func associateEmail(did: String, email: AccountEmailAddress, now: Date) async throws
    /// Atomically replaces an exact active account/address generation's proof
    /// and delivery row. No raw proof is accepted by this boundary.
    func enqueueEmailProofDelivery(
        _ request: AccountEmailProofDeliveryRequest
    ) async throws -> AccountEmailEnqueueOutcome
    /// Enumeration-resistant recovery request. A canonical address which is
    /// unknown, unverified, or inactive performs only a keyed blind-work write
    /// and still returns successfully.
    func enqueuePasswordRecoveryDelivery(
        _ request: AccountPasswordRecoveryDeliveryRequest
    ) async throws
    /// Claims one account-free password-recovery request under a durable lease.
    /// The caller must authenticate/decrypt the envelope before materializing it.
    func claimNextPasswordRecoveryWork(
        workerID: String,
        now: Date,
        leaseDuration: TimeInterval
    ) async throws -> AccountPasswordRecoveryWorkLease?
    /// Resolves one leased request to an account-specific token/outbox row, or
    /// discards it when the address is unknown/inactive. The transaction does
    /// not perform network I/O.
    func materializePasswordRecoveryWork(
        _ work: AccountPasswordRecoveryWorkLease,
        email: AccountEmailAddress,
        workerID: String,
        now: Date
    ) async throws -> AccountPasswordRecoveryWorkMaterialization
    /// Deletes malformed or otherwise unprocessable leased work without
    /// exposing its address or retrying an authenticated-invalid envelope.
    func discardPasswordRecoveryWork(
        _ work: AccountPasswordRecoveryWorkLease,
        workerID: String,
        now: Date
    ) async throws
    /// Claims one due delivery under a bounded lease. Expired leases are
    /// reclaimable after restart; SMTP happens outside this transaction. Once
    /// `beginEmailDeliveryAttempt` succeeds, the storage implementation keeps
    /// the lease alive through its bounded network-attempt window. The
    /// delivery implementation must honor task cancellation before that
    /// window expires; the account recovery coordinator enforces a shorter
    /// deadline than the durable fence.
    func claimNextEmailDelivery(
        workerID: String,
        now: Date,
        leaseDuration: TimeInterval
    ) async throws -> AccountEmailDeliveryLease?
    /// Establishes the durable pre-network fence for one claimed delivery.
    /// Deletion and this transition serialize in control.sqlite: if this call
    /// succeeds, deletion must not scrub the row until the bounded SMTP attempt
    /// has finished; if deletion wins first, this returns false and no network
    /// operation may begin.
    func beginEmailDeliveryAttempt(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date
    ) async throws -> Bool
    func acknowledgeEmailDelivery(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date
    ) async throws -> Bool
    func retryEmailDelivery(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date,
        policy: AccountEmailRetryPolicy
    ) async throws -> AccountEmailRetryDisposition
    func purgeExpiredEmailRecoveryState(now: Date) async throws
    func confirmEmailProof(
        _ request: AccountEmailConfirmationRequest,
        now: Date
    ) async throws -> AccountEmailConfirmationOutcome
    func passwordRecoveryLookup(
        proofDigest: Data,
        now: Date
    ) async throws -> AccountPasswordRecoveryLookupOutcome
    func consumeEmailRateLimit(
        key: AccountEmailRateLimitKey,
        policy: AccountEmailRateLimitPolicy,
        now: Date
    ) async throws -> AccountEmailRateLimitDecision
    /// Issues a proof only if `email` is still the account's current address.
    /// This expected-address check is the storage-side linearization point
    /// between choosing a delivery destination and making its token usable.
    func issueEmailToken(
        did: String,
        email: AccountEmailAddress,
        purpose: AccountEmailTokenPurpose,
        digest: Data,
        expiresAt: Date,
        now: Date
    ) async throws
    /// Atomically consumes one verification proof only when its exact DID and
    /// current email match, then marks that email verified. A mismatch returns
    /// `false` without burning the proof.
    func confirmEmail(
        _ request: AccountEmailConfirmationRequest,
        now: Date
    ) async throws -> Bool
    /// Compatibility-only consumer for pre-outbox verification fixtures.
    /// Durable delivery proofs must fail closed here because they require the
    /// exact DID+email binding in `confirmEmailProof`. Password-recovery
    /// proofs are consumable only through `completePasswordRecovery`.
    func consumeEmailToken(digest: Data, purpose: AccountEmailTokenPurpose, now: Date) async throws -> String?
    func associatedEmail(did: String) async throws -> AccountEmailAddress?
    func verifiedEmail(did: String) async throws -> AccountEmailAddress?
    /// Resolves a live recovery proof to its exact active DID and current
    /// verified email without consuming it. This is a preflight for loading
    /// the expected verifier and running Argon2id; only
    /// `completePasswordRecovery` grants authority and consumes the proof.
    func passwordRecoveryConfirmation(
        proofDigest: Data,
        now: Date
    ) async throws -> AccountPasswordRecoveryConfirmation?
    /// Atomically checks the exact DID, current verified email, live recovery
    /// proof, active lifecycle state, and expected verifier; on success it
    /// replaces the verifier, deletes every outstanding email proof for the
    /// account, and revokes every OAuth token family for that DID. Password
    /// hashing and proof-digest derivation must happen before this call.
    func completePasswordRecovery(
        _ request: AccountPasswordRecoveryRequest,
        now: Date
    ) async throws -> AccountPasswordRecoveryResult
}

/// Optional extension implemented by durable stores that can atomically
/// promote a verified PLC rotation. Keeping it separate preserves the
/// read/authentication boundary for stores that intentionally do not support
/// lifecycle mutation.
public protocol AccountControlKeyRotationStore: AccountControlStore {
    func rotateAccountKeys(
        did: String,
        request: AccountControlKeyRotationRequest,
        now: Date
    ) async throws -> AccountControlAccount
}

public extension AccountControlStore {
    /// Stores that predate the startup inventory capability must fail closed:
    /// a service must never infer an account-database location by probing a
    /// request's authority DID.
    func activeAccountDIDs() async throws -> [String] {
        throw AccountControlStoreError.unavailable
    }
    func associateEmail(did: String, email: AccountEmailAddress, now: Date) async throws { throw AccountControlStoreError.unavailable }
    func enqueueEmailProofDelivery(
        _ request: AccountEmailProofDeliveryRequest
    ) async throws -> AccountEmailEnqueueOutcome {
        throw AccountControlStoreError.unavailable
    }
    func enqueuePasswordRecoveryDelivery(
        _ request: AccountPasswordRecoveryDeliveryRequest
    ) async throws {
        throw AccountControlStoreError.unavailable
    }
    func claimNextPasswordRecoveryWork(
        workerID: String,
        now: Date,
        leaseDuration: TimeInterval
    ) async throws -> AccountPasswordRecoveryWorkLease? {
        throw AccountControlStoreError.unavailable
    }
    func materializePasswordRecoveryWork(
        _ work: AccountPasswordRecoveryWorkLease,
        email: AccountEmailAddress,
        workerID: String,
        now: Date
    ) async throws -> AccountPasswordRecoveryWorkMaterialization {
        throw AccountControlStoreError.unavailable
    }
    func discardPasswordRecoveryWork(
        _ work: AccountPasswordRecoveryWorkLease,
        workerID: String,
        now: Date
    ) async throws {
        throw AccountControlStoreError.unavailable
    }
    func claimNextEmailDelivery(
        workerID: String,
        now: Date,
        leaseDuration: TimeInterval
    ) async throws -> AccountEmailDeliveryLease? {
        throw AccountControlStoreError.unavailable
    }
    func beginEmailDeliveryAttempt(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date
    ) async throws -> Bool {
        throw AccountControlStoreError.unavailable
    }
    func acknowledgeEmailDelivery(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date
    ) async throws -> Bool {
        throw AccountControlStoreError.unavailable
    }
    func retryEmailDelivery(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date,
        policy: AccountEmailRetryPolicy
    ) async throws -> AccountEmailRetryDisposition {
        throw AccountControlStoreError.unavailable
    }
    func purgeExpiredEmailRecoveryState(now: Date) async throws {
        throw AccountControlStoreError.unavailable
    }
    func confirmEmailProof(
        _ request: AccountEmailConfirmationRequest,
        now: Date
    ) async throws -> AccountEmailConfirmationOutcome {
        throw AccountControlStoreError.unavailable
    }
    func passwordRecoveryLookup(
        proofDigest: Data,
        now: Date
    ) async throws -> AccountPasswordRecoveryLookupOutcome {
        throw AccountControlStoreError.unavailable
    }
    func consumeEmailRateLimit(
        key: AccountEmailRateLimitKey,
        policy: AccountEmailRateLimitPolicy,
        now: Date
    ) async throws -> AccountEmailRateLimitDecision {
        throw AccountControlStoreError.unavailable
    }
    func issueEmailToken(
        did: String,
        email: AccountEmailAddress,
        purpose: AccountEmailTokenPurpose,
        digest: Data,
        expiresAt: Date,
        now: Date
    ) async throws { throw AccountControlStoreError.unavailable }
    func confirmEmail(
        _ request: AccountEmailConfirmationRequest,
        now: Date
    ) async throws -> Bool {
        throw AccountControlStoreError.unavailable
    }
    func consumeEmailToken(digest: Data, purpose: AccountEmailTokenPurpose, now: Date) async throws -> String? { throw AccountControlStoreError.unavailable }
    func associatedEmail(did: String) async throws -> AccountEmailAddress? { throw AccountControlStoreError.unavailable }
    func verifiedEmail(did: String) async throws -> AccountEmailAddress? { throw AccountControlStoreError.unavailable }
    func passwordRecoveryConfirmation(
        proofDigest: Data,
        now: Date
    ) async throws -> AccountPasswordRecoveryConfirmation? {
        throw AccountControlStoreError.unavailable
    }
    func completePasswordRecovery(
        _ request: AccountPasswordRecoveryRequest,
        now: Date
    ) async throws -> AccountPasswordRecoveryResult {
        throw AccountControlStoreError.unavailable
    }
}

/// Strict lexical account identifiers shared by durable adapters that cannot
/// depend on the higher-level account service. `SwanAccounts.AccountIdentifiers`
/// validates the same DID and handle forms before public service calls.
public enum AccountControlIdentifiers {
    public static func isDID(_ value: String) -> Bool {
        AccountControlMetadata.isDID(value)
    }

    public static func isCanonicalHandle(_ value: String) -> Bool {
        AccountControlMetadata.isCanonicalHandle(value)
    }

    public static func isPublicGenesisCommitCID(_ value: String) -> Bool {
        AccountControlMetadata.isPublicGenesisCommitCID(value)
    }
}

enum AccountControlMetadata {
    static func isIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 2_048 &&
            value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }

    static func isSafeText(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 &&
            value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            }
    }

    static func isControlDate(_ value: Date) -> Bool {
        let seconds = value.timeIntervalSince1970
        let microseconds = seconds * 1_000_000
        return seconds.isFinite && seconds >= 0 &&
            microseconds.isFinite && microseconds <= Double(Int.max)
    }

    /// A public repository commit CID is Swan's canonical CIDv1 dag-cbor
    /// SHA-256 base32 representation. Full CAR/CID verification is owned by
    /// SwanPublicRepository; this control-plane boundary prevents arbitrary
    /// text from becoming a provenance marker.
    static func isPublicGenesisCommitCID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        let alphabet = Set("abcdefghijklmnopqrstuvwxyz234567".utf8)
        return bytes.count == 59
            && value.hasPrefix("bafyrei")
            && bytes.allSatisfy(alphabet.contains)
    }

    static func isVerifier(_ value: String) -> Bool {
        value.hasPrefix("$argon2id$v=19$") && value.utf8.count <= 1_024 &&
            value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }

    /// Storage cannot depend on SwanAccounts without a cycle, so it retains
    /// the same strict lexical boundary as `AccountIdentifiers`. The account
    /// service repeats validation before every store call as its public-edge
    /// guard; this second check protects direct store consumers and migration
    /// decoders as well.
    static func isDID(_ did: String) -> Bool {
        let bytes = Array(did.utf8)
        guard bytes.count <= 2_048,
              bytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            return false
        }
        let components = did.split(separator: ":", omittingEmptySubsequences: false)
        guard components.count >= 3, components[0] == "did" else { return false }
        switch components[1] {
        case "plc":
            return components.count == 3 && components[2].utf8.count == 24 &&
                components[2].utf8.allSatisfy {
                    ($0 >= 97 && $0 <= 122) || ($0 >= 50 && $0 <= 55)
                }
        case "web":
            return isWebDID(components)
        default:
            return false
        }
    }

    static func isCanonicalHandle(_ handle: String) -> Bool {
        let bytes = Array(handle.utf8)
        guard !bytes.isEmpty, bytes.count <= 253,
              bytes.allSatisfy({
                  ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 46
              }) else {
            return false
        }
        return isCanonicalDNSName(handle)
    }

    private static func isWebDID(_ components: [Substring]) -> Bool {
        let authorityParts = String(components[2]).components(separatedBy: "%3A")
        guard (1 ... 2).contains(authorityParts.count),
              !authorityParts[0].contains("%"),
              isCanonicalDNSName(authorityParts[0]) else {
            return false
        }
        if authorityParts.count == 2 {
            let port = authorityParts[1]
            guard !port.isEmpty, !port.contains("%"),
                  port.count == 1 || port.first != "0",
                  let number = UInt16(port), number > 0 else {
                return false
            }
        }
        return components.dropFirst(3).allSatisfy(isCanonicalWebPathSegment)
    }

    private static func isCanonicalDNSName(_ name: String) -> Bool {
        guard name.utf8.count <= 253,
              name.utf8.allSatisfy({
                  ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 46
              }) else {
            return false
        }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        let finalLabelStartsWithASCIIAlpha = labels.last?.utf8.first.map {
            ($0 >= 97 && $0 <= 122)
        } == true
        return labels.count >= 2 && labels.allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 63 && $0.first != "-" && $0.last != "-"
        } && finalLabelStartsWithASCIIAlpha
    }

    private static func isCanonicalWebPathSegment(_ segment: Substring) -> Bool {
        guard !segment.isEmpty, segment != ".", segment != ".." else { return false }
        let bytes = Array(segment.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x25 {
                guard index + 2 < bytes.count,
                      isUppercaseHex(bytes[index + 1]), isUppercaseHex(bytes[index + 2]),
                      let decoded = decodedHex(bytes[index + 1], bytes[index + 2]),
                      !isUnreserved(decoded) else { return false }
                index += 3
            } else {
                guard isUnreserved(bytes[index]) else { return false }
                index += 1
            }
        }
        return true
    }

    private static func isUnreserved(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) ||
            (byte >= 48 && byte <= 57) || byte == 45 || byte == 46 || byte == 95 || byte == 126
    }

    private static func isUppercaseHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 70)
    }

    private static func decodedHex(_ first: UInt8, _ second: UInt8) -> UInt8? {
        func value(_ byte: UInt8) -> UInt8? {
            if byte >= 48, byte <= 57 { return byte - 48 }
            if byte >= 65, byte <= 70 { return byte - 55 }
            return nil
        }
        guard let high = value(first), let low = value(second) else { return nil }
        return high * 16 + low
    }
}
