import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwanCore
import SwanPublicRepository

public enum AccountKeyPurpose: String, Codable, Sendable, CaseIterable {
    case signing = "account-signing"
    case rotation = "account-rotation"
}

public struct AccountKeyReference: Codable, Sendable, Hashable {
    public let accountDID: String
    public let purpose: AccountKeyPurpose
    public let generation: UInt64

    public init(accountDID: String, purpose: AccountKeyPurpose, generation: UInt64) throws {
        guard generation > 0 else {
            throw SwanError.invalidIdentifier("account key generation")
        }
        self.accountDID = try AccountIdentifiers.validateDID(accountDID)
        self.purpose = purpose
        self.generation = generation
    }

    private enum CodingKeys: String, CodingKey {
        case accountDID
        case purpose
        case generation
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            accountDID: container.decode(String.self, forKey: .accountDID),
            purpose: container.decode(AccountKeyPurpose.self, forKey: .purpose),
            generation: container.decode(UInt64.self, forKey: .generation)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(accountDID, forKey: .accountDID)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(generation, forKey: .generation)
    }
}

public struct AccountKeyMaterial: Sendable, Equatable {
    public let reference: AccountKeyReference
    public let key: Data

    public init(reference: AccountKeyReference, key: Data) throws {
        guard key.count == 32 else {
            throw SwanError.malformed("P-256 private key material must be exactly 32 bytes")
        }
        self.reference = reference
        self.key = key
    }
}

public struct AccountKeyEncryptionConfiguration: Sendable {
    public let activeKeyID: String
    fileprivate let keysByID: [String: Data]

    public init(activeKeyID: String, activeKey: Data, decryptOnlyKeys: [String: Data] = [:]) throws {
        try Self.validateKeyID(activeKeyID)
        guard activeKey.count == 32 else {
            throw SwanError.malformed("active account KEK must be exactly 32 bytes")
        }
        guard decryptOnlyKeys[activeKeyID] == nil else {
            throw SwanError.malformed("active account KEK cannot also be decrypt-only")
        }

        var seenKeys = [activeKey]
        for (keyID, key) in decryptOnlyKeys {
            try Self.validateKeyID(keyID)
            guard key.count == 32 else {
                throw SwanError.malformed("decrypt-only account KEK must be exactly 32 bytes")
            }
            guard !seenKeys.contains(key) else {
                throw SwanError.malformed("account KEKs with different KIDs must use distinct key bytes")
            }
            seenKeys.append(key)
        }
        self.activeKeyID = activeKeyID
        keysByID = decryptOnlyKeys.merging([activeKeyID: activeKey]) { _, active in active }
    }

    func key(for keyID: String) -> Data? {
        keysByID[keyID]
    }

    fileprivate static func validateKeyID(_ keyID: String) throws {
        guard !keyID.isEmpty, keyID.utf8.count <= 128,
              keyID.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("invalid account KEK identifier")
        }
    }
}

public struct AccountKeyEnvelopeInventory: Sendable, Equatable {
    public let activeKeyID: String
    public let writerKeyID: String
    public let envelopeCountByKeyID: [String: Int]

    public var totalEnvelopeCount: Int {
        envelopeCountByKeyID.values.reduce(0, +)
    }

    public var isMigrationComplete: Bool {
        writerKeyID == activeKeyID
            && envelopeCountByKeyID.allSatisfy { keyID, _ in keyID == activeKeyID }
    }
}

public struct AccountKeyMigrationReport: Sendable, Equatable {
    public let migratedEnvelopeCount: Int
    public let inventory: AccountKeyEnvelopeInventory
}

public protocol AccountKeyMaterialReader: Sendable {
    func key(for reference: AccountKeyReference) async throws -> Data
}

public protocol AccountKeyStore: AccountKeyMaterialReader {
    func create(_ key: Data, for reference: AccountKeyReference) async throws
    func createBatch(_ materials: [AccountKeyMaterial]) async throws
}

/// The only pre-DID private-material persistence surface. It is purpose-bound
/// to PLC genesis preparation and cannot store arbitrary values.
public protocol PLCAccountIdentityStagingKeyStore: AccountKeyStore {
    func stagePLCAccountIdentity(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) async throws -> StagedPLCAccountIdentity

    func stagedPLCAccountIdentity(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) async throws -> StagedPLCAccountIdentity?

    func reclaimStagedPLCAccountIdentity(
        requestID: String,
        expectedDID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) async throws
}

public struct StagedPLCAccountIdentity: Sendable {
    public let requestID: String
    public let did: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let repositoryRevision: String
    public let operation: PLCSignedOperation
    let signingKey: P256.Signing.PrivateKey
    let rotationKey: P256.Signing.PrivateKey

    public var operationCID: String {
        get throws { try operation.cid.string }
    }
}

/// Exposes authenticated P-256 public-key metadata without making an account
/// private scalar readable. Callers that only verify signatures should depend
/// on this capability rather than on ``AccountKeyStore``.
public protocol AccountKeyPublicKeyStore: Sendable {
    /// Returns `nil` for a legacy envelope that predates authenticated public
    /// metadata. Implementations must not decrypt private key material to
    /// synthesize a result for that case.
    func publicKey(for reference: AccountKeyReference) async throws -> Data?
}

/// Purpose-bound encrypted file storage anchored to a pinned directory
/// descriptor. KEKs are deployment configuration and are never serialized.
public actor FileAccountKeyStore:
    AccountKeyStore,
    AccountKeyPublicKeyStore,
    PLCAccountIdentityStagingKeyStore
{
    public static let envelopeFormat = "swan-key-envelope-v1"

    private static let journalFormat = "swan-key-provisioning-journal-v1"
    private static let journalFilename = ".swan-key-provisioning-journal-v1"
    private static let lockFilename = ".swan-key-store.lock"
    private static let activeKeyMarkerFilename = ".swan-active-kek-v1"
    private static let maximumEnvelopeBytes = 16 * 1_024
    private static let maximumJournalBytes = 128 * 1_024
    private static let maximumMarkerBytes = 128
    private static let plcStagingFormat = "swan-plc-account-staging-v1"
    private static let maximumPLCStagingBytes = 64 * 1_024

    private struct Envelope: Codable {
        let format: String
        let kid: String
        let purpose: AccountKeyPurpose
        let accountDID: String
        let generation: UInt64
        let sealedKey: Data
        /// An optional authenticated copy of the P-256 public key. It stays
        /// optional so existing v1 envelopes remain decryptable; those
        /// envelopes intentionally cannot serve verification-only requests.
        let publicKey: Data?
        let publicKeyAuthentication: Data?
    }

    private struct JournalEntry: Codable {
        let filename: String
        let envelope: Data
    }

    private struct ProvisioningJournal: Codable {
        let format: String
        let entries: [JournalEntry]
    }

    private struct LoadedEnvelope {
        let filename: String
        let envelope: Envelope
        let reference: AccountKeyReference
    }

    private struct PLCStagingEnvelope: Codable {
        let format: String
        let kid: String
        let requestDigest: Data
        let sealedPayload: Data
    }

    private struct PLCStagingPayload: Codable {
        let signingKey: Data
        let rotationKey: Data
        let did: String
        let operationJSON: Data
    }

    private let directoryDescriptor: Int32
    private let lockDescriptor: Int32
    private let configuration: AccountKeyEncryptionConfiguration
    private let failAfterBatchInstallCount: Int?
    private let failDirectoryIterationAfterEntryCount: Int?

    public init(root: URL, configuration: AccountKeyEncryptionConfiguration) throws {
        let descriptor = try Self.openProtectedRoot(root)
        var openedLockDescriptor: Int32 = -1
        do {
            openedLockDescriptor = try Self.openLockFile(directoryDescriptor: descriptor)
            try Self.withExclusiveLock(openedLockDescriptor) {
                try Self.initializeActiveKeyMarkerIfNeeded(
                    directoryDescriptor: descriptor,
                    activeKeyID: configuration.activeKeyID
                )
                try Self.recoverProvisioningJournal(
                    directoryDescriptor: descriptor,
                    configuration: configuration
                )
            }
        } catch {
            if openedLockDescriptor >= 0 { _ = close(openedLockDescriptor) }
            _ = close(descriptor)
            throw error
        }
        directoryDescriptor = descriptor
        lockDescriptor = openedLockDescriptor
        self.configuration = configuration
        failAfterBatchInstallCount = nil
        failDirectoryIterationAfterEntryCount = nil
    }

    /// Restore-only constructor for a key directory already opened below a
    /// pinned unpublished root. All subsequent key operations remain relative
    /// to the duplicated descriptor and never reopen a lexical staging path.
    @_spi(OperatorRestore)
    public init(
        operatorRestoreDirectoryDescriptor descriptor: Int32,
        configuration: AccountKeyEncryptionConfiguration
    ) throws {
        let descriptor = try Self.duplicateProtectedRoot(descriptor)
        var openedLockDescriptor: Int32 = -1
        do {
            openedLockDescriptor = try Self.openLockFile(directoryDescriptor: descriptor)
            try Self.withExclusiveLock(openedLockDescriptor) {
                try Self.initializeActiveKeyMarkerIfNeeded(
                    directoryDescriptor: descriptor,
                    activeKeyID: configuration.activeKeyID
                )
                try Self.recoverProvisioningJournal(
                    directoryDescriptor: descriptor,
                    configuration: configuration
                )
            }
        } catch {
            if openedLockDescriptor >= 0 { _ = close(openedLockDescriptor) }
            _ = close(descriptor)
            throw error
        }
        directoryDescriptor = descriptor
        lockDescriptor = openedLockDescriptor
        self.configuration = configuration
        failAfterBatchInstallCount = nil
        failDirectoryIterationAfterEntryCount = nil
    }

    init(
        root: URL,
        configuration: AccountKeyEncryptionConfiguration,
        failAfterBatchInstallCount: Int? = nil,
        failDirectoryIterationAfterEntryCount: Int? = nil
    ) throws {
        let descriptor = try Self.openProtectedRoot(root)
        var openedLockDescriptor: Int32 = -1
        do {
            openedLockDescriptor = try Self.openLockFile(directoryDescriptor: descriptor)
            try Self.withExclusiveLock(openedLockDescriptor) {
                try Self.initializeActiveKeyMarkerIfNeeded(
                    directoryDescriptor: descriptor,
                    activeKeyID: configuration.activeKeyID
                )
                try Self.recoverProvisioningJournal(
                    directoryDescriptor: descriptor,
                    configuration: configuration
                )
            }
        } catch {
            if openedLockDescriptor >= 0 { _ = close(openedLockDescriptor) }
            _ = close(descriptor)
            throw error
        }
        directoryDescriptor = descriptor
        lockDescriptor = openedLockDescriptor
        self.configuration = configuration
        self.failAfterBatchInstallCount = failAfterBatchInstallCount
        self.failDirectoryIterationAfterEntryCount = failDirectoryIterationAfterEntryCount
    }

    deinit {
        _ = close(lockDescriptor)
        _ = close(directoryDescriptor)
    }

    public func create(_ key: Data, for reference: AccountKeyReference) throws {
        try withExclusiveLock {
            try requireActiveWriterKey()
            guard key.count == 32 else {
                throw SwanError.malformed("P-256 private key material must be exactly 32 bytes")
            }
            let encoded = try encodeEnvelope(
                key,
                reference: reference,
                keyID: configuration.activeKeyID
            )
            try Self.installCreateOnly(
                encoded,
                named: Self.filename(for: reference),
                directoryDescriptor: directoryDescriptor
            )
        }
    }

    public func createBatch(_ materials: [AccountKeyMaterial]) throws {
        try withExclusiveLock {
            try requireActiveWriterKey()
            try createBatchUnlocked(materials)
        }
    }

    public func stagePLCAccountIdentity(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) throws -> StagedPLCAccountIdentity {
        try withExclusiveLock {
            try requireActiveWriterKey()
            if let existing = try loadStagedPLCAccountIdentity(
                requestID: requestID,
                canonicalHandle: canonicalHandle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision
            ) {
                return existing
            }
            let signingKey = P256.Signing.PrivateKey()
            let rotationKey = P256.Signing.PrivateKey()
            guard signingKey.rawRepresentation != rotationKey.rawRepresentation else {
                throw SwanError.unavailable("P-256 key generation returned duplicate account keys")
            }
            let unsigned = try PLCATProfile.regularOperation(
                handle: canonicalHandle,
                signingPublicKey: signingKey.publicKey,
                rotationPublicKeys: [rotationKey.publicKey],
                pdsOrigin: pdsOrigin,
                prev: nil
            )
            let operation = try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
            let did = try PLCOperationCodec.genesisDID(for: operation)
            guard let origin = operation.regular?.services["atproto_pds"]?.endpoint else {
                throw SwanError.malformed("PLC staging origin is unavailable")
            }
            let payload = PLCStagingPayload(
                signingKey: signingKey.rawRepresentation,
                rotationKey: rotationKey.rawRepresentation,
                did: did,
                operationJSON: try operation.canonicalJSON
            )
            let payloadData = try JSONEncoder().encode(payload)
            let keyID = configuration.activeKeyID
            guard let keyData = configuration.key(for: keyID) else {
                throw SwanError.unavailable("active account KEK is unavailable")
            }
            let sealed = try AES.GCM.seal(
                payloadData,
                using: SymmetricKey(data: keyData),
                authenticating: Self.plcStagingAAD(
                    requestID: requestID,
                    canonicalHandle: canonicalHandle,
                    pdsOrigin: origin,
                    repositoryRevision: repositoryRevision,
                    keyID: keyID
                )
            )
            guard let combined = sealed.combined else {
                throw SwanError.unavailable("PLC staging encryption is unavailable")
            }
            let envelope = PLCStagingEnvelope(
                format: Self.plcStagingFormat,
                kid: keyID,
                requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
                sealedPayload: combined
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            do {
                try Self.installCreateOnly(
                    encoder.encode(envelope),
                    named: Self.plcStagingFilename(requestID: requestID),
                    directoryDescriptor: directoryDescriptor
                )
            } catch let error as SwanError where error == .conflict(expected: 0, actual: 1) {
                guard let existing = try loadStagedPLCAccountIdentity(
                    requestID: requestID,
                    canonicalHandle: canonicalHandle,
                    pdsOrigin: pdsOrigin,
                    repositoryRevision: repositoryRevision
                ) else {
                    throw SwanError.unavailable("PLC staging race is unavailable")
                }
                return existing
            }
            return StagedPLCAccountIdentity(
                requestID: requestID,
                did: did,
                canonicalHandle: canonicalHandle,
                pdsOrigin: origin,
                repositoryRevision: repositoryRevision,
                operation: operation,
                signingKey: signingKey,
                rotationKey: rotationKey
            )
        }
    }

    public func stagedPLCAccountIdentity(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) throws -> StagedPLCAccountIdentity? {
        try withExclusiveLock {
            try loadStagedPLCAccountIdentity(
                requestID: requestID,
                canonicalHandle: canonicalHandle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision
            )
        }
    }

    public func reclaimStagedPLCAccountIdentity(
        requestID: String,
        expectedDID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) throws {
        try withExclusiveLock {
            let filename = try Self.plcStagingFilename(requestID: requestID)
            guard try Self.entryExists(
                named: filename,
                directoryDescriptor: directoryDescriptor
            ) else { return }
            guard let staged = try loadStagedPLCAccountIdentity(
                requestID: requestID,
                canonicalHandle: canonicalHandle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision
            ), staged.did == expectedDID else {
                throw SwanError.unauthorized("PLC account staging reclamation is invalid")
            }
            let signingReference = try AccountKeyReference(
                accountDID: expectedDID,
                purpose: .signing,
                generation: 1
            )
            let rotationReference = try AccountKeyReference(
                accountDID: expectedDID,
                purpose: .rotation,
                generation: 1
            )
            // The authenticated staging record is loaded with its immutable
            // request binding by the service immediately before reclamation.
            // Here the DID-bound envelopes must both exist and belong to the
            // expected DID before the only request locator is removed.
            let signingEnvelope = try loadEnvelope(
                named: Self.filename(for: signingReference),
                expectedReference: signingReference
            )
            let rotationEnvelope = try loadEnvelope(
                named: Self.filename(for: rotationReference),
                expectedReference: rotationReference
            )
            guard try decrypt(signingEnvelope.envelope, reference: signingReference)
                    == staged.signingKey.rawRepresentation,
                  try decrypt(rotationEnvelope.envelope, reference: rotationReference)
                    == staged.rotationKey.rawRepresentation else {
                throw SwanError.unauthorized("PLC account staging promotion is invalid")
            }
            try Self.remove(named: filename, directoryDescriptor: directoryDescriptor)
        }
    }

    private func loadStagedPLCAccountIdentity(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) throws -> StagedPLCAccountIdentity? {
        try Self.validatePLCStagingRequestID(requestID)
        try PublicRepositoryGenesisCodec.validateRevision(repositoryRevision)
        let canonical = try PLCATProfile.regularOperation(
            handle: canonicalHandle,
            signingPublicKey: P256.Signing.PrivateKey().publicKey,
            rotationPublicKeys: [P256.Signing.PrivateKey().publicKey],
            pdsOrigin: pdsOrigin,
            prev: nil
        ).services["atproto_pds"]!.endpoint
        let filename = try Self.plcStagingFilename(requestID: requestID)
        guard try Self.entryExists(named: filename, directoryDescriptor: directoryDescriptor) else {
            return nil
        }
        let encoded = try Self.readProtected(
            named: filename,
            maximumBytes: Self.maximumPLCStagingBytes,
            directoryDescriptor: directoryDescriptor
        )
        let envelope: PLCStagingEnvelope
        do {
            envelope = try JSONDecoder().decode(PLCStagingEnvelope.self, from: encoded)
        } catch {
            throw SwanError.malformed("invalid PLC account staging envelope")
        }
        guard envelope.format == Self.plcStagingFormat,
              envelope.requestDigest == Data(SHA256.hash(data: Data(requestID.utf8))),
              let keyData = configuration.key(for: envelope.kid) else {
            throw SwanError.unauthorized("PLC account staging binding is invalid")
        }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                AES.GCM.SealedBox(combined: envelope.sealedPayload),
                using: SymmetricKey(data: keyData),
                authenticating: Self.plcStagingAAD(
                    requestID: requestID,
                    canonicalHandle: canonicalHandle,
                    pdsOrigin: canonical,
                    repositoryRevision: repositoryRevision,
                    keyID: envelope.kid
                )
            )
        } catch {
            throw SwanError.unauthorized("PLC account staging authentication failed")
        }
        let payload: PLCStagingPayload
        do {
            payload = try JSONDecoder().decode(PLCStagingPayload.self, from: plaintext)
        } catch {
            throw SwanError.malformed("invalid PLC account staging payload")
        }
        let signingKey = try P256.Signing.PrivateKey(rawRepresentation: payload.signingKey)
        let rotationKey = try P256.Signing.PrivateKey(rawRepresentation: payload.rotationKey)
        guard payload.signingKey != payload.rotationKey else {
            throw SwanError.malformed("PLC account staging keys are not distinct")
        }
        let operation = try PLCOperationCodec.decodeSignedJSON(payload.operationJSON)
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: payload.did)
        guard let regular = operation.regular,
              regular.verificationMethods["atproto"]
                == P256DIDKey(publicKey: signingKey.publicKey).value,
              regular.rotationKeys == [P256DIDKey(publicKey: rotationKey.publicKey).value],
              regular.alsoKnownAs == ["at://\(canonicalHandle)"],
              regular.services["atproto_pds"]?.endpoint == canonical else {
            throw SwanError.unauthorized("PLC account staging identity is invalid")
        }
        return StagedPLCAccountIdentity(
            requestID: requestID,
            did: payload.did,
            canonicalHandle: canonicalHandle,
            pdsOrigin: canonical,
            repositoryRevision: repositoryRevision,
            operation: operation,
            signingKey: signingKey,
            rotationKey: rotationKey
        )
    }

    private func createBatchUnlocked(_ materials: [AccountKeyMaterial]) throws {
        guard !materials.isEmpty, materials.count <= 16,
              Set(materials.map(\.reference)).count == materials.count,
              materials.allSatisfy({ $0.key.count == 32 }) else {
            throw SwanError.malformed("invalid account key provisioning batch")
        }

        let entries = try materials.map { material in
            JournalEntry(
                filename: Self.filename(for: material.reference),
                envelope: try encodeEnvelope(
                    material.key,
                    reference: material.reference,
                    keyID: configuration.activeKeyID
                )
            )
        }
        for entry in entries where try Self.entryExists(
            named: entry.filename,
            directoryDescriptor: directoryDescriptor
        ) {
            throw SwanError.conflict(expected: 0, actual: 1)
        }

        let journal = ProvisioningJournal(format: Self.journalFormat, entries: entries)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try Self.installCreateOnly(
            try encoder.encode(journal),
            named: Self.journalFilename,
            directoryDescriptor: directoryDescriptor
        )

        for (index, entry) in entries.enumerated() {
            if failAfterBatchInstallCount == index {
                throw SwanError.unavailable("injected account key provisioning interruption")
            }
            try Self.installCreateOnly(
                entry.envelope,
                named: entry.filename,
                directoryDescriptor: directoryDescriptor
            )
        }
        try Self.remove(
            named: Self.journalFilename,
            directoryDescriptor: directoryDescriptor
        )
    }

    public func key(for reference: AccountKeyReference) throws -> Data {
        try withExclusiveLock {
            let loaded = try loadEnvelope(
                named: Self.filename(for: reference),
                expectedReference: reference
            )
            let plaintext = try decrypt(loaded.envelope, reference: reference)
            if loaded.envelope.kid != configuration.activeKeyID,
               try currentWriterKeyID() == configuration.activeKeyID {
                try replaceEnvelope(plaintext, reference: reference)
            }
            return plaintext
        }
    }

    /// Reads only an authenticated public-key projection from the envelope. This path
    /// authenticates metadata with the configured KEK but never calls
    /// ``decrypt(_:reference:)`` or otherwise reads the private scalar.
    public func publicKey(for reference: AccountKeyReference) throws -> Data? {
        try withExclusiveLock {
            let loaded = try loadEnvelope(
                named: Self.filename(for: reference),
                expectedReference: reference
            )
            guard let publicKey = loaded.envelope.publicKey,
                  let authentication = loaded.envelope.publicKeyAuthentication else {
                // A mixed optional state is tampering, while two absent
                // fields describe a pre-metadata v1 envelope.
                guard loaded.envelope.publicKey == nil,
                      loaded.envelope.publicKeyAuthentication == nil else {
                    throw SwanError.malformed("account key public metadata is incomplete")
                }
                return nil
            }
            guard let keyData = configuration.key(for: loaded.envelope.kid) else {
                throw SwanError.unavailable("account key envelope references an unavailable KEK")
            }
            do {
                _ = try P256.Signing.PublicKey(x963Representation: publicKey)
            } catch {
                throw SwanError.malformed("account key public metadata is invalid")
            }
            let expected = Self.publicKeyAuthentication(
                keyID: loaded.envelope.kid,
                reference: reference,
                sealedKey: loaded.envelope.sealedKey,
                publicKey: publicKey,
                keyData: keyData
            )
            guard Self.constantTimeEqual(expected, authentication) else {
                throw SwanError.unauthorized("account key public metadata authentication failed")
            }
            return publicKey
        }
    }

    public func inventory() throws -> AccountKeyEnvelopeInventory {
        try withExclusiveLock {
            try inventoryUnlocked()
        }
    }

    private func inventoryUnlocked() throws -> AccountKeyEnvelopeInventory {
        var counts: [String: Int] = [:]
        for loaded in try loadAllEnvelopes() {
            counts[loaded.envelope.kid, default: 0] += 1
        }
        return AccountKeyEnvelopeInventory(
            activeKeyID: configuration.activeKeyID,
            writerKeyID: try currentWriterKeyID(),
            envelopeCountByKeyID: counts
        )
    }

    public func migrateAllEnvelopesToActiveKey() throws -> AccountKeyMigrationReport {
        try withExclusiveLock {
            let writerKeyID = try currentWriterKeyID()
            guard writerKeyID == configuration.activeKeyID
                    || configuration.key(for: writerKeyID) != nil else {
                throw SwanError.unavailable(
                    "active account KEK migration requires the currently active KEK"
                )
            }
            if writerKeyID != configuration.activeKeyID,
               try Self.directoryEntryNames(directoryDescriptor: directoryDescriptor)
                   .contains(where: { $0.hasSuffix(".plcstage") }) {
                // Staging AAD includes request inputs which deliberately are
                // not exposed in the outer envelope. Finish or reclaim the
                // pending preparation before retiring its writer KEK.
                throw SwanError.unavailable(
                    "pending PLC account staging blocks account KEK migration"
                )
            }

            let loaded = try loadAllEnvelopes()
            var migrations: [(Data, AccountKeyReference)] = []
            for item in loaded where item.envelope.kid != configuration.activeKeyID {
                migrations.append((
                    try decrypt(item.envelope, reference: item.reference),
                    item.reference
                ))
            }
            for (plaintext, reference) in migrations {
                try replaceEnvelope(plaintext, reference: reference)
            }

            if writerKeyID != configuration.activeKeyID {
                try Self.installReplacing(
                    Data(configuration.activeKeyID.utf8),
                    named: Self.activeKeyMarkerFilename,
                    directoryDescriptor: directoryDescriptor
                )
            }
            let finalInventory = try inventoryUnlocked()
            guard finalInventory.isMigrationComplete,
                  try currentWriterKeyID() == configuration.activeKeyID else {
                throw SwanError.unavailable("account KEK migration did not reach completion")
            }
            return AccountKeyMigrationReport(
                migratedEnvelopeCount: migrations.count,
                inventory: finalInventory
            )
        }
    }

    private func withExclusiveLock<Result>(_ body: () throws -> Result) throws -> Result {
        try Self.withExclusiveLock(lockDescriptor, body)
    }

    private func currentWriterKeyID() throws -> String {
        try Self.readActiveKeyMarker(directoryDescriptor: directoryDescriptor)
    }

    private func requireActiveWriterKey() throws {
        guard try currentWriterKeyID() == configuration.activeKeyID else {
            throw SwanError.unavailable(
                "active KEK migration is required before writing account keys"
            )
        }
    }

    private func replaceEnvelope(_ key: Data, reference: AccountKeyReference) throws {
        let encoded = try encodeEnvelope(
            key,
            reference: reference,
            keyID: configuration.activeKeyID
        )
        try Self.installReplacing(
            encoded,
            named: Self.filename(for: reference),
            directoryDescriptor: directoryDescriptor
        )
    }

    private func encodeEnvelope(
        _ key: Data,
        reference: AccountKeyReference,
        keyID: String
    ) throws -> Data {
        guard key.count == 32 else {
            throw SwanError.malformed("P-256 private key material must be exactly 32 bytes")
        }
        guard let keyData = configuration.key(for: keyID) else {
            throw SwanError.unavailable("account KEK is unavailable")
        }
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(
                key,
                using: SymmetricKey(data: keyData),
                authenticating: Self.additionalAuthenticatedData(
                    keyID: keyID,
                    reference: reference
                )
            )
        } catch {
            throw SwanError.unavailable("could not encrypt account key")
        }
        guard let combined = sealed.combined else {
            throw SwanError.unavailable("could not serialize encrypted account key")
        }
        let publicKey = try? P256.Signing.PrivateKey(rawRepresentation: key)
            .publicKey
            .x963Representation
        let publicKeyAuthentication = publicKey.map {
            Self.publicKeyAuthentication(
                keyID: keyID,
                reference: reference,
                sealedKey: combined,
                publicKey: $0,
                keyData: keyData
            )
        }
        let envelope = Envelope(
            format: Self.envelopeFormat,
            kid: keyID,
            purpose: reference.purpose,
            accountDID: reference.accountDID,
            generation: reference.generation,
            sealedKey: combined,
            publicKey: publicKey,
            publicKeyAuthentication: publicKeyAuthentication
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(envelope)
        guard encoded.count <= Self.maximumEnvelopeBytes else {
            throw SwanError.malformed("account key envelope exceeds the readable size bound")
        }
        return encoded
    }

    private func loadEnvelope(
        named filename: String,
        expectedReference: AccountKeyReference? = nil
    ) throws -> LoadedEnvelope {
        let encoded = try Self.readProtected(
            named: filename,
            maximumBytes: Self.maximumEnvelopeBytes,
            directoryDescriptor: directoryDescriptor
        )
        let envelope: Envelope
        do {
            envelope = try JSONDecoder().decode(Envelope.self, from: encoded)
        } catch {
            throw SwanError.malformed("invalid account key envelope")
        }
        guard envelope.format == Self.envelopeFormat else {
            throw SwanError.malformed("account key envelope format mismatch")
        }
        let reference = try AccountKeyReference(
            accountDID: envelope.accountDID,
            purpose: envelope.purpose,
            generation: envelope.generation
        )
        guard filename == Self.filename(for: reference),
              expectedReference == nil || expectedReference == reference else {
            throw SwanError.malformed("account key envelope binding mismatch")
        }
        return LoadedEnvelope(
            filename: filename,
            envelope: envelope,
            reference: reference
        )
    }

    private func loadAllEnvelopes() throws -> [LoadedEnvelope] {
        try Self.directoryEntryNames(
            directoryDescriptor: directoryDescriptor,
            failAfterEntryCount: failDirectoryIterationAfterEntryCount
        )
            .filter { $0.hasSuffix(".key") }
            .map { filename in
                guard Self.isCanonicalKeyFilename(filename) else {
                    throw SwanError.malformed("invalid account key envelope filename")
                }
                return try loadEnvelope(named: filename)
            }
    }

    private func decrypt(_ envelope: Envelope, reference: AccountKeyReference) throws -> Data {
        guard let keyData = configuration.key(for: envelope.kid) else {
            throw SwanError.unavailable("account key envelope references an unavailable KEK")
        }
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                AES.GCM.SealedBox(combined: envelope.sealedKey),
                using: SymmetricKey(data: keyData),
                authenticating: Self.additionalAuthenticatedData(
                    keyID: envelope.kid,
                    reference: reference
                )
            )
        } catch {
            throw SwanError.unauthorized("account key envelope authentication failed")
        }
        guard plaintext.count == 32 else {
            throw SwanError.malformed("account key envelope contains an invalid private key size")
        }
        return plaintext
    }

    private static func filename(for reference: AccountKeyReference) -> String {
        let identity = [
            envelopeFormat,
            reference.accountDID,
            reference.purpose.rawValue,
            String(reference.generation),
        ].joined(separator: "\u{0}")
        return "\(Hex.encode(SHA256.hash(data: Data(identity.utf8)))).key"
    }

    private static func isCanonicalKeyFilename(_ filename: String) -> Bool {
        guard filename.utf8.count == 68, filename.hasSuffix(".key") else { return false }
        return filename.dropLast(4).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private static func validatePLCStagingRequestID(_ requestID: String) throws {
        guard !requestID.isEmpty, requestID.utf8.count <= 128,
              requestID.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                      || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
              }) else {
            throw SwanError.invalidIdentifier("PLC account staging request")
        }
    }

    private static func plcStagingFilename(requestID: String) throws -> String {
        try validatePLCStagingRequestID(requestID)
        let digest = Hex.encode(SHA256.hash(
            data: Data("\(plcStagingFormat)\u{0}\(requestID)".utf8)
        ))
        return "\(digest).plcstage"
    }

    private static func plcStagingAAD(
        requestID: String,
        canonicalHandle: String,
        pdsOrigin: String,
        repositoryRevision: String,
        keyID: String
    ) -> Data {
        var data = Data()
        for value in [
            plcStagingFormat, keyID, requestID, canonicalHandle,
            pdsOrigin, repositoryRevision,
        ] {
            var length = UInt64(value.utf8.count).bigEndian
            withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
            data.append(contentsOf: value.utf8)
        }
        return data
    }

    private static func additionalAuthenticatedData(
        keyID: String,
        reference: AccountKeyReference
    ) -> Data {
        var data = Data()
        for field in [
            envelopeFormat,
            keyID,
            reference.purpose.rawValue,
            reference.accountDID,
            String(reference.generation),
        ] {
            var length = UInt64(field.utf8.count).bigEndian
            withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
            data.append(contentsOf: field.utf8)
        }
        return data
    }

    private static func publicKeyAuthentication(
        keyID: String,
        reference: AccountKeyReference,
        sealedKey: Data,
        publicKey: Data,
        keyData: Data
    ) -> Data {
        var metadata = Data("swan-account-public-key-v1\u{0}".utf8)
        metadata.append(additionalAuthenticatedData(keyID: keyID, reference: reference))
        for value in [sealedKey, publicKey] {
            var length = UInt64(value.count).bigEndian
            withUnsafeBytes(of: &length) { metadata.append(contentsOf: $0) }
            metadata.append(value)
        }
        return Data(HMAC<SHA256>.authenticationCode(
            for: metadata,
            using: SymmetricKey(data: keyData)
        ))
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }

    private static func openProtectedRoot(_ root: URL) throws -> Int32 {
        let parent = root.deletingLastPathComponent()
        let name = root.lastPathComponent
        try validateFilename(name)
        guard name != root.path else {
            throw SwanError.unavailable("account key-store root requires an existing parent")
        }

        let parentDescriptor = open(
            parent.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard parentDescriptor >= 0 else {
            throw SwanError.unavailable("could not open account key-store parent securely")
        }
        defer { _ = close(parentDescriptor) }

        var descriptor = openat(
            parentDescriptor,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0, errno == ENOENT {
            let created: Bool
            if mkdirat(parentDescriptor, name, mode_t(0o700)) == 0 {
                created = true
            } else if errno == EEXIST {
                created = false
            } else {
                throw SwanError.unavailable(
                    "could not create account key-store root securely"
                )
            }
            if created, fsync(parentDescriptor) != 0 {
                _ = unlinkat(parentDescriptor, name, AT_REMOVEDIR)
                _ = fsync(parentDescriptor)
                throw SwanError.unavailable(
                    "could not durably create account key-store root"
                )
            }
            descriptor = openat(
                parentDescriptor,
                name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("could not open account key-store root securely")
        }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              status.st_uid == geteuid(),
              fchmod(descriptor, mode_t(0o700)) == 0,
              fstat(descriptor, &status) == 0,
              Int(status.st_mode & mode_t(0o777)) == 0o700 else {
            _ = close(descriptor)
            throw SwanError.unavailable("account key-store root failed ownership or permission validation")
        }
        return descriptor
    }

    private static func duplicateProtectedRoot(_ descriptor: Int32) throws -> Int32 {
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else {
            throw SwanError.unavailable("account key-store root is unavailable")
        }
        var status = stat()
        guard fstat(duplicate, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              status.st_uid == geteuid(),
              Int(status.st_mode & mode_t(0o777)) == 0o700 else {
            _ = close(duplicate)
            throw SwanError.unavailable(
                "account key-store root failed ownership or permission validation"
            )
        }
        return duplicate
    }

    private static func openLockFile(directoryDescriptor: Int32) throws -> Int32 {
        let descriptor = openat(
            directoryDescriptor,
            lockFilename,
            O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw SwanError.unavailable("could not open account key-store writer lock")
        }
        var status = stat()
        guard fchmod(descriptor, mode_t(0o600)) == 0,
              fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_uid == geteuid(),
              status.st_nlink == 1,
              Int(status.st_mode & mode_t(0o777)) == 0o600,
              fsync(descriptor) == 0,
              fsync(directoryDescriptor) == 0 else {
            _ = close(descriptor)
            throw SwanError.unavailable("account key-store writer lock failed validation")
        }
        return descriptor
    }

    private static func withExclusiveLock<Result>(
        _ descriptor: Int32,
        _ body: () throws -> Result
    ) throws -> Result {
        while flock(descriptor, LOCK_EX) != 0 {
            guard errno == EINTR else {
                throw SwanError.unavailable("could not acquire account key-store writer lock")
            }
        }
        defer {
            while flock(descriptor, LOCK_UN) != 0, errno == EINTR {}
        }
        return try body()
    }

    private static func initializeActiveKeyMarkerIfNeeded(
        directoryDescriptor: Int32,
        activeKeyID: String
    ) throws {
        if try entryExists(
            named: activeKeyMarkerFilename,
            directoryDescriptor: directoryDescriptor
        ) {
            _ = try readActiveKeyMarker(directoryDescriptor: directoryDescriptor)
            return
        }
        try installCreateOnly(
            Data(activeKeyID.utf8),
            named: activeKeyMarkerFilename,
            directoryDescriptor: directoryDescriptor
        )
    }

    private static func readActiveKeyMarker(directoryDescriptor: Int32) throws -> String {
        let encoded = try readProtected(
            named: activeKeyMarkerFilename,
            maximumBytes: maximumMarkerBytes,
            directoryDescriptor: directoryDescriptor
        )
        guard let keyID = String(data: encoded, encoding: .utf8) else {
            throw SwanError.malformed("invalid active account KEK marker")
        }
        do {
            try AccountKeyEncryptionConfiguration.validateKeyID(keyID)
        } catch {
            throw SwanError.malformed("invalid active account KEK marker")
        }
        return keyID
    }

    private static func recoverProvisioningJournal(
        directoryDescriptor: Int32,
        configuration: AccountKeyEncryptionConfiguration
    ) throws {
        guard try entryExists(
            named: journalFilename,
            directoryDescriptor: directoryDescriptor
        ) else {
            return
        }
        let encoded = try readProtected(
            named: journalFilename,
            maximumBytes: maximumJournalBytes,
            directoryDescriptor: directoryDescriptor
        )
        let journal: ProvisioningJournal
        do {
            journal = try JSONDecoder().decode(ProvisioningJournal.self, from: encoded)
        } catch {
            throw SwanError.malformed("invalid account key provisioning journal")
        }
        guard journal.format == journalFormat,
              !journal.entries.isEmpty,
              journal.entries.count <= 16,
              Set(journal.entries.map(\.filename)).count == journal.entries.count,
              journal.entries.allSatisfy({
                  isCanonicalKeyFilename($0.filename)
                      && !$0.envelope.isEmpty
                      && $0.envelope.count <= maximumEnvelopeBytes
              }) else {
            throw SwanError.malformed("invalid account key provisioning journal")
        }

        for entry in journal.entries {
            try validateJournalEntry(entry, configuration: configuration)
            if try entryExists(
                named: entry.filename,
                directoryDescriptor: directoryDescriptor
            ) {
                guard try readProtected(
                    named: entry.filename,
                    maximumBytes: maximumEnvelopeBytes,
                    directoryDescriptor: directoryDescriptor
                ) == entry.envelope else {
                    throw SwanError.conflict(expected: 0, actual: 1)
                }
            } else {
                try installCreateOnly(
                    entry.envelope,
                    named: entry.filename,
                    directoryDescriptor: directoryDescriptor
                )
            }
        }
        try remove(named: journalFilename, directoryDescriptor: directoryDescriptor)
    }

    private static func validateJournalEntry(
        _ entry: JournalEntry,
        configuration: AccountKeyEncryptionConfiguration
    ) throws {
        let envelope: Envelope
        do {
            envelope = try JSONDecoder().decode(Envelope.self, from: entry.envelope)
        } catch {
            throw SwanError.malformed("invalid account key provisioning journal envelope")
        }
        guard envelope.format == envelopeFormat else {
            throw SwanError.malformed("invalid account key provisioning journal envelope")
        }
        let reference = try AccountKeyReference(
            accountDID: envelope.accountDID,
            purpose: envelope.purpose,
            generation: envelope.generation
        )
        guard entry.filename == filename(for: reference),
              let keyData = configuration.key(for: envelope.kid) else {
            throw SwanError.malformed("invalid account key provisioning journal binding")
        }
        do {
            let plaintext = try AES.GCM.open(
                AES.GCM.SealedBox(combined: envelope.sealedKey),
                using: SymmetricKey(data: keyData),
                authenticating: additionalAuthenticatedData(
                    keyID: envelope.kid,
                    reference: reference
                )
            )
            guard plaintext.count == 32 else {
                throw SwanError.malformed(
                    "invalid account key provisioning journal key size"
                )
            }
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unauthorized("account key provisioning journal authentication failed")
        }
    }

    private static func readProtected(
        named filename: String,
        maximumBytes: Int,
        directoryDescriptor: Int32
    ) throws -> Data {
        try validateFilename(filename)
        let descriptor = openat(
            directoryDescriptor,
            filename,
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw SwanError.malformed("account key-store entry is unavailable")
        }
        defer { _ = close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_uid == geteuid(),
              Int(status.st_mode & mode_t(0o777)) == 0o600,
              status.st_size > 0,
              status.st_size <= off_t(maximumBytes) else {
            throw SwanError.malformed("account key-store entry failed validation")
        }

        let expectedSize = Int(status.st_size)
        var data = Data(count: expectedSize)
        try data.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) in
            var offset = 0
            while offset < expectedSize {
                let count = posixRead(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    expectedSize - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw SwanError.malformed("account key-store entry changed during read")
                }
                offset += count
            }
        }
        var extra: UInt8 = 0
        let extraCount = withUnsafeMutablePointer(to: &extra) {
            posixRead(descriptor, $0, 1)
        }
        guard extraCount == 0 else {
            throw SwanError.malformed("account key-store entry changed during read")
        }
        return data
    }

    private static func installCreateOnly(
        _ data: Data,
        named filename: String,
        directoryDescriptor: Int32
    ) throws {
        let temporary = try writeTemporary(
            data,
            destinationName: filename,
            directoryDescriptor: directoryDescriptor
        )
        defer {
            _ = unlinkat(directoryDescriptor, temporary, 0)
        }
        guard linkat(
            directoryDescriptor,
            temporary,
            directoryDescriptor,
            filename,
            secureLinkFlags
        ) == 0 else {
            if errno == EEXIST {
                throw SwanError.conflict(expected: 0, actual: 1)
            }
            throw SwanError.unavailable("could not install account key-store entry")
        }
        guard unlinkat(directoryDescriptor, temporary, 0) == 0,
              fsync(directoryDescriptor) == 0 else {
            throw SwanError.unavailable("could not durably install account key-store entry")
        }
    }

    private static func installReplacing(
        _ data: Data,
        named filename: String,
        directoryDescriptor: Int32
    ) throws {
        let temporary = try writeTemporary(
            data,
            destinationName: filename,
            directoryDescriptor: directoryDescriptor
        )
        defer {
            _ = unlinkat(directoryDescriptor, temporary, 0)
        }
        guard renameat(
            directoryDescriptor,
            temporary,
            directoryDescriptor,
            filename
        ) == 0,
            fsync(directoryDescriptor) == 0 else {
            throw SwanError.unavailable("could not durably replace account key-store entry")
        }
    }

    private static func writeTemporary(
        _ data: Data,
        destinationName: String,
        directoryDescriptor: Int32
    ) throws -> String {
        try validateFilename(destinationName)
        guard !data.isEmpty, data.count <= maximumJournalBytes else {
            throw SwanError.malformed("account key-store entry has an invalid size")
        }
        let temporary = ".\(destinationName).\(UUID().uuidString).tmp"
        let descriptor = openat(
            directoryDescriptor,
            temporary,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard descriptor >= 0 else {
            throw SwanError.unavailable("could not create protected account key-store entry")
        }
        var status = stat()
        guard fchmod(descriptor, mode_t(0o600)) == 0,
              fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_uid == geteuid(),
              Int(status.st_mode & mode_t(0o777)) == 0o600 else {
            _ = close(descriptor)
            _ = unlinkat(directoryDescriptor, temporary, 0)
            throw SwanError.unavailable("protected account key-store entry failed validation")
        }
        var shouldClose = true
        var shouldRemove = true
        defer {
            if shouldClose {
                _ = close(descriptor)
            }
            if shouldRemove {
                _ = unlinkat(directoryDescriptor, temporary, 0)
            }
        }

        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = posixWrite(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw SwanError.unavailable("could not write protected account key-store entry")
                }
                offset += count
            }
        }
        guard fsync(descriptor) == 0, close(descriptor) == 0 else {
            throw SwanError.unavailable("could not synchronize protected account key-store entry")
        }
        shouldClose = false
        shouldRemove = false
        return temporary
    }

    private static func remove(named filename: String, directoryDescriptor: Int32) throws {
        try validateFilename(filename)
        guard unlinkat(directoryDescriptor, filename, 0) == 0,
              fsync(directoryDescriptor) == 0 else {
            throw SwanError.unavailable("could not durably remove account key-store entry")
        }
    }

    private static func entryExists(
        named filename: String,
        directoryDescriptor: Int32
    ) throws -> Bool {
        try validateFilename(filename)
        var status = stat()
        if fstatat(directoryDescriptor, filename, &status, AT_SYMLINK_NOFOLLOW) == 0 {
            return true
        }
        if errno == ENOENT {
            return false
        }
        throw SwanError.unavailable("could not inspect account key-store entry")
    }

    private static func directoryEntryNames(
        directoryDescriptor: Int32,
        failAfterEntryCount: Int? = nil
    ) throws -> [String] {
        let inventoryDescriptor = openat(
            directoryDescriptor,
            ".",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard inventoryDescriptor >= 0, let directory = fdopendir(inventoryDescriptor) else {
            if inventoryDescriptor >= 0 { _ = close(inventoryDescriptor) }
            throw SwanError.unavailable("could not inventory account key-store directory")
        }
        defer { _ = closedir(directory) }

        var names: [String] = []
        while true {
            errno = 0
            let entry: UnsafeMutablePointer<dirent>?
            if failAfterEntryCount == names.count {
                errno = EIO
                entry = nil
            } else {
                entry = readdir(directory)
            }
            guard let entry else {
                guard errno == 0 else {
                    throw SwanError.unavailable(
                        "could not inventory account key-store directory"
                    )
                }
                break
            }
            var nameStorage = entry.pointee.d_name
            let capacity = MemoryLayout.size(ofValue: nameStorage)
            let name = withUnsafePointer(to: &nameStorage) {
                $0.withMemoryRebound(to: CChar.self, capacity: capacity) {
                    String(cString: $0)
                }
            }
            if name != ".", name != ".." {
                names.append(name)
            }
        }
        return names
    }

    private static func validateFilename(_ filename: String) throws {
        guard !filename.isEmpty, filename.utf8.count <= 255,
              filename != ".", filename != "..",
              !filename.contains("/"), !filename.contains("\u{0}") else {
            throw SwanError.malformed("invalid account key-store filename")
        }
    }

    private static func posixRead(
        _ descriptor: Int32,
        _ buffer: UnsafeMutableRawPointer,
        _ count: Int
    ) -> Int {
        #if canImport(Darwin)
        Darwin.read(descriptor, buffer, count)
        #else
        Glibc.read(descriptor, buffer, count)
        #endif
    }

    private static var secureLinkFlags: Int32 {
        #if canImport(Darwin)
        AT_SYMLINK_NOFOLLOW_ANY
        #else
        0
        #endif
    }

    private static func posixWrite(
        _ descriptor: Int32,
        _ buffer: UnsafeRawPointer,
        _ count: Int
    ) -> Int {
        #if canImport(Darwin)
        Darwin.write(descriptor, buffer, count)
        #else
        Glibc.write(descriptor, buffer, count)
        #endif
    }
}
