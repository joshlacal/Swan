import CBLAKE3
import Crypto
import Foundation
import Petrel
import SwanCore

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum Blake3 {
    /// Produces a BLAKE3 XOF output of an explicit size using only the vendored
    /// portable reference implementation.
    public static func xof(_ input: Data, outputLength: Int) -> Data {
        precondition(outputLength >= 0)
        var hasher = blake3_hasher()
        blake3_hasher_init(&hasher)
        if !input.isEmpty {
            input.withUnsafeBytes { bytes in
                blake3_hasher_update(&hasher, bytes.baseAddress, bytes.count)
            }
        }
        var output = Data(repeating: 0, count: outputLength)
        output.withUnsafeMutableBytes { bytes in
            blake3_hasher_finalize(
                &hasher,
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                bytes.count
            )
        }
        return output
    }
}

/// The three-part permissioned-data space identifier:
/// `at://{authorityDid}/space/{spaceType}/{skey}`.
public struct SpaceURI: Sendable, Codable, Hashable, CustomStringConvertible {
    public let authority: String
    public let spaceType: String
    public let skey: String

    public init(authority: String, spaceType: String, skey: String) throws {
        guard Self.isValidDID(authority), Self.isValidNSID(spaceType), Self.isValidRecordKey(skey) else {
            throw SwanError.invalidIdentifier("space URI")
        }
        self.authority = authority
        self.spaceType = spaceType
        self.skey = skey
    }

    public init(_ rawValue: String) throws {
        let parsed = try Self.parse(rawValue)
        guard parsed.path.count == 3, parsed.path[0] == "space" else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        try self.init(authority: parsed.authority, spaceType: parsed.path[1], skey: parsed.path[2])
    }

    public var description: String { "at://\(authority)/space/\(spaceType)/\(skey)" }
    public var rawValue: String { description }

    fileprivate static func parse(_ rawValue: String) throws -> (authority: String, path: [String]) {
        guard rawValue.hasPrefix("at://"), !rawValue.contains("?") && !rawValue.contains("#") else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        let remainder = rawValue.dropFirst(5)
        let pieces = remainder.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard let authority = pieces.first, !authority.isEmpty, pieces.count > 1,
              !pieces.dropFirst().contains(where: { $0.isEmpty }) else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        return (authority, Array(pieces.dropFirst()))
    }

    fileprivate static func isValidDID(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count >= 3 && parts[0] == "did" && !parts[1].isEmpty && !parts.dropFirst(2).joined(separator: ":").isEmpty &&
            value.utf8.allSatisfy { $0 >= 33 && $0 <= 126 && $0 != 47 && $0 != 63 && $0 != 35 }
    }

    fileprivate static func isValidNSID(_ value: String) -> Bool {
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 3, value.utf8.count <= 317 else { return false }
        return labels.allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63, label.first?.isLetter == true else { return false }
            return label.utf8.allSatisfy { byte in
                (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) ||
                    (byte >= 97 && byte <= 122) || byte == 45
            }
        }
    }

    fileprivate static func isValidRecordKey(_ value: String) -> Bool {
        guard (1...512).contains(value.utf8.count), value != ".", value != ".." else { return false }
        return value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) ||
                (byte >= 97 && byte <= 122) || byte == 45 || byte == 46 ||
                byte == 95 || byte == 58 || byte == 126
        }
    }
}

/// The complete permissioned-record identifier:
/// `at://{spaceDid}/space/{type}/{skey}/{authorDid}/{collection}/{rkey}`.
public struct SpaceRecordURI: Sendable, Codable, Hashable, CustomStringConvertible {
    public let space: SpaceURI
    public let author: String
    public let collection: String
    public let rkey: String

    public init(space: SpaceURI, author: String, collection: String, rkey: String) throws {
        guard SpaceURI.isValidDID(author), SpaceURI.isValidNSID(collection), SpaceURI.isValidRecordKey(rkey) else {
            throw SwanError.invalidIdentifier("space record URI")
        }
        self.space = space
        self.author = author
        self.collection = collection
        self.rkey = rkey
    }

    public init(_ rawValue: String) throws {
        let parsed = try SpaceURI.parse(rawValue)
        guard parsed.path.count == 6, parsed.path[0] == "space" else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        let space = try SpaceURI(authority: parsed.authority, spaceType: parsed.path[1], skey: parsed.path[2])
        try self.init(space: space, author: parsed.path[3], collection: parsed.path[4], rkey: parsed.path[5])
    }

    public var description: String { "\(space)/\(author)/\(collection)/\(rkey)" }
    public var rawValue: String { description }
}

/// The 2,048-byte LtHash state is 1,024 little-endian UInt16 lanes. Elements
/// are added and removed modulo 2^16; XOR is not an equivalent construction.
public struct LtHash: Sendable, Equatable {
    public static let byteCount = 2048
    private var bytes: Data

    public init() { bytes = Data(repeating: 0, count: Self.byteCount) }

    public init(serialized: Data) throws {
        guard serialized.count == Self.byteCount else {
            throw SwanError.malformed("LtHash must contain \(Self.byteCount) bytes")
        }
        bytes = serialized
    }

    public mutating func add(element: String) { apply(element: Data(element.utf8), subtracting: false) }
    public mutating func remove(element: String) { apply(element: Data(element.utf8), subtracting: true) }

    public var serialized: Data { bytes }
    public var commitment: Data { Data(SHA256.hash(data: bytes)) }

    private mutating func apply(element: Data, subtracting: Bool) {
        let contribution = Blake3.xof(element, outputLength: Self.byteCount)
        bytes.withUnsafeMutableBytes { state in
            contribution.withUnsafeBytes { expanded in
                guard let state = state.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let expanded = expanded.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                for offset in stride(from: 0, to: Self.byteCount, by: 2) {
                    let existing = UInt16(state[offset]) | UInt16(state[offset + 1]) << 8
                    let value = UInt16(expanded[offset]) | UInt16(expanded[offset + 1]) << 8
                    let result = subtracting ? existing &- value : existing &+ value
                    state[offset] = UInt8(truncatingIfNeeded: result)
                    state[offset + 1] = UInt8(truncatingIfNeeded: result >> 8)
                }
            }
        }
    }
}

public enum SpacePermission: String, Codable, Sendable, CaseIterable {
    case readSelf = "read_self"
    case read
    case create
    case update
    case delete
    case manage
}

/// The pinned OAuth `manage` vocabulary for authority-owned simple-space
/// lifecycle operations.  It is intentionally separate from record actions:
/// a grant that can write a permissioned record must never imply membership or
/// lifecycle control.
public enum SimpleSpaceManagementOperation: String, Codable, Sendable, CaseIterable {
    case create
    case update
    case delete
}

public struct SpaceGrant: Codable, Sendable, Equatable {
    public let subject: String
    public let space: SpaceURI
    public let permissions: Set<SpacePermission>
    public let expiresAt: Date
    public let clientID: String?

    public init(subject: String, space: SpaceURI, permissions: Set<SpacePermission>, expiresAt: Date, clientID: String? = nil) {
        self.subject = subject
        self.space = space
        self.permissions = permissions
        self.expiresAt = expiresAt
        self.clientID = clientID
    }

    public func allows(_ permission: SpacePermission, now: Date = Date()) throws {
        guard expiresAt > now else { throw SwanError.expired }
        guard permissions.contains(permission) || permissions.contains(.manage) else {
            throw SwanError.unauthorized("missing \(permission.rawValue) grant")
        }
    }
}

/// Authorization is modeled explicitly. Repository operations never accept an
/// unauditable `authenticated: Bool` escape hatch.
public enum AuthorizationContext: Sendable, Equatable {
    case `public`
    /// Carries a parsed, frozen permissions value rather than raw strings
    /// (§6.5.1). This is the single highest-leverage change in the scope
    /// rollout: it moves parsing from "every predicate, every call" to "once,
    /// at the boundary that already validated the token"
    /// (`SwanOAuthResourceAuthorization.swift:145-160`).
    ///
    /// `SwanScopePermissions` is `Sendable, Equatable, Hashable`, so this
    /// enum's existing conformance is preserved with no `@unchecked` anywhere.
    case accountOAuth(subject: String, permissions: SwanScopePermissions)
    /// A short-lived, signature-verified user-to-space-host delegation. This
    /// context exists only while the authority evaluates whether that user may
    /// exchange it for a read credential. It is deliberately not a repository
    /// capability: a delegation cannot read or write records directly.
    case spaceDelegation(subject: String, space: SpaceURI)
    case spaceSelfRead(subject: String, space: SpaceURI)
    case spaceCredential(SpaceGrant)
    case service(subject: String, audience: String)
}

/// The permissioned-repository authorization policy. Keeping this decision at
/// the domain layer means durable adapters preflight the exact same facts as
/// the in-memory laboratory repository; no adapter gets an `authenticated`
/// boolean escape hatch.
public enum SpaceAuthorizationPolicy {
    public static func require(
        space: SpaceURI,
        author: String,
        uri: SpaceRecordURI?,
        authorization: AuthorizationContext,
        permission: SpacePermission
    ) throws {
        switch authorization {
        case let .spaceCredential(grant):
            guard grant.space == space else {
                throw SwanError.unauthorized("credential is for another space")
            }
            // A proposal space credential is a read credential. Writes require
            // a user OAuth grant for the author of this repository.
            guard permission == .read else {
                throw SwanError.unauthorized("space credentials are read-only")
            }
            try grant.allows(.read)
        case let .spaceSelfRead(subject, grantSpace):
            guard permission == .read, grantSpace == space, subject == author else {
                throw SwanError.unauthorized("self grant cannot perform this operation")
            }
        case .spaceDelegation:
            throw SwanError.unauthorized("delegation tokens cannot access repositories")
        case let .accountOAuth(subject, permissions):
            // A `.manage` DOMAIN permission reaching the record path is a
            // denial, preserving today's unsatisfiable-by-construction
            // behaviour explicitly rather than by accident (§6.2). Likewise a
            // write naming no collection: `SpaceScopeTarget.record` returns
            // `nil` rather than widening it into a collection-free write.
            guard subject == author,
                  let action = SpaceRecordAction(permission),
                  let target = SpaceScopeTarget.record(
                      space,
                      action: action,
                      collection: uri?.collection
                  ),
                  permissions.allowsSpace(target)
            else {
                throw SwanError.unauthorized("OAuth scope does not cover this space operation")
            }
        case let .service(_, audience):
            guard permission == .read, audience == space.authority else {
                throw SwanError.unauthorized("service authentication is read-only")
            }
        case .public:
            throw SwanError.unauthorized("space credential or OAuth grant required")
        }
    }

    /// A single-blob read (Erratum 03). Every arm except `accountOAuth`
    /// delegates to ``require(space:author:uri:authorization:permission:)``
    /// with `.read` — credentials, self-reads, service auth, and the refusals
    /// are unchanged. The OAuth arm alone differs: it matches against
    /// ``SpaceScopeTarget/blobRead(_:)`` (non-aggregate, collection-free)
    /// instead of the derived aggregate target, so a collection-qualified
    /// grant that reads its records can also fetch the blobs those records
    /// reference. See the constructor's doc for why this is not a §6.5.5
    /// bypass.
    public static func requireBlobRead(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) throws {
        if case let .accountOAuth(subject, permissions) = authorization {
            guard subject == author,
                  permissions.allowsSpace(SpaceScopeTarget.blobRead(space))
            else {
                throw SwanError.unauthorized("OAuth scope does not cover this space operation")
            }
            return
        }
        try require(
            space: space,
            author: author,
            uri: nil,
            authorization: authorization,
            permission: .read
        )
    }

    /// Requires the exact pinned `manage` verb for a simple-space authority
    /// operation.  The broad `atproto` grant is deliberately retained for an
    /// account's own PDS, while a scoped grant must bind the type, authority,
    /// skey, and one lifecycle verb.  `action=manage` is not an OAuth scope
    /// form and is therefore not accepted here.
    public static func requireManagement(
        space: SpaceURI,
        authorization: AuthorizationContext,
        operation: SimpleSpaceManagementOperation
    ) throws {
        guard case let .accountOAuth(subject, permissions) = authorization,
              subject == space.authority else {
            throw SwanError.unauthorized("authority account OAuth is required")
        }
        // The ambient `atproto` bypass is preserved verbatim and stays gated on
        // `subject == space.authority` above (§6.5.6). Worth stating: this
        // bypass is *stricter* than upstream's transition scopes, which never
        // reach a space at all (`scope-permissions-transition.ts:55-61`) —
        // Swan's applies only to an account acting on its own authority, so it
        // is not the same hazard.
        if permissions.hasBaseATProtocolScope { return }
        guard permissions.allowsSpace(.manage(space, operation: operation)) else {
            throw SwanError.unauthorized("OAuth scope does not cover this space management operation")
        }
    }
}

/// Transitional laboratory credential envelope. It is deliberately distinct
/// from an author signature and is only used by the in-process policy tests;
/// production wire credentials are JWTs handled by SwanOAuth.
public struct SpaceCredential: Codable, Sendable, Equatable {
    public let grant: SpaceGrant
    public let issuedAt: Date
    public let nonce: String

    public init(grant: SpaceGrant, issuedAt: Date = Date(), nonce: String = UUID().uuidString) {
        self.grant = grant
        self.issuedAt = issuedAt
        self.nonce = nonce
    }
}

public struct SignedSpaceCredential: Codable, Sendable, Equatable {
    public let credential: SpaceCredential
    public let mac: Data
}

// Crypto.SymmetricKey is immutable for this use, but the Swift Crypto 3.15
// Linux overlay does not yet declare it Sendable. The authority never mutates
// or exposes the key after initialization, so make that invariant explicit at
// this boundary rather than weakening the package's strict-concurrency mode.
public struct HMACSpaceCredentialAuthority: @unchecked Sendable {
    private let key: SymmetricKey

    public init(key: Data) { self.key = SymmetricKey(data: key) }

    public func issue(_ credential: SpaceCredential) throws -> SignedSpaceCredential {
        SignedSpaceCredential(credential: credential, mac: try mac(for: credential))
    }

    public func verify(_ signed: SignedSpaceCredential, now: Date = Date()) throws -> SpaceGrant {
        let expected = try mac(for: signed.credential)
        guard constantTimeEqual(expected, signed.mac) else {
            throw SwanError.unauthorized("invalid space credential")
        }
        guard signed.credential.grant.expiresAt > now else { throw SwanError.expired }
        return signed.credential.grant
    }

    private func mac(for credential: SpaceCredential) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return Data(HMAC<SHA256>.authenticationCode(for: try encoder.encode(credential), using: key))
    }
}

public struct SpaceCommitContext: Codable, Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let rev: String
    public let ikm: Data

    public init(space: SpaceURI, author: String, rev: String, ikm: Data) throws {
        guard SpaceURI.isValidDID(author), ikm.count == 32 else {
            throw SwanError.malformed("invalid commit author or IKM")
        }
        self.space = space
        self.author = author
        self.rev = rev
        self.ikm = ikm
    }
}

public struct SpaceCommitEnvelope: Codable, Sendable, Equatable {
    public let ver: Int
    public let context: SpaceCommitContext
    public let contextSignature: Data
    public let contentBinding: Data
    public let commitment: Data

    public init(ver: Int = 1, context: SpaceCommitContext, contextSignature: Data, contentBinding: Data, commitment: Data) {
        self.ver = ver
        self.context = context
        self.contextSignature = contextSignature
        self.contentBinding = contentBinding
        self.commitment = commitment
    }
}

public enum SpaceCommitCodec {
    /// Creates a distinct reader response each time. Repository state stores
    /// the LtHash commitment, never one reader's IKM/signature envelope.
    public static func createReaderEnvelope(
        space: SpaceURI,
        author: String,
        rev: String,
        commitment: Data,
        key: P256.Signing.PrivateKey
    ) throws -> SpaceCommitEnvelope {
        var generator = SystemRandomNumberGenerator()
        let ikm = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        return try sign(context: SpaceCommitContext(space: space, author: author, rev: rev, ikm: ikm), commitment: commitment, key: key)
    }

    public static func sign(
        context: SpaceCommitContext,
        commitment: Data,
        key: P256.Signing.PrivateKey
    ) throws -> SpaceCommitEnvelope {
        guard commitment.count == 32 else { throw SwanError.malformed("commitment must be SHA-256 bytes") }
        let payload = try encodedContext(context)
        let signature = try P256WireSignature.sign(payload, using: key)
        let binding = contentBinding(ikm: context.ikm, context: payload, commitment: commitment)
        return SpaceCommitEnvelope(context: context, contextSignature: signature, contentBinding: binding, commitment: commitment)
    }

    /// Verifies only the author signature over `(space, author, rev, ikm)`.
    /// It intentionally does not claim that the author signed repository data.
    public static func verifyContextSignature(_ envelope: SpaceCommitEnvelope, publicKey: P256.Signing.PublicKey) throws -> Bool {
        guard envelope.ver == 1 else { return false }
        let signature = try P256WireSignature.decodeCanonical(envelope.contextSignature)
        return publicKey.isValidSignature(signature, for: try contextSigningBytes(envelope.context))
    }

    /// Returns the exact proposal-0016 context bytes signed by a repository
    /// author.  Cross-implementation consumers use this to select the
    /// author-key algorithm (for example ES256K) without duplicating the
    /// length-prefix/domain encoding.
    public static func contextSigningBytes(_ context: SpaceCommitContext) throws -> Data {
        try encodedContext(context)
    }

    /// Verifies the deniable HMAC content binding. This must never be called a
    /// signature: every reader can derive its key from the public IKM.
    public static func verifyContentBinding(_ envelope: SpaceCommitEnvelope) -> Bool {
        guard envelope.ver == 1, envelope.commitment.count == 32,
              let context = try? encodedContext(envelope.context) else { return false }
        return constantTimeEqual(
            contentBinding(ikm: envelope.context.ikm, context: context, commitment: envelope.commitment),
            envelope.contentBinding
        )
    }

    private static func contentBinding(ikm: Data, context: Data, commitment: Data) -> Data {
        // The pinned proposal/TypeScript implementation uses the 32-byte IKM
        // directly as the HKDF-Expand pseudorandom key.  CryptoKit's
        // `HKDF.deriveKey` convenience performs an additional Extract step,
        // which is a different wire value even when the IKM is already the
        // required PRK.  This is the one-block HKDF-Expand construction from
        // RFC 5869: HMAC(PRK, info || 0x01).
        var expandInput = context
        expandInput.append(0x01)
        let derived = SymmetricKey(data: Data(HMAC<SHA256>.authenticationCode(
            for: expandInput,
            using: SymmetricKey(data: ikm)
        )))
        return Data(HMAC<SHA256>.authenticationCode(for: commitment, using: derived))
    }

    private static func encodedContext(_ context: SpaceCommitContext) throws -> Data {
        var output = Data("atproto-space-v1".utf8)
        for field in [Data(context.space.rawValue.utf8), Data(context.author.utf8), Data(context.rev.utf8), context.ikm] {
            guard field.count <= Int(UInt16.max) else { throw SwanError.malformed("commit context field too large") }
            let length = UInt16(field.count).bigEndian
            withUnsafeBytes(of: length) { output.append(contentsOf: $0) }
            output.append(field)
        }
        return output
    }
}

public struct SpaceCAR: Sendable, Equatable {
    public let data: Data
    public let commitCID: CID
    public let indexCID: CID
}

/// Fully revalidated recovery facts decoded from a two-root permissioned CAR.
/// Reader-specific envelope material is deliberately omitted: restore callers
/// receive only the wire revision and repository facts authenticated by it.
public struct VerifiedSpaceCARRecovery: Sendable, Equatable {
    public let wireRevision: TID
    public let records: [SpaceRecord]
    public let ltHash: Data
    public let commitment: Data

    public init(
        wireRevision: TID,
        records: [SpaceRecord],
        ltHash: Data,
        commitment: Data
    ) {
        self.wireRevision = wireRevision
        self.records = records
        self.ltHash = ltHash
        self.commitment = commitment
    }
}

/// Immutable producer-side admission for a proposal-0016 full recovery.
/// Swan reserves the consumer's entire 64 KiB signed-commit allowance even
/// though ordinary P-256 commits are much smaller, so storage can reject an
/// oversized suffix before a reader-specific envelope exists.
public enum SpaceCARProductionLimits {
    public static let maximumRecordCount =
        SpaceCARRecoveryLimits.absoluteMaximumIndexEntries
    public static let maximumRecordBytes =
        SpaceCARRecoveryLimits.absoluteMaximumRecordBytes
    public static let maximumLogicalMetadataBytes = 64 * 1_024 * 1_024
    /// Conservative process admission includes the final CAR allowance plus
    /// two metadata allowances: one for the encoded index during handoff and
    /// one for the connection-local SQLite projection/B-tree overhead that
    /// remains live while the body spool is assembled.
    public static let maximumWorkingSpoolBytes =
        SpaceCARRecoveryLimits.absoluteMaximumCARBytes
            + 2 * maximumLogicalMetadataBytes

    /// One-byte length + canonical 99-byte CAR header + a three-byte frame
    /// length + 36-byte CID + the consumer's 64 KiB commit-body allowance.
    public static let maximumRecoveryPrefixBytes =
        1 + 99 + 3 + 36
            + SpaceCARRecoveryLimits.absoluteMaximumCommitBytes
    public static let maximumBodyBytes =
        SpaceCARRecoveryLimits.absoluteMaximumCARBytes
            - maximumRecoveryPrefixBytes

    public static func limitExceeded() -> SwanError {
        SwanError.unavailable("permissioned CAR exceeds production limits")
    }
}

/// Process-wide and per-account reservation for private full-recovery spools.
/// Each request reserves the complete consumer CAR allowance plus its bounded
/// producer metadata working set before a path is created, bounding both disk
/// amplification and slow-reader concurrency.
public final class SpaceCARSpoolAdmission: @unchecked Sendable {
    public struct Snapshot: Sendable, Equatable {
        public let reservedBytes: Int
        public let activeLeases: Int

        public init(reservedBytes: Int, activeLeases: Int) {
            self.reservedBytes = reservedBytes
            self.activeLeases = activeLeases
        }
    }

    private let maximumGlobalBytes: Int
    private let maximumPerAccountBytes: Int
    private let lock = NSLock()
    private var leases: [UUID: (account: String, bytes: Int)] = [:]
    private var reservedByAccount: [String: Int] = [:]

    public init(
        maximumGlobalBytes: Int = 1_024 * 1_024 * 1_024,
        maximumPerAccountBytes: Int = 512 * 1_024 * 1_024
    ) throws {
        guard maximumGlobalBytes > 0,
              maximumPerAccountBytes > 0,
              maximumPerAccountBytes <= maximumGlobalBytes
        else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        self.maximumGlobalBytes = maximumGlobalBytes
        self.maximumPerAccountBytes = maximumPerAccountBytes
    }

    public func reserve(
        accountDID: String,
        maximumBytes: Int
    ) -> SpaceCARSpoolLease? {
        guard SpaceURI.isValidDID(accountDID), maximumBytes > 0 else {
            return nil
        }
        return lock.withLock {
            let global = leases.values.reduce(0) { partial, lease in
                let (next, overflow) = partial.addingReportingOverflow(
                    lease.bytes
                )
                return overflow ? Int.max : next
            }
            let account = reservedByAccount[accountDID, default: 0]
            guard global <= maximumGlobalBytes,
                  account <= maximumPerAccountBytes,
                  maximumBytes <= maximumGlobalBytes - global,
                  maximumBytes <= maximumPerAccountBytes - account
            else {
                return nil
            }
            let id = UUID()
            leases[id] = (accountDID, maximumBytes)
            reservedByAccount[accountDID] = account + maximumBytes
            return SpaceCARSpoolLease(admission: self, id: id)
        }
    }

    public var snapshot: Snapshot {
        lock.withLock {
            Snapshot(
                reservedBytes: leases.values.reduce(0) { partial, lease in
                    partial + lease.bytes
                },
                activeLeases: leases.count
            )
        }
    }

    fileprivate func release(_ id: UUID) {
        lock.withLock {
            guard let lease = leases.removeValue(forKey: id) else { return }
            let remaining =
                reservedByAccount[lease.account, default: 0] - lease.bytes
            if remaining == 0 {
                reservedByAccount.removeValue(forKey: lease.account)
            } else {
                reservedByAccount[lease.account] = remaining
            }
        }
    }
}

public final class SpaceCARSpoolLease: @unchecked Sendable {
    private weak var admission: SpaceCARSpoolAdmission?
    private let id: UUID
    private let lock = NSLock()
    private var released = false

    fileprivate init(admission: SpaceCARSpoolAdmission, id: UUID) {
        self.admission = admission
        self.id = id
    }

    deinit { release() }

    public func release() {
        let target = lock.withLock {
            guard !released else {
                return nil as SpaceCARSpoolAdmission?
            }
            released = true
            return admission
        }
        target?.release(id)
    }
}

/// An owner-only, private spool containing the index and record-block suffix
/// of a full-recovery CAR.  It deliberately never contains the request's
/// reader-specific commit envelope: fresh IKM, the context signature, and the
/// deniable binding stay in the small HTTP response prefix until the response
/// is written.
///
/// `SwanSQLite` is the sole production source. It adopts an owner-only file
/// descriptor after unlinking its directory entry, so consumers cannot obtain
/// or replace a path and a crash cannot orphan private bytes. The descriptor is
/// single-use and drains only through bounded chunks on success, write failure,
/// or task cancellation.
public final class SpaceCARBodySpool: @unchecked Sendable {
    /// A deliberately small maximum for a single Hummingbird body write. It
    /// bounds response-side buffering independently of the CAR size.
    public static let maximumChunkBytes = 64 * 1_024

    public let indexCID: CID
    /// Exact index-plus-record suffix bytes. HTTP can combine this with its
    /// freshly created prefix before constructing response headers.
    public let bodyByteCount: Int
    private let adoptedHandle: FileHandle?
    private let bodyURL: URL?
    private let lease: SpaceCARSpoolLease?
    private let cleanupLock = NSLock()
    private enum State {
        case available
        case streaming
        case cleaned
    }
    private var state: State = .available

    /// Compatibility initializer for small local tests. Production SQLite
    /// adopts an already-open, unlinked descriptor through the initializer
    /// below so no permissioned bytes remain reachable by pathname.
    package init(
        indexCID: CID,
        bodyURL: URL,
        bodyByteCount: Int? = nil,
        lease: SpaceCARSpoolLease? = nil
    ) throws {
        self.indexCID = indexCID
        adoptedHandle = nil
        self.bodyURL = bodyURL
        self.lease = lease
        let discovered = try? bodyURL.resourceValues(
            forKeys: [.fileSizeKey]
        ).fileSize
        let resolvedByteCount = bodyByteCount ?? discovered ?? 0
        guard resolvedByteCount >= 0 else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        self.bodyByteCount = resolvedByteCount
    }

    /// Adopts an owner-only descriptor whose pathname has already been
    /// unlinked. The spool is single-use and owns both close and lease release.
    package init(
        indexCID: CID,
        fileHandle: FileHandle,
        bodyByteCount: Int,
        lease: SpaceCARSpoolLease? = nil
    ) throws {
        guard bodyByteCount >= 0 else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        self.indexCID = indexCID
        adoptedHandle = fileHandle
        bodyURL = nil
        self.lease = lease
        self.bodyByteCount = bodyByteCount
    }

    deinit {
        cleanup()
    }

    /// An observable cleanup state is intentionally useful for deterministic
    /// storage/transport tests. It reveals no repository path or data.
    public var isCleanedUp: Bool {
        cleanupLock.withLock { state == .cleaned }
    }

    /// Drains the private CAR suffix through fixed-size chunks. The caller is
    /// expected to write each chunk directly to a streaming response body.
    /// This method owns cleanup even when the consumer throws or the request
    /// is cancelled.
    public func streamBody(
        maximumChunkBytes: Int = SpaceCARBodySpool.maximumChunkBytes,
        consume: (Data) async throws -> Void
    ) async throws {
        let admitted = cleanupLock.withLock {
            guard state == .available else { return false }
            state = .streaming
            return true
        }
        guard admitted else {
            throw SwanError.unavailable(
                "permissioned CAR spool is unavailable"
            )
        }
        guard (1 ... Self.maximumChunkBytes).contains(maximumChunkBytes) else {
            cleanup()
            throw SwanError.malformed("permissioned CAR chunk size is invalid")
        }
        let handle: FileHandle
        if let adoptedHandle {
            handle = adoptedHandle
        } else {
            guard let bodyURL else {
                cleanup()
                throw SwanError.unavailable(
                    "permissioned CAR spool is unavailable"
                )
            }
            do {
                handle = try FileHandle(forReadingFrom: bodyURL)
            } catch {
                cleanup()
                throw SwanError.unavailable(
                    "permissioned CAR spool is unavailable"
                )
            }
        }
        defer {
            try? handle.close()
            cleanup()
        }

        var streamedByteCount = 0
        var reusableChunk = Data(count: maximumChunkBytes)
        while streamedByteCount < bodyByteCount {
            try Task.checkCancellation()
            let requestedByteCount = min(
                maximumChunkBytes,
                bodyByteCount - streamedByteCount
            )
            let chunkByteCount = try readPOSIXBytes(
                fileDescriptor: handle.fileDescriptor,
                offset: streamedByteCount,
                maximumBytes: requestedByteCount,
                into: &reusableChunk
            )
            guard chunkByteCount > 0 else {
                throw SwanError.unavailable(
                    "permissioned CAR spool is unavailable"
                )
            }
            let (nextByteCount, overflow) =
                streamedByteCount.addingReportingOverflow(chunkByteCount)
            guard !overflow, nextByteCount <= bodyByteCount else {
                throw SwanError.unavailable(
                    "permissioned CAR spool is unavailable"
                )
            }
            streamedByteCount = nextByteCount
            if chunkByteCount == reusableChunk.count {
                try await consume(reusableChunk)
            } else {
                // Regular-file pread fills all nonterminal requests. Keep the
                // reusable allocation at maximum size and copy only the one
                // terminal short chunk (or an anomalous short read).
                try await consume(Data(reusableChunk.prefix(chunkByteCount)))
            }
        }
        // The byte count is part of the authenticated producer handoff. Check
        // that the descriptor has neither truncated nor grown behind it.
        var endProbe = Data(count: 1)
        guard try readPOSIXBytes(
            fileDescriptor: handle.fileDescriptor,
            offset: streamedByteCount,
            maximumBytes: 1,
            into: &endProbe
        ) == 0 else {
            throw SwanError.unavailable(
                "permissioned CAR spool is unavailable"
            )
        }
    }

    /// Foundation's `FileHandle.read(upToCount:)` can retain one autoreleased
    /// NSData per iteration until an async task yields back to its outer pool.
    /// A near-256 MiB response then appears bounded by chunk size while RSS
    /// still grows by the complete CAR. `pread(2)` fills native Swift `Data`
    /// directly and lets ARC/malloc reuse each completed 64 KiB region.
    private func readPOSIXBytes(
        fileDescriptor: Int32,
        offset: Int,
        maximumBytes: Int,
        into buffer: inout Data
    ) throws -> Int {
        guard fileDescriptor >= 0,
              offset >= 0,
              maximumBytes > 0,
              maximumBytes <= buffer.count
        else {
            throw SwanError.unavailable(
                "permissioned CAR spool is unavailable"
            )
        }
        return try buffer.withUnsafeMutableBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return 0 }
            while true {
                #if canImport(Darwin)
                let result = Darwin.pread(
                    fileDescriptor,
                    baseAddress,
                    maximumBytes,
                    off_t(offset)
                )
                #elseif canImport(Glibc)
                let result = Glibc.pread(
                    fileDescriptor,
                    baseAddress,
                    maximumBytes,
                    off_t(offset)
                )
                #else
                let result = -1
                #endif
                if result >= 0 { return result }
                guard errno == EINTR else {
                    throw SwanError.unavailable(
                        "permissioned CAR spool is unavailable"
                    )
                }
            }
        }
    }

    /// Removes the private spool idempotently. It is safe to call before a
    /// response begins, after a failed write, or more than once.
    public func cleanup() {
        let shouldClean = cleanupLock.withLock {
            guard state != .cleaned else { return false }
            state = .cleaned
            return true
        }
        guard shouldClean else { return }
        try? adoptedHandle?.close()
        if let bodyURL,
           FileManager.default.fileExists(atPath: bodyURL.path)
        {
            try? FileManager.default.removeItem(at: bodyURL)
        }
        lease?.release()
    }
}

/// CAR v1 full-recovery encoding for a permissioned repository. Its roots are
/// exactly `[signedCommit, index]`; records are neither public-repository CAR
/// data nor blobs and therefore cannot be passed to public export surfaces.
public enum SpaceCARCodec {
    public static func encode(commit: SpaceCommitEnvelope, records: [SpaceRecord]) throws -> SpaceCAR {
        let commitBlock = try encodeCommit(commit)
        let commitCID = CID.fromDAGCBOR(commitBlock)

        let orderedRecords = records.sorted { left, right in
            recordPath(left).utf8.lexicographicallyPrecedes(recordPath(right).utf8)
        }
        guard Set(orderedRecords.map(recordPath)).count == orderedRecords.count else {
            throw SwanError.malformed("duplicate permissioned record path")
        }
        let index = OrderedCBORMap(entries: orderedRecords.map { record in
            (key: recordPath(record), value: ATProtoLink(cid: CID.fromDAGCBOR(record.value)))
        })
        let indexBlock = try DAGCBOR.encodeValue(index)
        let indexCID = CID.fromDAGCBOR(indexBlock)

        let header = OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: commitCID), ATProtoLink(cid: indexCID)]),
            (key: "version", value: 1),
        ])
        var output = Data()
        let headerBlock = try DAGCBOR.encodeValue(header)
        appendVarint(headerBlock.count, to: &output)
        output.append(headerBlock)
        appendBlock(cid: commitCID, data: commitBlock, to: &output)
        appendBlock(cid: indexCID, data: indexBlock, to: &output)
        var emittedCIDs = Set<String>()
        for record in orderedRecords {
            let cid = CID.fromDAGCBOR(record.value)
            // DRISL retains every path, while CAR block storage is
            // content-addressed. Proposal 0016 and the pinned TypeScript PDS
            // therefore emit one block per unique CID, ordered by the first
            // lexical path that references it.
            guard emittedCIDs.insert(cid.string).inserted else { continue }
            appendBlock(cid: cid, data: record.value, to: &output)
        }
        return SpaceCAR(data: output, commitCID: commitCID, indexCID: indexCID)
    }

    /// Produces the short CAR prefix for a bounded-memory recovery response.
    /// The caller appends the already validated index+record suffix from a
    /// private spool. The root order is fixed by proposal 0016: signed commit,
    /// then DRISL index.
    public static func recoveryPrefix(
        commit: SpaceCommitEnvelope,
        indexCID: CID
    ) throws -> Data {
        let commitBlock = try encodeCommit(commit)
        guard commitBlock.count
            <= SpaceCARRecoveryLimits.absoluteMaximumCommitBytes
        else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        let commitCID = CID.fromDAGCBOR(commitBlock)
        let header = OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: commitCID), ATProtoLink(cid: indexCID)]),
            (key: "version", value: 1),
        ])
        let headerBlock = try DAGCBOR.encodeValue(header)
        var output = Data()
        appendVarint(headerBlock.count, to: &output)
        output.append(headerBlock)
        appendBlock(cid: commitCID, data: commitBlock, to: &output)
        guard output.count <= SpaceCARProductionLimits.maximumRecoveryPrefixBytes
        else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        return output
    }

    /// Starts a canonical DAG-CBOR DRISL index map without retaining the map
    /// or its values in memory. Entries must follow Petrel's canonical
    /// length-then-byte key order; record blocks themselves remain in the
    /// proposal's lexicographic `collection/rkey` order.
    public static func streamingIndexPrefix(recordCount: Int) throws -> Data {
        guard recordCount >= 0 else {
            throw SwanError.malformed("permissioned CAR record count is invalid")
        }
        return cborMajorHeader(major: 5, argument: UInt64(recordCount))
    }

    /// Encodes exactly one canonical DRISL map entry. Keeping this operation
    /// in the space domain avoids exposing a generic CBOR/CAR writer to the
    /// SQLite adapter.
    public static func streamingIndexEntry(path: String, cid: CID) throws -> Data {
        guard isRecordPath(path), cid.bytes.count <= Int(UInt16.max) else {
            throw SwanError.malformed("permissioned CAR index entry is invalid")
        }
        let key = Data(path.utf8)
        var output = cborMajorHeader(major: 3, argument: UInt64(key.count))
        output.append(key)
        // DAG-CBOR CID links are tag 42 around a byte string whose leading
        // zero distinguishes the CID binary representation from a raw byte
        // string. Petrel's `ATProtoLink` emits this same representation.
        output.append(0xd8)
        output.append(0x2a)
        output.append(cborMajorHeader(major: 2, argument: UInt64(cid.bytes.count + 1)))
        output.append(0)
        output.append(cid.bytes)
        return output
    }

    /// The CAR block framing for a previously validated block. This is kept
    /// separate from `encode` so storage can copy a large value directly to a
    /// private spool rather than assembling a response-wide `Data` value.
    public static func streamingBlockPrefix(cid: CID, dataLength: Int) throws -> Data {
        guard dataLength >= 0, dataLength <= Int.max - cid.bytes.count else {
            throw SwanError.malformed("permissioned CAR block length is invalid")
        }
        var output = Data()
        appendVarint(cid.bytes.count + dataLength, to: &output)
        output.append(cid.bytes)
        return output
    }

    /// Verifies both roots, the deniable commit binding, the index-derived
    /// LtHash, and each indexed record CID before returning any recovery data.
    public static func verify(
        _ car: Data,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey
    ) throws -> [String: Data] {
        let recovery = try decodeRecovery(
            car,
            space: space,
            author: author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature($0, publicKey: publicKey)
            }
        )
        return Dictionary(
            uniqueKeysWithValues: recovery.records.map {
                ("\($0.uri.collection)/\($0.uri.rkey)", $0.value)
            }
        )
    }

    /// Verifies a recovery CAR and returns the exact state needed by the
    /// offline SQLite restore boundary. This does not authorize a request or
    /// create any authority/member policy.
    public static func verifyRecovery(
        _ car: Data,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey
    ) throws -> VerifiedSpaceCARRecovery {
        try verifyRecovery(
            car,
            space: space,
            author: author,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature($0, publicKey: publicKey)
            }
        )
    }

    /// Verifies a recovery CAR with an algorithm-bound context verifier.
    /// This keeps CAR framing and content checks independent of the concrete
    /// signing curve while requiring callers to supply a trusted key policy.
    public static func verifyRecovery(
        _ car: Data,
        space: SpaceURI,
        author: String,
        contextSignatureVerifier: @Sendable (SpaceCommitEnvelope) throws -> Bool
    ) throws -> VerifiedSpaceCARRecovery {
        let decoded = try decodeRecovery(
            car,
            space: space,
            author: author,
            contextSignatureVerifier: contextSignatureVerifier
        )
        return VerifiedSpaceCARRecovery(
            wireRevision: try TID(tidString: decoded.revision),
            records: decoded.records,
            ltHash: decoded.ltHash,
            commitment: decoded.commitment
        )
    }

    private struct DecodedSpaceCARRecovery {
        let revision: String
        let records: [SpaceRecord]
        let ltHash: Data
        let commitment: Data
    }

    private static func decodeRecovery(
        _ car: Data,
        space: SpaceURI,
        author: String,
        contextSignatureVerifier: @Sendable (SpaceCommitEnvelope) throws -> Bool
    ) throws -> DecodedSpaceCARRecovery {
        let reader = try CARReader(data: car)
        guard reader.roots.count == 2 else { throw SwanError.malformed("permissioned CAR must have two roots") }
        let commitCID = reader.roots[0]
        let indexCID = reader.roots[1]
        let frames = try strictRecoveryFrames(
            car,
            commitCID: commitCID,
            indexCID: indexCID
        )
        let commitBlock = frames[0].body
        let indexBlock = frames[1].body

        let envelope = try decodeCommit(commitBlock, space: space, author: author)
        guard try encodeCommit(envelope) == commitBlock else {
            throw SwanError.malformed("permissioned CAR commit is not canonical DAG-CBOR")
        }
        guard try contextSignatureVerifier(envelope),
              SpaceCommitCodec.verifyContentBinding(envelope) else {
            throw SwanError.unauthorized("permissioned CAR commit did not verify")
        }
        guard let rawIndex = try decodeDAGCBORMap(indexBlock) else {
            throw SwanError.malformed("permissioned CAR index is not a map")
        }

        var validatedIndex: [(path: String, cid: CID)] = []
        validatedIndex.reserveCapacity(rawIndex.count)
        for (path, value) in rawIndex {
            guard isRecordPath(path),
                  let cid = value as? CID,
                  isProfileDAGCBORCID(cid)
            else {
                throw SwanError.malformed(
                    "permissioned CAR index entry is invalid"
                )
            }
            validatedIndex.append((path, cid))
        }
        let canonicalIndex = validatedIndex.sorted {
            let left = Data($0.path.utf8)
            let right = Data($1.path.utf8)
            return left.count < right.count
                || (
                    left.count == right.count
                        && left.lexicographicallyPrecedes(right)
                )
        }
        let canonicalIndexBlock = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: canonicalIndex.map {
                (key: $0.path, value: ATProtoLink(cid: $0.cid))
            })
        )
        guard canonicalIndexBlock == indexBlock else {
            throw SwanError.malformed(
                "permissioned CAR index is not canonical DAG-CBOR"
            )
        }

        let lexicalIndex = validatedIndex.sorted {
            $0.path.utf8.lexicographicallyPrecedes($1.path.utf8)
        }
        var orderedUniqueCIDs: [CID] = []
        var seenRecordCIDs = Set<String>()
        for entry in lexicalIndex
        where seenRecordCIDs.insert(entry.cid.string).inserted {
            orderedUniqueCIDs.append(entry.cid)
        }
        guard frames.count == orderedUniqueCIDs.count + 2 else {
            throw SwanError.malformed("permissioned CAR has unindexed blocks")
        }
        var recordBlocks: [String: Data] = [:]
        recordBlocks.reserveCapacity(orderedUniqueCIDs.count)
        for (offset, expectedCID) in orderedUniqueCIDs.enumerated() {
            let frame = frames[offset + 2]
            guard frame.cid == expectedCID,
                  recordBlocks.updateValue(
                      frame.body,
                      forKey: frame.cid.string
                  ) == nil
            else {
                throw SwanError.malformed(
                    "permissioned CAR record block order is invalid"
                )
            }
        }

        var setHash = LtHash()
        var records: [SpaceRecord] = []
        records.reserveCapacity(lexicalIndex.count)
        for entry in lexicalIndex {
            let path = entry.path
            let cid = entry.cid
            guard let value = recordBlocks[cid.string] else {
                throw SwanError.malformed(
                    "permissioned CAR record block is missing"
                )
            }
            do {
                try CanonicalSpaceRecordValidator.validate(value)
            } catch {
                throw SwanError.malformed("permissioned CAR record is not canonical DAG-CBOR")
            }
            setHash.add(element: "\(path)/\(cid.string)")
            let components = path.split(separator: "/", omittingEmptySubsequences: false)
            let uri = try SpaceRecordURI(
                space: space,
                author: author,
                collection: String(components[0]),
                rkey: String(components[1])
            )
            records.append(
                SpaceRecord(uri: uri, value: value, cid: cid.string, revision: 1)
            )
        }
        guard constantTimeEqual(setHash.commitment, envelope.commitment) else {
            throw SwanError.malformed("permissioned CAR index does not match commit")
        }
        return DecodedSpaceCARRecovery(
            revision: envelope.context.rev,
            records: records,
            ltHash: setHash.serialized,
            commitment: setHash.commitment
        )
    }

    private struct StrictRecoveryFrame {
        let cid: CID
        let body: Data
    }

    private static let profileCIDByteCount = 36

    /// Petrel's general-purpose reader indexes blocks by CID. A duplicate CID
    /// therefore replaces the earlier dictionary entry, and malformed trailing
    /// bytes can terminate its permissive indexing loop. Recovery needs a
    /// stricter contract: every byte belongs to one canonical frame, roots
    /// occupy the first two frames, and each frame's body hashes to its CID.
    private static func strictRecoveryFrames(
        _ car: Data,
        commitCID: CID,
        indexCID: CID
    ) throws -> [StrictRecoveryFrame] {
        guard isProfileDAGCBORCID(commitCID),
              isProfileDAGCBORCID(indexCID),
              commitCID != indexCID
        else {
            throw SwanError.malformed("permissioned CAR roots are invalid")
        }
        var offset = 0
        let headerLength = try readCanonicalRecoveryVarint(
            car,
            offset: &offset
        )
        guard headerLength <= car.count - offset else {
            throw SwanError.malformed("permissioned CAR header is truncated")
        }
        let header = Data(car[offset ..< offset + headerLength])
        offset += headerLength
        let canonicalHeader = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [
                (key: "roots", value: [
                    ATProtoLink(cid: commitCID),
                    ATProtoLink(cid: indexCID),
                ]),
                (key: "version", value: 1),
            ])
        )
        guard header == canonicalHeader else {
            throw SwanError.malformed(
                "permissioned CAR header is not canonical"
            )
        }

        var frames: [StrictRecoveryFrame] = []
        while offset < car.count {
            let frameLength = try readCanonicalRecoveryVarint(
                car,
                offset: &offset
            )
            guard frameLength > profileCIDByteCount,
                  frameLength <= car.count - offset
            else {
                throw SwanError.malformed(
                    "permissioned CAR frame is truncated"
                )
            }
            let cidBytes = Data(
                car[
                    offset
                        ..< offset + profileCIDByteCount
                ]
            )
            let cid: CID
            do {
                cid = try CID(bytes: cidBytes)
            } catch {
                throw SwanError.malformed(
                    "permissioned CAR block CID is invalid"
                )
            }
            guard cid.bytes == cidBytes, isProfileDAGCBORCID(cid) else {
                throw SwanError.malformed(
                    "permissioned CAR block CID is invalid"
                )
            }
            offset += profileCIDByteCount
            let bodyLength =
                frameLength - profileCIDByteCount
            let body = Data(car[offset ..< offset + bodyLength])
            offset += bodyLength
            guard CID.fromDAGCBOR(body) == cid else {
                throw SwanError.malformed(
                    "permissioned CAR block CID does not match body"
                )
            }
            frames.append(StrictRecoveryFrame(cid: cid, body: body))
        }
        guard frames.count >= 2,
              frames[0].cid == commitCID,
              frames[1].cid == indexCID
        else {
            throw SwanError.malformed(
                "permissioned CAR root block order is invalid"
            )
        }
        return frames
    }

    private static func readCanonicalRecoveryVarint(
        _ data: Data,
        offset: inout Int
    ) throws -> Int {
        let start = offset
        var value: UInt64 = 0
        var shift: UInt64 = 0
        while offset < data.count, offset - start < 10 {
            let byte = data[offset]
            offset += 1
            let portion = UInt64(byte & 0x7f)
            guard shift < 63 || portion <= 1 else {
                throw SwanError.malformed(
                    "permissioned CAR varint is invalid"
                )
            }
            value |= portion << shift
            if byte & 0x80 == 0 {
                guard value <= UInt64(Int.max) else {
                    throw SwanError.malformed(
                        "permissioned CAR varint is invalid"
                    )
                }
                var canonical = Data()
                appendVarint(Int(value), to: &canonical)
                guard canonical == Data(data[start ..< offset]) else {
                    throw SwanError.malformed(
                        "permissioned CAR varint is not canonical"
                    )
                }
                return Int(value)
            }
            shift += 7
        }
        throw SwanError.malformed("permissioned CAR varint is invalid")
    }

    private static func isProfileDAGCBORCID(_ cid: CID) -> Bool {
        cid.bytes.count == profileCIDByteCount
            && cid.codec == .dagCBOR
            && cid.multihash.algorithm == Multihash.sha256Code
            && cid.multihash.length == Multihash.sha256Length
            && cid.multihash.digest.count == Int(Multihash.sha256Length)
    }

    static func encodeCommit(_ commit: SpaceCommitEnvelope) throws -> Data {
        guard commit.ver == 1 else { throw SwanError.malformed("unsupported commit version") }
        let block = OrderedCBORMap(entries: [
            (key: "$type", value: "com.atproto.space.defs#signedCommit"),
            (key: "ver", value: commit.ver),
            (key: "hash", value: commit.commitment),
            (key: "mac", value: commit.contentBinding),
            (key: "ikm", value: commit.context.ikm),
            (key: "sig", value: commit.contextSignature),
            (key: "rev", value: commit.context.rev),
        ])
        return try DAGCBOR.encodeValue(block)
    }

    static func decodeCommit(_ data: Data, space: SpaceURI, author: String) throws -> SpaceCommitEnvelope {
        guard let map = try decodeDAGCBORMap(data),
              map["$type"] as? String == "com.atproto.space.defs#signedCommit",
              let ver = map["ver"] as? UInt64,
              ver == 1,
              let hash = map["hash"] as? Data,
              let mac = map["mac"] as? Data,
              let ikm = map["ikm"] as? Data,
              let sig = map["sig"] as? Data,
              let rev = map["rev"] as? String else {
            throw SwanError.malformed("permissioned CAR commit is invalid")
        }
        let decodedContext = try SpaceCommitContext(space: space, author: author, rev: rev, ikm: ikm)
        return SpaceCommitEnvelope(ver: Int(ver), context: decodedContext, contextSignature: sig, contentBinding: mac, commitment: hash)
    }

    private static func decodeDAGCBORMap(_ data: Data) throws -> [String: Any]? {
        // CARReader deliberately exposes its decoder through a block index. A
        // tiny one-block CAR keeps this conversion inside the same Petrel
        // decoder used for normal CAR validation.
        let cid = CID.fromDAGCBOR(data)
        let header = OrderedCBORMap(entries: [
            (key: "roots", value: [ATProtoLink(cid: cid)]),
            (key: "version", value: 1),
        ])
        let headerData = try DAGCBOR.encodeValue(header)
        var singleBlockCAR = Data()
        appendVarint(headerData.count, to: &singleBlockCAR)
        singleBlockCAR.append(headerData)
        appendBlock(cid: cid, data: data, to: &singleBlockCAR)
        let reader = try CARReader(data: singleBlockCAR)
        return try reader.decodeBlock(for: CARReader.cidHex(from: cid)) as? [String: Any]
    }

    private static func appendBlock(cid: CID, data: Data, to output: inout Data) {
        appendVarint(cid.bytes.count + data.count, to: &output)
        output.append(cid.bytes)
        output.append(data)
    }

    private static func appendVarint(_ value: Int, to output: inout Data) {
        precondition(value >= 0)
        var remaining = UInt64(value)
        repeat {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            output.append(byte)
        } while remaining != 0
    }

    private static func cborMajorHeader(major: UInt8, argument: UInt64) -> Data {
        precondition(major <= 7)
        let prefix = major << 5
        var output = Data()
        switch argument {
        case 0 ..< 24:
            output.append(prefix | UInt8(argument))
        case 24 ... UInt64(UInt8.max):
            output.append(prefix | 24)
            output.append(UInt8(argument))
        case (UInt64(UInt8.max) + 1) ... UInt64(UInt16.max):
            output.append(prefix | 25)
            var value = UInt16(argument).bigEndian
            withUnsafeBytes(of: &value) { output.append(contentsOf: $0) }
        case (UInt64(UInt16.max) + 1) ... UInt64(UInt32.max):
            output.append(prefix | 26)
            var value = UInt32(argument).bigEndian
            withUnsafeBytes(of: &value) { output.append(contentsOf: $0) }
        default:
            output.append(prefix | 27)
            var value = argument.bigEndian
            withUnsafeBytes(of: &value) { output.append(contentsOf: $0) }
        }
        return output
    }

    private static func recordPath(_ record: SpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)"
    }

    static func isRecordPath(_ path: String) -> Bool {
        let fields = path.split(separator: "/", omittingEmptySubsequences: false)
        return fields.count == 2 && SpaceURI.isValidNSID(String(fields[0])) && SpaceURI.isValidRecordKey(String(fields[1]))
    }
}

public struct SpaceRecord: Sendable, Equatable {
    public let uri: SpaceRecordURI
    /// Canonical DAG-CBOR bytes. JSON values must be canonicalized before they
    /// reach this domain boundary so CIDs agree across implementations.
    public let value: Data
    public let cid: String
    public let revision: UInt64

    public init(uri: SpaceRecordURI, value: Data, cid: String, revision: UInt64) {
        self.uri = uri
        self.value = value
        self.cid = cid
        self.revision = revision
    }
}

public enum SpaceWrite: Sendable, Equatable {
    case put(uri: SpaceRecordURI, value: Data)
    case delete(uri: SpaceRecordURI)

    public var valueByteCount: Int {
        switch self {
        case let .put(_, value): value.count
        case .delete: 0
        }
    }
}

/// Shared admission limits for permissioned repository mutations.
///
/// The HTTP decoder has the same limits, but keeping them here is important:
/// storage and in-memory callers are public APIs too and must not be able to
/// bypass the request-layer bound by handing an adapter a giant already-
/// materialized array.  The aggregate value limit is intentionally below the
/// CAR record limit because `applyWrites` is a JSON control-plane operation,
/// not a streaming transfer.
public enum SpaceWriteLimits {
    public static let maximumOperations = 4_096
    public static let maximumRecordValueBytes = 1 * 1_024 * 1_024
    public static let maximumAggregateValueBytes = 1 * 1_024 * 1_024

    public static func validate(_ writes: [SpaceWrite]) throws {
        guard !writes.isEmpty else { return }
        var aggregateValueBytes = 0
        for write in writes {
            switch write {
            case let .put(_, value):
                aggregateValueBytes = try addingValueBytes(
                    aggregateValueBytes,
                    value.count
                )
            case .delete:
                break
            }
        }
        try validate(
            operationCount: writes.count,
            aggregateValueBytes: aggregateValueBytes
        )
    }

    public static func addingValueBytes(
        _ current: Int,
        _ next: Int
    ) throws -> Int {
        guard (0...maximumRecordValueBytes).contains(next), current >= 0 else {
            throw SwanError.malformed("repository write value exceeds its limit")
        }
        let (total, overflow) = current.addingReportingOverflow(next)
        guard !overflow, total <= maximumAggregateValueBytes else {
            throw SwanError.malformed("repository write batch exceeds its limit")
        }
        return total
    }

    public static func validate(
        operationCount: Int,
        aggregateValueBytes: Int
    ) throws {
        guard (1...maximumOperations).contains(operationCount),
              (0...maximumAggregateValueBytes).contains(aggregateValueBytes)
        else {
            throw SwanError.malformed("repository write batch exceeds its limit")
        }
    }
}

public struct SpaceOplogEntry: Sendable, Equatable {
    public let revision: UInt64
    public let write: SpaceWrite
    public let commitment: Data

    public init(revision: UInt64, write: SpaceWrite, commitment: Data) {
        self.revision = revision
        self.write = write
        self.commitment = commitment
    }
}

public enum SpaceSyncResponse: Sendable, Equatable {
    case incremental([SpaceOplogEntry])
    case fullSnapshot(revision: UInt64, records: [SpaceRecord], commitment: Data)
}

public struct SpaceRepositoryState: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let ltHash: Data
    public let commitment: Data

    public init(
        space: SpaceURI,
        author: String,
        revision: UInt64,
        ltHash: Data,
        commitment: Data
    ) {
        self.space = space
        self.author = author
        self.revision = revision
        self.ltHash = ltHash
        self.commitment = commitment
    }
}

public enum SimpleSpacePolicy: String, Codable, Sendable {
    case `public`
    case memberList = "member-list"
    case managingApp = "managing-app"
}

public enum SimpleSpaceAppAccess: Sendable, Codable, Equatable {
    case open
    case allowList(Set<String>)
}

/// Hard bounds for authority-owned simple-space policy state. These limits
/// belong to the domain model so every adapter, including the in-memory
/// laboratory authority, rejects state that would otherwise require
/// materializing an unbounded member, client, or decision set.
public enum SimpleSpaceLimits {
    /// Maximum number of space records retained by the process-local
    /// laboratory authority.  Durable authorities enforce equivalent
    /// per-space bounds in SQLite; this cap prevents the in-memory test and
    /// development coordinator from becoming an unbounded dictionary sink.
    public static let maximumSpacesPerAuthority = 10_000
    /// Maximum number of member DIDs in one space, including its owner.
    public static let maximumMembersPerSpace = 10_000
    /// Maximum number of client metadata URLs in an allow-list policy.
    public static let maximumClientAllowListEntries = 1_000
    /// Maximum number of persisted managing-app decisions in one space.
    public static let maximumManagingAppDecisionsPerSpace = 10_000

}

/// A durable credential-policy denial whose wire meaning is narrower than a
/// generic user authorization failure. It intentionally carries no client,
/// space, or policy material.
public enum SimpleSpaceCredentialPolicyError: Error, Sendable, Equatable {
    case appNotAuthorized
}

/// The pinned `com.atproto.simplespace` policy surface. A policy decision is
/// made only by the authority; repo hosts merely verify the resulting read
/// credential and never infer membership from a record request.
public struct SimpleSpaceConfiguration: Sendable, Codable, Equatable {
    private enum CodingKeys: String, CodingKey {
        case policy
        case appAccess
        case managingApp
    }

    public let policy: SimpleSpacePolicy
    public let appAccess: SimpleSpaceAppAccess
    public let managingApp: String?

    public init(policy: SimpleSpacePolicy = .memberList, appAccess: SimpleSpaceAppAccess = .open, managingApp: String? = nil) throws {
        guard managingApp?.isEmpty != true else {
            throw SwanError.malformed("managing app must not be empty")
        }
        if case let .allowList(clients) = appAccess,
           clients.count > SimpleSpaceLimits.maximumClientAllowListEntries {
            throw SwanError.malformed("simple-space client allow-list is too large")
        }
        if case let .allowList(clients) = appAccess {
            for client in clients {
                try Self.validateAppIdentifier(client)
            }
        }
        if let managingApp {
            try Self.validateAppIdentifier(managingApp)
        }
        // The pinned `updateSpace` handler patches each property independently:
        // a policy-only update must preserve an omitted `managingApp`, even
        // when the policy becomes non-managing. An empty wire update is first
        // translated to nil by `SimpleSpaceConfigurationPatch`, so it remains
        // a valid explicit clear. The policy evaluator consults this property
        // only while policy is `managing-app`.
        self.policy = policy
        self.appAccess = appAccess
        self.managingApp = managingApp
    }

    /// Client identifiers are opaque app/service names in the wire protocol,
    /// not URLs or DIDs. Keep their lexical contract in the shared domain
    /// initializer so the in-memory authority and SQLite adapter cannot
    /// disagree about what state is valid. The HTTP layer applies any stricter
    /// transport policy before using an identifier as a network destination.
    fileprivate static func validateAppIdentifier(_ identifier: String) throws {
        guard !identifier.isEmpty,
              identifier.utf8.count <= 2_048,
              identifier.unicodeScalars.allSatisfy({
                  $0.value >= 0x20 && $0.value != 0x7F
              })
        else {
            throw SwanError.invalidIdentifier(identifier)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            policy: container.decode(SimpleSpacePolicy.self, forKey: .policy),
            appAccess: container.decode(SimpleSpaceAppAccess.self, forKey: .appAccess),
            managingApp: container.decodeIfPresent(String.self, forKey: .managingApp)
        )
    }
}

/// A non-destructive update to simple-space configuration.  The wire
/// `updateSpace` schema makes each field optional; representing that directly
/// prevents an omitted field from silently resetting durable policy state.
public struct SimpleSpaceConfigurationPatch: Sendable, Equatable {
    public enum ManagingApp: Sendable, Equatable {
        case unchanged
        case set(String?)
    }

    public let policy: SimpleSpacePolicy?
    public let appAccess: SimpleSpaceAppAccess?
    public let managingApp: ManagingApp

    public init(
        policy: SimpleSpacePolicy? = nil,
        appAccess: SimpleSpaceAppAccess? = nil,
        managingApp: ManagingApp = .unchanged
    ) {
        self.policy = policy
        self.appAccess = appAccess
        self.managingApp = managingApp
    }

    public func applying(to current: SimpleSpaceConfiguration) throws -> SimpleSpaceConfiguration {
        let nextManagingApp: String?
        switch managingApp {
        case .unchanged:
            nextManagingApp = current.managingApp
        case let .set(value):
            nextManagingApp = value
        }
        return try SimpleSpaceConfiguration(
            policy: policy ?? current.policy,
            appAccess: appAccess ?? current.appAccess,
            managingApp: nextManagingApp
        )
    }
}

public struct SimpleSpace: Sendable, Equatable {
    public let uri: SpaceURI
    public let owner: String
    public let configuration: SimpleSpaceConfiguration
    public let members: Set<String>
    public let isDeleted: Bool

    /// A decoded authority state must still satisfy the same ownership and
    /// membership invariants as a newly created space.  SQLite adapters use
    /// this failable construction point to reject tampered rows rather than
    /// exposing a partially-valid policy object.
    public init(
        uri: SpaceURI,
        owner: String,
        configuration: SimpleSpaceConfiguration,
        members: Set<String>,
        isDeleted: Bool
    ) throws {
        guard owner == uri.authority,
              SpaceURI.isValidDID(owner),
              members.count <= SimpleSpaceLimits.maximumMembersPerSpace,
              members.contains(owner),
              members.allSatisfy(SpaceURI.isValidDID)
        else {
            throw SwanError.malformed("invalid simple-space authority state")
        }
        self.init(
            uncheckedURI: uri,
            owner: owner,
            configuration: configuration,
            members: members,
            isDeleted: isDeleted
        )
    }

    fileprivate init(
        uncheckedURI uri: SpaceURI,
        owner: String,
        configuration: SimpleSpaceConfiguration,
        members: Set<String>,
        isDeleted: Bool
    ) {
        self.uri = uri
        self.owner = owner
        self.configuration = configuration
        self.members = members
        self.isDeleted = isDeleted
    }
}

private struct MutableSimpleSpace: Sendable {
    let uri: SpaceURI
    let owner: String
    var configuration: SimpleSpaceConfiguration
    var members: Set<String>
    var isDeleted: Bool

    var snapshot: SimpleSpace {
        SimpleSpace(
            uncheckedURI: uri,
            owner: owner,
            configuration: configuration,
            members: members,
            isDeleted: isDeleted
        )
    }
}

/// Process-local policy coordinator for the laboratory. Durable deployments
/// persist the same decisions with the authority account; it never writes to a
/// member repository during credential issuance.
public actor SimpleSpaceAuthority {
    private let credentials: HMACSpaceCredentialAuthority
    private var spaces: [SpaceURI: MutableSimpleSpace] = [:]
    private var managingAppDecisions: [SpaceURI: Set<String>] = [:]

    public init(credentialSecret: Data) {
        credentials = HMACSpaceCredentialAuthority(key: credentialSecret)
    }

    public func create(space: SpaceURI, owner: String, configuration: SimpleSpaceConfiguration) throws -> SimpleSpace {
        guard owner == space.authority else { throw SwanError.unauthorized("only the authority DID may create this simple space") }
        guard spaces[space] == nil else { throw SwanError.conflict(expected: 0, actual: 1) }
        guard spaces.count < SimpleSpaceLimits.maximumSpacesPerAuthority else {
            throw SwanError.unavailable("simple-space authority capacity exhausted")
        }
        let state = MutableSimpleSpace(uri: space, owner: owner, configuration: configuration, members: [owner], isDeleted: false)
        spaces[space] = state
        return state.snapshot
    }

    public func space(_ uri: SpaceURI) -> SimpleSpace? { spaces[uri]?.snapshot }

    public func update(space: SpaceURI, configuration: SimpleSpaceConfiguration, by subject: String) throws {
        var state = try activeSpace(space)
        try requireOwner(state, subject: subject)
        let previous = state.configuration
        state.configuration = configuration
        spaces[space] = state
        // Decisions are scoped to one managing-app identity. Preserve them
        // only when that identity remains actively governing the space.
        if previous.policy != .managingApp
            || configuration.policy != .managingApp
            || previous.managingApp != configuration.managingApp {
            managingAppDecisions[space] = []
        }
    }

    public func addMember(space: SpaceURI, member: String, by subject: String) throws {
        var state = try activeSpace(space)
        try requireOwner(state, subject: subject)
        guard SpaceURI.isValidDID(member) else { throw SwanError.invalidIdentifier(member) }
        guard state.members.contains(member)
            || state.members.count < SimpleSpaceLimits.maximumMembersPerSpace
        else {
            throw SwanError.unavailable("simple-space member capacity exhausted")
        }
        state.members.insert(member)
        spaces[space] = state
    }

    public func removeMember(space: SpaceURI, member: String, by subject: String) throws {
        var state = try activeSpace(space)
        try requireOwner(state, subject: subject)
        guard SpaceURI.isValidDID(member) else {
            throw SwanError.invalidIdentifier(member)
        }
        guard member != state.owner else { throw SwanError.malformed("a space owner cannot be removed") }
        state.members.remove(member)
        spaces[space] = state
    }

    public func delete(space: SpaceURI, by subject: String) throws {
        var state = try activeSpace(space)
        try requireOwner(state, subject: subject)
        state.isDeleted = true
        spaces[space] = state
        // Deleted-space tombstones remain addressable, but their managing-app
        // decisions no longer have any authorization meaning. Release that
        // auxiliary set so deletion cannot retain stale policy state forever.
        managingAppDecisions.removeValue(forKey: space)
    }

    /// A managing app can publish the result of its application-level access
    /// check. The authority consults this only for `managing-app` spaces.
    public func setManagingAppAccess(space: SpaceURI, user: String, allowed: Bool, by app: String) throws {
        guard SpaceURI.isValidDID(user) else {
            throw SwanError.invalidIdentifier(user)
        }
        let state = try activeSpace(space)
        guard state.configuration.policy == .managingApp,
              state.configuration.managingApp == app else {
            throw SwanError.unauthorized("wrong managing app")
        }
        if allowed {
            var decisions = managingAppDecisions[space, default: []]
            guard decisions.contains(user)
                || decisions.count < SimpleSpaceLimits.maximumManagingAppDecisionsPerSpace
            else {
                throw SwanError.unavailable(
                    "simple-space managing-app decision capacity exhausted"
                )
            }
            decisions.insert(user)
            managingAppDecisions[space] = decisions
        }
        else { managingAppDecisions[space, default: []].remove(user) }
    }

    /// Evaluates user and app policy independently, then returns a read-only
    /// credential. The caller is responsible for first validating the signed
    /// delegation token and any required client attestation at the OAuth layer.
    public func issueReadCredential(space: SpaceURI, user: String, clientID: String?, now: Date = Date()) throws -> SignedSpaceCredential {
        guard SpaceURI.isValidDID(user) else {
            throw SwanError.invalidIdentifier(user)
        }
        if let clientID {
            try SimpleSpaceConfiguration.validateAppIdentifier(clientID)
        }
        let state = try activeSpace(space)
        switch state.configuration.appAccess {
        case .open: break
        case let .allowList(allowed):
            guard let clientID, allowed.contains(clientID) else { throw SwanError.unauthorized("app is not authorized for this space") }
        }
        switch state.configuration.policy {
        case .public: break
        case .memberList:
            guard state.members.contains(user) else { throw SwanError.unauthorized("user is not a space member") }
        case .managingApp:
            guard managingAppDecisions[space, default: []].contains(user) else {
                throw SwanError.unauthorized("managing app denied user access")
            }
        }
        let grant = SpaceGrant(
            subject: user, space: space, permissions: [.read],
            expiresAt: now.addingTimeInterval(2 * 60 * 60), clientID: clientID
        )
        return try credentials.issue(SpaceCredential(grant: grant, issuedAt: now))
    }

    private func activeSpace(_ uri: SpaceURI) throws -> MutableSimpleSpace {
        guard let state = spaces[uri] else { throw SwanError.malformed("space not found") }
        guard !state.isDeleted else { throw SwanError.unauthorized("space deleted") }
        return state
    }

    private func requireOwner(_ state: MutableSimpleSpace, subject: String) throws {
        guard state.owner == subject else { throw SwanError.unauthorized("only the space owner may manage membership") }
    }
}

/// One actor represents one `(account, space)` repository. It coordinates
/// local state only: a persistent implementation must repeat revision CAS,
/// oplog insertion, and outbox insertion in one database transaction.
public actor SpaceRepository {
    private let space: SpaceURI
    private let author: String
    private let retention: Int
    private var records: [SpaceRecordURI: SpaceRecord] = [:]
    private var lthash = LtHash()
    private var revision: UInt64 = 0
    private var oplog: [SpaceOplogEntry] = []

    public init(space: SpaceURI, author: String, retention: Int = 10_000) throws {
        guard SpaceURI.isValidDID(author), retention > 0 else { throw SwanError.malformed("invalid repository configuration") }
        self.space = space
        self.author = author
        self.retention = retention
    }

    public func record(_ uri: SpaceRecordURI, authorization: AuthorizationContext) throws -> SpaceRecord? {
        guard uri.space == space, uri.author == author else { throw SwanError.unauthorized("record belongs to another repository") }
        try require(uri: uri, authorization: authorization, permission: .read)
        return records[uri]
    }

    public func apply(
        _ write: SpaceWrite,
        expectedRevision: UInt64? = nil,
        authorization: AuthorizationContext
    ) throws -> SpaceOplogEntry {
        try applyAtomically([write], expectedRevision: expectedRevision, authorization: authorization)[0]
    }

    /// Validates the full batch against a private copy and publishes it only if
    /// every write is valid. No partially-applied permissioned transaction can
    /// become visible after a failed `applyWrites` request.
    public func applyAtomically(
        _ writes: [SpaceWrite],
        expectedRevision: UInt64? = nil,
        authorization: AuthorizationContext
    ) throws -> [SpaceOplogEntry] {
        guard !writes.isEmpty else { return [] }
        try SpaceWriteLimits.validate(writes)
        if let expectedRevision, expectedRevision != revision {
            throw SwanError.conflict(expected: expectedRevision, actual: revision)
        }

        var nextRecords = records
        var nextLtHash = lthash
        var nextRevision = revision
        var entries: [SpaceOplogEntry] = []
        for write in writes {
            let uri = switch write { case let .put(uri, _), let .delete(uri): uri }
            guard uri.space == space, uri.author == author else { throw SwanError.unauthorized("record belongs to another repository") }
            let permission: SpacePermission = switch write {
            case .delete: .delete
            case .put: nextRecords[uri] == nil ? .create : .update
            }
            try require(uri: uri, authorization: authorization, permission: permission)
            switch write {
            case let .put(uri, value):
                if let old = nextRecords[uri] { nextLtHash.remove(element: element(for: old)) }
                nextRevision += 1
                let record = SpaceRecord(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string, revision: nextRevision)
                nextLtHash.add(element: element(for: record))
                nextRecords[uri] = record
            case let .delete(uri):
                guard let old = nextRecords.removeValue(forKey: uri) else {
                    throw SwanError.malformed("cannot delete a missing record")
                }
                nextLtHash.remove(element: element(for: old))
                nextRevision += 1
            }
            entries.append(SpaceOplogEntry(revision: nextRevision, write: write, commitment: nextLtHash.commitment))
        }

        records = nextRecords
        lthash = nextLtHash
        revision = nextRevision
        oplog.append(contentsOf: entries)
        if oplog.count > retention { oplog.removeFirst(oplog.count - retention) }
        return entries
    }

    public func sync(since requestedRevision: UInt64, authorization: AuthorizationContext) throws -> SpaceSyncResponse {
        try require(uri: nil, authorization: authorization, permission: .read)
        guard requestedRevision < revision else { return .incremental([]) }
        let oldestRevision = oplog.first?.revision ?? revision
        guard requestedRevision >= oldestRevision - 1 else {
            return .fullSnapshot(revision: revision, records: records.values.sorted { $0.uri.rawValue < $1.uri.rawValue }, commitment: lthash.commitment)
        }
        return .incremental(oplog.filter { $0.revision > requestedRevision })
    }

    public func currentState() -> SpaceRepositoryState {
        SpaceRepositoryState(space: space, author: author, revision: revision, ltHash: lthash.serialized, commitment: lthash.commitment)
    }

    public func snapshot(authorization: AuthorizationContext) throws -> [SpaceRecord] {
        try require(uri: nil, authorization: authorization, permission: .read)
        return records.values.sorted { $0.uri.rawValue < $1.uri.rawValue }
    }

    /// Produces a full-recovery CAR with a fresh reader-specific commit
    /// envelope. The stored repository state is unchanged by this operation.
    public func exportCAR(rev: String, signingKey: P256.Signing.PrivateKey, authorization: AuthorizationContext) throws -> SpaceCAR {
        try require(uri: nil, authorization: authorization, permission: .read)
        let commit = try SpaceCommitCodec.createReaderEnvelope(
            space: space, author: author, rev: rev, commitment: lthash.commitment, key: signingKey
        )
        return try SpaceCARCodec.encode(commit: commit, records: records.values.sorted { $0.uri.rawValue < $1.uri.rawValue })
    }

    private func require(uri: SpaceRecordURI?, authorization: AuthorizationContext, permission: SpacePermission) throws {
        try SpaceAuthorizationPolicy.require(
            space: space,
            author: author,
            uri: uri,
            authorization: authorization,
            permission: permission
        )
    }

    private func element(for record: SpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
    }
}

private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
    return difference == 0
}
