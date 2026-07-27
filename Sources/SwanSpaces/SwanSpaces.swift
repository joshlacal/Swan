import CBLAKE3
import Crypto
import Foundation
import Petrel
import SwanCore

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
    case accountOAuth(subject: String, scopes: Set<String>)
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
        case let .accountOAuth(subject, scopes):
            guard subject == author,
                  scopeAllows(scopes, space: space, permission: permission, collection: uri?.collection)
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
        guard case let .accountOAuth(subject, scopes) = authorization,
              subject == space.authority else {
            throw SwanError.unauthorized("authority account OAuth is required")
        }
        if scopes.contains("atproto") { return }
        guard scopes.contains(where: {
            managementScopeAllows($0, space: space, operation: operation)
        }) else {
            throw SwanError.unauthorized("OAuth scope does not cover this space management operation")
        }
    }

    private static func scopeAllows(
        _ scopes: Set<String>,
        space: SpaceURI,
        permission: SpacePermission,
        collection: String?
    ) -> Bool {
        if scopes.contains("atproto") { return true }
        let action = permission.rawValue
        let base = "space:\(space.spaceType)"
        guard scopes.contains(where: { $0.hasPrefix(base + "?") }) else {
            return false
        }
        // Shared OAuth boundaries reject unqualified grants. This domain
        // matcher is also fail-closed: a qualified grant must explicitly
        // cover this authority/skey/action/collection. A bare `space:<type>`
        // grant has no trusted authority or action context, and is not
        // normalized here.
        return scopes.contains { scope in
            guard scope.hasPrefix(base + "?"),
                  PermissionedSpaceScopeSyntax.isQualified(scope),
                  let parameters = strictQueryParameters(
                    String(scope.dropFirst(base.count + 1))
                  ),
                  parameters["authority"] == space.authority,
                  parameters["skey"] == space.skey,
                  parameters["action"] == action
            else {
                return false
            }
            if permission == .read {
                // A collection-qualified grant may read only that collection's
                // individual records. Aggregate surfaces must not silently
                // censor their response; they require an unqualified or
                // wildcard collection grant instead.
                guard let collection else {
                    return parameters["collection"] == nil || parameters["collection"] == "*"
                }
                return parameters["collection"] == nil
                    || parameters["collection"] == "*"
                    || parameters["collection"] == collection
            }
            // Space-management operations address the authority state rather
            // than one repository record, so their scoped grant has no
            // collection component.  Treating that as an implicit denial
            // would make a syntactically valid `action=manage` scope useless
            // while still allowing the broad `atproto` escape hatch.
            guard collection == nil else {
                return parameters["collection"] == collection
                    || parameters["collection"] == "*"
            }
            return parameters["collection"] == nil || parameters["collection"] == "*"
        }
    }

    private static func managementScopeAllows(
        _ scope: String,
        space: SpaceURI,
        operation: SimpleSpaceManagementOperation
    ) -> Bool {
        let base = "space:\(space.spaceType)"
        guard scope.hasPrefix(base + "?"),
              PermissionedSpaceScopeSyntax.isQualified(scope),
              let parameters = strictQueryParameters(
                String(scope.dropFirst(base.count + 1))
              ),
              parameters["authority"] == space.authority,
              parameters["skey"] == space.skey,
              parameters["manage"] == operation.rawValue,
              parameters["action"] == nil,
              parameters["collection"] == nil else {
            return false
        }
        return true
    }

    /// Parses only the compact query grammar used by scoped space grants.
    /// Every key is single-valued and percent-decoded before comparison, so a
    /// prefix (`action=creates`) or duplicate-key (`action=create&action=...`)
    /// trick cannot broaden an authorization decision.
    private static func strictQueryParameters(_ query: String) -> [String: String]? {
        guard !query.isEmpty else { return nil }
        var parameters: [String: String] = [:]
        for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
            let pair = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2,
                  !pair[0].isEmpty,
                  let key = String(pair[0]).removingPercentEncoding,
                  let value = String(pair[1]).removingPercentEncoding,
                  parameters[key] == nil
            else {
                return nil
            }
            parameters[key] = value
        }
        return parameters
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

public struct HMACSpaceCredentialAuthority: Sendable {
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
        return publicKey.isValidSignature(signature, for: try encodedContext(envelope.context))
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
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), info: context, outputByteCount: 32
        )
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
        for record in orderedRecords {
            appendBlock(cid: CID.fromDAGCBOR(record.value), data: record.value, to: &output)
        }
        return SpaceCAR(data: output, commitCID: commitCID, indexCID: indexCID)
    }

    /// Verifies both roots, the deniable commit binding, the index-derived
    /// LtHash, and each indexed record CID before returning any recovery data.
    public static func verify(
        _ car: Data,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey
    ) throws -> [String: Data] {
        let reader = try CARReader(data: car)
        guard reader.roots.count == 2 else { throw SwanError.malformed("permissioned CAR must have two roots") }
        let commitCID = reader.roots[0]
        let indexCID = reader.roots[1]
        let commitBlock = try reader.rawBlockData(for: CARReader.cidHex(from: commitCID))
        let indexBlock = try reader.rawBlockData(for: CARReader.cidHex(from: indexCID))
        guard CID.fromDAGCBOR(commitBlock) == commitCID, CID.fromDAGCBOR(indexBlock) == indexCID else {
            throw SwanError.malformed("CAR root CID does not match block")
        }

        let envelope = try decodeCommit(commitBlock, space: space, author: author)
        guard try SpaceCommitCodec.verifyContextSignature(envelope, publicKey: publicKey),
              SpaceCommitCodec.verifyContentBinding(envelope) else {
            throw SwanError.unauthorized("permissioned CAR commit did not verify")
        }
        guard let rawIndex = try reader.decodeBlock(for: CARReader.cidHex(from: indexCID)) as? [String: Any] else {
            throw SwanError.malformed("permissioned CAR index is not a map")
        }

        var setHash = LtHash()
        var recovered: [String: Data] = [:]
        for path in rawIndex.keys.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
            guard isRecordPath(path), let cid = rawIndex[path] as? CID else {
                throw SwanError.malformed("permissioned CAR index entry is invalid")
            }
            let value = try reader.rawBlockData(for: CARReader.cidHex(from: cid))
            guard CID.fromDAGCBOR(value) == cid else { throw SwanError.malformed("record CID does not match block") }
            setHash.add(element: "\(path)/\(cid.string)")
            recovered[path] = value
        }
        guard constantTimeEqual(setHash.commitment, envelope.commitment) else {
            throw SwanError.malformed("permissioned CAR index does not match commit")
        }
        guard reader.blockIndex.count == recovered.count + 2 else {
            throw SwanError.malformed("permissioned CAR has unindexed blocks")
        }
        return recovered
    }

    private static func encodeCommit(_ commit: SpaceCommitEnvelope) throws -> Data {
        guard commit.ver == 1 else { throw SwanError.malformed("unsupported commit version") }
        let block = OrderedCBORMap(entries: [
            (key: "ver", value: commit.ver),
            (key: "hash", value: commit.commitment),
            (key: "mac", value: commit.contentBinding),
            (key: "ikm", value: commit.context.ikm),
            (key: "sig", value: commit.contextSignature),
            (key: "rev", value: commit.context.rev),
        ])
        return try DAGCBOR.encodeValue(block)
    }

    private static func decodeCommit(_ data: Data, space: SpaceURI, author: String) throws -> SpaceCommitEnvelope {
        guard let map = try decodeDAGCBORMap(data),
              let ver = map["ver"] as? UInt64,
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

    private static func recordPath(_ record: SpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)"
    }

    private static func isRecordPath(_ path: String) -> Bool {
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

/// The pinned `com.atproto.simplespace` policy surface. A policy decision is
/// made only by the authority; repo hosts merely verify the resulting read
/// credential and never infer membership from a record request.
public struct SimpleSpaceConfiguration: Sendable, Codable, Equatable {
    public let policy: SimpleSpacePolicy
    public let appAccess: SimpleSpaceAppAccess
    public let managingApp: String?

    public init(policy: SimpleSpacePolicy = .memberList, appAccess: SimpleSpaceAppAccess = .open, managingApp: String? = nil) throws {
        guard managingApp?.isEmpty != true else {
            throw SwanError.malformed("managing app must not be empty")
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
        state.members.insert(member)
        spaces[space] = state
    }

    public func removeMember(space: SpaceURI, member: String, by subject: String) throws {
        var state = try activeSpace(space)
        try requireOwner(state, subject: subject)
        guard member != state.owner else { throw SwanError.malformed("a space owner cannot be removed") }
        state.members.remove(member)
        spaces[space] = state
    }

    public func delete(space: SpaceURI, by subject: String) throws {
        var state = try activeSpace(space)
        try requireOwner(state, subject: subject)
        state.isDeleted = true
        spaces[space] = state
    }

    /// A managing app can publish the result of its application-level access
    /// check. The authority consults this only for `managing-app` spaces.
    public func setManagingAppAccess(space: SpaceURI, user: String, allowed: Bool, by app: String) throws {
        let state = try activeSpace(space)
        guard state.configuration.policy == .managingApp,
              state.configuration.managingApp == app else {
            throw SwanError.unauthorized("wrong managing app")
        }
        if allowed { managingAppDecisions[space, default: []].insert(user) }
        else { managingAppDecisions[space, default: []].remove(user) }
    }

    /// Evaluates user and app policy independently, then returns a read-only
    /// credential. The caller is responsible for first validating the signed
    /// delegation token and any required client attestation at the OAuth layer.
    public func issueReadCredential(space: SpaceURI, user: String, clientID: String?, now: Date = Date()) throws -> SignedSpaceCredential {
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
