import Crypto
import Foundation
import SwanCore
import SwanSpaces
import SwanStorage

/// A repo host's record of space credentials their authority has revoked
/// (`com.atproto.space.notifyCredentialRevoked`, atproto#5567), consulted on
/// every credential presentation. Short credential lifetimes stay the primary
/// bound; this closes the window early for the credentials an authority names.
///
/// Revocations are keyed by `(space, jti)` through a fixed SHA-256 digest, so
/// the control plane stores neither credentials nor raw identifiers and the
/// key survives a server-key rotation.
public struct DurableSpaceCredentialRevocations: Sendable {
    /// How long a revocation is honoured after receipt. It must outlast any
    /// credential the revocation could name: the 3600 s lifetime ceiling,
    /// plus the 5 s `iat` lead a verifier tolerates, plus the expiry clock
    /// skew a verifier tolerates. The reference uses 3600 + 2 × 5 = 3610 s
    /// because it allows 5 s of expiry skew; Swan's credential verifier
    /// allows up to 300 s (60 s by default), so Swan retains for the widest
    /// configurable skew: 3600 + 5 + 300 = 3905 s.
    public static let retention: TimeInterval =
        PermissionedDataJWT.spaceCredentialLifetime
        + TimeInterval(PermissionedDataJWT.spaceCredentialMaximumIssuedAtLead)
        + DurableSpaceCredentialVerifier.Configuration.maximumClockSkew

    /// The lexicon bounds a notification to 1...100 credential IDs.
    public static let maximumCredentialsPerNotification = 100

    private let store: any SpaceCredentialRevocationStore

    public init(store: any SpaceCredentialRevocationStore) {
        self.store = store
    }

    /// Persists the revocations, idempotently. Throws
    /// `SwanError.malformed` for an out-of-range or invalid ID list and
    /// `SwanError.unavailable` when the store cannot record them.
    public func record(
        space: SpaceURI,
        credentialIDs: [String],
        now: Date = Date()
    ) async throws {
        guard (1 ... Self.maximumCredentialsPerNotification).contains(credentialIDs.count),
              credentialIDs.allSatisfy(Self.isValidCredentialID) else {
            throw SwanError.malformed("credential revocation list is invalid")
        }
        do {
            try await store.recordSpaceCredentialRevocations(
                digests: credentialIDs.map { Self.digest(space: space, credentialID: $0) },
                retainUntil: now.addingTimeInterval(Self.retention),
                now: now
            )
        } catch {
            throw SwanError.unavailable("credential revocation store unavailable")
        }
    }

    public func isRevoked(
        space: SpaceURI,
        credentialID: String,
        now: Date = Date()
    ) async throws -> Bool {
        do {
            return try await store.isSpaceCredentialRevoked(
                digest: Self.digest(space: space, credentialID: credentialID),
                now: now
            )
        } catch {
            throw SwanError.unavailable("credential revocation store unavailable")
        }
    }

    /// A revoked ID is a nonempty JWT `jti`, never a JWT. The bound matches
    /// what credential verification itself accepts as a `jti`.
    static func isValidCredentialID(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty
            && bytes.count <= PermissionedDataJWT.maximumOpaqueJTIBytes
            && bytes.allSatisfy { $0 >= 0x20 && $0 != 0x7f }
    }

    static func digest(space: SpaceURI, credentialID: String) -> Data {
        var input = Data()
        for part in ["swan.space.credential-revocation.v1", space.rawValue, credentialID] {
            let bytes = Data(part.utf8)
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
            input.append(bytes)
        }
        return Data(SHA256.hash(data: input))
    }
}
