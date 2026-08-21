import Crypto
import Foundation
import SwanAccounts
import SwanCore

/// Production ``SwanSigningKeyProviding`` for the did:web identity surface.
///
/// The operator mounts a 32-byte base64url secret; the provider derives a
/// deterministic P-256 key from it (RFC 8037-style: the secret is the raw
/// private scalar) and publishes the compressed 33-byte public key as the
/// reserved did:web signing material. The key is a binding check only — it is
/// never used to sign assertions for the external DID — and the same secret
/// must be mounted on every replica so reservations and revalidation agree.
public struct ServeDidWebSigningKeyProvider: SwanSigningKeyProviding, Sendable {
    private let secret: Data

    public init(secret: Data) throws {
        guard secret.count == 32 else {
            throw SwanError.invalidIdentifier("did:web signing key")
        }
        self.secret = secret
    }

    public func configuredSigningKey() async throws -> SwanReservedSigningKey {
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: secret)
        let publicKey = privateKey.publicKey
        // Compressed x963 form: 0x02/0x03 prefix + 32-byte x coordinate.
        let compressed = publicKey.compactRepresentation ?? publicKey.x963Representation
        return try SwanReservedSigningKey(
            keyID: "#atproto",
            keyType: "Multikey",
            publicKey: compressed
        )
    }
}
