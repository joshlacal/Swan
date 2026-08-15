import Foundation
import SwanCore
import SwanStorage

/// A newly created app password, with the one and only copy of its secret.
public struct AppPasswordIssuance: Sendable, Equatable {
    public let record: AppPasswordRecord
    /// Shown once. Never persisted in this form.
    public let password: String

    public init(record: AppPasswordRecord, password: String) {
        self.record = record
        self.password = password
    }
}

/// Generates app-password secrets.
///
/// The format is Bluesky's — hyphen-separated groups, e.g.
/// `abcd-efgh-ijkl-mnop` — because the official client displays and accepts
/// exactly this shape and users copy it by hand.
///
/// **Entropy is the load-bearing property.** The digest that indexes these is
/// deterministically salted (see `AppPasswordCredentials`), which is only safe
/// because the secret is machine-generated and uniformly random. Do not add a
/// user-supplied component, and do not shorten it.
public enum AppPasswordSecret {
    /// Excludes `l`, `1`, `0` and `o`, which are transcribed by hand and
    /// confused with each other.
    static let alphabet = Array("abcdefghijkmnpqrstuvwxyz23456789")
    static let groups = 4
    static let charactersPerGroup = 5

    /// 20 characters over a 32-symbol alphabet.
    public static var entropyBits: Int { groups * charactersPerGroup * 5 }

    /// `SystemRandomNumberGenerator` is the CSPRNG this codebase already uses
    /// for token and nonce material (`SwanOAuth.swift:304-305`,
    /// `DurableOAuthTokenService.swift:1488`). `random(in:using:)` rejection-
    /// samples, so no symbol is biased — which matters more here than usual,
    /// since entropy is the only thing standing between a leaked digest and the
    /// secret.
    public static func generate() -> String {
        var generator = SystemRandomNumberGenerator()
        var characters: [Character] = []
        characters.reserveCapacity(groups * charactersPerGroup + groups - 1)
        for group in 0 ..< groups {
            if group > 0 { characters.append("-") }
            for _ in 0 ..< charactersPerGroup {
                characters.append(alphabet[Int.random(in: 0 ..< alphabet.count, using: &generator)])
            }
        }
        return String(characters)
    }
}

/// Turns an app-password secret into the digest the store matches on.
///
/// ## Why the digest is deterministic
///
/// A login presents `(identifier, password)` and nothing that says WHICH app
/// password it is. A per-row random salt would therefore mean verifying the
/// presented secret against every row the account owns — an O(n) Argon2id loop
/// on an unauthenticated endpoint, and a denial-of-service lever pointed at
/// login. Salting by the account DID makes the digest deterministic, so
/// resolution is one KDF evaluation and one indexed probe.
///
/// This is upstream's design with a stronger KDF: `verifyAppPassword` computes
/// `scrypt.hashAppPassword(did, password)` and selects the row by equality
/// (`account-manager/helpers/password.ts:26-43`).
///
/// ## The divergence from D7, and why it is safe
///
/// The design says to reuse `LibsodiumArgon2idHasher` directly. That API is
/// `crypto_pwhash_str_alg`, which mints a fresh random salt per call and so
/// cannot be looked up. The property D7 protects — an expensive KDF between a
/// leaked database and the secret — is preserved: the work factor is the same
/// `Argon2idPolicy`. What a per-row salt additionally protects is LOW-ENTROPY,
/// user-chosen passwords against precomputation, and an app password is
/// neither: it is machine-generated with `AppPasswordSecret.entropyBits` of
/// entropy and shown once. There is no dictionary to precompute against.
///
/// Salting by DID still separates accounts, so a digest is useless against any
/// other account.
///
/// **The account password keeps its per-credential random salt.** It is
/// user-chosen, and none of the above applies to it.
public struct AppPasswordCredentials: Sendable {
    private let hasher: LibsodiumArgon2idHasher

    public init(policy: Argon2idPolicy = .interactive) throws {
        self.hasher = try LibsodiumArgon2idHasher(policy: policy)
    }

    public func digest(did: String, password: String) throws -> Data {
        try hasher.deterministicDigest(password, salt: Data(did.utf8))
    }

    /// Generates a secret, derives its digest, and records it.
    ///
    /// The KDF runs before the store call rather than inside it: at the
    /// configured policy Argon2id holds a CPU for the better part of 100ms and
    /// 64 MiB, and doing that inside the control-database actor would serialise
    /// every other control write behind it.
    public func issue(
        did: String,
        name: String,
        scopes: String,
        into store: some AppPasswordStore,
        now: Date = Date()
    ) async throws -> AppPasswordIssuance {
        let password = AppPasswordSecret.generate()
        let digest = try digest(did: did, password: password)
        let record = try await store.createAppPassword(
            did: did,
            name: name,
            scopes: scopes,
            digest: digest,
            now: now
        )
        return AppPasswordIssuance(record: record, password: password)
    }

    /// Resolves a presented secret to its row, or `nil`.
    public func resolve(
        did: String,
        password: String,
        in store: some AppPasswordStore
    ) async throws -> AppPasswordRecord? {
        try await store.appPassword(did: did, digest: digest(did: did, password: password))
    }
}
