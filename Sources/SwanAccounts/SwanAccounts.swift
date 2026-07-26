import Crypto
import Foundation
import SwanCore
import SwanStorage

public enum AccountStatus: String, Codable, Sendable {
    case active
    case deactivated
    case deleted
}

public struct SwanAccount: Codable, Sendable, Equatable {
    public let did: String
    public var handle: String
    public var status: AccountStatus
    public let createdAt: Date

    public init(did: String, handle: String, status: AccountStatus = .active, createdAt: Date = Date()) throws {
        guard did.hasPrefix("did:"), handle.split(separator: ".").count >= 2 else {
            throw SwanError.invalidIdentifier("account DID or handle")
        }
        self.did = did
        self.handle = handle
        self.status = status
        self.createdAt = createdAt
    }
}

public actor AccountDirectory {
    private var accounts: [String: SwanAccount] = [:]
    private var handles: [String: String] = [:]

    public init() {}

    public func create(_ account: SwanAccount) throws {
        guard accounts[account.did] == nil, handles[account.handle] == nil else {
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        accounts[account.did] = account
        handles[account.handle] = account.did
    }

    public func account(did: String) -> SwanAccount? { accounts[did] }
    public func resolve(handle: String) -> SwanAccount? { handles[handle].flatMap { accounts[$0] } }

    public func setStatus(_ status: AccountStatus, did: String) throws {
        guard var account = accounts[did] else { throw SwanError.malformed("unknown account") }
        account.status = status
        accounts[did] = account
    }
}

public protocol AccountKeyStore: Sendable {
    func put(_ key: Data, named name: String) async throws
    func key(named name: String) async throws -> Data
}

/// Development-only encrypted file key store. The caller supplies the master
/// key from process configuration or a mounted secret; it is never written to
/// SQLite or to the key-store directory.
public actor FileAccountKeyStore: AccountKeyStore {
    private let root: URL
    private let masterKey: SymmetricKey

    public init(root: URL, masterKey: Data) throws {
        guard masterKey.count >= 32 else { throw SwanError.malformed("key-store master key is too short") }
        self.root = root
        self.masterKey = SymmetricKey(data: masterKey)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    public func put(_ key: Data, named name: String) throws {
        let sealed = try AES.GCM.seal(key, using: masterKey)
        guard let combined = sealed.combined else { throw SwanError.unavailable("could not serialize encrypted key") }
        let destination = fileURL(for: name)
        try combined.write(to: destination, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    }

    public func key(named name: String) throws -> Data {
        let combined = try Data(contentsOf: fileURL(for: name))
        return try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: masterKey)
    }

    private func fileURL(for name: String) -> URL {
        let digest = Hex.encode(SHA256.hash(data: Data(name.utf8)))
        return root.appending(path: "\(digest).key")
    }
}

public protocol PasswordHasher: Sendable {
    func hash(_ password: String) throws -> String
    func verify(_ password: String, encodedHash: String) throws -> Bool
}

/// Password login fails closed until a deployment configures the planned
/// Argon2id/libsodium adapter. Swan intentionally never substitutes a fast
/// hash for a password verifier.
public struct UnavailablePasswordHasher: PasswordHasher {
    public init() {}
    public func hash(_ password: String) throws -> String { throw SwanError.unavailable("Argon2id password hashing is not configured") }
    public func verify(_ password: String, encodedHash: String) throws -> Bool { throw SwanError.unavailable("Argon2id password hashing is not configured") }
}

public struct PortableAccountExportManifest: Codable, Sendable, Equatable {
    public let format: String
    public let did: String
    public let createdAt: Date
    public let publicRepositoryPath: String
    public let spaceRepositoryPaths: [String]
    public let blobPaths: [String]
    public let includesPrivateKeys: Bool

    public init(did: String, publicRepositoryPath: String, spaceRepositoryPaths: [String], blobPaths: [String], includesPrivateKeys: Bool = false) {
        format = "swan-account-export-v1"
        self.did = did
        createdAt = Date()
        self.publicRepositoryPath = publicRepositoryPath
        self.spaceRepositoryPaths = spaceRepositoryPaths
        self.blobPaths = blobPaths
        self.includesPrivateKeys = includesPrivateKeys
    }
}
