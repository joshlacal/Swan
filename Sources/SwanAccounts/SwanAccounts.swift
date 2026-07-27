import Foundation
import SwanCore
import SwanStorage

/// Compatibility name for the account-domain lifecycle state now shared with
/// durable storage. New control-plane APIs use `AccountControlStatus`.
public typealias AccountStatus = AccountControlStatus

public extension AccountControlStatus {
    var isActive: Bool { authorizesAccount }
}

public struct SwanAccount: Codable, Sendable, Equatable {
    public let did: String
    public private(set) var handle: String
    public var status: AccountStatus
    public let createdAt: Date

    public init(did: String, handle: String, status: AccountStatus = .active, createdAt: Date = Date()) throws {
        guard status.isCanonicalValue else {
            throw SwanError.malformed("invalid account status")
        }
        self.did = try AccountIdentifiers.validateDID(did)
        self.handle = try AccountIdentifiers.canonicalHandle(handle)
        self.status = status
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case did
        case handle
        case status
        case createdAt
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            did: container.decode(String.self, forKey: .did),
            handle: container.decode(String.self, forKey: .handle),
            status: container.decode(AccountStatus.self, forKey: .status),
            createdAt: container.decode(Date.self, forKey: .createdAt)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(did, forKey: .did)
        try container.encode(handle, forKey: .handle)
        try container.encode(status, forKey: .status)
        try container.encode(createdAt, forKey: .createdAt)
    }
}

/// A small process-local fixture for narrow unit tests. It is deliberately not
/// the production control path; use `DurableAccountDirectory` with an
/// `AccountControlStore` for any account that must survive a restart.
public actor InMemoryAccountDirectory {
    private var accounts: [String: SwanAccount] = [:]
    private var handles: [String: String] = [:]

    public init() {}

    public func create(_ account: SwanAccount) throws {
        guard account.status.isCanonicalValue else {
            throw SwanError.malformed("invalid account status")
        }
        guard accounts[account.did] == nil, handles[account.handle] == nil else {
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        accounts[account.did] = account
        handles[account.handle] = account.did
    }

    public func account(did: String) -> SwanAccount? { accounts[did] }
    public func resolve(handle: String) -> SwanAccount? {
        guard let canonical = try? AccountIdentifiers.canonicalHandle(handle) else { return nil }
        return handles[canonical].flatMap { accounts[$0] }
    }

    public func setStatus(_ status: AccountStatus, did: String) throws {
        guard status.isCanonicalValue else {
            throw SwanError.malformed("invalid account status")
        }
        guard var account = accounts[did] else { throw SwanError.malformed("unknown account") }
        account.status = status
        accounts[did] = account
    }
}
