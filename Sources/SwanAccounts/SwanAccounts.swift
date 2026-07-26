import Foundation
import SwanCore

public enum AccountStatus: Codable, Sendable, Equatable {
    case active
    case deactivated
    case deleted
    case takendown
    case suspended
    case desynchronized
    case throttled
    case unknown(String)

    public init(rawValue: String) throws {
        guard Self.isCanonicalStatusToken(rawValue) else {
            throw SwanError.malformed("invalid account status")
        }
        self = switch rawValue {
        case "active": .active
        case "deactivated": .deactivated
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
        case .deleted: "deleted"
        case .takendown: "takendown"
        case .suspended: "suspended"
        case .desynchronized: "desynchronized"
        case .throttled: "throttled"
        case let .unknown(value): value
        }
    }

    public var isActive: Bool {
        self == .active
    }

    public init(from decoder: any Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        if case let .unknown(value) = self {
            guard Self.isCanonicalStatusToken(value),
                  try AccountStatus(rawValue: value) == .unknown(value) else {
                throw SwanError.malformed("invalid unknown account status")
            }
        }
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    private static func isCanonicalStatusToken(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64,
              let first = value.utf8.first,
              first >= 97, first <= 122 else {
            return false
        }
        return value.utf8.allSatisfy {
            ($0 >= 97 && $0 <= 122)
                || ($0 >= 48 && $0 <= 57)
                || $0 == 45
                || $0 == 95
        }
    }
}

public struct SwanAccount: Codable, Sendable, Equatable {
    public let did: String
    public private(set) var handle: String
    public var status: AccountStatus
    public let createdAt: Date

    public init(did: String, handle: String, status: AccountStatus = .active, createdAt: Date = Date()) throws {
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
    public func resolve(handle: String) -> SwanAccount? {
        guard let canonical = try? AccountIdentifiers.canonicalHandle(handle) else { return nil }
        return handles[canonical].flatMap { accounts[$0] }
    }

    public func setStatus(_ status: AccountStatus, did: String) throws {
        guard var account = accounts[did] else { throw SwanError.malformed("unknown account") }
        account.status = status
        accounts[did] = account
    }
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
