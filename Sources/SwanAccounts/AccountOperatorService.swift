import Foundation
import SwanStorage

#if os(Linux)
import Glibc
#else
import Darwin
#endif

/// Errors intentionally safe to expose from the local `swan account` command.
/// None carries an operator-secret value, path, verifier, key reference, or
/// account-private data.
public enum AccountOperatorError: Error, Sendable, Equatable, LocalizedError {
    case operatorSecretMissing
    case operatorSecretRejected
    case operatorSecretFileUnavailable
    case unknownAccount

    public var errorDescription: String? {
        switch self {
        case .operatorSecretMissing:
            "operator secret is required"
        case .operatorSecretRejected:
            "operator authorization failed"
        case .operatorSecretFileUnavailable:
            "operator secret file is unavailable"
        case .unknownAccount:
            "account not found"
        }
    }
}

/// An opaque, non-Codable capability which is issued only after the command
/// process has obtained an operator secret from an allowed local source.
/// The secret value itself never crosses this boundary.
public struct AccountOperatorAuthorization: Sendable {
    fileprivate let isVerified: Bool

    fileprivate init() {
        isVerified = true
    }
}

/// Resolves the local operator secret without offering a command-line secret
/// argument. A deployment may expose exactly one OS-protected source (an
/// environment variable or a mounted secret file). If both are supplied, they
/// must match through a no-early-exit comparison so one source cannot silently
/// override the other due to a configuration mistake.
public enum OperatorSecretResolver {
    private static let maximumSecretBytes = 4_096

    /// Production entry point. The command receives its credential only from
    /// the process environment injected by its supervisor and/or a mounted
    /// secret file explicitly selected by the operator.
    public static func authorize(secretFile: URL? = nil) throws -> AccountOperatorAuthorization {
        try authorize(
            environment: ProcessInfo.processInfo.environment,
            secretFile: secretFile
        )
    }

    /// Internal seam for unit tests. It is deliberately not public API: a
    /// library consumer must not be able to manufacture an authorization by
    /// passing an arbitrary dictionary instead of the real process environment.
    static func authorize(
        environment: [String: String],
        secretFile: URL?
    ) throws -> AccountOperatorAuthorization {
        let environmentSecret = try environment["SWAN_OPERATOR_SECRET"].map(secretData)
        let fileSecret = try secretFile.map(readSecretFile)

        guard environmentSecret != nil || fileSecret != nil else {
            throw AccountOperatorError.operatorSecretMissing
        }
        if let environmentSecret, let fileSecret,
           !constantTimeEqual(environmentSecret, fileSecret) {
            throw AccountOperatorError.operatorSecretRejected
        }
        return AccountOperatorAuthorization()
    }

    private static func secretData(_ value: String) throws -> Data {
        try validatedSecret(Data(value.utf8))
    }

    private static func readSecretFile(_ url: URL) throws -> Data {
        // Open the selected object once, without following links, then inspect
        // that same descriptor. Checking path metadata followed by a separate
        // path read would permit a link/rename race to swap in a different
        // secret after validation.
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { throw AccountOperatorError.operatorSecretFileUnavailable }
        defer { _ = close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & (S_IRWXG | S_IRWXO)) == 0,
              metadata.st_size > 0,
              metadata.st_size <= off_t(maximumSecretBytes + 2) else {
            throw AccountOperatorError.operatorSecretFileUnavailable
        }
        do {
            // Read one byte past the largest legal on-disk form so a file that
            // grew after fstat still cannot evade the bounded input rule.
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            let data = try handle.read(upToCount: maximumSecretBytes + 3) ?? Data()
            guard data.count <= maximumSecretBytes + 2 else {
                throw AccountOperatorError.operatorSecretRejected
            }
            return try validatedSecret(data)
        } catch let error as AccountOperatorError {
            throw error
        } catch {
            throw AccountOperatorError.operatorSecretFileUnavailable
        }
    }

    private static func validatedSecret(_ data: Data) throws -> Data {
        // Kubernetes/Docker mounted secret files conventionally include a
        // terminating newline. Preserve every other byte and strip only that
        // transport terminator before comparing it with the environment form.
        var normalized = data
        if normalized.last == 0x0A {
            normalized.removeLast()
            if normalized.last == 0x0D {
                normalized.removeLast()
            }
        }
        guard !normalized.isEmpty, normalized.count <= maximumSecretBytes else {
            throw AccountOperatorError.operatorSecretRejected
        }
        return normalized
    }

    /// Performs a full-length XOR reduction without returning early for a
    /// differing byte. The length contribution is folded into the same result
    /// so unequal-size values cannot compare equal.
    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        let comparisonLength = max(lhs.count, rhs.count)
        var difference = UInt64(lhs.count) ^ UInt64(rhs.count)
        for index in 0 ..< comparisonLength {
            let left = index < lhs.count ? lhs[lhs.startIndex + index] : 0
            let right = index < rhs.count ? rhs[rhs.startIndex + index] : 0
            difference |= UInt64(left ^ right)
        }
        return difference == 0
    }
}

/// The only account identifiers accepted by the operator-facing service.
/// Keeping the lookup explicit prevents a DID/handle string from being guessed
/// by command parsing or routed into an unintended storage query.
public enum AccountOperatorLookup: Sendable, Equatable {
    case did(String)
    case handle(String)
}

/// Deliberately allow-listed representation for local command output. It does
/// not model credential state, password verifiers, key-store references,
/// sessions, OAuth state, or repository data.
public struct AccountOperatorView: Codable, Sendable, Equatable {
    public let did: String
    public let canonicalHandle: String
    public let status: String
    public let createdAt: Date
    public let updatedAt: Date
    public let tombstone: AccountTombstoneMetadata?
    public let export: AccountExportMetadata?

    public init(account: AccountControlAccount) {
        did = account.did
        canonicalHandle = account.canonicalHandle
        status = account.status.rawValue
        createdAt = account.createdAt
        updatedAt = account.updatedAt
        tombstone = account.tombstone
        export = account.export
    }
}

/// Centralizes the JSON encoder used by the command. The output is structured
/// and stable enough for lab automation while remaining restricted to
/// `AccountOperatorView`'s explicit allow-list.
public enum AccountOperatorJSON {
    public static func render(_ view: AccountOperatorView) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(view)
    }
}

/// Testable account-control boundary used by the `swan account` command. It
/// delegates lifecycle state changes to the existing durable control-store
/// transaction rather than creating any raw SQLite tables or queries itself.
public struct AccountOperatorService: Sendable {
    private let store: any AccountControlStore

    public init(store: any AccountControlStore) {
        self.store = store
    }

    /// Read-only lookup is intentionally separate from lifecycle authority.
    /// The projected result is sanitized before it can reach command output.
    public func show(_ lookup: AccountOperatorLookup) async throws -> AccountOperatorView {
        let account: AccountControlAccount?
        switch lookup {
        case let .did(value):
            account = try await store.account(did: AccountIdentifiers.validateDID(value))
        case let .handle(value):
            account = try await store.account(
                canonicalHandle: AccountIdentifiers.canonicalHandle(value)
            )
        }
        guard let account else { throw AccountOperatorError.unknownAccount }
        return AccountOperatorView(account: account)
    }

    public func deactivate(
        did: String,
        authorization: AccountOperatorAuthorization,
        now: Date = Date()
    ) async throws -> AccountOperatorView {
        try await transition(
            did: did,
            to: .deactivated,
            declaration: .init(),
            authorization: authorization,
            now: now
        )
    }

    public func reactivate(
        did: String,
        authorization: AccountOperatorAuthorization,
        now: Date = Date()
    ) async throws -> AccountOperatorView {
        try await transition(
            did: did,
            to: .active,
            declaration: .init(),
            authorization: authorization,
            now: now
        )
    }

    public func delete(
        did: String,
        tombstoneReason: String? = nil,
        exportReference: String? = nil,
        authorization: AccountOperatorAuthorization,
        now: Date = Date()
    ) async throws -> AccountOperatorView {
        let declaration = AccountLifecycleDeclaration(
            tombstone: try AccountTombstoneMetadata(declaredAt: now, reason: tombstoneReason),
            export: try exportReference.map {
                try AccountExportMetadata(declaredAt: now, reference: $0)
            }
        )
        return try await transition(
            did: did,
            to: .deleted,
            declaration: declaration,
            authorization: authorization,
            now: now
        )
    }

    private func transition(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration,
        authorization: AccountOperatorAuthorization,
        now: Date
    ) async throws -> AccountOperatorView {
        guard authorization.isVerified else {
            throw AccountOperatorError.operatorSecretRejected
        }
        do {
            let account = try await store.transitionStatus(
                did: AccountIdentifiers.validateDID(did),
                to: status,
                declaration: declaration,
                now: now
            )
            return AccountOperatorView(account: account)
        } catch AccountControlStoreError.notFound {
            throw AccountOperatorError.unknownAccount
        }
    }
}
