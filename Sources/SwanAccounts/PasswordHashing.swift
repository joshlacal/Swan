import CLibsodium
import Dispatch
import Foundation
import SwanCore

public struct Argon2idPolicy: Sendable, Equatable {
    public static let minimumOperationsLimit: UInt64 = 2
    public static let maximumOperationsLimit: UInt64 = 10
    public static let minimumMemoryLimitBytes = 64 * 1_024 * 1_024
    public static let maximumMemoryLimitBytes = 512 * 1_024 * 1_024

    public static let interactive = try! Argon2idPolicy(
        operationsLimit: minimumOperationsLimit,
        memoryLimitBytes: minimumMemoryLimitBytes
    )

    public let operationsLimit: UInt64
    public let memoryLimitBytes: Int

    public init(operationsLimit: UInt64, memoryLimitBytes: Int) throws {
        guard (Self.minimumOperationsLimit ... Self.maximumOperationsLimit).contains(operationsLimit) else {
            throw SwanError.malformed("Argon2id operations limit is outside the supported range")
        }
        guard (Self.minimumMemoryLimitBytes ... Self.maximumMemoryLimitBytes).contains(memoryLimitBytes) else {
            throw SwanError.malformed("Argon2id memory limit is outside the supported range")
        }
        self.operationsLimit = operationsLimit
        self.memoryLimitBytes = memoryLimitBytes
    }
}

public protocol PasswordHasher: Sendable {
    func hash(_ password: String) throws -> String
    func verify(_ password: String, encodedHash: String) throws -> Bool
    func needsRehash(_ encodedHash: String) throws -> Bool
}

public struct LibsodiumArgon2idHasher: PasswordHasher {
    public let policy: Argon2idPolicy

    public init(policy: Argon2idPolicy = .interactive) throws {
        guard Self.sodiumInitializationResult >= 0 else {
            throw SwanError.unavailable("libsodium initialization failed")
        }
        self.policy = policy
    }

    public func hash(_ password: String) throws -> String {
        var output = [CChar](repeating: 0, count: Int(crypto_pwhash_STRBYTES))
        let result = Self.withPasswordBytes(password) { passwordBytes, passwordLength in
            crypto_pwhash_str_alg(
                &output,
                passwordBytes,
                passwordLength,
                policy.operationsLimit,
                policy.memoryLimitBytes,
                crypto_pwhash_ALG_ARGON2ID13
            )
        }
        guard result == 0 else {
            throw SwanError.unavailable("Argon2id password hashing failed")
        }
        let encodedBytes = output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard let encodedHash = String(bytes: encodedBytes, encoding: .utf8) else {
            throw SwanError.unavailable("Argon2id returned a non-UTF-8 PHC string")
        }
        return encodedHash
    }

    public func verify(_ password: String, encodedHash: String) throws -> Bool {
        let metadata = try Self.parsePHCString(encodedHash)
        guard metadata.algorithm == "argon2id", metadata.version == 19,
              metadata.parallelism == 1 else {
            throw SwanError.malformed("unsupported password PHC algorithm or version")
        }
        return encodedHash.withCString { hashBytes in
            Self.withPasswordBytes(password) { passwordBytes, passwordLength in
                crypto_pwhash_str_verify(
                    hashBytes,
                    passwordBytes,
                    passwordLength
                ) == 0
            }
        }
    }

    public func needsRehash(_ encodedHash: String) throws -> Bool {
        let metadata = try Self.parsePHCString(encodedHash)
        return metadata.algorithm != "argon2id"
            || metadata.version != 19
            || metadata.operationsLimit != policy.operationsLimit
            || metadata.memoryLimitBytes != policy.memoryLimitBytes
            || metadata.parallelism != 1
    }

    private struct PHCMetadata {
        let algorithm: Substring
        let version: UInt64
        let operationsLimit: UInt64
        let memoryLimitBytes: Int
        let parallelism: UInt64
    }

    private static let sodiumInitializationResult = sodium_init()

    private static func parsePHCString(_ encodedHash: String) throws -> PHCMetadata {
        guard !encodedHash.isEmpty,
              encodedHash.utf8.count < Int(crypto_pwhash_STRBYTES),
              encodedHash.utf8.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else {
            throw SwanError.malformed("invalid Argon2 PHC string")
        }

        let components = encodedHash.split(separator: "$", omittingEmptySubsequences: false)
        guard components.count == 6,
              components[0].isEmpty,
              ["argon2id", "argon2i"].contains(components[1]),
              components[2].hasPrefix("v="),
              let version = UInt64(components[2].dropFirst(2)),
              components[4].count == 22,
              components[5].count == 43,
              components[4].utf8.allSatisfy(Self.isPHCBase64Byte),
              components[5].utf8.allSatisfy(Self.isPHCBase64Byte) else {
            throw SwanError.malformed("invalid Argon2 PHC string")
        }

        var parameters: [Substring: UInt64] = [:]
        for parameter in components[3].split(separator: ",") {
            let pair = parameter.split(separator: "=", omittingEmptySubsequences: false)
            guard pair.count == 2, parameters[pair[0]] == nil,
                  let value = UInt64(pair[1]), value > 0 else {
                throw SwanError.malformed("invalid Argon2 PHC parameters")
            }
            parameters[pair[0]] = value
        }
        guard parameters.count == 3,
              let memoryKiB = parameters["m"],
              let operations = parameters["t"],
              let parallelism = parameters["p"],
              parallelism <= 16,
              operations <= Argon2idPolicy.maximumOperationsLimit,
              memoryKiB <= UInt64(Argon2idPolicy.maximumMemoryLimitBytes / 1_024) else {
            throw SwanError.malformed("unsupported Argon2 PHC parameters")
        }
        return PHCMetadata(
            algorithm: components[1],
            version: version,
            operationsLimit: operations,
            memoryLimitBytes: Int(memoryKiB) * 1_024,
            parallelism: parallelism
        )
    }

    private static func withPasswordBytes<Result>(
        _ password: String,
        _ body: (UnsafePointer<CChar>, UInt64) throws -> Result
    ) rethrows -> Result {
        let passwordBytes = password.utf8CString
        return try passwordBytes.withUnsafeBufferPointer { buffer in
            try body(buffer.baseAddress!, UInt64(buffer.count - 1))
        }
    }

    private static func isPHCBase64Byte(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122)
            || (byte >= 48 && byte <= 57)
            || byte == 43
            || byte == 47
    }
}

public struct Argon2idVerificationMetrics: Sendable, Equatable {
    public let active: Int
    public let queued: Int
    public let peakActive: Int
    public let totalAdmitted: Int
    public let totalRejected: Int
}

/// Bounds admission on an actor while running libsodium on a dedicated
/// Dispatch queue, never on Swift's cooperative executor.
public actor Argon2idVerificationExecutor {
    private typealias Verification = @Sendable (String, String) throws -> Bool

    private struct PendingVerification {
        let id: UUID
        let password: String
        let encodedHash: String
        let continuation: CheckedContinuation<Bool, any Error>
    }

    public let maximumConcurrentVerifications: Int
    public let maximumQueuedVerifications: Int
    private let blockingQueue: DispatchQueue
    private let verification: Verification
    private var pending: [PendingVerification] = []
    private var active = 0
    private var peakActive = 0
    private var totalAdmitted = 0
    private var totalRejected = 0

    public init(
        hasher: LibsodiumArgon2idHasher,
        maximumConcurrentVerifications: Int = 2,
        maximumQueuedVerifications: Int = 32
    ) throws {
        try Self.validateBounds(
            maximumConcurrentVerifications,
            maximumQueuedVerifications
        )
        self.maximumConcurrentVerifications = maximumConcurrentVerifications
        self.maximumQueuedVerifications = maximumQueuedVerifications
        blockingQueue = DispatchQueue(
            label: "org.swan.accounts.argon2id",
            qos: .userInitiated,
            attributes: .concurrent
        )
        verification = { password, encodedHash in
            try hasher.verify(password, encodedHash: encodedHash)
        }
    }

    init(
        maximumConcurrentVerifications: Int,
        maximumQueuedVerifications: Int = 32,
        verification: @escaping @Sendable (String, String) throws -> Bool
    ) throws {
        try Self.validateBounds(
            maximumConcurrentVerifications,
            maximumQueuedVerifications
        )
        self.maximumConcurrentVerifications = maximumConcurrentVerifications
        self.maximumQueuedVerifications = maximumQueuedVerifications
        blockingQueue = DispatchQueue(
            label: "org.swan.accounts.argon2id.test",
            attributes: .concurrent
        )
        self.verification = verification
    }

    public func verify(_ password: String, encodedHash: String) async throws -> Bool {
        try Task.checkCancellation()
        let requestID = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                if active >= maximumConcurrentVerifications,
                   pending.count >= maximumQueuedVerifications {
                    totalRejected += 1
                    continuation.resume(throwing: SwanError.unavailable(
                        "Argon2id verification capacity exhausted"
                    ))
                    return
                }
                pending.append(PendingVerification(
                    id: requestID,
                    password: password,
                    encodedHash: encodedHash,
                    continuation: continuation
                ))
                scheduleAdmittedWork()
            }
        } onCancel: {
            // The cancellation callback is synchronous and nonisolated; this
            // Task only bridges cancellation into the actor state machine.
            Task {
                await self.cancelQueued(requestID)
            }
        }
    }

    public func metrics() -> Argon2idVerificationMetrics {
        Argon2idVerificationMetrics(
            active: active,
            queued: pending.count,
            peakActive: peakActive,
            totalAdmitted: totalAdmitted,
            totalRejected: totalRejected
        )
    }

    private func scheduleAdmittedWork() {
        while active < maximumConcurrentVerifications, !pending.isEmpty {
            let request = pending.removeFirst()
            active += 1
            peakActive = max(peakActive, active)
            totalAdmitted += 1
            let verification = self.verification
            blockingQueue.async {
                let result = Result {
                    try verification(request.password, request.encodedHash)
                }
                // A Task is required only to bridge the blocking Dispatch
                // callback back into this actor's isolation domain.
                Task {
                    await self.complete(request, result: result)
                }
            }
        }
    }

    private func complete(
        _ request: PendingVerification,
        result: Result<Bool, any Error>
    ) {
        active -= 1
        request.continuation.resume(with: result)
        scheduleAdmittedWork()
    }

    private func cancelQueued(_ requestID: UUID) {
        guard let index = pending.firstIndex(where: { $0.id == requestID }) else {
            return
        }
        let request = pending.remove(at: index)
        request.continuation.resume(throwing: CancellationError())
        scheduleAdmittedWork()
    }

    private static func validateBounds(
        _ maximumConcurrentVerifications: Int,
        _ maximumQueuedVerifications: Int
    ) throws {
        guard (1 ... 4).contains(maximumConcurrentVerifications),
              (0 ... 1_024).contains(maximumQueuedVerifications) else {
            throw SwanError.malformed(
                "Argon2id verification concurrency or queue bound is unsupported"
            )
        }
    }
}

/// Explicit fail-closed option for deployments that have not made libsodium
/// available to the account service.
public struct UnavailablePasswordHasher: PasswordHasher {
    public init() {}

    public func hash(_ password: String) throws -> String {
        throw SwanError.unavailable("Argon2id password hashing is not configured")
    }

    public func verify(_ password: String, encodedHash: String) throws -> Bool {
        throw SwanError.unavailable("Argon2id password hashing is not configured")
    }

    public func needsRehash(_ encodedHash: String) throws -> Bool {
        throw SwanError.unavailable("Argon2id password hashing is not configured")
    }
}
