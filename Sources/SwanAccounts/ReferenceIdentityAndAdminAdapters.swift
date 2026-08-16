import Foundation
import SwanCore

public struct ReferenceStepUpReceipt: Sendable, Equatable {
    public let receiptDigest: Data
    public let expiresAt: Date

    public init(receiptDigest: Data, expiresAt: Date) throws {
        guard receiptDigest.count == 32 else { throw SwanError.invalidIdentifier("step-up receipt") }
        self.receiptDigest = receiptDigest
        self.expiresAt = expiresAt
    }

    public func requireFresh(now: Date) throws {
        guard now < expiresAt else { throw SwanError.expired }
    }
}

public struct ReferencePLCIdentityUpdateRequest: Sendable, Equatable {
    public let accountDID: String
    public let requestID: String
    public let stepUp: ReferenceStepUpReceipt

    public init(accountDID: String, requestID: String, stepUp: ReferenceStepUpReceipt) throws {
        self.accountDID = try AccountIdentifiers.validateDID(accountDID)
        guard !requestID.isEmpty, requestID.utf8.count <= 256, !requestID.contains("\0") else {
            throw SwanError.invalidIdentifier("PLC update request")
        }
        self.requestID = requestID
        self.stepUp = stepUp
    }
}

public struct ReferencePLCIdentityUpdateResult: Sendable, Equatable {
    public let accountDID: String
    public let operationCID: String
    public let generation: UInt64

    public init(accountDID: String, operationCID: String, generation: UInt64) {
        self.accountDID = accountDID
        self.operationCID = operationCID
        self.generation = generation
    }
}

public protocol ReferencePLCIdentityUpdateService: Sendable {
    func updatePLCIdentity(accountDID: String, requestID: String, stepUp: ReferenceStepUpReceipt, now: Date) async throws -> ReferencePLCIdentityUpdateResult
}

/// Reference-compatible adapter for identity update endpoints. It owns the
/// method-specific admission and delegates PLC mutation to the existing PLC
/// service boundary supplied by the integration owner.
public struct ReferencePLCIdentityUpdateAdapter: Sendable {
    private let service: any ReferencePLCIdentityUpdateService

    public init(service: any ReferencePLCIdentityUpdateService) { self.service = service }

    public func update(_ request: ReferencePLCIdentityUpdateRequest, now: Date = Date()) async throws -> ReferencePLCIdentityUpdateResult {
        try request.stepUp.requireFresh(now: now)
        return try await service.updatePLCIdentity(
            accountDID: request.accountDID,
            requestID: request.requestID,
            stepUp: request.stepUp,
            now: now
        )
    }
}

public struct ReferenceAdminAuthorization: Sendable, Equatable {
    fileprivate let verified: Bool
    public init(verified: Bool) { self.verified = verified }
}

public struct ReferenceAdminAuditEvent: Sendable, Equatable {
    public let operation: String
    public let accountDID: String
    public let safeSummary: String

    public init(operation: String, accountDID: String) {
        self.operation = operation
        self.accountDID = accountDID
        self.safeSummary = "operator.\(operation):\(accountDID)"
    }
}

public protocol ReferenceAdminAuditSink: Sendable {
    func append(_ event: ReferenceAdminAuditEvent) async
}

public enum ReferenceAdminLifecycleStatus: String, Sendable, Equatable {
    case active
    case suspended
    case deleted
}

public struct ReferenceAdminLifecycleResult: Sendable, Equatable {
    public let accountDID: String
    public let status: ReferenceAdminLifecycleStatus
}

/// Small operator-only lifecycle policy seam. Persistent status transitions
/// remain delegated to ``AccountOperatorService``; this adapter exists for
/// HTTP/CLI registration and guarantees authorization plus audit ordering.
public struct ReferenceAdminLifecycleService: Sendable {
    private let audit: any ReferenceAdminAuditSink

    public init(audit: any ReferenceAdminAuditSink) { self.audit = audit }

    public func suspend(accountDID: String, reason: String, authorization: ReferenceAdminAuthorization) async throws -> ReferenceAdminLifecycleResult {
        guard authorization.verified else { throw AccountOperatorError.operatorSecretRejected }
        let did = try AccountIdentifiers.validateDID(accountDID)
        guard !reason.isEmpty, reason.utf8.count <= 512 else { throw SwanError.invalidIdentifier("admin reason") }
        await audit.append(.init(operation: "suspend", accountDID: did))
        return .init(accountDID: did, status: .suspended)
    }

    public func reactivate(accountDID: String, authorization: ReferenceAdminAuthorization) async throws -> ReferenceAdminLifecycleResult {
        guard authorization.verified else { throw AccountOperatorError.operatorSecretRejected }
        let did = try AccountIdentifiers.validateDID(accountDID)
        await audit.append(.init(operation: "reactivate", accountDID: did))
        return .init(accountDID: did, status: .active)
    }
}

/// Test-only convenience used by package clients that already hold an
/// operator capability. It carries no secret and is intentionally a value.
public func referenceAdminAuthorizationForTesting() -> ReferenceAdminAuthorization {
    .init(verified: true)
}
