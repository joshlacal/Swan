import Foundation
import SwanCore

public struct ReferencePLCIdentityUpdateRequest: Sendable, Equatable {
    public let accountDID: String
    public let requestID: String
    public let sessionID: ManagementSessionID

    public init(accountDID: String, requestID: String, sessionID: ManagementSessionID) throws {
        self.accountDID = try AccountIdentifiers.validateDID(accountDID)
        guard !requestID.isEmpty, requestID.utf8.count <= 256, !requestID.contains("\0") else {
            throw SwanError.invalidIdentifier("PLC update request")
        }
        self.requestID = requestID
        self.sessionID = sessionID
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
    func updatePLCIdentity(accountDID: String, requestID: String, sessionID: ManagementSessionID, minimumStrength: AuthenticationStrength, now: Date) async throws -> ReferencePLCIdentityUpdateResult
}

public protocol ReferenceStepUpPolicy: Sendable {
    func consumeFreshStepUp(sessionID: ManagementSessionID, accountDID: String, requiredStrength: AuthenticationStrength, now: Date) async throws
}

/// Reference-compatible adapter for identity update endpoints. It owns the
/// method-specific admission and delegates PLC mutation to the existing PLC
/// service boundary supplied by the integration owner.
public struct ReferencePLCIdentityUpdateAdapter: Sendable {
    private let service: any ReferencePLCIdentityUpdateService
    private let stepUp: any ReferenceStepUpPolicy

    public init(service: any ReferencePLCIdentityUpdateService, stepUp: any ReferenceStepUpPolicy) {
        self.service = service
        self.stepUp = stepUp
    }

    public func update(_ request: ReferencePLCIdentityUpdateRequest, now: Date = Date()) async throws -> ReferencePLCIdentityUpdateResult {
        let minimumStrength: AuthenticationStrength = .passwordPlusTOTP
        try await stepUp.consumeFreshStepUp(sessionID: request.sessionID, accountDID: request.accountDID, requiredStrength: minimumStrength, now: now)
        return try await service.updatePLCIdentity(
            accountDID: request.accountDID,
            requestID: request.requestID,
            sessionID: request.sessionID,
            minimumStrength: minimumStrength,
            now: now
        )
    }
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

public protocol ReferenceAdminLifecycleMutation: Sendable {
    func suspend(accountDID: String, reason: String) async throws -> ReferenceAdminLifecycleResult
    func reactivate(accountDID: String) async throws -> ReferenceAdminLifecycleResult
}

/// Small operator-only lifecycle policy seam. Persistent status transitions
/// remain delegated to ``AccountOperatorService``; this adapter exists for
/// HTTP/CLI registration and guarantees authorization plus audit ordering.
public struct ReferenceAdminLifecycleService: Sendable {
    private let mutation: any ReferenceAdminLifecycleMutation
    private let audit: any ReferenceAdminAuditSink

    public init(mutation: any ReferenceAdminLifecycleMutation, audit: any ReferenceAdminAuditSink) {
        self.mutation = mutation
        self.audit = audit
    }

    public func suspend(accountDID: String, reason: String, authorization: AccountOperatorAuthorization) async throws -> ReferenceAdminLifecycleResult {
        let did = try AccountIdentifiers.validateDID(accountDID)
        guard !reason.isEmpty, reason.utf8.count <= 512 else { throw SwanError.invalidIdentifier("admin reason") }
        let result = try await mutation.suspend(accountDID: did, reason: reason)
        await audit.append(.init(operation: "suspend", accountDID: did))
        return result
    }

    public func reactivate(accountDID: String, authorization: AccountOperatorAuthorization) async throws -> ReferenceAdminLifecycleResult {
        let did = try AccountIdentifiers.validateDID(accountDID)
        let result = try await mutation.reactivate(accountDID: did)
        await audit.append(.init(operation: "reactivate", accountDID: did))
        return result
    }
}
