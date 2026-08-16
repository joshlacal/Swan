import Foundation
import SwanAccounts
import SwanCore
import SwanStorage

/// Wire-shaped inputs for the reference `com.atproto.server.createAccount`
/// adapter. The adapter does not silently accept verificationPhone: callers
/// must use the frozen email-proof path.
public struct SwanCreateAccountXRPCInput: Codable, Sendable, Equatable {
    public let handle: String
    public let email: String?
    public let password: String
    public let inviteCode: String?
    public let verificationCode: String?
    public let did: String?
    public let recoveryKey: String?
    public let plcOp: String?
    public let verificationPhone: String?
}

public protocol SwanCreateAccountProvisioning: Sendable {
    func createAccount(_ input: SwanCreateAccountXRPCInput, now: Date) async throws -> (account: AccountControlAccount, session: Data)
}

/// The adapter boundary is intentionally separate from account creation: the
/// implementation must verify policy, email proof, invite/Turnstile and DID
/// preparation before provisioning can run.
public protocol SwanCreateAccountAuthorizationPipeline: Sendable {
    func authorize(_ input: SwanCreateAccountXRPCInput, now: Date) async throws
}

public enum AccountLifecycleAuthorizationRole: String, Sendable, Equatable {
    case operatorRole
    case managementSession
}

public struct AccountLifecycleCapability: Sendable, Equatable {
    public let role: AccountLifecycleAuthorizationRole
    public let subjectDID: String?
    public let nonce: Data
    public let expiresAt: Date
    public let action: String
    public let stepUpDigest: Data
    fileprivate init(role: AccountLifecycleAuthorizationRole, subjectDID: String?, nonce: Data, expiresAt: Date, action: String, stepUpDigest: Data) {
        self.role = role; self.subjectDID = subjectDID; self.nonce = nonce; self.expiresAt = expiresAt; self.action = action; self.stepUpDigest = stepUpDigest
    }

    public func permits(did: String, action: String, now: Date) -> Bool {
        expiresAt > now && self.action == action && !nonce.isEmpty && !stepUpDigest.isEmpty && (role == .operatorRole || subjectDID == did)
    }
}

/// Only the authenticated session/step-up verifier may mint a lifecycle
/// capability. XRPC callers cannot construct one from a role string.
public protocol AccountLifecycleCapabilityVerifier: Sendable {
    func verify(role: AccountLifecycleAuthorizationRole, subjectDID: String?, sessionDigest: Data, stepUpReceipt: Data, now: Date) async throws -> AccountLifecycleCapability
    func consume(_ capability: AccountLifecycleCapability, action: String, now: Date) async throws
}

public struct SwanAccountLifecycleXRPCAdapter: Sendable {
    private let lifecycle: AccountLifecycleService
    private let provisioning: (any SwanCreateAccountProvisioning)?
    private let authorization: (any SwanCreateAccountAuthorizationPipeline)?
    private let capabilityVerifier: (any AccountLifecycleCapabilityVerifier)?
    public init(lifecycle: AccountLifecycleService, provisioning: (any SwanCreateAccountProvisioning)? = nil, authorization: (any SwanCreateAccountAuthorizationPipeline)? = nil, capabilityVerifier: (any AccountLifecycleCapabilityVerifier)? = nil) {
        self.lifecycle = lifecycle; self.provisioning = provisioning; self.authorization = authorization; self.capabilityVerifier = capabilityVerifier
    }

    public func createAccount(_ input: SwanCreateAccountXRPCInput, now: Date = Date()) async throws -> (account: AccountControlAccount, session: Data) {
        guard input.verificationPhone == nil else { throw SwanError.invalidIdentifier("verificationPhone unsupported") }
        guard input.email != nil, input.verificationCode != nil else { throw SwanError.invalidIdentifier("verified email required") }
        guard let authorization else { throw SwanError.unavailable("signup authorization unavailable") }
        try await authorization.authorize(input, now: now)
        guard let provisioning else { throw SwanError.unavailable("account provisioning unavailable") }
        return try await provisioning.createAccount(input, now: now)
    }

    public func capability(role: AccountLifecycleAuthorizationRole, subjectDID: String?, sessionDigest: Data, stepUpReceipt: Data, now: Date = Date()) async throws -> AccountLifecycleCapability {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        return try await capabilityVerifier.verify(role: role, subjectDID: subjectDID, sessionDigest: sessionDigest, stepUpReceipt: stepUpReceipt, now: now)
    }

    public func activate(did: String, capability: AccountLifecycleCapability, now: Date = Date()) async throws -> AccountControlAccount {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        guard capability.permits(did: did, action: "activate", now: now), capability.role == .operatorRole else { throw SwanError.unavailable("operator authorization required") }
        try await capabilityVerifier.consume(capability, action: "activate", now: now)
        return try await lifecycle.activate(did: did, now: now)
    }

    public func status(did: String, capability: AccountLifecycleCapability) async throws -> AccountControlAccount? {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        guard capability.permits(did: did, action: "status", now: Date()) else { throw SwanError.unavailable("account authorization required") }
        try await capabilityVerifier.consume(capability, action: "status", now: Date())
        return try await lifecycle.status(did: did)
    }

    public func deactivate(did: String, capability: AccountLifecycleCapability, now: Date = Date()) async throws -> AccountControlAccount {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        guard capability.permits(did: did, action: "deactivate", now: now) else { throw SwanError.unavailable("account authorization required") }
        try await capabilityVerifier.consume(capability, action: "deactivate", now: now)
        return try await lifecycle.deactivate(did: did, now: now)
    }

    public func delete(did: String, capability: AccountLifecycleCapability, now: Date = Date()) async throws -> AccountDeletionJob {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        guard capability.permits(did: did, action: "delete", now: now) else { throw SwanError.unavailable("account authorization required") }
        try await capabilityVerifier.consume(capability, action: "delete", now: now)
        return try await lifecycle.delete(did: did, now: now)
    }

    public func invite(code: String, capability: AccountLifecycleCapability, expiresAt: Date? = nil) async throws -> SignupInviteIssue {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        guard capability.permits(did: capability.subjectDID ?? "", action: "invite", now: Date()), capability.role == .operatorRole else { throw SwanError.unavailable("operator authorization required") }
        try await capabilityVerifier.consume(capability, action: "invite", now: Date())
        return try await lifecycle.issueInvite(code: code, expiresAt: expiresAt)
    }

    public func listInvites(capability: AccountLifecycleCapability, limit: Int = 100) async throws -> [SignupInvite] {
        guard let capabilityVerifier else { throw SwanError.unavailable("lifecycle authorization unavailable") }
        guard capability.role == .operatorRole, capability.permits(did: capability.subjectDID ?? "", action: "invite.list", now: Date()) else { throw SwanError.unavailable("operator authorization required") }
        try await capabilityVerifier.consume(capability, action: "invite.list", now: Date())
        return try await lifecycle.listInvites(limit: limit)
    }
}
