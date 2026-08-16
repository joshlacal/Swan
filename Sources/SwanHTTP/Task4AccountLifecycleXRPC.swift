import Foundation
import SwanAccounts
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
    fileprivate init(role: AccountLifecycleAuthorizationRole, subjectDID: String?) {
        self.role = role
        self.subjectDID = subjectDID
    }

    public func permits(did: String) -> Bool {
        role == .operatorRole || subjectDID == did
    }
}

/// Only the authenticated session/step-up verifier may mint a lifecycle
/// capability. XRPC callers cannot construct one from a role string.
public protocol AccountLifecycleCapabilityVerifier: Sendable {
    func verify(role: AccountLifecycleAuthorizationRole, subjectDID: String?, sessionDigest: Data, stepUpReceipt: Data, now: Date) async throws -> AccountLifecycleCapability
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

    public func activate(did: String, capability: AccountLifecycleCapability, now: Date = Date()) async throws -> AccountControlAccount {
        guard capability.role == .operatorRole else { throw SwanError.unavailable("operator authorization required") }
        return try await lifecycle.activate(did: did, now: now)
    }

    public func status(did: String, capability: AccountLifecycleCapability) async throws -> AccountControlAccount? {
        guard capability.permits(did: did) else { throw SwanError.unavailable("account authorization required") }
        return try await lifecycle.status(did: did)
    }

    public func deactivate(did: String, capability: AccountLifecycleCapability, now: Date = Date()) async throws -> AccountControlAccount {
        guard capability.permits(did: did) else { throw SwanError.unavailable("account authorization required") }
        return try await lifecycle.deactivate(did: did, now: now)
    }

    public func delete(did: String, capability: AccountLifecycleCapability, now: Date = Date()) async throws -> AccountDeletionJob {
        guard capability.permits(did: did) else { throw SwanError.unavailable("account authorization required") }
        return try await lifecycle.delete(did: did, now: now)
    }

    public func invite(code: String, capability: AccountLifecycleCapability, expiresAt: Date? = nil) throws -> SignupInviteIssue {
        guard capability.role == .operatorRole else { throw SwanError.unavailable("operator authorization required") }
        return try lifecycle.invite(code: code, expiresAt: expiresAt)
    }
}
