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

public enum AccountLifecycleAuthorizationRole: String, Sendable, Equatable {
    case operatorRole
    case managementSession
}

public struct AccountLifecycleAuthorizationContext: Sendable, Equatable {
    public let role: AccountLifecycleAuthorizationRole
    public let subjectDID: String?
    public init(role: AccountLifecycleAuthorizationRole, subjectDID: String? = nil) {
        self.role = role
        self.subjectDID = subjectDID
    }

    public func permits(did: String) -> Bool {
        role == .operatorRole || subjectDID == did
    }
}

public struct SwanAccountLifecycleXRPCAdapter: Sendable {
    private let lifecycle: AccountLifecycleService
    private let provisioning: (any SwanCreateAccountProvisioning)?
    public init(lifecycle: AccountLifecycleService, provisioning: (any SwanCreateAccountProvisioning)? = nil) {
        self.lifecycle = lifecycle; self.provisioning = provisioning
    }

    public func createAccount(_ input: SwanCreateAccountXRPCInput, now: Date = Date()) async throws -> (account: AccountControlAccount, session: Data) {
        guard input.verificationPhone == nil else { throw SwanError.invalidIdentifier("verificationPhone unsupported") }
        guard let provisioning else { throw SwanError.unavailable("account provisioning unavailable") }
        return try await provisioning.createAccount(input, now: now)
    }

    public func activate(did: String, context: AccountLifecycleAuthorizationContext, now: Date = Date()) async throws -> AccountControlAccount {
        guard context.role == .operatorRole else { throw SwanError.unavailable("operator authorization required") }
        return try await lifecycle.activate(did: did, now: now)
    }

    public func status(did: String, context: AccountLifecycleAuthorizationContext) async throws -> AccountControlAccount? {
        guard context.permits(did: did) else { throw SwanError.unavailable("account authorization required") }
        return try await lifecycle.status(did: did)
    }

    public func deactivate(did: String, context: AccountLifecycleAuthorizationContext, now: Date = Date()) async throws -> AccountControlAccount {
        guard context.permits(did: did) else { throw SwanError.unavailable("account authorization required") }
        return try await lifecycle.deactivate(did: did, now: now)
    }

    public func delete(did: String, context: AccountLifecycleAuthorizationContext, now: Date = Date()) async throws -> AccountDeletionJob {
        guard context.permits(did: did) else { throw SwanError.unavailable("account authorization required") }
        return try await lifecycle.delete(did: did, now: now)
    }

    public func invite(code: String, context: AccountLifecycleAuthorizationContext, expiresAt: Date? = nil) throws -> SignupInviteIssue {
        guard context.role == .operatorRole else { throw SwanError.unavailable("operator authorization required") }
        return try lifecycle.invite(code: code, expiresAt: expiresAt)
    }
}
