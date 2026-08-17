import Foundation
import HTTPTypes
import Petrel
import SwanAccounts
import SwanCore
import SwanSpaces

/// Pure XRPC boundary for the pinned `com.atproto.server` lexicons. Router
/// registration is intentionally left to the integration owner; this adapter
/// is independently testable and never accepts management cookies.
public struct SwanLegacyAuthXRPCAdapter: Sendable {
    private let service: LegacyAuthService

    /// The exact generated legacy-auth methods owned by this adapter. Keeping
    /// this set explicit prevents a future registry entry from becoming live
    /// merely because it shares the `com.atproto.server` namespace.
    public static let methodNSIDs: Set<String> = [
        ComAtprotoServerCreateSession.typeIdentifier,
        ComAtprotoServerRefreshSession.typeIdentifier,
        ComAtprotoServerGetSession.typeIdentifier,
        ComAtprotoServerDeleteSession.typeIdentifier,
        ComAtprotoServerGetServiceAuth.typeIdentifier,
        ComAtprotoServerCreateAppPassword.typeIdentifier,
        ComAtprotoServerListAppPasswords.typeIdentifier,
        ComAtprotoServerRevokeAppPassword.typeIdentifier,
    ]
    public init(service: LegacyAuthService) {
        self.service = service
    }

    public func createSession(_ input: ComAtprotoServerCreateSession.Input, now: Date = Date()) async throws -> ComAtprotoServerCreateSession.Output {
        let tokens = try await service.createSession(identifier: input.identifier, password: input.password, authFactorToken: input.authFactorToken, now: now)
        return try createSessionOutput(tokens)
    }

    public func refreshSession(refreshToken: String, now: Date = Date()) async throws -> ComAtprotoServerRefreshSession.Output {
        try refreshSessionOutput(try await service.refreshSession(refreshToken, now: now))
    }

    public func getSession(accessToken: String, now: Date = Date()) async throws -> ComAtprotoServerGetSession.Output {
        let tokens = try await service.getSession(accessToken, now: now)
        return try ComAtprotoServerGetSession.Output(handle: Handle(handleString: tokens.handle), did: DID(didString: tokens.did), email: tokens.email, emailConfirmed: tokens.emailConfirmed, emailAuthFactor: tokens.emailAuthFactor, active: tokens.active, status: tokens.status)
    }

    public func deleteSession(accessToken: String, now: Date = Date()) async throws {
        try await service.deleteSession(accessToken, now: now)
    }

    public func getServiceAuth(accessToken: String, parameters: ComAtprotoServerGetServiceAuth.Parameters, now: Date = Date()) async throws -> ComAtprotoServerGetServiceAuth.Output {
        let result = try await service.getServiceAuth(accessToken: accessToken, lxm: parameters.lxm.map(\.description), aud: parameters.aud, requestedExpiry: parameters.exp.map { Date(timeIntervalSince1970: TimeInterval($0)) }, now: now)
        return ComAtprotoServerGetServiceAuth.Output(token: result.token)
    }

    public func createAppPassword(context: LegacyXRPCAuthorizationContext, name: String, scopes: Set<String>, now: Date = Date()) async throws -> ComAtprotoServerCreateAppPassword.AppPassword {
        guard let stepUp = context.freshStepUpReceipt else { throw SwanError.unauthorized("management step-up required") }
        let result = try await service.createAppPassword(accountDID: context.accountDID, name: name, scopes: scopes, managementSessionToken: context.opaqueAuthorization, stepUpToken: stepUp, now: now)
        return ComAtprotoServerCreateAppPassword.AppPassword(name: result.name, password: result.secret, createdAt: ATProtocolDate(date: now), privileged: nil)
    }

    public func listAppPasswords(context: LegacyXRPCAuthorizationContext, now: Date = Date()) async throws -> ComAtprotoServerListAppPasswords.Output {
        let values = try await service.listAppPasswords(accountDID: context.accountDID, managementSessionToken: context.opaqueAuthorization, now: now)
        return ComAtprotoServerListAppPasswords.Output(passwords: values.map { .init(name: $0.name, createdAt: ATProtocolDate(date: $0.createdAt), privileged: nil) })
    }

    public func revokeAppPassword(context: LegacyXRPCAuthorizationContext, input: ComAtprotoServerRevokeAppPassword.Input, now: Date = Date()) async throws {
        guard let stepUp = context.freshStepUpReceipt else { throw SwanError.unauthorized("management step-up required") }
        try await service.revokeAppPassword(accountDID: context.accountDID, name: input.name, managementSessionToken: context.opaqueAuthorization, stepUpToken: stepUp, now: now)
    }

    private func createSessionOutput(_ tokens: LegacyCompatibilitySessionTokens) throws -> ComAtprotoServerCreateSession.Output {
        try ComAtprotoServerCreateSession.Output(
            accessJwt: tokens.accessToken,
            refreshJwt: tokens.refreshToken,
            handle: Handle(handleString: tokens.handle),
            did: DID(didString: tokens.did),
            didDoc: nil, email: tokens.email, emailConfirmed: tokens.emailConfirmed, emailAuthFactor: tokens.emailAuthFactor,
            active: tokens.active, status: tokens.status
        )
    }

    private func refreshSessionOutput(_ tokens: LegacyCompatibilitySessionTokens) throws -> ComAtprotoServerRefreshSession.Output {
        try ComAtprotoServerRefreshSession.Output(
            accessJwt: tokens.accessToken,
            refreshJwt: tokens.refreshToken,
            handle: Handle(handleString: tokens.handle),
            did: DID(didString: tokens.did),
            didDoc: nil, email: tokens.email, emailConfirmed: tokens.emailConfirmed, emailAuthFactor: tokens.emailAuthFactor,
            active: tokens.active, status: tokens.status
        )
    }
}

/// Authenticates legacy access tokens without entering the OAuth DPoP path.
/// A successful lookup returns the distinct typed legacy grant, including its
/// durable session identity and effective scopes; it never collapses into
/// `accountOAuth` or a boolean authenticated flag.
public struct SwanLegacyBearerAuthorizer: Sendable {
    private let service: LegacyAuthService

    public init(service: LegacyAuthService) {
        self.service = service
    }

    public func authorize(accessToken: String, now: Date = Date()) async throws -> AuthorizationContext {
        guard Self.validToken(accessToken) else {
            throw SwanError.unauthorized("invalid legacy bearer")
        }
        let session = try await service.getSession(accessToken, now: now)
        return .accountLegacySession(
            subject: session.did,
            permissions: SwanScopePermissions(
                rawScopes: session.scopes,
                subject: session.did
            )
        )
    }

    /// Extracts only the RFC 9110 `Bearer` credential form. DPoP proofs and
    /// management cookies are intentionally not accepted by this boundary.
    public static func accessToken(from headers: HTTPFields) throws -> String {
        let values = headers[values: .authorization]
        guard values.count == 1, values[0].hasPrefix("Bearer ") else {
            throw SwanError.unauthorized("legacy bearer required")
        }
        let token = String(values[0].dropFirst("Bearer ".count))
        guard validToken(token) else {
            throw SwanError.unauthorized("invalid legacy bearer")
        }
        return token
    }

    private static func validToken(_ token: String) -> Bool {
        guard !token.isEmpty, token.utf8.count <= 8 * 1024 else { return false }
        return token.utf8.allSatisfy { byte in
            switch byte {
            case 0x21, 0x23 ... 0x27, 0x2A ... 0x2B, 0x2D ... 0x39,
                 0x3C ... 0x5B, 0x5D ... 0x7E:
                true
            default:
                false
            }
        }
    }
}

/// Created only by the authenticated XRPC layer; it is deliberately opaque
/// and is not a browser cookie or a caller-supplied account identifier.
public struct LegacyXRPCAuthorizationContext: Sendable {
    public let accountDID: String
    public let opaqueAuthorization: String
    public let freshStepUpReceipt: String?
    internal init(accountDID: String, opaqueAuthorization: String, freshStepUpReceipt: String? = nil) {
        self.accountDID = accountDID; self.opaqueAuthorization = opaqueAuthorization; self.freshStepUpReceipt = freshStepUpReceipt
    }
}
