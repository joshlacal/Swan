import Foundation
import Petrel
import SwanAccounts

/// Pure XRPC boundary for the pinned `com.atproto.server` lexicons. Router
/// registration is intentionally left to the integration owner; this adapter
/// is independently testable and never accepts management cookies.
public struct SwanLegacyAuthXRPCAdapter: Sendable {
    private let service: LegacyAuthService

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
        return try ComAtprotoServerGetSession.Output(handle: Handle(handleString: tokens.handle), did: DID(didString: tokens.did))
    }

    public func deleteSession(accessToken: String, now: Date = Date()) async throws {
        try await service.deleteSession(accessToken, now: now)
    }

    public func getServiceAuth(accessToken: String, parameters: ComAtprotoServerGetServiceAuth.Parameters, now: Date = Date()) async throws -> ComAtprotoServerGetServiceAuth.Output {
        let result = try await service.getServiceAuth(accessToken: accessToken, lxm: parameters.lxm.map(\.description), aud: parameters.aud, now: now)
        return ComAtprotoServerGetServiceAuth.Output(token: result.token)
    }

    public func createAppPassword(accountDID: String, name: String, scopes: Set<String>, now: Date = Date()) async throws -> ComAtprotoServerCreateAppPassword.AppPassword {
        let result = try await service.createAppPassword(accountDID: accountDID, name: name, scopes: scopes, now: now)
        return ComAtprotoServerCreateAppPassword.AppPassword(name: result.name, password: result.secret, createdAt: ATProtocolDate(date: now), privileged: nil)
    }

    public func listAppPasswords(accountDID: String, now: Date = Date()) async throws -> ComAtprotoServerListAppPasswords.Output {
        let values = try await service.listAppPasswords(accountDID: accountDID, now: now)
        return ComAtprotoServerListAppPasswords.Output(passwords: values.map { .init(name: $0.name, createdAt: ATProtocolDate(date: $0.createdAt), privileged: nil) })
    }

    public func revokeAppPassword(accountDID: String, input: ComAtprotoServerRevokeAppPassword.Input, now: Date = Date()) async throws {
        try await service.revokeAppPassword(accountDID: accountDID, name: input.name, now: now)
    }

    private func createSessionOutput(_ tokens: LegacySessionTokens) throws -> ComAtprotoServerCreateSession.Output {
        try ComAtprotoServerCreateSession.Output(
            accessJwt: tokens.accessToken,
            refreshJwt: tokens.refreshToken,
            handle: Handle(handleString: tokens.handle),
            did: DID(didString: tokens.did),
            didDoc: nil, email: nil, emailConfirmed: nil, emailAuthFactor: nil,
            active: true, status: nil
        )
    }

    private func refreshSessionOutput(_ tokens: LegacySessionTokens) throws -> ComAtprotoServerRefreshSession.Output {
        try ComAtprotoServerRefreshSession.Output(
            accessJwt: tokens.accessToken,
            refreshJwt: tokens.refreshToken,
            handle: Handle(handleString: tokens.handle),
            did: DID(didString: tokens.did),
            didDoc: nil, email: nil, emailConfirmed: nil, emailAuthFactor: nil,
            active: true, status: nil
        )
    }
}
