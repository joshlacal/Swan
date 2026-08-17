import Foundation
import SwanAccounts
import SwanCore

/// Production ``SwanAccountPortalIdentityProjection`` backed by the durable
/// did:web identity surface.
///
/// The portal facade reads the account's identity binding and forwards
/// identity mutations to the did:web HTTP adapter with the authenticated
/// management-session value (the portal context's `sessionID` is the
/// re-bound session value). Absent a binding the read returns `nil`; a
/// mutation without a binding fails closed through the adapter's stable
/// error vocabulary.
public struct SwanAccountPortalIdentityProjectionProduction:
    SwanAccountPortalIdentityProjection, Sendable
{
    private let didWeb: SwanDidWebIdentityHTTP

    public init(didWeb: SwanDidWebIdentityHTTP) {
        self.didWeb = didWeb
    }

    public func identity(
        accountDID: String,
        now: Date = Date()
    ) async throws -> SwanAccountPortalSnapshot.Identity? {
        guard let binding = try await didWeb.bindings.identityBinding(
            accountDID: accountDID
        ) else {
            return nil
        }
        return SwanAccountPortalSnapshot.Identity(
            method: binding.method.rawValue,
            handle: binding.handle,
            state: binding.state.rawValue
        )
    }

    public func mutateIdentity(
        path: String,
        accountDID: String,
        sessionID: String,
        strength: AuthenticationStrength,
        stepUpToken: String?,
        payload: Data?,
        now: Date = Date()
    ) async throws {
        switch path {
        case "identity":
            // Claim a reserved did:web binding. The payload is the
            // `SwanDidWebClaimRequest` wire shape.
            let request = try Self.decode(SwanDidWebClaimRequest.self, payload)
            _ = try await didWeb.claim(request, sessionValue: sessionID, now: now)
        case "identity/rotate":
            let request = try Self.decode(SwanDidWebRotateRequest.self, payload)
            _ = try await didWeb.rotate(request, sessionValue: sessionID, now: now)
        case "identity/remove":
            let request = try Self.decode(SwanDidWebRemoveRequest.self, payload)
            _ = try await didWeb.remove(request, sessionValue: sessionID, now: now)
        case "identity/reverify":
            _ = try await didWeb.reverify(sessionValue: sessionID, now: now)
        default:
            throw SwanAccountPortalServiceError.unsupported
        }
    }

    private static func decode<Value: Decodable>(
        _ type: Value.Type,
        _ payload: Data?
    ) throws -> Value {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do {
            return try JSONDecoder().decode(type, from: payload)
        } catch {
            throw SwanAccountPortalServiceError.invalidRequest
        }
    }
}
