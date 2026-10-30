import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
import SwanStorage

/// The outbound `com.atproto.managedspace.checkUserAccess` client a
/// managedspace authority uses to ask its managing app about one user
/// (October 29 section 1d).
///
/// The request carries service auth signed by the space authority with
/// `lxm=com.atproto.managedspace.checkUserAccess` and `aud` set to
/// `managingApp` exactly as the policy names it, as the reference
/// `resolveNotifyTarget` does. The endpoint is the named service of the
/// managing app's DID document, or its `#atproto_pds` service for a bare
/// DID. `clientId` is sent on reads only.
///
/// Every failure denies: an unresolvable app, a transport error, a non-200
/// status, or a body that is not exactly `{ "authorized": true }`. Failing
/// open would hand out credentials for the spaces that asked for the
/// strictest gate. No answer is cached.
public struct RemoteManagedSpaceAccessChecker: ManagedSpaceAccessChecking {
    public static let method = "com.atproto.managedspace.checkUserAccess"
    static let maximumResponseBytes = 4_096

    private let resolver: SwanServiceEndpointResolver
    private let signer: any SpaceServiceAuthenticationIssuer
    private let policy: OAuthRemoteFetchPolicy
    private let hostnameResolver: any OAuthHostnameResolving
    private let transport: NIOPeerPinnedOAuthPostTransport
    private let logger = SwanLog(label: "swan.managed-space")

    public init(
        resolver: SwanServiceEndpointResolver,
        signer: any SpaceServiceAuthenticationIssuer,
        policy: OAuthRemoteFetchPolicy,
        transport: NIOPeerPinnedOAuthPostTransport,
        hostnameResolver: any OAuthHostnameResolving = SystemOAuthHostnameResolver()
    ) {
        self.resolver = resolver
        self.signer = signer
        self.policy = policy
        self.transport = transport
        self.hostnameResolver = hostnameResolver
    }

    public func checkUserAccess(
        space: SpaceURI,
        user: String,
        access: SimpleSpaceAccessKind,
        clientID: String?,
        managingApp: String
    ) async -> Bool {
        do {
            return try await ask(
                space: space, user: user, access: access,
                clientID: access == .read ? clientID : nil,
                managingApp: managingApp
            )
        } catch {
            logger.warning("managing app check failed", fields: [
                "space": space.rawValue,
                "access": access.rawValue,
            ])
            return false
        }
    }

    private func ask(
        space: SpaceURI,
        user: String,
        access: SimpleSpaceAccessKind,
        clientID: String?,
        managingApp: String
    ) async throws -> Bool {
        let parts = managingApp.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        let did = String(parts[0])
        let fragment = parts.count == 2 ? String(parts[1]) : "atproto_pds"
        let base = try await resolver.endpoint(did: did, fragment: fragment)
        let url = try Self.requestURL(
            base: base, space: space, user: user, access: access,
            clientID: access == .read ? clientID : nil
        )
        let token = try await signer.issue(
            issuer: space.authority,
            audience: managingApp,
            method: Self.method,
            eventID: UUID().uuidString.lowercased(),
            requestBodyDigest: nil,
            now: Date()
        )
        let host = try policy.validateURL(url)
        let before = Set(try await resolveOAuthHostname(hostnameResolver, host: host, timeout: policy.timeout))
        try policy.validateResolved(Array(before), host: host)
        let response = try await transport.getAuthenticated(
            url: url,
            approvedPeers: before,
            headers: ["Authorization": "Bearer " + token, "Accept": "application/json"],
            timeout: policy.timeout,
            maximumResponseBodyBytes: Self.maximumResponseBytes
        )
        guard response.status == 200, response.redirectCount == 0,
              response.body.count <= Self.maximumResponseBytes else {
            return false
        }
        return Self.isAuthorized(response.body)
    }

    /// `GET <endpoint>/xrpc/com.atproto.managedspace.checkUserAccess` with
    /// `space`, `user`, `access` and, on reads only, `clientId`.
    static func requestURL(
        base: URL,
        space: SpaceURI,
        user: String,
        access: SimpleSpaceAccessKind,
        clientID: String?
    ) throws -> URL {
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw SwanError.unavailable("managing app endpoint is invalid")
        }
        components.path = "/xrpc/" + method
        var query = [
            URLQueryItem(name: "space", value: space.rawValue),
            URLQueryItem(name: "user", value: user),
            URLQueryItem(name: "access", value: access.rawValue),
        ]
        if access == .read, let clientID {
            query.append(URLQueryItem(name: "clientId", value: clientID))
        }
        components.queryItems = query
        // `+` is literal in a query value but a space to form decoders.
        components.percentEncodedQuery = components.percentEncodedQuery?
            .replacingOccurrences(of: "+", with: "%2B")
        guard let url = components.url else {
            throw SwanError.unavailable("managing app URL is unavailable")
        }
        return url
    }

    /// Only a JSON object whose `authorized` member is the boolean `true`.
    static func isAuthorized(_ body: Data) -> Bool {
        guard (try? StrictJSON.validate(body)) != nil,
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let value = object["authorized"],
              SpacePolicy.isJSONBoolean(value),
              let authorized = value as? Bool else {
            return false
        }
        return authorized
    }
}
