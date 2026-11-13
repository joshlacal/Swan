import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
import SwanStorage

/// The outbound `com.atproto.managedspace.checkAccess` client used by a
/// managedspace authority.
///
/// The request carries service auth signed by the space authority with
/// `lxm=com.atproto.managedspace.checkAccess` and `aud` set to the policy's
/// `did#serviceId`. A missing repository means the credential request carried
/// no delegation token. `clientId` is included only for an attested client.
///
/// Resolution, transport, timeout, status, and response-shape failures are
/// upstream failures rather than access denials. No answer is cached.
public struct RemoteManagedSpaceAccessChecker: ManagedSpaceAccessChecking {
    public static let method = "com.atproto.managedspace.checkAccess"
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

    public func checkAccess(
        space: SpaceURI,
        repo: String?,
        clientID: String?,
        managingApp: String
    ) async throws -> ManagedSpaceAccess {
        do {
            return try await ask(
                space: space, repo: repo, clientID: clientID,
                managingApp: managingApp
            )
        } catch {
            logger.warning("managing app check failed", fields: [
                "space": space.rawValue,
            ])
            throw ManagedSpaceAccessError.upstreamFailure
        }
    }

    private func ask(
        space: SpaceURI,
        repo: String?,
        clientID: String?,
        managingApp: String
    ) async throws -> ManagedSpaceAccess {
        let parts = managingApp.split(
            separator: "#", maxSplits: 1, omittingEmptySubsequences: false
        )
        guard parts.count == 2, !parts[1].isEmpty else {
            throw ManagedSpaceAccessError.upstreamFailure
        }
        let did = String(parts[0])
        let base = try await resolver.endpoint(did: did, fragment: String(parts[1]))
        let url = try Self.requestURL(
            base: base, space: space, repo: repo, clientID: clientID
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
        let timeout = min(policy.timeout, 10)
        let before = Set(try await resolveOAuthHostname(
            hostnameResolver, host: host, timeout: timeout
        ))
        try policy.validateResolved(Array(before), host: host)
        let response = try await transport.getAuthenticated(
            url: url,
            approvedPeers: before,
            headers: ["Authorization": "Bearer " + token, "Accept": "application/json"],
            timeout: timeout,
            maximumResponseBodyBytes: Self.maximumResponseBytes
        )
        guard (200 ... 299).contains(response.status), response.redirectCount == 0,
              response.body.count <= Self.maximumResponseBytes else {
            throw ManagedSpaceAccessError.upstreamFailure
        }
        return try Self.access(from: response.body)
    }

    /// `GET <endpoint>/xrpc/com.atproto.managedspace.checkAccess`.
    static func requestURL(
        base: URL,
        space: SpaceURI,
        repo: String?,
        clientID: String?
    ) throws -> URL {
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw SwanError.unavailable("managing app endpoint is invalid")
        }
        components.path = "/xrpc/" + method
        var query = [URLQueryItem(name: "space", value: space.rawValue)]
        if let repo {
            query.append(URLQueryItem(name: "repo", value: repo))
        }
        if let clientID {
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

    /// Boolean `read` and `write` members are required; unknown fields are ignored.
    static func access(from body: Data) throws -> ManagedSpaceAccess {
        guard (try? StrictJSON.validate(body)) != nil,
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let readValue = object["read"], SpacePolicy.isJSONBoolean(readValue),
              let writeValue = object["write"], SpacePolicy.isJSONBoolean(writeValue),
              let read = readValue as? Bool,
              let write = writeValue as? Bool else {
            throw ManagedSpaceAccessError.upstreamFailure
        }
        return ManagedSpaceAccess(read: read, write: write)
    }
}
