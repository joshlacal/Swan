import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
import SwanStorage

public protocol ConversationSpaceMembershipChecking: Sendable {
    func requireMembership(space: SpaceURI, user: String, now: Date) async throws
}

public protocol ConversationSpaceDeleting: Sendable {
    func deleteGeneration(space: SpaceURI, now: Date) async throws
}

/// An internal, operator-configured policy lookup. The DS service owns the
/// committed conversation generation and membership. No affirmative result
/// is cached: every credential issuance observes that service again.
public struct RemoteConversationSpaceMembershipChecker: ConversationSpaceMembershipChecking, ConversationSpaceDeleting {
    public static let method = "blue.catbird.labyrinth.getSpaceMembership"
    public static let deletionMethod = "blue.catbird.labyrinth.deleteSpaceGeneration"
    private let origin: URL
    private let audience: String
    private let signer: any SpaceServiceAuthenticationIssuer
    private let policy: OAuthRemoteFetchPolicy
    private let resolver: any OAuthHostnameResolving
    private let transport: NIOPeerPinnedOAuthPostTransport

    public init(origin: URL, audience: String, signer: any SpaceServiceAuthenticationIssuer,
                policy: OAuthRemoteFetchPolicy, transport: NIOPeerPinnedOAuthPostTransport,
                resolver: any OAuthHostnameResolving = SystemOAuthHostnameResolver()) throws {
        guard let components = URLComponents(url: origin, resolvingAgainstBaseURL: false),
              components.path.isEmpty || components.path == "/", components.query == nil,
              components.fragment == nil, !audience.isEmpty else { throw SwanError.malformed("invalid conversation policy origin") }
        _ = try policy.validateURL(origin)
        self.origin = origin; self.audience = audience; self.signer = signer
        self.policy = policy; self.resolver = resolver; self.transport = transport
    }

    public func requireMembership(space: SpaceURI, user: String, now: Date = Date()) async throws {
        let response = try await request(space: space, method: Self.method, query: [
            URLQueryItem(name: "space", value: space.rawValue), URLQueryItem(name: "user", value: user)
        ], now: now)
        if response.status == 410 { throw AuthorizedSimpleSpaceLifecycleError.deleted }
        if response.status == 403 || response.status == 404 { throw SwanError.unauthorized("conversation membership required") }
        guard response.status == 200 else { throw SwanError.unavailable("conversation policy service unavailable") }
        struct Membership: Decodable {
            let space: String
            let generation: String
            let user: String
            let chatGeneration: Int64
            let chatSeq: Int64
        }
        let result: Membership
        do { result = try StrictJSON.decode(Membership.self, from: response.body) }
        catch { throw SwanError.unavailable("conversation policy response invalid") }
        guard result.space == space.rawValue, result.generation == space.skey, result.user == user,
              result.chatGeneration >= 0, result.chatSeq >= 0 else {
            throw SwanError.unauthorized("conversation policy response binding mismatch")
        }
    }

    public func deleteGeneration(space: SpaceURI, now: Date = Date()) async throws {
        struct Request: Encodable { let space: String; let generation: String }
        let body = try JSONEncoder().encode(Request(space: space.rawValue, generation: space.skey))
        let response = try await request(space: space, method: Self.deletionMethod, body: body, now: now)
        guard !(400...499).contains(response.status) else {
            throw SwanError.unauthorized("conversation generation deletion denied")
        }
        guard response.status == 200 else {
            throw SwanError.unavailable("conversation deletion service unavailable")
        }
        struct Deleted: Decodable { let space: String; let generation: String; let deleted: Bool }
        let result: Deleted
        do {
            try StrictJSON.validate(response.body)
            guard let object = try JSONSerialization.jsonObject(with: response.body) as? [String: Any],
                  Set(object.keys) == ["space", "generation", "deleted"] else {
                throw SwanError.malformed("unexpected deletion response fields")
            }
            result = try JSONDecoder().decode(Deleted.self, from: response.body)
        } catch { throw SwanError.unavailable("conversation deletion response invalid") }
        guard result.space == space.rawValue, result.generation == space.skey, result.deleted else {
            throw SwanError.unauthorized("conversation deletion response binding mismatch")
        }
    }

    /// Both operations use the same operator-selected peer, bounded response,
    /// DNS checks and hostname-verified TLS. Retry decisions belong to the caller.
    private func request(
        space: SpaceURI, method: String, query: [URLQueryItem]? = nil,
        body: Data? = nil, now: Date
    ) async throws -> OAuthRemoteHTTPResponse {
        guard space.spaceType == "blue.catbird.labyrinth.conversation", UUID(uuidString: space.skey) != nil else {
            throw SwanError.unauthorized("conversation storage generation is invalid")
        }
        var components = URLComponents(url: origin, resolvingAgainstBaseURL: false)!
        components.path = "/xrpc/" + method
        components.queryItems = query
        guard let url = components.url else { throw SwanError.unavailable("conversation policy URL unavailable") }
        let token = try await signer.issue(issuer: space.authority, audience: audience, method: method,
            eventID: UUID().uuidString.lowercased(), requestBodyDigest: nil, now: now)
        let host = try policy.validateURL(url)
        let before = Set(try await resolveOAuthHostname(resolver, host: host, timeout: policy.timeout))
        try policy.validateResolved(Array(before), host: host)
        var headers = ["Authorization": "Bearer " + token, "Accept": "application/json"]
        let response: OAuthRemoteHTTPResponse
        if let body {
            headers["Content-Type"] = "application/json"
            response = try await transport.post(url: url, approvedPeers: before, headers: headers,
                body: body, timeout: policy.timeout, maximumResponseBodyBytes: 8192)
        } else {
            response = try await transport.getAuthenticated(url: url, approvedPeers: before, headers: headers,
                timeout: policy.timeout, maximumResponseBodyBytes: 8192)
        }
        let after = Set(try await resolveOAuthHostname(resolver, host: host, timeout: policy.timeout))
        try policy.validateResolved(Array(after), host: host)
        guard response.redirectCount == 0, response.responseURL == url,
              let peer = response.connectedPeerAddress, before.contains(peer), after.contains(peer),
              response.body.count <= 8192 else { throw SwanError.unavailable("conversation policy response unavailable") }
        return response
    }

}

/// Selects the trusted conversation policy only for the configured local
/// authority and exact conversation space type. Other authority policies
/// continue using their persisted simple-space state.
public struct ConversationSpaceCredentialDirectory: AuthorizedSimpleSpaceCredentialDirectory {
    private let local: any AuthorizedSimpleSpaceCredentialDirectory
    private let accounts: any AuthorizedPreopenedAccountDirectory
    private let authority: String
    private let membership: any ConversationSpaceMembershipChecking
    private let lifecycle: any ConversationSpaceAuthorityLifecycle

    public init(local: any AuthorizedSimpleSpaceCredentialDirectory,
                accounts: any AuthorizedPreopenedAccountDirectory, authority: String,
                membership: any ConversationSpaceMembershipChecking,
                lifecycle: any ConversationSpaceAuthorityLifecycle) {
        self.local = local; self.accounts = accounts; self.authority = authority; self.membership = membership
        self.lifecycle = lifecycle
    }

    public func authorizeSimpleSpaceCredentialRead(space: SpaceURI, user: String?, clientID: String?,
                                                   authorization: AuthorizationContext) async throws {
        guard space.spaceType == "blue.catbird.labyrinth.conversation" else {
            return try await local.authorizeSimpleSpaceCredentialRead(space: space, user: user,
                clientID: clientID, authorization: authorization)
        }
        guard space.authority == authority else {
            throw SwanError.unauthorized("verified conversation delegation required")
        }
        // Oct 22 §1 and §6: the local deletion record answers SpaceDeleted
        // before any policy check, with or without a delegation token. A
        // generation this authority has not registered yet is not deleted.
        do {
            try await lifecycle.requireConversationSpaceActive(space: space)
        } catch AuthorizedSimpleSpaceLifecycleError.notFound {}
        // A conversation space is never public: without a delegation it is
        // hidden as SpaceNotFound, like any non-public space.
        guard let user else { throw AuthorizedSimpleSpaceLifecycleError.notFound }
        guard case let .spaceDelegation(subject, delegatedSpace) = authorization,
              subject == user, delegatedSpace == space else {
            throw SwanError.unauthorized("verified conversation delegation required")
        }
        try await accounts.requireActivePreopenedAccount(authority)
        try await membership.requireMembership(space: space, user: user, now: Date())
        try await lifecycle.registerKnownConversationSpace(space: space, now: Date())
        try await accounts.requireActivePreopenedAccount(authority)
        try await lifecycle.requireConversationSpaceActive(space: space)
    }
}
