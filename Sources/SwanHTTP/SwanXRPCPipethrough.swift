import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// Bounds for the `/xrpc/**` proxy fallback.
///
/// `maximumRequestBodyBytes` is stated explicitly rather than inherited from
/// the transport's own default: the proxy is the boundary that decides how
/// much of a client's body it is willing to buffer, and an implicit value here
/// would silently follow a transport change.
public struct SwanXRPCPipethroughLimits: Sendable, Equatable {
    public static let `default` = SwanXRPCPipethroughLimits()

    public let maximumRequestBodyBytes: Int
    public let maximumResponseBodyBytes: Int
    public let timeout: TimeInterval
    /// Simultaneous in-flight proxied requests. The peer-pinned transport has
    /// no admission budget of its own and can hold a request for its full
    /// timeout, so without this an authenticated client could pin every
    /// connection slot and every event-loop-bound outbound socket.
    public let maximumConcurrentRequests: Int

    public init(
        maximumRequestBodyBytes: Int = 1_048_576,
        maximumResponseBodyBytes: Int = 5 * 1_048_576,
        timeout: TimeInterval = 10,
        maximumConcurrentRequests: Int = 32
    ) {
        precondition((1 ... 8 * 1_048_576).contains(maximumRequestBodyBytes))
        precondition((1 ... 16 * 1_048_576).contains(maximumResponseBodyBytes))
        precondition(timeout > 0 && timeout <= 15)
        precondition(maximumConcurrentRequests > 0)
        self.maximumRequestBodyBytes = maximumRequestBodyBytes
        self.maximumResponseBodyBytes = maximumResponseBodyBytes
        self.timeout = timeout
        self.maximumConcurrentRequests = maximumConcurrentRequests
    }
}

/// Narrow OAuth boundary for the proxy fallback, mirroring
/// ``SwanActorPreferencesResourceAuthorizing``: tests can substitute an
/// authorizer without constructing bearer tokens or DPoP proofs, and
/// production delegates to the same sender-constrained resource authorizer
/// every other protected route uses.
public protocol SwanXRPCPipethroughResourceAuthorizing: Sendable {
    func authorizePipethrough(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext

    func issuePipethroughNonce(now: Date) async -> String
}

extension SwanOAuthResourceAuthorizer: SwanXRPCPipethroughResourceAuthorizing {
    public func authorizePipethrough(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext {
        try await authorize(
            request: request,
            method: method,
            fixedPath: fixedPath,
            now: now
        )
    }

    public func issuePipethroughNonce(now: Date) async -> String {
        issueNonce(now: now)
    }
}

/// The configured AppView. Its endpoint is known from configuration, so the
/// common path needs no DID document resolution at all.
public struct SwanAppViewConfiguration: Sendable, Equatable {
    public let did: String
    public let url: URL
    /// The `#fragment` a client names in `atproto-proxy` for this service. It
    /// is retained for operator visibility and for the CLI's own validation;
    /// the configured AppView is matched by DID, not by fragment.
    public let serviceFragment: String

    public init(
        did: String = "did:web:api.bsky.app",
        url: URL = URL(string: "https://api.bsky.app")!,
        serviceFragment: String = "bsky_appview"
    ) throws {
        guard did.hasPrefix("did:"), did.utf8.count <= 2_048, !did.contains("#"),
              did.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
              !serviceFragment.isEmpty, serviceFragment.utf8.count <= 512,
              serviceFragment.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              scheme == "https" || (scheme == "http" && host == "localhost") else {
            throw SwanError.malformed("AppView proxy configuration is invalid")
        }
        self.did = did
        self.url = url
        self.serviceFragment = serviceFragment
    }
}

/// The bundled dependency capability for the `/xrpc/**` proxy fallback, in the
/// same shape as ``SwanActorPreferencesXRPCServer``: `SwanHTTPServer` holds one
/// optional instance and registers it conditionally during `buildRouter()`. A
/// `nil` capability means Swan proxies nothing, exactly as before this route
/// existed.
public struct SwanXRPCPipethroughServer: Sendable {
    let authorizer: any SwanXRPCPipethroughResourceAuthorizing
    let tokens: any SwanProxyServiceTokenIssuing
    let sender: any SwanProxySending
    let resolver: SwanServiceEndpointResolver
    let appView: SwanAppViewConfiguration
    let limits: SwanXRPCPipethroughLimits
    let admission: SwanXRPCPipethroughAdmission

    public init(
        authorizer: any SwanXRPCPipethroughResourceAuthorizing,
        tokens: any SwanProxyServiceTokenIssuing,
        sender: any SwanProxySending,
        resolver: SwanServiceEndpointResolver,
        appView: SwanAppViewConfiguration,
        limits: SwanXRPCPipethroughLimits = .default
    ) {
        self.authorizer = authorizer
        self.tokens = tokens
        self.sender = sender
        self.resolver = resolver
        self.appView = appView
        self.limits = limits
        admission = SwanXRPCPipethroughAdmission(limit: limits.maximumConcurrentRequests)
    }

    /// Installs the fallback using the process-wide production body admission
    /// policy. Exposed for focused standalone testing of this capability in
    /// isolation from `SwanHTTPServer`.
    public func register(on router: Router<SwanHTTPRequestContext>) {
        register(
            on: router,
            requestBodyAdmission: .init(admission: .processShared, policy: .productionDefault)
        )
    }

    /// Installs the fallback using the caller's shared body admission policy.
    /// `SwanHTTPServer.buildRouter()` calls this so every route in the process
    /// shares the same admission instance.
    func register(
        on router: Router<SwanHTTPRequestContext>,
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    ) {
        registerSwanXRPCPipethrough(
            on: router,
            capability: self,
            requestBodyAdmission: requestBodyAdmission
        )
    }
}

/// Simultaneous-request budget for the proxy fallback. Mirrors
/// `OAuthRemoteFetchAdmission`: a plain counting gate with a lease that
/// releases exactly once, whether by `release()` or by deinit on an early
/// throw.
public final class SwanXRPCPipethroughAdmission: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var active = 0

    init(limit: Int) {
        precondition(limit > 0)
        self.limit = limit
    }

    func acquire() -> SwanXRPCPipethroughLease? {
        lock.lock()
        guard active < limit else {
            lock.unlock()
            return nil
        }
        active += 1
        lock.unlock()
        return SwanXRPCPipethroughLease(admission: self)
    }

    fileprivate func release() {
        lock.lock()
        precondition(active > 0)
        active -= 1
        lock.unlock()
    }
}

final class SwanXRPCPipethroughLease: @unchecked Sendable {
    private let lock = NSLock()
    private var admission: SwanXRPCPipethroughAdmission?

    fileprivate init(admission: SwanXRPCPipethroughAdmission) {
        self.admission = admission
    }

    func release() {
        lock.lock()
        let held = admission
        admission = nil
        lock.unlock()
        held?.release()
    }

    deinit { release() }
}

enum SwanXRPCPipethroughFailure: Error {
    /// Not a proxyable request target, a Swan-owned namespace, or a namespace
    /// with no route. All three are the same 404: a client must not be able to
    /// use this route to enumerate which namespaces Swan reserves.
    case notFound
    /// A malformed `atproto-proxy`, an unusable service endpoint, or an
    /// unforwardable header/target. Deliberately never a fallback to the
    /// configured AppView.
    case invalidRequest
    case payloadTooLarge
    case unauthorized
    case nonce
    /// The proxy's own capacity, not the upstream's.
    case busy
    case unavailable
    /// The upstream service could not be reached or answered unusably.
    case badGateway
}

/// Header names copied from the inbound request to the outbound one.
///
/// This is an allow-list precisely so that `authorization`, `cookie`, `dpop`,
/// and every future credential header are excluded by construction rather than
/// by remembering to add them to a deny-list. The client's Swan credentials
/// must never reach a third-party service.
let swanXRPCPipethroughForwardedHeaderNames: Set<String> = [
    "accept-language",
    "atproto-accept-labelers",
]

/// Names that must never be forwarded even if the allow-list above is later
/// widened by mistake. Checked as a belt-and-braces assertion at build time.
let swanXRPCPipethroughNeverForwardedHeaderNames: Set<String> = [
    "authorization", "cookie", "cookie2", "set-cookie", "dpop", "dpop-nonce",
    "proxy-authorization", "atproto-proxy",
]

func registerSwanXRPCPipethrough(
    on router: Router<SwanHTTPRequestContext>,
    capability: SwanXRPCPipethroughServer,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    // `/xrpc/**` is the lowest-priority token in Hummingbird's trie
    // (`recursiveWildcard`), so every exact `/xrpc/<nsid>` route and every
    // `/xrpc/<prefix>.*` guard registered anywhere in `buildRouter()` resolves
    // ahead of it regardless of registration order. `SwanXRPCRouterPrecedence
    // Tests` pins that behaviour so a Hummingbird upgrade cannot quietly turn
    // this into a shadow of Swan's own lexicons.
    let path: RouterPath = "/xrpc/**"
    router.get(path) { request, context async -> Response in
        await handleSwanXRPCPipethrough(
            request,
            context: context,
            method: "GET",
            capability: capability,
            requestBodyAdmission: requestBodyAdmission
        )
    }
    router.post(path) { request, context async -> Response in
        await handleSwanXRPCPipethrough(
            request,
            context: context,
            method: "POST",
            capability: capability,
            requestBodyAdmission: requestBodyAdmission
        )
    }
    // Only GET and POST are proxyable XRPC shapes. Everything else gets the
    // same opaque 404 an unrouted namespace gets.
    let allMethods: [HTTPRequest.Method] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ]
    for method in allMethods where method != .get && method != .post {
        router.on(path, method: method) { _, _ -> Response in
            pipethroughError(.notFound, "EndpointUnavailable")
        }
    }
}

private func handleSwanXRPCPipethrough(
    _ request: Request,
    context: SwanHTTPRequestContext,
    method: String,
    capability: SwanXRPCPipethroughServer,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
    let now = Date()
    // A request refused before its body was read still has bytes on the wire.
    // The single drain in the failure path below keeps a refusal from stalling
    // the channel, exactly as the actor-preferences routes do.
    var consumedBody = method != "POST"
    do {
        // 1. The request target must be a well-formed NSID before anything
        //    else looks at it.
        guard let nsid = pipethroughNSID(from: request.uri.path) else {
            throw SwanXRPCPipethroughFailure.notFound
        }

        // 2. Routing, which comes before authentication. `.denied`/`.unrouted`
        //    are 404; a malformed proxy header is 400 and never silently
        //    becomes the default AppView. Header extraction is deliberately
        //    outside the inner `do`: an unusable header must reach the 400
        //    path, not the routing failure switch.
        //
        //    Routing used to run *after* authentication, which meant every NSID
        //    this host does not implement answered 401 rather than 404 —
        //    indistinguishable, from outside, from a credential problem. Swan's
        //    missing-route list stayed invisible for exactly that reason: a
        //    relay, an AppView, or another PDS probing anonymously saw
        //    "unauthorized" everywhere and could not report what was absent.
        //
        //    Nothing here reads a credential or does I/O — `SwanXRPCProxyRouter`
        //    is pure and `pipethroughProxyHeader` only reads one inbound header
        //    — so deciding the route first hands an anonymous caller nothing
        //    but a status code. The first step that opens a socket is the
        //    resolver at step 5, and it stays behind step 3.
        let proxyHeader = try pipethroughProxyHeader(request.headers)
        let route: SwanXRPCProxyRoute
        do {
            route = try SwanXRPCProxyRouter(
                appViewDID: capability.appView.did,
                appViewServiceFragment: capability.appView.serviceFragment
            ).route(nsid: nsid, proxyHeader: proxyHeader)
        } catch let failure as SwanXRPCProxyRoutingFailure {
            switch failure {
            case .denied, .unrouted:
                throw SwanXRPCPipethroughFailure.notFound
            case .malformedProxyHeader:
                throw SwanXRPCPipethroughFailure.invalidRequest
            }
        }

        // 3. Authentication, before the body is buffered, before a concurrency
        //    slot is taken, and before any outbound work, so an anonymous
        //    caller can never make Swan open a socket.
        let principal = try await authorizedPipethroughSubject(
            request,
            method: method,
            path: "/xrpc/\(nsid)",
            authorizer: capability.authorizer,
            now: now
        )
        let subject = principal.subject

        // 3b. `assertRpc({lxm, aud})` — `pipethrough.ts:66-68`. This is the
        //     caller-DEPENDENT question, and it is deliberately NOT folded into
        //     `SwanXRPCProxyRouter.route` at step 2: that router is pure and
        //     caller-independent, and a scope check there would be worthless
        //     because it does not know who is calling — any scoped credential
        //     could then mint a service token for every proxyable NSID.
        //
        //     Placed here it is both sufficient and complete: `lxm` binds the
        //     minted token to one exact NSID, so an out-of-scope method never
        //     reaches step 6 to have a credential minted for it. It also runs
        //     before the body is buffered and before a concurrency slot is
        //     taken, so a denied caller costs the host nothing.
        try enforcingScope(
            route: "/xrpc/\(nsid)",
            logger: context.logger,
            denial: SwanXRPCPipethroughFailure.unauthorized
        ) {
            try principal.permissions.requireRPC(
                .init(
                    lxm: nsid,
                    aud: pipethroughScopeAudience(
                        route: route,
                        appViewServiceFragment: capability.appView.serviceFragment
                    )
                )
            )
        }

        // 4. The query string is validated here, before the resolver, the
        //    token issuer, or the sender can be reached, so an unforwardable
        //    query costs the host nothing outbound. `pipethroughOutbound
        //    Request` re-checks it — it is a separate entry point, and the
        //    consequence of admitting a bad byte there is a process kill, not
        //    a bad request.
        _ = try pipethroughForwardableQuery(request.uri.query)

        // The body is buffered only once the request is known to be
        // authenticated and routable.
        consumedBody = true
        let body = try await pipethroughRequestBody(
            request,
            context: context,
            method: method,
            requestBodyAdmission: requestBodyAdmission,
            maximumBytes: capability.limits.maximumRequestBodyBytes
        )

        guard let lease = capability.admission.acquire() else {
            throw SwanXRPCPipethroughFailure.busy
        }
        defer { lease.release() }

        // 5. Endpoint selection. The configured AppView needs no lookup; any
        //    other service is resolved from its DID document. This is the
        //    first step that can reach the network, and it is deliberately
        //    downstream of step 3.
        let audience: String
        let endpoint: URL
        switch route {
        case let .configuredAppView(did):
            audience = did
            endpoint = capability.appView.url
        case let .resolvedService(did, fragment):
            audience = did
            do {
                endpoint = try await capability.resolver.endpoint(did: did, fragment: fragment)
            } catch {
                throw SwanXRPCPipethroughFailure.invalidRequest
            }
        }

        // 6. The service token. `lxm` binds it to this exact method, so a
        //    remote service cannot replay it against another endpoint.
        let token: String
        do {
            token = try await capability.tokens.issueProxyServiceToken(
                issuer: subject,
                audience: audience,
                method: nsid,
                now: now
            )
        } catch {
            throw SwanXRPCPipethroughFailure.unavailable
        }

        // 7. The outbound request: path and query verbatim, the minted token,
        //    and only allow-listed headers.
        let outbound = try pipethroughOutboundRequest(
            request,
            method: method,
            nsid: nsid,
            endpoint: endpoint,
            token: token,
            body: body
        )

        // 8. Send through the peer-pinned sender. This is the only thing
        //    stopping a hostile `serviceEndpoint` from reaching an internal
        //    address, so a resolved endpoint must never bypass it.
        let response: OAuthRemoteHTTPResponse
        do {
            response = try await capability.sender.send(
                outbound,
                timeout: capability.limits.timeout,
                maximumBodyBytes: capability.limits.maximumResponseBodyBytes
            )
        } catch {
            // A 502 with no server-side trace makes every outbound failure —
            // DNS, TLS, peer pinning, timeout — look identical to the client
            // and to the operator. The endpoint host and the transport error
            // are deployment facts, not credentials: the minted service token
            // never appears here.
            context.logger.info(
                "xrpc pipethrough upstream failed",
                metadata: [
                    "nsid": .string(nsid),
                    "host": .string(endpoint.host() ?? "unknown"),
                    "reason": .string(String(describing: error)),
                ]
            )
            throw SwanXRPCPipethroughFailure.badGateway
        }
        return try pipethroughResponse(response)
    } catch {
        if !consumedBody {
            try? await drainRejectedRequestBody(
                request,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                termination: context.jsonWriteBodyTermination
            )
        }
        return await pipethroughFailureResponse(
            for: error,
            authorizer: capability.authorizer,
            now: now
        )
    }
}

/// `/xrpc/<nsid>` and nothing else. A nested path, an empty segment, or a
/// percent-encoded target is not an NSID and is refused here.
func pipethroughNSID(from path: String) -> String? {
    let prefix = "/xrpc/"
    guard path.hasPrefix(prefix) else { return nil }
    let candidate = String(path.dropFirst(prefix.count))
    guard !candidate.contains("/"), ProxyServiceJWT.isNSID(candidate) else { return nil }
    return candidate
}

/// Reads the single `atproto-proxy` header, distinguishing "absent" from
/// "sent more than once".
///
/// `HTTPFields[values:]` returns one entry per header line and does not
/// comma-split, so a `nil` for `count > 1` would mean "absent" and let a
/// request carrying two conflicting `atproto-proxy` lines fall through to the
/// default AppView route — forwarding the account's traffic to a service the
/// client did not unambiguously name. That is the same silent fallback the
/// malformed-header path exists to prevent, so a duplicate is a 400.
private func pipethroughProxyHeader(_ headers: HTTPFields) throws -> String? {
    guard let name = HTTPField.Name("atproto-proxy") else { return nil }
    let values = headers[values: name]
    switch values.count {
    case 0:
        return nil
    case 1:
        return values[0]
    default:
        throw SwanXRPCPipethroughFailure.invalidRequest
    }
}

private func authorizedPipethroughSubject(
    _ request: Request,
    method: String,
    path: String,
    authorizer: any SwanXRPCPipethroughResourceAuthorizing,
    now: Date
) async throws -> AuthorizedPrincipal {
    let authorization: AuthorizationContext
    do {
        authorization = try await authorizer.authorizePipethrough(
            request: request,
            method: method,
            fixedPath: path,
            now: now
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        switch failure {
        case .nonceChallengeRequired:
            throw SwanXRPCPipethroughFailure.nonce
        case .denied:
            throw SwanXRPCPipethroughFailure.unauthorized
        case .unavailable:
            throw SwanXRPCPipethroughFailure.unavailable
        }
    } catch {
        throw SwanXRPCPipethroughFailure.unavailable
    }
    // The authorization FLOOR only. `assertRpc({lxm, aud})` needs the routing
    // decision's `did#serviceId`, which this function does not have and must
    // not compute — see the caller, which asserts immediately after this
    // returns and strictly before any outbound work.
    // OPT-IN for legacy sessions (§D3). The `.accountLegacySession` case was
    // introduced failing closed everywhere; this is one of the two surfaces
    // deliberately opened, because the official client's traffic is almost
    // entirely proxied reads and a session that cannot proxy is a session that
    // logs in and then shows an empty app.
    //
    // Both cases carry a parsed permissions value and both are handed to the
    // same `requireRPC` below, so opting in widens WHO may proxy, never WHAT
    // they may reach.
    let subject: String
    let permissions: SwanScopePermissions
    switch authorization {
    case let .accountOAuth(oauthSubject, oauthPermissions):
        subject = oauthSubject
        permissions = oauthPermissions
    case let .accountLegacySession(legacySubject, legacyPermissions):
        subject = legacySubject
        permissions = legacyPermissions
    default:
        throw SwanXRPCPipethroughFailure.unauthorized
    }
    guard permissions.hasBaseATProtocolScope else {
        throw SwanXRPCPipethroughFailure.unauthorized
    }
    return AuthorizedPrincipal(subject: subject, permissions: permissions)
}

/// The `aud` an `rpc:` grant is matched against, per the `scopeAud`/`tokenAud`
/// split at `pipethrough.ts:101-106`.
///
/// The SCOPE check sees the combined `did#serviceId` form, so a caller's
/// `rpc:...?aud=did#service` grant matches. The outbound service-auth JWT keeps
/// a bare-DID `aud` regardless — that is `tokenAud`, computed separately at
/// step 5. Collapsing the two either breaks outbound auth or leaves every
/// fragment-qualified `rpc:` scope unmatched.
///
/// `RpcPermission.matches` compares `aud` as an exact string with no fragment
/// stripping (`rpc-permission.ts:43-49`), which is why the fragment must be
/// appended here rather than relied upon to be ignored.
private func pipethroughScopeAudience(
    route: SwanXRPCProxyRoute,
    appViewServiceFragment: String
) -> String {
    switch route {
    case let .configuredAppView(did):
        "\(did)#\(appViewServiceFragment)"
    case let .resolvedService(did, fragment):
        "\(did)#\(fragment)"
    }
}

private func pipethroughRequestBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    method: String,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    maximumBytes: Int
) async throws -> Data? {
    guard method == "POST" else { return nil }
    let buffer: SwanAdmittedRequestBody
    do {
        buffer = try await collectAdmittedRequestBody(
            request,
            // The proxy does not interpret the body, so it does not impose a
            // media type. The upstream lexicon decides what is acceptable.
            mediaType: .unspecified,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: maximumBytes,
            termination: context.jsonWriteBodyTermination
        )
    } catch let failure as SwanRequestBodyCollectionFailure {
        switch failure {
        case .invalidRequest:
            throw SwanXRPCPipethroughFailure.invalidRequest
        case .payloadTooLarge:
            throw SwanXRPCPipethroughFailure.payloadTooLarge
        case .unavailable:
            throw SwanXRPCPipethroughFailure.unavailable
        }
    } catch {
        throw SwanXRPCPipethroughFailure.invalidRequest
    }
    defer { withExtendedLifetime(buffer) {} }
    guard buffer.readableBytes > 0 else { return Data() }
    guard let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) else {
        throw SwanXRPCPipethroughFailure.invalidRequest
    }
    return Data(bytes)
}

/// The client's query string, verbatim, once it is known to be a query string
/// `URLComponents.percentEncodedQuery` will accept — or `nil` when there is
/// none. Anything else throws, which the handler turns into a 400.
///
/// This check cannot be skipped or deferred. The setter validates the RFC 3986
/// query grammar with a **`fatalError`, not a throw**, so handing it a byte it
/// rejects terminates the whole PDS process for every session. The previous
/// `0x21 ... 0x7E` byte-range guard admitted `%`, `"`, `<`, `>`, `\`, `^`,
/// `` ` ``, `{`, `|`, `}`, `[`, and `]`, none of which are legal in a query —
/// so an ordinary `?cursor=100%` or `?q="foo"` was a remote process kill.
///
/// Re-encoding rather than validating is deliberately NOT the fix: `%` is
/// legal input when it introduces a valid escape, so escaping it would corrupt
/// every already-percent-encoded cursor. Preserving the client's query byte for
/// byte is a requirement of the feature — the upstream service must see exactly
/// what the client sent — so the only sound option is to admit exactly the
/// grammar and refuse the rest.
func pipethroughForwardableQuery(_ query: String?) throws -> String? {
    guard let query, !query.isEmpty else { return nil }
    guard query.utf8.count <= 4_096, isPercentEncodedQuery(query) else {
        throw SwanXRPCPipethroughFailure.invalidRequest
    }
    return query
}

/// RFC 3986 `query = *( pchar / "/" / "?" )`, where
/// `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"` and
/// `pct-encoded = "%" HEXDIG HEXDIG`.
///
/// Matched against the byte sequence rather than `Character`s: the grammar is
/// defined over octets, and a multi-byte scalar must be rejected byte by byte
/// rather than treated as one unit.
func isPercentEncodedQuery(_ query: String) -> Bool {
    let bytes = Array(query.utf8)
    var index = 0
    while index < bytes.count {
        let byte = bytes[index]
        if byte == UInt8(ascii: "%") {
            // Exactly two hex digits, and both must exist: a trailing `%` or
            // `%A` at the end of a cursor is the crash that motivated this.
            guard index + 2 < bytes.count,
                  isASCIIHexDigit(bytes[index + 1]),
                  isASCIIHexDigit(bytes[index + 2]) else {
                return false
            }
            index += 3
            continue
        }
        guard isRFC3986QueryByte(byte) else { return false }
        index += 1
    }
    return true
}

private func isASCIIHexDigit(_ byte: UInt8) -> Bool {
    switch byte {
    case 0x30 ... 0x39, 0x41 ... 0x46, 0x61 ... 0x66: true
    default: false
    }
}

/// One unescaped query octet: `unreserved`, `sub-delims`, `:`, `@`, `/`, `?`.
/// `%` is excluded here on purpose — it is only ever valid as the head of a
/// `pct-encoded` triple, which the caller handles.
private func isRFC3986QueryByte(_ byte: UInt8) -> Bool {
    switch byte {
    // ALPHA / DIGIT
    case 0x30 ... 0x39, 0x41 ... 0x5A, 0x61 ... 0x7A:
        true
    // unreserved: "-" / "." / "_" / "~"
    case UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"):
        true
    // sub-delims: "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
    case UInt8(ascii: "!"), UInt8(ascii: "$"), UInt8(ascii: "&"), UInt8(ascii: "'"),
         UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "*"), UInt8(ascii: "+"),
         UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "="):
        true
    // pchar additions plus "/" and "?"
    case UInt8(ascii: ":"), UInt8(ascii: "@"), UInt8(ascii: "/"), UInt8(ascii: "?"):
        true
    default:
        false
    }
}

func pipethroughOutboundRequest(
    _ request: Request,
    method: String,
    nsid: String,
    endpoint: URL,
    token: String,
    body: Data?
) throws -> SwanProxyRequest {
    // Rebuilt from the validated NSID rather than reused from `request.uri`,
    // so nothing that was not accepted by the NSID grammar can enter the
    // outbound target.
    let nsidPath = "/xrpc/\(nsid)"
    guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else {
        throw SwanXRPCPipethroughFailure.invalidRequest
    }
    // Preserve the client's path and query byte for byte. A trailing slash on
    // a configured endpoint must not produce `//xrpc/...`.
    let base = components.percentEncodedPath == "/" ? "" : components.percentEncodedPath
    components.percentEncodedPath = base + nsidPath
    if let query = try pipethroughForwardableQuery(request.uri.query) {
        components.percentEncodedQuery = query
    } else {
        components.percentEncodedQuery = nil
    }
    components.fragment = nil
    guard let url = components.url else {
        throw SwanXRPCPipethroughFailure.invalidRequest
    }

    var headers: [(name: String, value: String)] = [
        ("authorization", "Bearer \(token)"),
        // The response reader does not decompress, so never invite a
        // content-coding the proxy would hand back unreadable.
        ("accept-encoding", "identity"),
    ]
    for field in request.headers {
        let name = field.name.canonicalName
        guard swanXRPCPipethroughForwardedHeaderNames.contains(name) else { continue }
        // Unreachable while the allow-list and the never-forward set stay
        // disjoint; kept so widening the allow-list cannot leak a credential.
        guard !swanXRPCPipethroughNeverForwardedHeaderNames.contains(name) else { continue }
        headers.append((name: name, value: field.value))
    }
    if method == "POST", let contentType = request.headers[.contentType] {
        headers.append((name: "content-type", value: contentType))
    }
    guard headers.count <= 32 else {
        throw SwanXRPCPipethroughFailure.invalidRequest
    }

    return SwanProxyRequest(method: method, url: url, headers: headers, body: body)
}

private func pipethroughResponse(_ response: OAuthRemoteHTTPResponse) throws -> Response {
    guard (100 ... 599).contains(response.status) else {
        throw SwanXRPCPipethroughFailure.badGateway
    }
    let status = HTTPResponse.Status(code: response.status)
    let canonical = response.headers.reduce(into: [String: [String]]()) { output, item in
        output[item.key.lowercased(), default: []].append(contentsOf: item.value)
    }
    var headers: HTTPFields = [.cacheControl: "no-store"]
    // Deliberately narrow, and narrower than it used to be: `location` is no
    // longer relayed. The reference PDS forwards only `atproto-repo-rev`,
    // `atproto-content-labelers`, `retry-after` and the `content-*` family
    // (`atproto/packages/pds/src/pipethrough.ts:527-531` for the explicit list,
    // and the `responseHeaders` generator immediately below it for `content-*`)
    // — never `location`. Swan now matches that shape, forwarding a strict
    // subset of it.
    //
    // The risk closed by dropping it is not a classic open redirect. It is a
    // *relative* `Location` ("/xrpc/com.atproto.server.createSession",
    // "../admin"): a client that resolves it against the request URL sends its
    // next request back to `swan.place`, carrying Swan credentials, to a path an
    // upstream third-party service chose. Every other upstream header stays
    // dropped for the same reason it always was, so nothing the proxy has not
    // reasoned about (cookies, auth challenges, caching directives) is relayed.
    //
    // A same-host restriction was considered and rejected: it forbids the
    // legitimate CDN redirect and has no principled boundary.
    let forwarded: [(String, HTTPField.Name)] = [
        ("content-type", .contentType),
    ]
    for (name, field) in forwarded {
        guard let values = canonical[name], values.count == 1,
              values[0].utf8.count <= 256,
              values[0].utf8.allSatisfy({ $0 == 0x09 || (0x20 ... 0x7E).contains($0) })
        else { continue }
        headers[field] = values[0]
    }
    return Response(
        status: status,
        headers: headers,
        body: .init(byteBuffer: ByteBuffer(data: response.body))
    )
}

private func pipethroughFailureResponse(
    for error: any Error,
    authorizer: any SwanXRPCPipethroughResourceAuthorizing,
    now: Date
) async -> Response {
    guard let failure = error as? SwanXRPCPipethroughFailure else {
        return pipethroughError(.serviceUnavailable, "temporarily_unavailable")
    }
    switch failure {
    case .notFound:
        return pipethroughError(.notFound, "EndpointUnavailable")
    case .invalidRequest:
        return pipethroughError(.badRequest, "InvalidRequest")
    case .payloadTooLarge:
        return pipethroughError(.contentTooLarge, "PayloadTooLarge")
    case .unauthorized:
        return pipethroughError(.unauthorized, "Unauthorized")
    case .nonce:
        let nonce = await authorizer.issuePipethroughNonce(now: now)
        var headers: HTTPFields = [
            .contentType: "application/json",
            .cacheControl: "no-store",
            .wwwAuthenticate: #"DPoP error="use_dpop_nonce""#,
        ]
        headers[HTTPField.Name("DPoP-Nonce")!] = nonce
        return pipethroughError(.unauthorized, "use_dpop_nonce", headers: headers)
    case .busy, .unavailable:
        return pipethroughError(.serviceUnavailable, "temporarily_unavailable")
    case .badGateway:
        return pipethroughError(.badGateway, "UpstreamFailure")
    }
}

private func pipethroughError(
    _ status: HTTPResponse.Status,
    _ code: String,
    headers: HTTPFields? = nil
) -> Response {
    struct Body: Encodable {
        let error: String
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(Body(error: code))) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: headers ?? [
            .contentType: "application/json",
            .cacheControl: "no-store",
        ],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
