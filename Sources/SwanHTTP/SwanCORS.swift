import Foundation
import HTTPTypes
import Hummingbird

/// Cross-Origin Resource Sharing for the public listener.
///
/// The Bluesky web client runs at `https://bsky.app` and talks to a PDS
/// directly from the browser, so every XRPC call is cross-origin and is
/// preceded by a preflight `OPTIONS`. Swan registered no `OPTIONS` responder
/// on its XRPC paths, so the router resolved the path, found no responder for
/// the method (`RouterResponder.swift:47-50`), and fell through to the
/// not-found responder. The browser reports that 404 against the request it
/// *intended* to make, which is why `com.atproto.server.createSession` looked
/// like a missing endpoint while `POST` to the same URL answered correctly —
/// the `POST` was never sent.
///
/// Upstream applies `cors({ maxAge: DAY / SECOND })` to the entire PDS
/// application (`packages/pds/src/index.ts:204`); this is that policy, and the
/// defaults below are the `cors` package's own.
///
/// ## Why the wildcard is safe here
///
/// No `Access-Control-Allow-Credentials` is ever emitted, and none may be
/// added without revisiting this comment. Browsers therefore withhold cookies
/// from these requests, and every Swan credential — legacy `Bearer`, OAuth
/// `DPoP` — travels in an `Authorization` header that a cross-origin page has
/// no way to obtain. CORS is a *read* barrier protecting the browser's user
/// from a hostile page reading responses it could already provoke; it is not
/// an authorization gate for the server. Widening it grants an attacker page
/// nothing beyond what a plain `curl` already has, while every existing
/// authentication and scope check stays exactly where it is.
///
/// This middleware is registered only on the public listener. Management HTTP
/// binds a separate port with its own router and context
/// (`SwanCommand.swift:3534-3542` refuses to share the public port), so no
/// operator surface is reachable cross-origin.
struct SwanCORSMiddleware<Context: RequestContext>: RouterMiddleware {
    /// `cors`'s default method list, plus `OPTIONS` so a preflight advertises
    /// the verb it was itself sent with.
    private static var allowedMethods: String {
        "GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS"
    }

    /// Headers a browser may read off an actual (non-preflight) response.
    ///
    /// The CORS-safelisted response headers are readable without this; these
    /// two are not, and both carry protocol-critical values. `DPoP-Nonce`
    /// drives the OAuth nonce handshake — a browser client that cannot read it
    /// can never satisfy the retry — and `WWW-Authenticate` carries the
    /// challenge. Swan's OAuth routes already declare exactly this pair
    /// (`oauthAPICORSHeaders`); hoisting it here extends the same decision to
    /// the XRPC surface rather than making a new one.
    private static var exposedHeaders: String {
        "DPoP-Nonce, WWW-Authenticate"
    }

    /// One day, matching upstream's `maxAge: DAY / SECOND`.
    private static var maxAge: String { "86400" }

    func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        // The account portal is a same-origin, cookie-authenticated surface.
        // It must not inherit the public listener's wildcard CORS policy: a
        // hostile page must not be able to preflight or read management
        // responses, and the portal owns its own origin/CSRF checks.  Keep the
        // boundary exact so a look-alike path such as `/accounting` remains a
        // normal public-listener request.
        if Self.isSameOriginAccountPath(request.uri.path) {
            return try await next(request, context)
        }

        // A request without `Origin` is not cross-origin. Adding CORS headers
        // to it would be noise, and — more importantly — leaving this path
        // untouched keeps every server-to-server caller (federation, relays,
        // other PDSes) byte-identical to what it sees today.
        guard request.headers[.origin] != nil else {
            return try await next(request, context)
        }

        if request.method == .options, request.headers[.accessControlRequestMethod] != nil {
            return Self.preflightResponse(for: request)
        }

        // An actual cross-origin request. The handler runs completely
        // unchanged — CORS decorates the response, it never decides it.
        do {
            var response = try await next(request, context)
            Self.decorate(&response.headers)
            return response
        } catch let error as any HTTPResponseError {
            // Errors need the header too, or the browser reports an opaque
            // network failure instead of the 401 the client must act on.
            // Hummingbird's own CORS middleware reaches for an internal
            // `EditedHTTPError` here; rendering the error through its public
            // `ResponseGenerator` conformance reaches the same result with
            // API this module is allowed to use.
            var response = try error.response(from: request, context: context)
            Self.decorate(&response.headers)
            return response
        }
    }

    private static func isSameOriginAccountPath(_ path: String) -> Bool {
        path == "/account"
            || path == "/account/"
            || path.hasPrefix("/account/api/")
            || path == "/account/api"
            || path.hasPrefix("/account/")
    }

    /// Answers the preflight without consulting the router.
    ///
    /// The requested header list is reflected rather than matched against a
    /// fixed allowlist, which is what upstream's `cors` does when
    /// `allowedHeaders` is unset: it echoes `Access-Control-Request-Headers`
    /// and adds the corresponding `Vary`. A fixed list is the failure mode
    /// this is chosen to avoid — it silently blocks the first client that
    /// sends a header nobody enumerated (`atproto-proxy` and
    /// `atproto-accept-labelers` are both routine), and the block surfaces as
    /// the same misleading browser-side error being fixed here. Reflection
    /// concedes nothing, because a preflight grants no authority: the actual
    /// request still has to pass authentication and scope enforcement.
    private static func preflightResponse(for request: Request) -> Response {
        var headers: HTTPFields = [
            .accessControlAllowOrigin: "*",
            .accessControlAllowMethods: allowedMethods,
            .accessControlMaxAge: maxAge,
            .cacheControl: "no-store",
        ]
        if let requested = request.headers[.accessControlRequestHeaders] {
            headers[.accessControlAllowHeaders] = requested
            headers[.vary] = "Access-Control-Request-Headers"
        }
        return Response(status: .noContent, headers: headers, body: .init())
    }

    /// Adds the response-side headers, without disturbing a route that has
    /// already stated its own policy.
    ///
    /// The OAuth routes set `Access-Control-Expose-Headers` themselves; an
    /// unconditional assignment here would overwrite a deliberate, narrower
    /// declaration with this one.
    private static func decorate(_ headers: inout HTTPFields) {
        headers[.accessControlAllowOrigin] = "*"
        if headers[.accessControlExposeHeaders] == nil {
            headers[.accessControlExposeHeaders] = exposedHeaders
        }
    }
}
