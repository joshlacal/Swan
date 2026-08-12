import Hummingbird

/// `com.atproto.sync.subscribeRepos`, spelled as a literal because the wire
/// generator emits no enum for a subscription — `SwanPublicWire` carries it
/// only as a `PublicXRPCMethodDescriptor` with `kind: .subscription`. A test
/// asserts this string is present in the shipped descriptor list, so a typo
/// here fails the suite rather than silently disabling the firehose route.
let publicSubscribeReposNSID = "com.atproto.sync.subscribeRepos"

/// Route registration filtered by the selected public route surface.
///
/// Selecting a public profile used to control only the fail-closed 503 gate
/// loop. Every real public handler — repository reads, repository mutations,
/// the firehose upgrade, the account-email routes — was registered
/// unconditionally, so a narrower profile removed nothing: `--public-profile`
/// worked in the widening direction only, and the startup log's method count
/// was a count of gates rather than of served endpoints.
///
/// These two helpers are the narrow seam that fixes that. A registration site
/// names the NSID it is about to install and the served set it must be inside;
/// an NSID outside the set installs no route at all, so the method falls to the
/// namespace guard (404) exactly as an unimplemented method does.
///
/// The served set is always ``SwanPublicRouteSurface/servedMethodNSIDs``, which
/// is derived from the allow-list registry and cannot be assembled by a caller,
/// so this stays an allow-list at the trust boundary rather than a filter a
/// call site can widen.
extension Router where Context == SwanHTTPRequestContext {
    /// Registers a public GET route only when the selected surface serves it.
    ///
    /// Takes an NSID rather than a path so the gate and the route cannot
    /// disagree about which method is being installed.
    @discardableResult
    func getIfServed(
        _ nsid: String,
        in servedMethods: Set<String>,
        use handler: @Sendable @escaping (Request, Context) async throws -> Response
    ) -> Self {
        guard servedMethods.contains(nsid) else { return self }
        return get(RouterPath("/xrpc/\(nsid)"), use: handler)
    }

    /// Registers a public POST route only when the selected surface serves it.
    @discardableResult
    func postIfServed(
        _ nsid: String,
        in servedMethods: Set<String>,
        use handler: @Sendable @escaping (Request, Context) async throws -> Response
    ) -> Self {
        guard servedMethods.contains(nsid) else { return self }
        return post(RouterPath("/xrpc/\(nsid)"), use: handler)
    }
}
