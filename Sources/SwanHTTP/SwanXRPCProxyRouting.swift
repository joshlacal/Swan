import Foundation

/// Where a proxied XRPC request should be sent.
public enum SwanXRPCProxyRoute: Sendable, Equatable {
    /// The configured AppView. Its endpoint is known from configuration, so no
    /// DID document resolution is needed.
    case configuredAppView(did: String)
    /// Some other service: resolve this DID's document and select the service
    /// entry whose id matches `fragment`.
    case resolvedService(did: String, fragment: String)
}

public enum SwanXRPCProxyRoutingFailure: Error, Sendable, Equatable {
    /// A Swan-owned namespace. Never leaves this host.
    case denied
    /// No default route and no explicit target.
    case unrouted
    /// `atproto-proxy` was present but unusable. Deliberately NOT a fallback to
    /// the default: forwarding to a service the client did not name would send
    /// the account's traffic somewhere it did not ask for.
    case malformedProxyHeader
}

/// Decides where an XRPC request goes. Pure: no I/O, no network.
///
/// Only consulted when no local Swan route matched, so local routes always
/// win. The deny-list is deliberately redundant with that ordering — a future
/// refactor that drops or renames a local route must not silently begin
/// forwarding Swan-owned traffic to a third party.
public struct SwanXRPCProxyRouter: Sendable {
    private static let deniedPrefixes = ["com.atproto.space.", "blue.catbird."]
    /// Exact NSIDs Swan owns inside a namespace it otherwise proxies.
    ///
    /// Account preferences are PDS state: the AppView does not store them, so
    /// forwarding these would both discard the write and disclose the
    /// account's saved feeds, content-label settings, and muted words to a
    /// third party. They must be matched exactly — a `app.bsky.actor.` prefix
    /// would over-match `getProfile`, `searchActors`, and every other genuinely
    /// AppView-owned method in that namespace.
    private static let deniedMethods: Set<String> = [
        "app.bsky.actor.getPreferences",
        "app.bsky.actor.putPreferences",
    ]
    private static let appViewPrefix = "app.bsky."

    private let appViewDID: String
    private let appViewServiceFragment: String

    /// Both halves of the configured AppView's service reference are required.
    /// There is deliberately no default for the fragment: the configuration
    /// shortcut below is only sound when the client named *this* service, and
    /// a defaulted fragment would let a call site silently keep the older
    /// DID-only match.
    public init(appViewDID: String, appViewServiceFragment: String) {
        self.appViewDID = appViewDID
        self.appViewServiceFragment = appViewServiceFragment
    }

    public func route(nsid: String, proxyHeader: String?) throws -> SwanXRPCProxyRoute {
        // Deny-list first: an explicit header must never override it.
        guard !Self.deniedPrefixes.contains(where: { nsid.hasPrefix($0) }),
              !Self.deniedMethods.contains(nsid) else {
            throw SwanXRPCProxyRoutingFailure.denied
        }
        if let proxyHeader {
            let (did, fragment) = try Self.parseProxyHeader(proxyHeader)
            // The configured-endpoint shortcut applies only when the client
            // named the exact service Swan has an endpoint for. Matching on the
            // DID alone would send a request for, say,
            // `did:web:api.bsky.app#atproto_labeler` to the AppView — a service
            // the client did not ask for. A different fragment at the same DID
            // takes the resolve path, where the DID document decides.
            if did == appViewDID, fragment == appViewServiceFragment {
                return .configuredAppView(did: did)
            }
            return .resolvedService(did: did, fragment: fragment)
        }
        guard nsid.hasPrefix(Self.appViewPrefix) else {
            throw SwanXRPCProxyRoutingFailure.unrouted
        }
        return .configuredAppView(did: appViewDID)
    }

    private static func parseProxyHeader(_ value: String) throws -> (did: String, fragment: String) {
        let parts = value.split(separator: "#", omittingEmptySubsequences: false)
        guard parts.count == 2 else { throw SwanXRPCProxyRoutingFailure.malformedProxyHeader }
        let did = String(parts[0])
        let fragment = String(parts[1])
        guard !did.isEmpty, !fragment.isEmpty,
              did.hasPrefix("did:"), did.utf8.count <= 2048, fragment.utf8.count <= 512,
              did.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
              fragment.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F })
        else { throw SwanXRPCProxyRoutingFailure.malformedProxyHeader }
        return (did, fragment)
    }
}
