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
    private static let appViewPrefix = "app.bsky."

    private let appViewDID: String

    public init(appViewDID: String) {
        self.appViewDID = appViewDID
    }

    public func route(nsid: String, proxyHeader: String?) throws -> SwanXRPCProxyRoute {
        // Deny-list first: an explicit header must never override it.
        guard !Self.deniedPrefixes.contains(where: { nsid.hasPrefix($0) }) else {
            throw SwanXRPCProxyRoutingFailure.denied
        }
        if let proxyHeader {
            let (did, fragment) = try Self.parseProxyHeader(proxyHeader)
            if did == appViewDID { return .configuredAppView(did: did) }
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
