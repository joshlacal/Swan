import Foundation
import SwanStorage

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
/// win. That ordering is not trusted on its own: local routes are registered
/// conditionally, so "no local route matched" can mean "the capability is nil
/// or its flag is off" rather than "Swan does not own this". Two independent
/// gates cover that — a deny-list for Swan-owned namespaces inside otherwise
/// proxyable space, and an allow-list of the namespaces that may be proxied at
/// all, so dropping or disabling a local route fails closed.
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

    /// The closed set of lexicon namespaces this host is willing to forward.
    ///
    /// The deny-list above cannot be the only gate. "Proxyable" used to mean
    /// "no local route matched and not explicitly denied", and local routes are
    /// registered *conditionally* — a `nil` capability or an off feature flag
    /// removes one, and the namespace it owned silently becomes proxyable.
    /// Measured against the composed production router, the reachable instance
    /// was `com.atproto.server.createSession`: nothing registers it locally, so
    /// a request naming `atproto-proxy: did:web:attacker.example#svc` was
    /// forwarded there — with the account identifier and password in its body.
    ///
    /// This comment used to claim `com.atproto.server.resetPassword` was
    /// "covered either way" because the `PublicDataTesting20260727` descriptor
    /// loop left an unavailable stub over it. That was false when it was
    /// written and false since: `20260727` declares twelve methods and not one
    /// `com.atproto.server.*` entry, so no stub was ever registered for it. A
    /// comment claiming a second layer that does not exist is worse than no
    /// comment, in this file most of all. The real second layer arrived later
    /// and is a different mechanism: `registerUnknownPublicEndpointGuards` now
    /// closes `/xrpc/com.atproto.server.*` with an explicit 404, alongside
    /// `identity.*`, `repo.*`, and `sync.*`. `admin.*` and `temp.*` still rest
    /// on this allow-list alone.
    ///
    /// Inverting the gate makes disabling a route fail closed: an NSID outside
    /// this list is a 404 no matter what the client asks for. The *destination*
    /// stays deliberately open — naming an arbitrary labeler, feed generator, or
    /// alternate AppView is the point of `atproto-proxy` — so what is closed
    /// here is the set of methods, not the set of services.
    ///
    /// `com.atproto.*` is absent on purpose. It is the PDS's own lexicon space,
    /// which is exactly the space where a conditionally-registered local route
    /// can vanish, so admitting any of it would reintroduce the hazard this
    /// list exists to remove.
    private static let proxyablePrefixes = [
        "app.bsky.",
        "chat.bsky.",
        "tools.ozone.",
    ]

    /// Exact NSIDs proxyable despite living outside every prefix above.
    ///
    /// Both are `com.atproto.*`, which the prefix list deliberately excludes,
    /// but both are also methods a client proxies to a third-party labeler as
    /// part of ordinary content moderation: reporting content
    /// (`createReport`) and reading label state (`queryLabels`). Neither has
    /// a local Swan route, so under the old fail-open deny-list they were
    /// reachable; the allow-list migration 404'd them as collateral damage.
    ///
    /// These must be exact NSIDs, never a `com.atproto.` (or even
    /// `com.atproto.moderation.`/`com.atproto.label.`) prefix. A prefix here
    /// would readmit the exact hazard the allow-list exists to close: an NSID
    /// like `com.atproto.server.createSession` — or any future
    /// `com.atproto.moderation.*`/`com.atproto.label.*` method that turns out
    /// to carry a credential — would become forwardable the moment it lost
    /// its local route, with no gate left to catch it.
    private static let proxyableMethods: Set<String> = [
        "com.atproto.moderation.createReport",
        "com.atproto.label.queryLabels",
    ]

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
            // Namespace allow-list before the header is even parsed. A
            // namespace Swan does not proxy is unrouted whether or not the
            // client named a destination, and it reports the same 404 an
            // unknown namespace gets so this cannot be used to enumerate what
            // Swan reserves.
            //
            // Admission is by namespace, NOT by membership in the generated
            // method registry. The registry is derived from a pinned lexicon
            // tree, and that pin trails upstream: 52 published methods were
            // missing from it here, so `chat.bsky.convo.getUnreadCounts` and
            // `app.bsky.video.*` 404'd for clients that legitimately asked for
            // them. A stale pin must not silently shrink what this host will
            // forward. The registry stays authoritative for scope
            // declarations, where lexicon truth is the whole point.
            //
            // This does not reopen the hazard the allow-list exists to close.
            // That hazard is a conditionally-registered *local* route
            // vanishing and its NSID becoming forwardable — the measured case
            // was `com.atproto.server.createSession` carrying an identifier
            // and password. `com.atproto.*` is deliberately absent from
            // `proxyablePrefixes`, so it is still unrouted here no matter what
            // the client names, and everything Swan owns inside a proxyable
            // namespace is covered by `deniedPrefixes`/`deniedMethods` above.
            guard Self.isProxyableNamespace(nsid) else {
                throw SwanXRPCProxyRoutingFailure.unrouted
            }
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
        // With no header the destination is the configured AppView, so the
        // admissible set is narrower still than `proxyablePrefixes`: only the
        // AppView's own namespace. `chat.bsky.` and `tools.ozone.` live at
        // other services and a client must name them explicitly.
        guard nsid.hasPrefix(Self.appViewPrefix) else {
            throw SwanXRPCProxyRoutingFailure.unrouted
        }
        return .configuredAppView(did: appViewDID)
    }

    /// A namespace this host forwards, ignoring the destination.
    static func isProxyableNamespace(_ nsid: String) -> Bool {
        proxyablePrefixes.contains(where: { nsid.hasPrefix($0) })
            || proxyableMethods.contains(nsid)
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
