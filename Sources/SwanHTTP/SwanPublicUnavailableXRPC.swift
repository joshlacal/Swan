import Hummingbird
import HTTPTypes
import SwanPublicWire

func registerUnavailablePublicEndpoint(
    _ descriptor: PublicXRPCMethodDescriptor,
    on router: Router<BasicRequestContext>
) {
    let path = RouterPath("/xrpc/\(descriptor.nsid)")
    let availableMethod: HTTPRequest.Method
    let isStreamingAdapter = [
        "com.atproto.repo.uploadBlob",
        "com.atproto.sync.getBlob",
        "com.atproto.sync.getRepo",
    ].contains(descriptor.nsid)
    switch descriptor.kind {
    case .query:
        router.get(path) { _, _ -> Response in
            isStreamingAdapter ? publicStreamingEndpointUnavailable() : publicDataUnavailable()
        }
        availableMethod = .get
    case .procedure:
        router.post(path) { _, _ -> Response in
            isStreamingAdapter ? publicStreamingEndpointUnavailable() : publicDataUnavailable()
        }
        availableMethod = .post
    case .subscription:
        return
    }
    for method in publicGuardedHTTPMethods where method != availableMethod {
        router.on(path, method: method) { _, _ -> Response in
            publicEndpointUnavailable()
        }
    }
}

func registerUnknownPublicEndpointGuards(on router: Router<BasicRequestContext>) {
    for path: RouterPath in [
        // `com.atproto.identity.*` is closed here for the same reason the two
        // below are: every method in the namespace is Swan's own to implement
        // or refuse. `resolveHandle` registers an exact route ahead of this
        // guard; `updateHandle`, `signPlcOperation`, and the rest are not
        // implemented and must answer 404 from Swan rather than be swept into
        // the AppView proxy, which would hand a third party a handle or a PLC
        // operation request.
        "/xrpc/com.atproto.identity.*",
        "/xrpc/com.atproto.repo.*",
        // `com.atproto.server.*` is Swan's own namespace in exactly the same
        // sense as the three around it: account creation, sessions, email
        // confirmation, and password reset are PDS methods, never a third
        // party's. It is closed here so a method the selected public profile
        // does not declare — or one an assembly's account-email runtime does
        // not install — answers a flat 404 from Swan rather than reaching the
        // pipethrough's routing decision with its request body still attached.
        //
        // `SwanXRPCProxyRouter` already refuses the whole `com.atproto.*` space
        // (its `proxyablePrefixes` are `app.bsky.`, `chat.bsky.`,
        // `tools.ozone.`, plus two exact moderation NSIDs), so this is not the
        // gate that stops forwarding today — it is the second one, added
        // because that allow-list is the only thing standing between a
        // conditionally-registered `com.atproto.server.*` route and the proxy,
        // and this codebase has already shipped a credential-forwarding bug of
        // exactly that shape once.
        //
        // `com.atproto.server.describeServer` registers an exact route above
        // and keeps it: exact paths outrank a `<prefix>.*` guard in
        // Hummingbird's trie regardless of registration order.
        "/xrpc/com.atproto.server.*",
        "/xrpc/com.atproto.sync.*",
    ] {
        for method in publicGuardedHTTPMethods {
            router.on(path, method: method) { _, _ -> Response in
                publicEndpointUnavailable()
            }
        }
    }
}

private let publicGuardedHTTPMethods: [HTTPRequest.Method] = [
    .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
]

private func publicEndpointUnavailable() -> Response {
    jsonResponseWithStatus(.notFound, body: ["error": "public_endpoint_unavailable"])
}

private func publicDataUnavailable() -> Response {
    jsonResponseWithStatus(.serviceUnavailable, body: ["error": "public_data_pending"])
}

/// The generated contracts for these endpoints materialize their request or
/// response as `Data`. Keeping a distinct adapter makes it impossible for the
/// later streaming implementation to accidentally call a generated handler.
private func publicStreamingEndpointUnavailable() -> Response {
    jsonResponseWithStatus(.serviceUnavailable, body: ["error": "public_streaming_pending"])
}
