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
        "/xrpc/com.atproto.repo.*",
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
