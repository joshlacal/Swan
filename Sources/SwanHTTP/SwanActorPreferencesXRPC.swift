import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The 1 MiB write cap mirrors the storage layer's CHECK constraint exactly.
/// A body over this bound is rejected here with 413 (`PayloadTooLarge`,
/// matching `SwanAccountEmailXRPC.swift`'s `.contentTooLarge` mapping) before
/// it ever reaches the database, so the constraint itself is never the thing
/// that fails an oversized write.
public enum SwanActorPreferencesXRPC {
    public static let maximumPreferencesJSONBytes = 1_048_576
}

/// Narrow OAuth boundary for the two `app.bsky.actor` preferences routes.
/// Mirrors ``SwanAccountEmailResourceAuthorizing`` exactly: tests can
/// substitute an authorizer without constructing bearer tokens or DPoP
/// proofs, and production delegates to the same sender-constrained resource
/// authorizer used by every other protected route.
public protocol SwanActorPreferencesResourceAuthorizing: Sendable {
    func authorizeActorPreferences(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext

    func issueActorPreferencesNonce(now: Date) async -> String
}

extension SwanOAuthResourceAuthorizer: SwanActorPreferencesResourceAuthorizing {
    public func authorizeActorPreferences(
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

    public func issueActorPreferencesNonce(now: Date) async -> String {
        issueNonce(now: now)
    }
}

private enum ActorPreferencesXRPCFailure: Error {
    case invalidRequest
    case payloadTooLarge
    case unauthorized
    case nonce
    case unavailable
}

/// The bundled dependency capability for the two `app.bsky.actor`
/// preferences routes, in the same shape as
/// ``SwanAccountEmailXRPCServer``: `SwanHTTPServer` holds one optional
/// instance of this type and registers it conditionally during
/// `buildRouter()`, exactly like `accountEmailXRPC`. A `nil` capability at
/// the server means the routes simply do not exist, the same as every other
/// optional capability on `SwanHTTPServer`.
public struct SwanActorPreferencesXRPCServer: Sendable {
    let authorizer: any SwanActorPreferencesResourceAuthorizing
    let store: any ActorPreferencesStore

    public init(
        authorizer: any SwanActorPreferencesResourceAuthorizing,
        store: any ActorPreferencesStore
    ) {
        self.authorizer = authorizer
        self.store = store
    }

    /// Installs the routes using the process-wide production body admission
    /// policy. Exposed for focused standalone testing of this capability in
    /// isolation from `SwanHTTPServer`.
    public func register(on router: Router<SwanHTTPRequestContext>) {
        registerSwanActorPreferencesXRPC(on: router, authorizer: authorizer, store: store)
    }

    /// Installs the routes using the caller's shared body admission policy.
    /// `SwanHTTPServer.buildRouter()` calls this so every route in the
    /// process shares the same admission instance, exactly like
    /// `accountEmailXRPC?.register(on:requestBodyAdmission:)`.
    func register(
        on router: Router<SwanHTTPRequestContext>,
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    ) {
        registerSwanActorPreferencesXRPC(
            on: router,
            authorizer: authorizer,
            store: store,
            requestBodyAdmission: requestBodyAdmission
        )
    }
}

/// Installs `app.bsky.actor.getPreferences` and `app.bsky.actor.putPreferences`
/// on an already assembled router, using the process-wide production body
/// admission policy. Callers must invoke this before constructing the
/// Hummingbird `Application`; adding routes after application construction is
/// unsupported by Hummingbird.
public func registerSwanActorPreferencesXRPC(
    on router: Router<SwanHTTPRequestContext>,
    authorizer: any SwanActorPreferencesResourceAuthorizing,
    store: any ActorPreferencesStore
) {
    registerSwanActorPreferencesXRPC(
        on: router,
        authorizer: authorizer,
        store: store,
        requestBodyAdmission: .init(
            admission: .processShared,
            policy: .productionDefault
        )
    )
}

func registerSwanActorPreferencesXRPC(
    on router: Router<SwanHTTPRequestContext>,
    authorizer: any SwanActorPreferencesResourceAuthorizing,
    store: any ActorPreferencesStore,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let getPath = RouterPath("/xrpc/\(AppBskyActorGetPreferences.typeIdentifier)")
    let putPath = RouterPath("/xrpc/\(AppBskyActorPutPreferences.typeIdentifier)")

    router.get(getPath) { request, context async -> Response in
        await handleGetActorPreferences(
            request,
            context: context,
            authorizer: authorizer,
            store: store
        )
    }
    router.post(putPath) { request, context async -> Response in
        await handlePutActorPreferences(
            request,
            context: context,
            authorizer: authorizer,
            store: store,
            requestBodyAdmission: requestBodyAdmission
        )
    }

    let allMethods: [HTTPRequest.Method] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ]
    for method in allMethods where method != .get {
        router.on(getPath, method: method) { _, _ -> Response in
            actorPreferencesError(.notFound, "EndpointUnavailable")
        }
    }
    for method in allMethods where method != .post {
        router.on(putPath, method: method) { _, _ -> Response in
            actorPreferencesError(.notFound, "EndpointUnavailable")
        }
    }
}

private func handleGetActorPreferences(
    _ request: Request,
    context: SwanHTTPRequestContext,
    authorizer: any SwanActorPreferencesResourceAuthorizing,
    store: any ActorPreferencesStore
) async -> Response {
    let path = "/xrpc/\(AppBskyActorGetPreferences.typeIdentifier)"
    let now = Date()
    do {
        guard request.uri.query?.isEmpty ?? true else {
            throw ActorPreferencesXRPCFailure.invalidRequest
        }
        let subject = try await authorizedActorPreferencesSubject(
            request,
            method: "GET",
            path: path,
            authorizer: authorizer,
            now: now
        )
        let stored = try await store.actorPreferences(did: subject)
        // An account that has never written preferences is not broken: it
        // must resolve to an empty array with 200, never 404.
        let body = stored ?? Data(#"{"preferences":[]}"#.utf8)
        return actorPreferencesJSON(.ok, body)
    } catch {
        return await actorPreferencesFailureResponse(
            for: error,
            authorizer: authorizer,
            now: now
        )
    }
}

private func handlePutActorPreferences(
    _ request: Request,
    context: SwanHTTPRequestContext,
    authorizer: any SwanActorPreferencesResourceAuthorizing,
    store: any ActorPreferencesStore,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
    let path = "/xrpc/\(AppBskyActorPutPreferences.typeIdentifier)"
    let now = Date()
    do {
        guard request.uri.query?.isEmpty ?? true else {
            try await drainRejectedRequestBody(
                request,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                termination: context.jsonWriteBodyTermination
            )
            throw ActorPreferencesXRPCFailure.invalidRequest
        }
        // Validate the body's shape before DPoP authorization, exactly like
        // the account-email routes: a malformed request must not consume the
        // proof's durable replay reservation.
        let json = try await collectValidatedActorPreferencesJSON(
            request,
            context: context,
            requestBodyAdmission: requestBodyAdmission
        )
        let subject = try await authorizedActorPreferencesSubject(
            request,
            method: "POST",
            path: path,
            authorizer: authorizer,
            now: now
        )
        // Always write under the authenticated subject. The request body
        // has no DID field at all in this lexicon, so there is nothing to
        // accidentally trust from the caller here.
        try await store.setActorPreferences(did: subject, json: json)
        return actorPreferencesSuccess()
    } catch {
        return await actorPreferencesFailureResponse(
            for: error,
            authorizer: authorizer,
            now: now
        )
    }
}

private func authorizedActorPreferencesSubject(
    _ request: Request,
    method: String,
    path: String,
    authorizer: any SwanActorPreferencesResourceAuthorizing,
    now: Date
) async throws -> String {
    let authorization: AuthorizationContext
    do {
        authorization = try await authorizer.authorizeActorPreferences(
            request: request,
            method: method,
            fixedPath: path,
            now: now
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        switch failure {
        case .nonceChallengeRequired:
            throw ActorPreferencesXRPCFailure.nonce
        case .denied:
            throw ActorPreferencesXRPCFailure.unauthorized
        case .unavailable:
            throw ActorPreferencesXRPCFailure.unavailable
        }
    } catch {
        throw ActorPreferencesXRPCFailure.unavailable
    }
    guard case let .accountOAuth(subject, scopes) = authorization,
          scopes.contains("atproto") else {
        throw ActorPreferencesXRPCFailure.unauthorized
    }
    return subject
}

/// Collects the PUT body under the shared admission policy and validates
/// only its wire shape: valid JSON, no duplicate members, exactly the one
/// `preferences` key, and that key holding an array. The array's elements
/// are deliberately not typed-decoded here — this boundary stores an opaque
/// document, exactly like the reference PDS.
private func collectValidatedActorPreferencesJSON(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> Data {
    let buffer: SwanAdmittedRequestBody
    do {
        buffer = try await collectAdmittedRequestBody(
            request,
            mediaType: .json,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: SwanActorPreferencesXRPC.maximumPreferencesJSONBytes,
            termination: context.jsonWriteBodyTermination
        )
    } catch let failure as SwanRequestBodyCollectionFailure {
        switch failure {
        case .invalidRequest:
            throw ActorPreferencesXRPCFailure.invalidRequest
        case .payloadTooLarge:
            throw ActorPreferencesXRPCFailure.payloadTooLarge
        case .unavailable:
            throw ActorPreferencesXRPCFailure.unavailable
        }
    } catch {
        throw ActorPreferencesXRPCFailure.invalidRequest
    }
    defer { withExtendedLifetime(buffer) {} }
    guard buffer.readableBytes > 0,
          let bytes = buffer.getBytes(
              at: buffer.readerIndex,
              length: buffer.readableBytes
          ) else {
        throw ActorPreferencesXRPCFailure.invalidRequest
    }
    let data = Data(bytes)
    do {
        try StrictJSON.validate(data)
        guard let object = try JSONSerialization.jsonObject(
            with: data,
            options: []
        ) as? [String: Any] else {
            throw ActorPreferencesXRPCFailure.invalidRequest
        }
        guard Set(object.keys) == ["preferences"],
              object["preferences"] is [Any] else {
            throw ActorPreferencesXRPCFailure.invalidRequest
        }
    } catch let failure as ActorPreferencesXRPCFailure {
        throw failure
    } catch {
        throw ActorPreferencesXRPCFailure.invalidRequest
    }
    return data
}

private func actorPreferencesFailureResponse(
    for error: any Error,
    authorizer: any SwanActorPreferencesResourceAuthorizing,
    now: Date
) async -> Response {
    if let failure = error as? ActorPreferencesXRPCFailure {
        switch failure {
        case .invalidRequest:
            return actorPreferencesError(.badRequest, "InvalidRequest")
        case .payloadTooLarge:
            return actorPreferencesError(.contentTooLarge, "PayloadTooLarge")
        case .unauthorized:
            return actorPreferencesError(.unauthorized, "Unauthorized")
        case .nonce:
            let nonce = await authorizer.issueActorPreferencesNonce(now: now)
            var headers: HTTPFields = [
                .contentType: "application/json",
                .cacheControl: "no-store",
                .wwwAuthenticate: #"DPoP error="use_dpop_nonce""#,
            ]
            headers[HTTPField.Name("DPoP-Nonce")!] = nonce
            return actorPreferencesError(
                .unauthorized,
                "use_dpop_nonce",
                headers: headers
            )
        case .unavailable:
            return actorPreferencesError(
                .serviceUnavailable,
                "temporarily_unavailable"
            )
        }
    }
    if let storageError = error as? AccountControlStoreError {
        return actorPreferencesError(
            storageError == .unavailable
                ? .serviceUnavailable
                : .badRequest,
            storageError == .unavailable
                ? "temporarily_unavailable"
                : "InvalidRequest"
        )
    }
    return actorPreferencesError(
        .serviceUnavailable,
        "temporarily_unavailable"
    )
}

private func actorPreferencesSuccess() -> Response {
    Response(status: .ok, headers: [.cacheControl: "no-store"])
}

private func actorPreferencesJSON(
    _ status: HTTPResponse.Status,
    _ data: Data
) -> Response {
    Response(
        status: status,
        headers: [
            .contentType: "application/json",
            .cacheControl: "no-store",
        ],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

private func actorPreferencesError(
    _ status: HTTPResponse.Status,
    _ code: String,
    headers: HTTPFields? = nil
) -> Response {
    struct Body: Encodable {
        let error: String
    }
    let data = (try? SwanJSONEncoders.sortedKeys.encode(Body(error: code))) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: headers ?? [
            .contentType: "application/json",
            .cacheControl: "no-store",
        ],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
