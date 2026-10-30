import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// October 29 sections 5b and 5d on the space host:
/// `com.atproto.space.exportSpaceMeta` and `importSpaceMeta`, which move an
/// authority's space state between hosts with its account. Both answer
/// `NotSpaceOwner`, as the reference `assertSpaceOwner` does, when the space
/// is not anchored on the caller's DID.

private struct AuthenticatedExportSpaceMetaHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(space: SpaceURI, request: Request) async throws -> Data {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.exportSpaceMeta",
            method: "GET"
        )
        try requireSpaceOwner(authorization, space: space)
        do {
            let archive = try await capability.directory.exportSpaceMeta(space, authorization: authorization)
            return try SpaceMetaSTARCodec.encode(archive)
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedImportSpaceMetaHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ bytes: Data, request: Request) async throws {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.importSpaceMeta"
        )
        let archive: SpaceMetaArchive
        do {
            archive = try SpaceMetaSTARCodec.decode(bytes)
        } catch SpacePolicyError.unsupportedPolicy {
            throw AuthenticatedSimpleSpaceLifecycleFailure.unsupportedPolicy
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        try requireSpaceOwner(authorization, space: archive.space)
        do {
            try await capability.directory.importSpaceMeta(archive, authorization: authorization)
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private func requireSpaceOwner(_ authorization: AuthorizationContext, space: SpaceURI) throws {
    guard case let .accountOAuth(subject, _) = authorization else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.denied
    }
    guard subject == space.authority else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.notSpaceOwner
    }
}

func registerAuthenticatedSpaceMetaEndpoints(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let export = AuthenticatedExportSpaceMetaHandler(capability: capability)
    let exportPath: RouterPath = "/xrpc/com.atproto.space.exportSpaceMeta"
    router.get(exportPath) { request, _ async -> Response in
        do {
            let space = try parseExportSpaceMetaQuery(request)
            let archive = try await export.handle(space: space, request: request)
            return Response(
                status: .ok,
                headers: [
                    .contentType: SpaceSTARCodec.mediaType,
                    .cacheControl: "no-store",
                    .contentLength: String(archive.count),
                ],
                body: ResponseBody(byteBuffer: ByteBuffer(bytes: archive))
            )
        } catch let failure as AuthenticatedSimpleSpaceLifecycleFailure {
            return simpleSpaceLifecycleResponse(for: failure, capability: capability)
        } catch {
            return simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: exportPath, liveMethod: .get)

    let importer = AuthenticatedImportSpaceMetaHandler(capability: capability)
    let importPath: RouterPath = "/xrpc/com.atproto.space.importSpaceMeta"
    router.post(importPath) { request, context async -> Response in
        guard SpaceImportBody.acceptsHeaders(request) else {
            context.jsonWriteBodyTermination.terminate()
            return simpleSpaceLifecycleResponse(for: .invalidRequest, capability: capability)
        }
        return await withAdmittedJSONWriteResponse(
            request.body,
            admission: SpaceImportBody.admission,
            policy: SpaceImportBody.policy,
            maximumBytes: min(SpaceImportBody.maximumBytes, SpaceMetaSTARCodec.maximumArchiveBytes),
            termination: context.jsonWriteBodyTermination
        ) { data in
            data
        } operation: { bytes in
            try await importer.handle(bytes, request: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } errorResponse: { error in
            if let failure = error as? AuthenticatedSimpleSpaceLifecycleFailure {
                return simpleSpaceLifecycleResponse(for: failure, capability: capability)
            }
            if let failure = error as? SwanJSONWriteBodyCollectionFailure, case .unavailable = failure {
                return simpleSpaceLifecycleError(.serviceUnavailable, code: "temporarily_unavailable")
            }
            return simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: importPath, liveMethod: .post)
}

/// Exactly one `space` query parameter.
private func parseExportSpaceMetaQuery(_ request: Request) throws -> SpaceURI {
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          query.utf8.count <= 4_096 else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    let pair = query.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
    guard pair.count == 2, pair[0] == "space", !pair[1].contains("&") else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    return try lifecycleSpace(try strictQueryDecode(pair[1]))
}
