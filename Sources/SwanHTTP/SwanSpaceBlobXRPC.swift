import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSpacesWire
import SwanStorage

private let maximumPermissionedBlobTransferBytes = 256 * 1024 * 1024

/// The composed capability for one permissioned blob read.  It contains only
/// the process-bound DPoP authorizer, a startup-preopened blob directory, and
/// an optional offline/pinned credential verifier; the route receives neither
/// a filesystem path nor a database/key handle.
public struct SwanAuthenticatedSpaceBlobCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSpaceBlobDirectory
    let credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?
    let streamAdmission: PublicRepositorySpoolAdmission

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSpaceBlobDirectory,
        credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?,
        streamAdmission: PublicRepositorySpoolAdmission = .shared
    ) {
        self.authorizer = authorizer
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        self.streamAdmission = streamAdmission
    }
}

private enum AuthenticatedSpaceBlobFailure: Error {
    case invalidRequest
    case blobNotFound
    case denied
    case nonceChallenge
    case unavailable
}

/// The metadata read and the body open are separate calls into the same
/// directory and must fail identically: a caller that can tell the two apart
/// learns from the *first* one whether a private blob exists.
private func blobFailure(for error: SwanError) -> AuthenticatedSpaceBlobFailure {
    switch error {
    case .unauthorized:
        .denied
    case .malformed, .invalidIdentifier:
        .invalidRequest
    case .unavailable, .invalidProfile, .conflict, .expired:
        .unavailable
    }
}

/// `getBlob`'s generated output is currently `Data`, which cannot represent
/// the alpha's bounded-memory response.  As with `getRepo`, the generated
/// server contract owns the typed request boundary while `prepare` returns an
/// opaque, already-open body for the Hummingbird streaming adapter.  Calling
/// `handle` would allocate the complete private blob and is deliberately
/// unavailable.
private struct AuthenticatedGetSpaceBlobHandler:
    ComAtprotoSpaceGetBlob.ServerHandler
{
    typealias Context = Request

    struct PreparedResponse: Sendable {
        let cid: CID
        let mimeType: String
        let blob: AuthorizedSpaceBlob
        let streamLease: PublicRepositorySpoolLease
    }

    let capability: SwanAuthenticatedSpaceBlobCapability

    func prepare(
        parameters: ComAtprotoSpaceGetBlob.Parameters,
        context request: Request
    ) async throws -> PreparedResponse {
        let target = try blobTarget(parameters)
        let authorization = try await authorizeBlobRead(
            capability,
            request: request,
            expectedSpace: target.space
        )
        try requireBlobReadAuthorization(authorization, author: target.author)

        // The transfer budget is a *byte* budget, and the lease this method
        // returns outlives the handler: it is released only when the response
        // writer finishes, i.e. for as long as the reader takes. Reserving a
        // fixed 256 MiB ceiling for the whole of that window is what the
        // finding is about — a 5 KiB avatar would cost a quarter of one
        // author's 512 MiB allowance, so two stalled tiny reads exhaust an
        // author and four exhaust the whole 1 GiB pool, starving the public
        // CAR, public blob, and blob-upload streams that share it while
        // moving almost nothing.
        //
        // The blob's declared length, read without opening or materializing a
        // body, so the reservation below covers exactly the bytes this
        // response will stream — the same shape `SwanPublicRepositoryReadXRPC`
        // uses via `publicBlobMetadata`. The ceiling survives only as the
        // bound on what this route will serve at all.
        //
        // This is what makes the *admission* right-sized, not just the held
        // reservation: a pool with 4 KiB free now admits a 4 KiB blob. An
        // earlier fix reserved the ceiling and then shrank the lease in place,
        // which right-sized the stall window but still refused that request
        // outright, so concurrency stayed pinned at two reads per account
        // regardless of size.
        let metadata: AuthorizedSpaceBlobMetadata?
        do {
            metadata = try await capability.directory.spaceBlobMetadata(
                space: target.space,
                author: target.author,
                cid: target.cid.string,
                authorization: authorization
            )
        } catch let error as SwanError {
            throw blobFailure(for: error)
        } catch {
            throw AuthenticatedSpaceBlobFailure.unavailable
        }
        guard let metadata else { throw AuthenticatedSpaceBlobFailure.blobNotFound }
        guard metadata.size > 0,
              metadata.size <= maximumPermissionedBlobTransferBytes else {
            throw AuthenticatedSpaceBlobFailure.unavailable
        }
        guard let streamLease = capability.streamAdmission.reserve(
            accountDID: target.author,
            maximumBytes: metadata.size
        ) else {
            throw AuthenticatedSpaceBlobFailure.unavailable
        }
        // A single lease, so no throw between here and the hand-off can
        // leak a second one.
        var handedOff = false
        defer {
            if !handedOff { streamLease.release() }
        }

        let blob: AuthorizedSpaceBlob?
        do {
            blob = try await capability.directory.spaceBlob(
                space: target.space,
                author: target.author,
                cid: target.cid.string,
                authorization: authorization
            )
        } catch let error as SwanError {
            throw blobFailure(for: error)
        } catch {
            throw AuthenticatedSpaceBlobFailure.unavailable
        }
        guard let blob else { throw AuthenticatedSpaceBlobFailure.blobNotFound }
        // A blob is content-addressed and immutable, so the opened body must
        // declare exactly the length the metadata did. Anything else means the
        // reservation does not cover the transfer it admitted — strictly worse
        // than reserving the ceiling — so the bytes do not leave. The same
        // declared length is what sizes the reservation, what is emitted as
        // `Content-Length`, and what the response writer refuses to move a
        // byte past.
        guard blob.body.contentLength == metadata.size else {
            throw AuthenticatedSpaceBlobFailure.unavailable
        }
        handedOff = true
        return PreparedResponse(
            cid: target.cid,
            mimeType: safeResponseMIMEType(blob.mimeType),
            blob: blob,
            streamLease: streamLease
        )
    }

    func handle(
        parameters: ComAtprotoSpaceGetBlob.Parameters,
        input _: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetBlob.Output {
        let prepared = try await prepare(parameters: parameters, context: request)
        prepared.streamLease.release()
        throw AuthenticatedSpaceBlobFailure.unavailable
    }
}

func registerAuthenticatedGetSpaceBlobEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceBlobCapability
) {
    let handler = AuthenticatedGetSpaceBlobHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getBlob"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceGetBlob.Parameters
        do {
            parameters = try parseAuthenticatedGetSpaceBlobParameters(request)
        } catch {
            return authenticatedSpaceBlobError(.badRequest, code: "InvalidRequest")
        }
        do {
            let prepared = try await handler.prepare(
                parameters: parameters,
                context: request
            )
            var headers: HTTPFields = [
                .contentType: prepared.mimeType,
                .cacheControl: "no-store",
            ]
            headers[.contentLength] = String(prepared.blob.body.contentLength)
            headers[HTTPField.Name("X-Content-Type-Options")!] = "nosniff"
            headers[HTTPField.Name("Content-Disposition")!] =
                "attachment; filename=\"\(prepared.cid.string)\""
            headers[HTTPField.Name("Content-Security-Policy")!] =
                "default-src 'none'; sandbox"
            return Response(
                status: .ok,
                headers: headers,
                body: .init { writer in
                    defer { prepared.streamLease.release() }
                    // The reservation held across this stream, the
                    // `Content-Length` emitted above, and this bound are all
                    // the same declared length. A body that delivered more
                    // than it declared would move bytes the reservation does
                    // not cover — strictly worse than reserving the ceiling —
                    // so the surplus is refused rather than written. A body
                    // that delivers less is refused too, rather than
                    // completing a response whose framing lies about it.
                    let declaredLength = prepared.blob.body.contentLength
                    var writtenBytes = 0
                    try await prepared.blob.body.streamBody(
                        maximumChunkBytes: 64 * 1_024
                    ) { chunk in
                        guard chunk.count <= declaredLength - writtenBytes else {
                            throw AuthenticatedSpaceBlobFailure.unavailable
                        }
                        writtenBytes += chunk.count
                        try await writer.write(ByteBuffer(data: chunk))
                    }
                    guard writtenBytes == declaredLength else {
                        throw AuthenticatedSpaceBlobFailure.unavailable
                    }
                    try await writer.finish(nil)
                }
            )
        } catch let failure as AuthenticatedSpaceBlobFailure {
            return authenticatedSpaceBlobResponse(for: failure, capability: capability)
        } catch {
            return authenticatedSpaceBlobError(
                .serviceUnavailable,
                code: "temporarily_unavailable"
            )
        }
    }
    registerAuthenticatedSpaceBlobWrongMethods(on: router, path: path)
}

private func blobTarget(
    _ parameters: ComAtprotoSpaceGetBlob.Parameters
) throws -> (space: SpaceURI, author: String, cid: CID) {
    do {
        let space = try SpaceURI(parameters.space.uriString())
        let author = parameters.repo.didString()
        // Retain the same strict account/repository grammar used by record and
        // sync reads without fabricating a record that could be serialized.
        _ = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.swan.blob",
            rkey: "scope"
        )
        let cid = parameters.cid
        guard cid.string == parameters.cid.string,
              cid.codec == .raw,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length) else {
            throw AuthenticatedSpaceBlobFailure.invalidRequest
        }
        return (space, author, cid)
    } catch let failure as AuthenticatedSpaceBlobFailure {
        throw failure
    } catch {
        throw AuthenticatedSpaceBlobFailure.invalidRequest
    }
}

private func authorizeBlobRead(
    _ capability: SwanAuthenticatedSpaceBlobCapability,
    request: Request,
    expectedSpace: SpaceURI
) async throws -> AuthorizationContext {
    let bearer: String?
    do {
        bearer = try spaceCredentialSchemeToken(from: request.headers)
    } catch {
        throw AuthenticatedSpaceBlobFailure.denied
    }
    if let bearer {
        guard let verifier = capability.credentialAuthorizer else {
            throw AuthenticatedSpaceBlobFailure.denied
        }
        do {
            return try await verifier.authorization(
                for: bearer,
                expectedSpace: expectedSpace,
                now: Date()
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AuthenticatedSpaceBlobFailure.unavailable
            }
            throw AuthenticatedSpaceBlobFailure.denied
        } catch {
            throw AuthenticatedSpaceBlobFailure.denied
        }
    }
    do {
        return try await capability.authorizer.authorize(
            request: request,
            method: "GET",
            fixedPath: "/xrpc/com.atproto.space.getBlob"
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        throw switch failure {
        case .nonceChallengeRequired: AuthenticatedSpaceBlobFailure.nonceChallenge
        case .denied: AuthenticatedSpaceBlobFailure.denied
        case .unavailable: AuthenticatedSpaceBlobFailure.unavailable
        }
    } catch {
        throw AuthenticatedSpaceBlobFailure.unavailable
    }
}

private func requireBlobReadAuthorization(
    _ authorization: AuthorizationContext,
    author: String
) throws {
    switch authorization {
    case let .accountOAuth(subject, _) where subject == author:
        return
    case .spaceCredential:
        return
    default:
        // A foreign account token never learns whether a target repository or
        // blob exists.  Keep this indistinguishable from ordinary denial.
        throw AuthenticatedSpaceBlobFailure.denied
    }
}

private let spaceGetBlobQuerySchema = StrictQuerySchema(
    required: ["space", "repo", "cid"]
)

private func parseAuthenticatedGetSpaceBlobParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetBlob.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        schema: spaceGetBlobQuerySchema
    )
    let space = try SpaceRef(
        uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048)
    )
    let repo = try DID(
        didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048)
    )
    let rawCID = try requiredQueryValue("cid", in: query, maximumBytes: 256)
    let cid = try CID.parse(rawCID)
    guard cid.string == rawCID,
          cid.codec == .raw,
          cid.multihash.algorithm == Multihash.sha256Code,
          cid.multihash.length == Multihash.sha256Length,
          cid.multihash.digest.count == Int(Multihash.sha256Length) else {
        throw AuthenticatedSpaceBlobFailure.invalidRequest
    }
    let parameters = ComAtprotoSpaceGetBlob.Parameters(
        space: space,
        repo: repo,
        cid: cid
    )
    _ = try blobTarget(parameters)
    return parameters
}

private func safeResponseMIMEType(_ value: String?) -> String {
    guard let value,
          !value.isEmpty,
          value.utf8.count <= 255,
          value.utf8.allSatisfy({ byte in
              (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                  || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                  || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                  || "!#$&^_.+-/".utf8.contains(byte)
          }),
          value.filter({ $0 == "/" }).count == 1,
          !value.hasPrefix("/"), !value.hasSuffix("/") else {
        return "application/octet-stream"
    }
    return value
}

private func registerAuthenticatedSpaceBlobWrongMethods(
    on router: Router<BasicRequestContext>,
    path: RouterPath
) {
    for method: HTTPRequest.Method in [
        .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ] {
        router.on(path, method: method) { _, _ -> Response in
            authenticatedSpaceBlobError(
                .notFound,
                code: "permissioned_endpoint_unavailable"
            )
        }
    }
}

private func authenticatedSpaceBlobResponse(
    for failure: AuthenticatedSpaceBlobFailure,
    capability: SwanAuthenticatedSpaceBlobCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedSpaceBlobError(.badRequest, code: "InvalidRequest")
    case .blobNotFound:
        authenticatedSpaceBlobError(.notFound, code: "BlobNotFound")
    case .denied:
        authenticatedSpaceBlobError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        authenticatedSpaceBlobError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func authenticatedSpaceBlobError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}
