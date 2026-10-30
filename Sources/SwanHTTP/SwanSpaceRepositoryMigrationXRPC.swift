import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// October 29 sections 4 and 5d on the repo host: `com.atproto.space.clearRecords`
/// and `com.atproto.space.importRepo`, both for the account's own repo only.

/// The bound and admission for octet-stream import bodies (importRepo,
/// importSpaceMeta). They get their own small pool so an import can never
/// starve the shared JSON command admission, and a longer total deadline
/// sized for the body bound on a slow link.
enum SpaceImportBody {
    static let maximumBytes = 64 * 1_024 * 1_024
    static let admission = try! PublicRepositoryJSONWriteAdmission(
        maximumConcurrentWrites: 2,
        maximumReservedRequestBytes: 2 * maximumBytes
    )
    static let policy = try! SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(300))

    /// `Content-Type: application/octet-stream` and, when present, a
    /// canonical `Content-Length` within the bound.
    static func acceptsHeaders(_ request: Request) -> Bool {
        let contentTypes = request.headers[values: .contentType]
        guard contentTypes.count == 1,
              contentTypes[0].split(separator: ";", maxSplits: 1).first?
                .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "application/octet-stream"
        else { return false }
        let lengths = request.headers[values: .contentLength]
        guard lengths.count <= 1 else { return false }
        guard let value = lengths.first else { return true }
        guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
              value.first != "0", let length = Int(value) else { return false }
        return length <= maximumBytes
    }
}

private struct SpaceClearRecordsWireInput: Decodable {
    let space: String
    let repo: String
}

private struct SpaceEmptyWireOutput: Encodable {}

private struct AuthenticatedClearRecordsHandler {
    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(_ input: SpaceClearRecordsWireInput, request: Request) async throws {
        let space: SpaceURI
        let author: String
        do {
            space = try SpaceURI(SpaceRef(uriString: input.space).uriString())
            author = try DID(didString: input.repo).didString()
        } catch {
            throw AuthenticatedSpaceWriteFailure.invalidRequest
        }
        let authorization = try await authorizeWrite(
            capability.authorizer, request: request,
            fixedPath: "/xrpc/com.atproto.space.clearRecords"
        )
        try requireSelfWrite(authorization, author: author)
        do {
            _ = try await capability.directory.clearRepository(
                space: space, author: author, authorization: authorization
            )
        } catch {
            throw spaceRepositoryMigrationFailure(for: error)
        }
    }
}

private struct AuthenticatedImportRepoHandler {
    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(_ archive: Data, request: Request) async throws {
        let authorization = try await authorizeWrite(
            capability.authorizer, request: request,
            fixedPath: "/xrpc/com.atproto.space.importRepo"
        )
        let verified: VerifiedSpaceSTARRecovery
        do {
            verified = try SpaceSTARCodec.decodeImport(archive)
        } catch {
            throw AuthenticatedSpaceWriteFailure.invalidRequest
        }
        guard case let .accountOAuth(subject, _) = authorization else {
            throw AuthenticatedSpaceWriteFailure.denied
        }
        guard verified.commit.repo == subject else {
            // The reference: "Repo does not match the authenticated account".
            throw AuthenticatedSpaceWriteFailure.invalidRequest
        }
        do {
            try await capability.directory.importRepository(
                space: verified.commit.space,
                author: subject,
                records: verified.records,
                ltHash: verified.ltHash,
                authorization: authorization
            )
        } catch {
            throw spaceRepositoryMigrationFailure(for: error)
        }
    }
}

private func spaceRepositoryMigrationFailure(for error: any Error) -> AuthenticatedSpaceWriteFailure {
    if let failure = error as? AuthenticatedSpaceWriteFailure { return failure }
    if error is AuthorizedSimpleSpaceLifecycleError { return .declaredSpaceNotFound }
    guard let error = error as? SwanError else { return .unavailable }
    switch error {
    case .conflict: return .conflict
    case .unauthorized, .expired: return .denied
    case .invalidIdentifier, .malformed: return .invalidRequest
    case .invalidProfile, .unavailable: return .unavailable
    }
}

func registerAuthenticatedClearRecordsEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedClearRecordsHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.clearRecords"
    router.post(path) { request, context async -> Response in
        await withAuthenticatedSpaceWriteInput(
            request,
            context: context,
            as: SpaceClearRecordsWireInput.self,
            capability: capability
        ) { input in
            try await handler.handle(input, request: request)
            return authenticatedSpaceWriteJSON(.ok, SpaceEmptyWireOutput())
        }
    }
    registerAuthenticatedWriteWrongMethods(on: router, path: path)
}

func registerAuthenticatedImportRepoEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedImportRepoHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.importRepo"
    router.post(path) { request, context async -> Response in
        guard SpaceImportBody.acceptsHeaders(request) else {
            context.jsonWriteBodyTermination.terminate()
            return authenticatedSpaceWriteResponse(for: AuthenticatedSpaceWriteFailure.invalidRequest, capability: capability)
        }
        return await withAdmittedJSONWriteResponse(
            request.body,
            admission: SpaceImportBody.admission,
            policy: SpaceImportBody.policy,
            maximumBytes: SpaceImportBody.maximumBytes,
            termination: context.jsonWriteBodyTermination
        ) { data in
            data
        } operation: { archive in
            try await handler.handle(archive, request: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } errorResponse: { error in
            authenticatedSpaceWriteResponse(for: error, capability: capability)
        }
    }
    registerAuthenticatedWriteWrongMethods(on: router, path: path)
}
