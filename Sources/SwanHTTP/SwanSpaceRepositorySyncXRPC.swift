import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The narrowly composed capability for the two read-only incremental-sync
/// endpoints.  It carries neither a SQLite handle nor raw key material: the
/// preopened directory returns safe durable projections, and the signer can
/// only construct a fixed reader-bound permissioned commit.
public struct SwanAuthenticatedSpaceRepositorySyncCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSpaceRepositoryDirectory
    let credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?
    let commitSigner: any SpaceRepositoryCommitSigner
    let jsonReadAdmission: PublicRepositoryJSONReadAdmission

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSpaceRepositoryDirectory,
        credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?,
        commitSigner: any SpaceRepositoryCommitSigner,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission = .processShared
    ) {
        self.authorizer = authorizer
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        self.commitSigner = commitSigner
        self.jsonReadAdmission = jsonReadAdmission
    }
}

private enum AuthenticatedSpaceRepositorySyncFailure: Error {
    case invalidRequest
    case spaceNotFound
    case repoNotFound
    case denied
    case credentialPresentation(SpaceCredentialPresentationFailure)
    case nonceChallenge
    case fullRecoveryRequired
    case malformedCursor
    case unavailable
}

/// The generated contract's `Output` currently contains a whole `Data`
/// payload even though its lexicon output is a streamed STAR archive
/// (`application/octet-stream`). The
/// semantic handler therefore conforms to the generated contract for its
/// typed parameter/context boundary, while the Hummingbird adapter invokes
/// `prepare` and streams the resulting suffix. Calling `handle` would force
/// an unsafe response-wide allocation and is intentionally unavailable.
private struct AuthenticatedGetRepoHandler:
    ComAtprotoSpaceGetRepo.ServerHandler
{
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRepositorySyncCapability

    struct PreparedResponse: Sendable {
        let prefix: Data
        let spool: SpaceSTARBodySpool
        let mac: Data?
    }

    func prepare(parameters: ComAtprotoSpaceGetRepo.Parameters, context request: Request) async throws -> PreparedResponse {
        let target = try syncTarget(parameters.space, parameters.repo)
        let authorization = try await authorizeRepositorySyncRead(
            capability, request: request, expectedSpace: target.space,
            expectedAudience: target.author, fixedPath: "/xrpc/com.atproto.space.getRepo"
        )
        try requireRepositoryReadAuthorization(authorization, author: target.author)
        let secret = try await spaceResponseMACSecret(
            request: request, author: target.author, type: .repository, provider: capability.commitSigner
        )
        guard let snapshot = try await capability.directory.repositorySTARSnapshot(
            space: target.space, author: target.author, authorization: authorization
        ) else { throw AuthenticatedSpaceRepositorySyncFailure.repoNotFound }
        do {
            guard snapshot.state.space == target.space, snapshot.state.author == target.author,
                  let revision = snapshot.state.wireRevision else {
                throw AuthenticatedSpaceRepositorySyncFailure.unavailable
            }
            let commit = try SpaceRepositoryCommit(repo: target.author, space: target.space,
                                                   rev: revision, data: snapshot.state.commitment)
            return PreparedResponse(prefix: try SpaceSTARCodec.prefix(commit: commit),
                                    spool: snapshot.spool, mac: try secret.map { try commit.mac(sharedSecret: $0) })
        } catch { snapshot.spool.cleanup(); throw error }
    }

    func handle(
        parameters: ComAtprotoSpaceGetRepo.Parameters,
        input _: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetRepo.Output {
        let prepared = try await prepare(parameters: parameters, context: request)
        prepared.spool.cleanup()
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
}

private struct AuthenticatedGetLatestCommitHandler:
    ComAtprotoSpaceGetLatestCommit.ServerHandler
{
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRepositorySyncCapability
    let fixedPath: String

    func handle(
        parameters: ComAtprotoSpaceGetLatestCommit.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetLatestCommit.Output {
        let target = try syncTarget(parameters.space, parameters.repo)
        let authorization = try await authorizeRepositorySyncRead(
            capability,
            request: request,
            expectedSpace: target.space,
            expectedAudience: target.author,
            fixedPath: fixedPath
        )
        try requireRepositoryReadAuthorization(authorization, author: target.author)
        let state = try await repositoryCommitState(
            capability,
            space: target.space,
            author: target.author,
            authorization: authorization
        )
        guard let commit = try await signedCommit(
            state: state,
            expectedSpace: target.space,
            expectedAuthor: target.author,
            capability: capability
        ) else {
            // The live lexicon requires `commit` and declares RepoNotFound
            // for an account holding no repo in the space.
            throw AuthenticatedSpaceRepositorySyncFailure.repoNotFound
        }
        return .init(commit: commit)
    }
}

private struct AuthenticatedListRepoOpsHandler:
    ComAtprotoSpaceListRepoOps.ServerHandler
{
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRepositorySyncCapability

    func handle(
        parameters: ComAtprotoSpaceListRepoOps.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceListRepoOps.Output {
        let target = try syncTarget(parameters.space, parameters.repo)
        let authorization = try await authorizeRepositorySyncRead(
            capability,
            request: request,
            expectedSpace: target.space,
            expectedAudience: target.author,
            fixedPath: "/xrpc/com.atproto.space.listRepoOps"
        )
        try requireRepositoryReadAuthorization(authorization, author: target.author)

        let limit = parameters.limit ?? 100
        guard (1 ... 1_000).contains(limit) else {
            throw AuthenticatedSpaceRepositorySyncFailure.invalidRequest
        }
        // The reference cursor (`${rev}/${idx}`) takes precedence over
        // `since`. Swan never splits one revision's atomic batch across pages
        // (see below), so every cursor Swan issues ends a revision and
        // resuming strictly after that revision is exact.
        let resumeAfter: String?
        if let cursor = parameters.cursor {
            resumeAfter = try parseRepositoryOplogCursor(cursor).revision
        } else {
            resumeAfter = parameters.since?.toString()
        }
        let read: AuthorizedSpaceRepositoryOplogRead
        do {
            read = try await capability.directory.repositoryOplog(
                space: target.space,
                author: target.author,
                since: resumeAfter,
                limit: limit,
                includeValues: parameters.excludeValues != true,
                maximumAggregateValueBytes: PublicRepositoryJSONReadLimits
                    .maximumListRepoOpsValueBytes,
                authorization: authorization
            )
        } catch let error as SwanError {
            if case .unauthorized = error {
                throw AuthenticatedSpaceRepositorySyncFailure.denied
            }
            if case .malformed = error {
                throw AuthenticatedSpaceRepositorySyncFailure.invalidRequest
            }
            throw AuthenticatedSpaceRepositorySyncFailure.unavailable
        } catch {
            throw AuthenticatedSpaceRepositorySyncFailure.unavailable
        }

        switch read {
        case .fullRecoveryRequired:
            throw AuthenticatedSpaceRepositorySyncFailure.fullRecoveryRequired
        case let .incremental(state, entries):
            let operations = try entries.map(syncWireOperation)
            let commit: ComAtprotoSpaceDefs.Commit?
            // This is deliberately the reference condition, not `ops.isEmpty`:
            // an exactly-full final page does not bind a head commit until the
            // caller asks again and receives the short/empty page. Storage can
            // extend the terminal revision beyond `limit` rather than split a
            // same-TID atomic batch that this endpoint's `since` cursor could
            // not resume; that conservative overflow likewise gets its commit
            // on the following empty page.
            if operations.count < limit {
                commit = try await signedCommit(
                    state: state,
                    expectedSpace: target.space,
                    expectedAuthor: target.author,
                    capability: capability
                )
            } else {
                commit = nil
            }
            // Like the reference, a cursor accompanies exactly the pages that
            // carry no commit (more may follow).
            var cursor: String?
            if commit == nil, let last = operations.last {
                let lastRevision = last.rev.toString()
                let index = operations.reduce(-1) {
                    $1.rev.toString() == lastRevision ? $0 + 1 : $0
                }
                cursor = formatRepositoryOplogCursor(
                    revision: lastRevision,
                    index: index
                )
            }
            return .init(ops: operations, commit: commit, cursor: cursor)
        }
    }
}

/// Parses the reference `listRepoOps` cursor, `${rev}/${idx}`. Anything else
/// is the lexicon's `InvalidCursor`.
private func parseRepositoryOplogCursor(
    _ cursor: String
) throws -> (revision: String, index: Int) {
    let parts = cursor.split(separator: "/", omittingEmptySubsequences: false)
    guard cursor.utf8.count <= 64,
          parts.count == 2,
          let revision = try? TID(tidString: String(parts[0])),
          !parts[1].isEmpty,
          parts[1].utf8.count <= 9,
          parts[1].utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
          let index = Int(parts[1]) else {
        throw AuthenticatedSpaceRepositorySyncFailure.malformedCursor
    }
    return (revision.toString(), index)
}

private func formatRepositoryOplogCursor(revision: String, index: Int) -> String {
    "\(revision)/\(index)"
}

private func syncTarget(
    _ spaceValue: SpaceRef,
    _ repoValue: DID
) throws -> (space: SpaceURI, author: String) {
    do {
        let space = try SpaceURI(spaceValue.uriString())
        let author = repoValue.didString()
        // Use a synthetic domain record to ensure the generated DID is also
        // accepted by Swan's repository author grammar before auth work.
        _ = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.swan.repository",
            rkey: "sync"
        )
        return (space, author)
    } catch {
        throw AuthenticatedSpaceRepositorySyncFailure.invalidRequest
    }
}

private func requireRepositoryReadAuthorization(
    _ authorization: AuthorizationContext,
    author: String
) throws {
    switch authorization {
    case let .accountOAuth(subject, _) where subject == author:
        return
    case .spaceCredential:
        return
    default:
        // OAuth for another repository must not reveal whether this one has
        // state, retained operations, or a valid account database.
        throw AuthenticatedSpaceRepositorySyncFailure.spaceNotFound
    }
}

/// A credential reading a repo signs the repo owner's DID as its audience
/// (`expectedAudience`); OAuth keeps its DPoP sender constraint.
private func authorizeRepositorySyncRead(
    _ capability: SwanAuthenticatedSpaceRepositorySyncCapability,
    request: Request,
    expectedSpace: SpaceURI,
    expectedAudience: String,
    fixedPath: String
) async throws -> AuthorizationContext {
    let bearerToken: String?
    do {
        bearerToken = try spaceCredentialSchemeToken(from: request.headers)
    } catch let failure as SpaceCredentialPresentationFailure {
        throw AuthenticatedSpaceRepositorySyncFailure.credentialPresentation(failure)
    } catch {
        throw AuthenticatedSpaceRepositorySyncFailure.denied
    }
    if let bearerToken {
        guard let credentialAuthorizer = capability.credentialAuthorizer else {
            throw AuthenticatedSpaceRepositorySyncFailure.denied
        }
        do {
            return try await capability.authorizer.authorizeSpaceCredential(
                bearerToken,
                verifier: credentialAuthorizer,
                request: request,
                expectedSpace: expectedSpace,
                expectedAudience: expectedAudience,
                now: Date()
            )
        } catch let failure as SpaceCredentialPresentationFailure {
            throw AuthenticatedSpaceRepositorySyncFailure.credentialPresentation(failure)
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AuthenticatedSpaceRepositorySyncFailure.unavailable
            }
            throw AuthenticatedSpaceRepositorySyncFailure.denied
        } catch {
            throw AuthenticatedSpaceRepositorySyncFailure.denied
        }
    }
    do {
        return try await capability.authorizer.authorizeSpaceRoute(
            request: request,
            method: "GET",
            fixedPath: fixedPath
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        throw switch failure {
        case .nonceChallengeRequired: AuthenticatedSpaceRepositorySyncFailure.nonceChallenge
        case .denied: AuthenticatedSpaceRepositorySyncFailure.denied
        case .unavailable: AuthenticatedSpaceRepositorySyncFailure.unavailable
        }
    } catch {
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
}

private func repositoryCommitState(
    _ capability: SwanAuthenticatedSpaceRepositorySyncCapability,
    space: SpaceURI,
    author: String,
    authorization: AuthorizationContext
) async throws -> AuthorizedSpaceRepositoryCommitState {
    do {
        let state = try await capability.directory.repositoryCommitState(
            space: space,
            author: author,
            authorization: authorization
        )
        guard state.space == space, state.author == author,
              state.commitment.count == 32 else {
            throw AuthenticatedSpaceRepositorySyncFailure.unavailable
        }
        if let revision = state.wireRevision {
            _ = try TID(tidString: revision)
        }
        return state
    } catch let failure as AuthenticatedSpaceRepositorySyncFailure {
        throw failure
    } catch let error as SwanError {
        if case .unauthorized = error {
            throw AuthenticatedSpaceRepositorySyncFailure.denied
        }
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    } catch {
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
}

private func signedCommit(
    state: AuthorizedSpaceRepositoryCommitState,
    expectedSpace: SpaceURI,
    expectedAuthor: String,
    capability: SwanAuthenticatedSpaceRepositorySyncCapability
) async throws -> ComAtprotoSpaceDefs.Commit? {
    guard let revision = state.wireRevision else { return nil }
    guard state.space == expectedSpace, state.author == expectedAuthor,
          state.commitment.count == 32 else {
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
    return .init(
        ver: 1, repo: try DID(didString: expectedAuthor),
        space: try SpaceRef(uriString: expectedSpace.rawValue),
        rev: try TID(tidString: revision), data: Bytes(data: state.commitment)
    )
}

private func syncWireOperation(
    _ entry: AuthorizedSpaceRepositoryOplogEntry
) throws -> ComAtprotoSpaceListRepoOps.OpEntry {
    let revision = try TID(tidString: entry.wireRevision)
    let collection = try NSID(nsidString: entry.collection)
    let rkey = try RecordKey(keyString: entry.rkey)
    let cid = try entry.cid.map(CID.parse)
    let previousCID = try entry.previousCID.map(CID.parse)
    // SQLite validates these relations while decoding its durable action.
    // Repeat the check at this trust boundary so an alternate directory or a
    // corrupted projection cannot render an ambiguous nullable-CID operation.
    switch (cid, previousCID) {
    case (.some, nil), (.some, .some):
        break // create or update
    case (nil, .some):
        guard entry.value == nil else {
            throw AuthenticatedSpaceRepositorySyncFailure.unavailable
        }
    case (nil, nil):
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
    if let value = entry.value {
        guard let cid,
              CID.fromDAGCBOR(value) == cid else {
            throw AuthenticatedSpaceRepositorySyncFailure.unavailable
        }
        return .init(
            rev: revision,
            collection: collection,
            rkey: rkey,
            cid: cid,
            prev: previousCID,
            value: try CARRepository.decodeRecordCBOR(value)
        )
    }
    return .init(
        rev: revision,
        collection: collection,
        rkey: rkey,
        cid: cid,
        prev: previousCID,
        value: nil
    )
}

/// The alias name for `com.atproto.space.getLatestCommit`.
///
/// `getLatestCommit` is the canonical proposal name; `getRepoState` is the
/// name the atproto-crates reference PDS shipped before the draft settled,
/// kept there (and in pds.js) as an alias to the same handler. Clients built
/// on those crates — bulleted.app — probe for the alias and treat a 404 as
/// "no spaces plane", so Swan serves both names for the one method.
let spaceGetRepoStateAliasNSID = "com.atproto.space.getRepoState"

func registerAuthenticatedGetLatestCommitEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRepositorySyncCapability
) {
    let paths = [
        "/xrpc/com.atproto.space.getLatestCommit",
        "/xrpc/\(spaceGetRepoStateAliasNSID)",
    ]
    for fixedPath in paths {
        let path = RouterPath(fixedPath)
        let handler = AuthenticatedGetLatestCommitHandler(
            capability: capability, fixedPath: fixedPath
        )
        router.get(path) { request, _ async -> Response in
            let parameters: ComAtprotoSpaceGetLatestCommit.Parameters
            do {
                parameters = try parseAuthenticatedGetLatestCommitParameters(request)
            } catch {
                return authenticatedRepositorySyncError(.badRequest, code: "InvalidRequest")
            }
            do {
                let output = try await handler.handle(parameters: parameters, input: (), context: request)
                let secret = try await spaceResponseMACSecret(
                    request: request, author: parameters.repo.didString(), type: .repository,
                    provider: capability.commitSigner
                )
                let mac = try secret.map { try responseCommit(output.commit).mac(sharedSecret: $0) }
                return try withSpaceResponseMAC(authenticatedGetLatestCommitJSON(.ok, output), mac: mac, type: .repository)
            } catch is SpaceMACHeaders.HeaderError {
                return authenticatedRepositorySyncError(.badRequest, code: "InvalidSpaceMac")
            } catch let failure as AuthenticatedSpaceRepositorySyncFailure {
                return authenticatedRepositorySyncResponse(for: failure, capability: capability)
            } catch {
                return authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
            }
        }
        registerAuthenticatedRepositorySyncWrongMethods(on: router, path: path)
    }
}

func registerAuthenticatedListRepoOpsEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRepositorySyncCapability
) {
    let handler = AuthenticatedListRepoOpsHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.listRepoOps"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceListRepoOps.Parameters
        do {
            parameters = try parseAuthenticatedListRepoOpsParameters(request)
        } catch AuthenticatedSpaceRepositorySyncFailure.malformedCursor {
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidCursor")
        } catch {
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidRequest")
        }
        guard let lease = capability.jsonReadAdmission.reserve(
            maximumResponseBytes: PublicRepositoryJSONReadLimits
                .maximumListRecordsResponseBytes
        ) else {
            return authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
        }
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            let secret = try await spaceResponseMACSecret(
                request: request, author: parameters.repo.didString(), type: .repository,
                provider: capability.commitSigner
            )
            let mac: Data?
            if let secret, let commit = output.commit { mac = try responseCommit(commit).mac(sharedSecret: secret) }
            else { mac = nil }
            return try withSpaceResponseMAC(authenticatedListRepoOpsJSON(.ok, output, lease: lease), mac: mac, type: .repository)
        } catch is SpaceMACHeaders.HeaderError {
            lease.release()
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidSpaceMac")
        } catch let failure as AuthenticatedSpaceRepositorySyncFailure {
            lease.release()
            return authenticatedRepositorySyncResponse(for: failure, capability: capability)
        } catch {
            lease.release()
            return authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRepositorySyncWrongMethods(on: router, path: path)
}

func registerAuthenticatedGetRepoEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRepositorySyncCapability
) {
    let handler = AuthenticatedGetRepoHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getRepo"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceGetRepo.Parameters
        do {
            parameters = try parseAuthenticatedGetRepoParameters(request)
        } catch {
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidRequest")
        }
        do {
            let prepared = try await handler.prepare(parameters: parameters, context: request)
            // No content length is supplied: writing directly from the private
            // spool is the deliberate bounded-memory transport contract.
            return try withSpaceResponseMAC(Response(
                status: .ok,
                headers: [
                    .contentType: SpaceSTARCodec.mediaType,
                    .cacheControl: "no-store",
                ],
                body: .init { writer in
                    defer { prepared.spool.cleanup() }
                    try await writer.write(ByteBuffer(data: prepared.prefix))
                    try await prepared.spool.streamBody { chunk in
                        try await writer.write(ByteBuffer(data: chunk))
                    }
                    try await writer.finish(nil)
                }
            ), mac: prepared.mac, type: .repository)
        } catch is SpaceMACHeaders.HeaderError {
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidSpaceMac")
        } catch let failure as AuthenticatedSpaceRepositorySyncFailure {
            return authenticatedRepositorySyncResponse(for: failure, capability: capability)
        } catch {
            return authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRepositorySyncWrongMethods(on: router, path: path)
}

private let spaceGetLatestCommitQuerySchema = StrictQuerySchema(
    required: ["space", "repo"]
)
private let spaceListRepoOpsQuerySchema = StrictQuerySchema(
    required: ["space", "repo"],
    optional: ["since", "limit", "cursor", "excludeValues"]
)
private let spaceGetRepoQuerySchema = StrictQuerySchema(required: ["space", "repo"])

private func parseAuthenticatedGetLatestCommitParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetLatestCommit.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        schema: spaceGetLatestCommitQuerySchema
    )
    let space = try SpaceRef(
        uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048)
    )
    let repo = try DID(
        didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048)
    )
    _ = try syncTarget(space, repo)
    return .init(space: space, repo: repo)
}

private func parseAuthenticatedListRepoOpsParameters(
    _ request: Request
) throws -> ComAtprotoSpaceListRepoOps.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        schema: spaceListRepoOpsQuerySchema
    )
    let space = try SpaceRef(
        uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048)
    )
    let repo = try DID(
        didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048)
    )
    _ = try syncTarget(space, repo)
    let since = try query["since"].map {
        let value = try bounded($0, maximumBytes: 32)
        return try TID(tidString: value)
    }
    let limit = try query["limit"].map(strictRepositoryOplogLimit)
    let cursor = try query["cursor"].map { value -> String in
        _ = try parseRepositoryOplogCursor(value)
        return value
    }
    let excludeValues = try query["excludeValues"].map(strictBoolean)
    return .init(
        space: space,
        repo: repo,
        since: since,
        limit: limit,
        cursor: cursor,
        excludeValues: excludeValues
    )
}

private func parseAuthenticatedGetRepoParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetRepo.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        schema: spaceGetRepoQuerySchema
    )
    let space = try SpaceRef(
        uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048)
    )
    let repo = try DID(
        didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048)
    )
    _ = try syncTarget(space, repo)
    return .init(space: space, repo: repo)
}

private func strictRepositoryOplogLimit(_ value: String) throws -> Int {
    guard !value.isEmpty,
          value.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
          let limit = Int(value),
          (1 ... 1_000).contains(limit) else {
        throw AuthenticatedSpaceRepositorySyncFailure.invalidRequest
    }
    return limit
}

private func registerAuthenticatedRepositorySyncWrongMethods(
    on router: Router<BasicRequestContext>,
    path: RouterPath
) {
    for method: HTTPRequest.Method in [
        .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ] {
        router.on(path, method: method) { _, _ -> Response in
            authenticatedRepositorySyncError(
                .notFound,
                code: "permissioned_endpoint_unavailable"
            )
        }
    }
}

private func authenticatedRepositorySyncResponse(
    for failure: AuthenticatedSpaceRepositorySyncFailure,
    capability: SwanAuthenticatedSpaceRepositorySyncCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedRepositorySyncError(.badRequest, code: "InvalidRequest")
    case .spaceNotFound:
        authenticatedRepositorySyncError(.notFound, code: "SpaceNotFound")
    case .repoNotFound:
        authenticatedRepositorySyncError(.notFound, code: "RepoNotFound")
    case .denied:
        authenticatedRepositorySyncError(.unauthorized, code: "Unauthorized")
    case let .credentialPresentation(failure):
        authenticatedRepositorySyncError(failure.httpStatus, code: failure.xrpcErrorCode)
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .fullRecoveryRequired:
        // The client learns only that its incremental cursor cannot converge;
        // `getRepo` is intentionally not installed until the CAR task.
        authenticatedRepositorySyncError(
            .conflict,
            code: "full_repo_recovery_required"
        )
    case .malformedCursor:
        authenticatedRepositorySyncError(.badRequest, code: "InvalidCursor")
    case .unavailable:
        authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func authenticatedRepositorySyncError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

/// Generated nested objects carry `$type` framing for generic lexicon values.
/// These two XRPC output schemas are plain JSON objects, so render a small
/// wire projection after the generated handler has performed typed work.
private struct SignedCommitWireOutput: Encodable {
    let ver: Int
    let repo: String
    let space: String
    let data: Bytes
    let rev: String
}

private struct GetLatestCommitWireOutput: Encodable {
    let commit: SignedCommitWireOutput?
}

private struct RepoOplogWireOutput: Encodable {
    let ops: [RepoOplogWireEntry]
    let commit: SignedCommitWireOutput?
    let cursor: String?
}

private struct RepoOplogWireEntry: Encodable {
    let rev: String
    let collection: String
    let rkey: String
    let cid: String?
    let prev: String?
    let value: ATProtocolValueContainer?

    private enum CodingKeys: String, CodingKey {
        case rev, collection, rkey, cid, prev, value
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rev, forKey: .rev)
        try container.encode(collection, forKey: .collection)
        try container.encode(rkey, forKey: .rkey)
        // The pinned endpoint distinguishes a missing value (stale or
        // excluded) from nullable operation CIDs.  Do not use synthesized
        // optional encoding here: it would omit `cid`/`prev` instead of
        // emitting the required JSON null for delete/create operations.
        try container.encode(cid, forKey: .cid)
        try container.encode(prev, forKey: .prev)
        try container.encodeIfPresent(value, forKey: .value)
    }
}

private func signedCommitWire(
    _ commit: ComAtprotoSpaceDefs.Commit?
) -> SignedCommitWireOutput? {
    commit.map {
        SignedCommitWireOutput(
            ver: $0.ver,
            repo: $0.repo.didString(),
            space: $0.space.uriString(),
            data: $0.data,
            rev: $0.rev.toString()
        )
    }
}

private func authenticatedGetLatestCommitJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSpaceGetLatestCommit.Output
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        GetLatestCommitWireOutput(commit: signedCommitWire(output.commit))
    )
}

private func authenticatedListRepoOpsJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSpaceListRepoOps.Output,
    lease: PublicRepositoryJSONReadLease? = nil
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        RepoOplogWireOutput(
            ops: output.ops.map {
                RepoOplogWireEntry(
                    rev: $0.rev.toString(),
                    collection: $0.collection.nsidString(),
                    rkey: $0.rkey.value,
                    cid: $0.cid?.string,
                    prev: $0.prev?.string,
                    value: $0.value
                )
            },
            commit: signedCommitWire(output.commit),
            cursor: output.cursor
        ),
        maximumBytes: PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes,
        lease: lease
    )
}

private func responseCommit(_ commit: ComAtprotoSpaceDefs.Commit) throws -> SpaceRepositoryCommit {
    try SpaceRepositoryCommit(ver: commit.ver, repo: commit.repo.didString(),
                              space: SpaceURI(commit.space.uriString()), rev: commit.rev.toString(), data: commit.data.data)
}
