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

/// The narrowly composed capability for the two read-only incremental-sync
/// endpoints.  It carries neither a SQLite handle nor raw key material: the
/// preopened directory returns safe durable projections, and the signer can
/// only construct a fixed reader-bound permissioned commit.
public struct SwanAuthenticatedSpaceRepositorySyncCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSpaceRepositoryDirectory
    let credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?
    let commitSigner: any SpaceRepositoryCommitSigner

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSpaceRepositoryDirectory,
        credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?,
        commitSigner: any SpaceRepositoryCommitSigner
    ) {
        self.authorizer = authorizer
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        self.commitSigner = commitSigner
    }
}

private enum AuthenticatedSpaceRepositorySyncFailure: Error {
    case invalidRequest
    case spaceNotFound
    case denied
    case nonceChallenge
    case fullRecoveryRequired
    case unavailable
}

private struct AuthenticatedGetLatestCommitHandler:
    ComAtprotoSpaceGetLatestCommit.ServerHandler
{
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRepositorySyncCapability

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
            fixedPath: "/xrpc/com.atproto.space.getLatestCommit"
        )
        try requireRepositoryReadAuthorization(authorization, author: target.author)
        let state = try await repositoryCommitState(
            capability,
            space: target.space,
            author: target.author,
            authorization: authorization
        )
        return .init(
            commit: try await signedCommit(
                state: state,
                expectedSpace: target.space,
                expectedAuthor: target.author,
                capability: capability
            )
        )
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
            fixedPath: "/xrpc/com.atproto.space.listRepoOps"
        )
        try requireRepositoryReadAuthorization(authorization, author: target.author)

        let limit = parameters.limit ?? 100
        guard (1 ... 1_000).contains(limit) else {
            throw AuthenticatedSpaceRepositorySyncFailure.invalidRequest
        }
        let read: AuthorizedSpaceRepositoryOplogRead
        do {
            read = try await capability.directory.repositoryOplog(
                space: target.space,
                author: target.author,
                since: parameters.since,
                limit: limit,
                includeValues: parameters.excludeValues != true,
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
            let commit: ComAtprotoSpaceDefs.SignedCommit?
            // This is deliberately the reference condition, not `ops.isEmpty`:
            // an exactly-full final page does not bind a head commit until the
            // caller asks again and receives the short/empty page.
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
            return .init(ops: operations, commit: commit, cursor: nil)
        }
    }
}

private func syncTarget(
    _ spaceValue: ATProtocolURI,
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

private func authorizeRepositorySyncRead(
    _ capability: SwanAuthenticatedSpaceRepositorySyncCapability,
    request: Request,
    expectedSpace: SpaceURI,
    fixedPath: String
) async throws -> AuthorizationContext {
    let bearerToken: String?
    do {
        bearerToken = try exactBearerToken(from: request.headers)
    } catch {
        throw AuthenticatedSpaceRepositorySyncFailure.denied
    }
    if let bearerToken {
        guard let credentialAuthorizer = capability.credentialAuthorizer else {
            throw AuthenticatedSpaceRepositorySyncFailure.denied
        }
        do {
            return try await credentialAuthorizer.authorization(
                for: bearerToken,
                expectedSpace: expectedSpace,
                now: Date()
            )
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
        return try await capability.authorizer.authorize(
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
) async throws -> ComAtprotoSpaceDefs.SignedCommit? {
    guard let revision = state.wireRevision else { return nil }
    let envelope: SpaceCommitEnvelope
    do {
        envelope = try await capability.commitSigner.signRepositoryCommit(
            space: expectedSpace,
            author: expectedAuthor,
            wireRevision: revision,
            commitment: state.commitment
        )
    } catch {
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
    guard envelope.ver == 1,
          envelope.context.space == expectedSpace,
          envelope.context.author == expectedAuthor,
          envelope.context.rev == revision,
          envelope.commitment == state.commitment,
          SpaceCommitCodec.verifyContentBinding(envelope) else {
        throw AuthenticatedSpaceRepositorySyncFailure.unavailable
    }
    return .init(
        ver: envelope.ver,
        hash: Bytes(data: envelope.commitment),
        ikm: Bytes(data: envelope.context.ikm),
        sig: Bytes(data: envelope.contextSignature),
        mac: Bytes(data: envelope.contentBinding),
        rev: envelope.context.rev
    )
}

private func syncWireOperation(
    _ entry: AuthorizedSpaceRepositoryOplogEntry
) throws -> ComAtprotoSpaceListRepoOps.OpEntry {
    let revision = try TID(tidString: entry.wireRevision).toString()
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

func registerAuthenticatedGetLatestCommitEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRepositorySyncCapability
) {
    let handler = AuthenticatedGetLatestCommitHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getLatestCommit"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceGetLatestCommit.Parameters
        do {
            parameters = try parseAuthenticatedGetLatestCommitParameters(request)
        } catch {
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidRequest")
        }
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedGetLatestCommitJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceRepositorySyncFailure {
            return authenticatedRepositorySyncResponse(for: failure, capability: capability)
        } catch {
            return authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRepositorySyncWrongMethods(on: router, path: path)
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
        } catch {
            return authenticatedRepositorySyncError(.badRequest, code: "InvalidRequest")
        }
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedListRepoOpsJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceRepositorySyncFailure {
            return authenticatedRepositorySyncResponse(for: failure, capability: capability)
        } catch {
            return authenticatedRepositorySyncError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRepositorySyncWrongMethods(on: router, path: path)
}

private func parseAuthenticatedGetLatestCommitParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetLatestCommit.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        required: ["space", "repo"],
        optional: []
    )
    let space = try ATProtocolURI(
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
        required: ["space", "repo"],
        optional: ["since", "limit", "excludeValues"]
    )
    let space = try ATProtocolURI(
        uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048)
    )
    let repo = try DID(
        didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048)
    )
    _ = try syncTarget(space, repo)
    let since = try query["since"].map {
        let value = try bounded($0, maximumBytes: 32)
        return try TID(tidString: value).toString()
    }
    let limit = try query["limit"].map(strictRepositoryOplogLimit)
    let excludeValues = try query["excludeValues"].map(strictBoolean)
    return .init(
        space: space,
        repo: repo,
        since: since,
        limit: limit,
        excludeValues: excludeValues
    )
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
    case .denied:
        authenticatedRepositorySyncError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .fullRecoveryRequired:
        // The client learns only that its incremental cursor cannot converge;
        // `getRepo` is intentionally not installed until the CAR task.
        authenticatedRepositorySyncError(
            .conflict,
            code: "full_repo_recovery_required"
        )
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
    let hash: Bytes
    let ikm: Bytes
    let sig: Bytes
    let mac: Bytes
    let rev: String
}

private struct GetLatestCommitWireOutput: Encodable {
    let commit: SignedCommitWireOutput?
}

private struct RepoOplogWireOutput: Encodable {
    let ops: [RepoOplogWireEntry]
    let commit: SignedCommitWireOutput?
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
    _ commit: ComAtprotoSpaceDefs.SignedCommit?
) -> SignedCommitWireOutput? {
    commit.map {
        SignedCommitWireOutput(
            ver: $0.ver,
            hash: $0.hash,
            ikm: $0.ikm,
            sig: $0.sig,
            mac: $0.mac,
            rev: $0.rev
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
    _ output: ComAtprotoSpaceListRepoOps.Output
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        RepoOplogWireOutput(
            ops: output.ops.map {
                RepoOplogWireEntry(
                    rev: $0.rev,
                    collection: $0.collection.nsidString(),
                    rkey: $0.rkey.value,
                    cid: $0.cid?.string,
                    prev: $0.prev?.string,
                    value: $0.value
                )
            },
            commit: signedCommitWire(output.commit)
        )
    )
}
