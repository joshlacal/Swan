import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanOAuth
import SwanPublicRepository
import SwanPublicWire
import SwanStorage
import SwanSpaces

private enum PublicMutationFailure: Error {
    case invalidRequest
    case unauthorized
    case nonce
    case notFound
    case invalidSwap
    case unavailable
}

private struct PublicMutationHandlers {
    let capability: SwanPublicRepositoryMutationCapability

    func applyWrites(
        _ input: SwanPublicWire.ComAtprotoRepoApplyWrites.Input,
        bodyDigest: Data,
        request: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoApplyWrites.Output {
        let target = try await authorizedTarget(selector: input.repo.stringValue(), request: request, method: "POST", path: "/xrpc/com.atproto.repo.applyWrites")
        var writes: [PublicRepositoryWrite] = []
        for union in input.writes {
            switch union {
            case let .comAtprotoRepoApplyWritesCreate(value):
                let rkey: RecordKey
                if let supplied = value.rkey { rkey = supplied }
                else { rkey = try RecordKey(keyString: try await capability.tidAllocator.next().toString()) }
                let path = try PublicRepositoryPath(collection: value.collection.nsidString(), recordKey: rkey.value)
                writes.append(.create(path: path, record: try PublicRepositoryRecordCodec.publicRecord(from: value.value, collection: path.collection)))
            case let .comAtprotoRepoApplyWritesUpdate(value):
                let path = try PublicRepositoryPath(collection: value.collection.nsidString(), recordKey: value.rkey.value)
                writes.append(.update(path: path, record: try PublicRepositoryRecordCodec.publicRecord(from: value.value, collection: path.collection), expectedRecordCID: nil))
            case let .comAtprotoRepoApplyWritesDelete(value):
                writes.append(.delete(path: try PublicRepositoryPath(collection: value.collection.nsidString(), recordKey: value.rkey.value), expectedRecordCID: nil))
            case .unexpected: throw PublicMutationFailure.invalidRequest
            }
        }
        let committed = try await SwanPublicRepositoryMutationCoordinator.applyBatch(
            store: target.store, did: target.did,
            batch: try PublicRepositoryWriteBatch(writes: writes, expectedCommitCID: input.swapCommit),
            requestID: UUID().uuidString, bodyDigest: bodyDigest,
            signerProvider: capability.signerProvider
        )
        let results: [SwanPublicWire.ComAtprotoRepoApplyWrites.OutputResultsUnion] = committed.recordResults.map { result in
            let uri = try! ATProtocolURI(uriString: "at://\(target.did)/\(result.path.mstKey)")
            switch result.action {
            case .create: return .comAtprotoRepoApplyWritesCreateResult(.init(uri: uri, cid: result.recordCID!, validationStatus: input.validate == nil ? nil : "valid"))
            case .update: return .comAtprotoRepoApplyWritesUpdateResult(.init(uri: uri, cid: result.recordCID!, validationStatus: input.validate == nil ? nil : "valid"))
            case .delete: return .comAtprotoRepoApplyWritesDeleteResult(.init())
            }
        }
        return .init(commit: .init(cid: committed.state.commitCID, rev: try TID(tidString: committed.state.revision)), results: results)
    }

    func create(
        _ input: SwanPublicWire.ComAtprotoRepoCreateRecord.Input,
        bodyDigest: Data,
        request: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoCreateRecord.Output {
        let target = try await authorizedTarget(
            selector: input.repo.stringValue(), request: request,
            method: "POST", path: "/xrpc/com.atproto.repo.createRecord"
        )
        let rkey: RecordKey
        if let supplied = input.rkey {
            rkey = supplied
        } else {
            rkey = try RecordKey(keyString: try await capability.tidAllocator.next().toString())
        }
        let path = try PublicRepositoryPath(collection: input.collection.nsidString(), recordKey: rkey.value)
        let record = try PublicRepositoryRecordCodec.publicRecord(from: input.record, collection: path.collection)
        let result = try await SwanPublicRepositoryMutationCoordinator.put(
            store: target.store, did: target.did, path: path, record: record,
            swapRecord: nil, swapCommit: input.swapCommit,
            requestID: UUID().uuidString, bodyDigest: bodyDigest,
            signerProvider: capability.signerProvider
        )
        guard result.action == .create else { throw PublicMutationFailure.invalidRequest }
        let uri = try ATProtocolURI(uriString: "at://\(target.did)/\(path.mstKey)")
        return SwanPublicWire.ComAtprotoRepoCreateRecord.Output(
            uri: uri, cid: try result.recordCID ?? PublicRepositoryRecordCodec.prepare(record, for: path).cid,
            commit: SwanPublicWire.ComAtprotoRepoDefs.CommitMeta(
                cid: result.state.commitCID, rev: try TID(tidString: result.state.revision)
            ), validationStatus: input.validate == nil ? nil : "valid"
        )
    }

    func put(
        _ input: SwanPublicWire.ComAtprotoRepoPutRecord.Input,
        bodyDigest: Data,
        request: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoPutRecord.Output {
        let target = try await authorizedTarget(
            selector: input.repo.stringValue(), request: request,
            method: "POST", path: "/xrpc/com.atproto.repo.putRecord"
        )
        let path = try PublicRepositoryPath(
            collection: input.collection.nsidString(), recordKey: input.rkey.value
        )
        let record = try PublicRepositoryRecordCodec.publicRecord(
            from: input.record, collection: path.collection
        )
        let result = try await SwanPublicRepositoryMutationCoordinator.put(
            store: target.store, did: target.did, path: path, record: record,
            swapRecord: input.swapRecord, swapCommit: input.swapCommit,
            requestID: UUID().uuidString, bodyDigest: bodyDigest,
            signerProvider: capability.signerProvider
        )
        let uri = try ATProtocolURI(uriString: "at://\(target.did)/\(path.mstKey)")
        let hasCommit = result.action == .create || result.action == .update
        let commit: SwanPublicWire.ComAtprotoRepoDefs.CommitMeta? = hasCommit
            ? SwanPublicWire.ComAtprotoRepoDefs.CommitMeta(
                cid: result.state.commitCID,
                rev: try TID(tidString: result.state.revision)
            )
            : nil
        // The coordinator returns the current state for a same-CID no-op; the
        // wire contract intentionally omits commit metadata for that case.
        let recordCID = try result.recordCID ?? PublicRepositoryRecordCodec.prepare(record, for: path).cid
        return SwanPublicWire.ComAtprotoRepoPutRecord.Output(
            uri: uri,
            cid: recordCID,
            commit: result.isNoOp ? nil : commit,
            validationStatus: input.validate == nil ? nil : "valid"
        )
    }

    func delete(
        _ input: SwanPublicWire.ComAtprotoRepoDeleteRecord.Input,
        bodyDigest: Data,
        request: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoDeleteRecord.Output {
        let target = try await authorizedTarget(
            selector: input.repo.stringValue(), request: request,
            method: "POST", path: "/xrpc/com.atproto.repo.deleteRecord"
        )
        let path = try PublicRepositoryPath(
            collection: input.collection.nsidString(), recordKey: input.rkey.value
        )
        let result = try await SwanPublicRepositoryMutationCoordinator.delete(
            store: target.store, did: target.did, path: path,
            swapRecord: input.swapRecord, swapCommit: input.swapCommit,
            requestID: UUID().uuidString, bodyDigest: bodyDigest,
            signerProvider: capability.signerProvider
        )
        guard let result else { return .init(commit: nil) }
        return .init(commit: .init(
            cid: result.state.commitCID,
            rev: try TID(tidString: result.state.revision)
        ))
    }

    private func authorizedTarget(
        selector: String,
        request: Request,
        method: String,
        path: String
    ) async throws -> PublicRepositoryMutationTarget {
        let authorization: AuthorizationContext
        do {
            authorization = try await capability.authorizer.authorize(
                request: request, method: method, fixedPath: path
            )
        } catch let failure as SwanResourceAuthorizationFailure {
            throw failure == .nonceChallengeRequired ? PublicMutationFailure.nonce : .unauthorized
        } catch {
            throw PublicMutationFailure.unavailable
        }
        guard case let .accountOAuth(subject, scopes) = authorization,
              scopes.contains("atproto") else {
            throw PublicMutationFailure.unauthorized
        }
        guard let target = try await capability.directory.publicRepositoryMutationTarget(
            selector: selector
        ) else { throw PublicMutationFailure.notFound }
        guard target.status == .active, target.did == subject else {
            throw PublicMutationFailure.notFound
        }
        return target
    }
}

func registerPublicRepositoryMutationEndpoints(
    on router: Router<BasicRequestContext>,
    capability: SwanPublicRepositoryMutationCapability
) {
    let handlers = PublicMutationHandlers(capability: capability)
    let putPath: RouterPath = "/xrpc/com.atproto.repo.putRecord"
    let createPath: RouterPath = "/xrpc/com.atproto.repo.createRecord"
    let applyPath: RouterPath = "/xrpc/com.atproto.repo.applyWrites"
    let deletePath: RouterPath = "/xrpc/com.atproto.repo.deleteRecord"
    router.post(putPath) { request, _ async -> Response in
        do {
            let (input, digest) = try await publicMutationInput(
                request, as: SwanPublicWire.ComAtprotoRepoPutRecord.Input.self
            )
            return publicMutationJSON(.ok, try await handlers.put(input, bodyDigest: digest, request: request))
        } catch let failure as PublicMutationFailure {
            return publicMutationResponse(failure, authorizer: capability.authorizer)
        } catch let failure as PublicRepositoryMutationCoordinatorError {
            return publicMutationResponse(failure)
        } catch {
            return publicMutationError(.badRequest, "InvalidRequest")
        }
    }
    router.post(createPath) { request, _ async -> Response in
        do {
            let (input, digest) = try await publicMutationInput(
                request, as: SwanPublicWire.ComAtprotoRepoCreateRecord.Input.self
            )
            return publicMutationJSON(.ok, try await handlers.create(input, bodyDigest: digest, request: request))
        } catch let failure as PublicMutationFailure {
            return publicMutationResponse(failure, authorizer: capability.authorizer)
        } catch let failure as PublicRepositoryMutationCoordinatorError {
            return publicMutationResponse(failure)
        } catch {
            return publicMutationError(.badRequest, "InvalidRequest")
        }
    }
    router.post(applyPath) { request, _ async -> Response in
        do {
            let (input, digest) = try await publicMutationInput(request, as: SwanPublicWire.ComAtprotoRepoApplyWrites.Input.self)
            return publicMutationJSON(.ok, try await handlers.applyWrites(input, bodyDigest: digest, request: request))
        } catch let failure as PublicMutationFailure { return publicMutationResponse(failure, authorizer: capability.authorizer) }
        catch let failure as PublicRepositoryMutationCoordinatorError { return publicMutationResponse(failure) }
        catch { return publicMutationError(.badRequest, "InvalidRequest") }
    }
    router.post(deletePath) { request, _ async -> Response in
        do {
            let (input, digest) = try await publicMutationInput(
                request, as: SwanPublicWire.ComAtprotoRepoDeleteRecord.Input.self
            )
            return publicMutationJSON(.ok, try await handlers.delete(input, bodyDigest: digest, request: request))
        } catch let failure as PublicMutationFailure {
            return publicMutationResponse(failure, authorizer: capability.authorizer)
        } catch let failure as PublicRepositoryMutationCoordinatorError {
            return publicMutationResponse(failure)
        } catch {
            return publicMutationError(.badRequest, "InvalidRequest")
        }
    }
    for path in [putPath, createPath, applyPath, deletePath] {
        for method: HTTPRequest.Method in [.get, .head, .put, .patch, .delete, .options, .connect, .trace] {
            router.on(path, method: method) { _, _ in publicMutationError(.notFound, "public_endpoint_unavailable") }
        }
    }
    if let blobStore = capability.blobStore {
        let blobPath: RouterPath = "/xrpc/com.atproto.sync.getBlob"
        router.get(blobPath) { request, _ async -> Response in
            guard let cid = publicQueryValue("cid", request: request) else {
                return publicMutationError(.notFound, "BlobNotFound")
            }
            let maybeData: Data?
            do { maybeData = try await blobStore.publicData(cid: cid) }
            catch { return publicMutationError(.notFound, "BlobNotFound") }
            guard let data = maybeData else {
                return publicMutationError(.notFound, "BlobNotFound")
            }
            var headers: HTTPFields = [.contentType: "application/octet-stream", .cacheControl: "no-store"]
            headers[.contentLength] = String(data.count)
            return Response(status: .ok, headers: headers, body: .init(byteBuffer: ByteBuffer(data: data)))
        }
    }
}

private func publicQueryValue(_ name: String, request: Request) -> String? {
    request.uri.query?.split(separator: "&").compactMap { pair in
        let pieces = pair.split(separator: "=", maxSplits: 1)
        guard pieces.first == Substring(name), pieces.count == 2 else { return nil }
        return String(pieces[1])
    }.first
}

private func publicMutationInput<Value: Decodable>(
    _ request: Request, as type: Value.Type
) async throws -> (Value, Data) {
    let contentTypes = request.headers[values: .contentType]
    guard contentTypes.count == 1,
          contentTypes[0].split(separator: ";", maxSplits: 1).first?.lowercased() == "application/json" else {
        throw PublicMutationFailure.invalidRequest
    }
    let body = try await request.body.collect(upTo: 1_000_000)
    guard let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) else {
        throw PublicMutationFailure.invalidRequest
    }
    let data = Data(bytes)
    try StrictPermissionedWriteJSON.validate(data)
    return (try JSONDecoder().decode(Value.self, from: data), Data(SHA256.hash(data: data)))
}

private func publicMutationResponse(
    _ failure: PublicMutationFailure,
    authorizer: SwanOAuthResourceAuthorizer
) -> Response {
    switch failure {
    case .invalidRequest: return publicMutationError(.badRequest, "InvalidRequest")
    case .unauthorized: return publicMutationError(.unauthorized, "Unauthorized")
    case .nonce: return authenticatedGetSpaceNonceChallenge(authorizer: authorizer)
    case .notFound: return publicMutationError(.notFound, "RepoNotFound")
    case .invalidSwap: return publicMutationError(.badRequest, "InvalidSwap")
    case .unavailable: return publicMutationError(.serviceUnavailable, "temporarily_unavailable")
    }
}

private func publicMutationResponse(
    _ failure: PublicRepositoryMutationCoordinatorError
) -> Response {
    switch failure {
    case .invalidSwap: return publicMutationError(.badRequest, "InvalidSwap")
    case .repositoryNotFound: return publicMutationError(.notFound, "RepoNotFound")
    case .inactiveAccount: return publicMutationError(.forbidden, "AccountInactive")
    case .unavailable: return publicMutationError(.serviceUnavailable, "temporarily_unavailable")
    }
}

private func publicMutationJSON(_ status: HTTPResponse.Status, _ value: some Encodable) -> Response {
    authenticatedGetSpaceJSON(status, value)
}

private func publicMutationError(_ status: HTTPResponse.Status, _ code: String) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}
