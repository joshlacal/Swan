import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanOAuth
import SwanPublicRepository
import SwanPublicWire
import SwanCore
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

private let publicMutationMaximumJSONBytes = 1_000_000

private final class PublicBlobUploadCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func add(_ amount: Int, maximum: Int) throws {
        lock.lock()
        defer { lock.unlock() }
        guard amount >= 0, amount <= maximum - value else {
            throw PublicMutationFailure.invalidRequest
        }
        value += amount
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private struct PublicMutationHandlers {
    let capability: SwanPublicRepositoryMutationCapability

    func uploadBlob(
        _ request: Request,
        context: SwanHTTPRequestContext
    ) async throws -> SwanPublicWire.ComAtprotoRepoUploadBlob.Output {
        let maximumBytes = 256 * 1024 * 1024
        try validateRequestBodyHeaders(
            request,
            mediaType: .unspecified,
            maximumBytes: maximumBytes,
            termination: context.jsonWriteBodyTermination
        )
        let declaredLength: Int
        do {
            declaredLength = try requiredPublicBlobContentLength(request.headers)
        } catch {
            try await drainRejectedRequestBody(
                request,
                admission: capability.jsonWriteAdmission,
                policy: capability.jsonWriteBodyPolicy,
                termination: context.jsonWriteBodyTermination
            )
            throw PublicMutationFailure.invalidRequest
        }
        let (blobStore, mimeType, lease) = try await withPublicBlobUploadPreflightDrain(
            request: request,
            context: context,
            admission: capability.jsonWriteAdmission,
            policy: capability.jsonWriteBodyPolicy
        ) {
            let subject = try await authorizedSubject(
                request: request, method: "POST", path: "/xrpc/com.atproto.repo.uploadBlob"
            )
            guard let target = try await capability.directory.publicRepositoryMutationTarget(selector: subject),
                  target.did == subject,
                  target.status == .active,
                  let blobStore = target.store as? any StreamingBlobStore else {
                throw PublicMutationFailure.notFound
            }
            let contentTypes = request.headers[values: .contentType]
            guard contentTypes.count <= 1 else {
                throw PublicMutationFailure.invalidRequest
            }
            let requestedMIMEType = contentTypes.first?.split(separator: ";", maxSplits: 1).first.map(String.init)
                ?? "application/octet-stream"
            let mimeType = safePublicBlobMIMEType(requestedMIMEType)
            guard let admission = capability.publicBlobSpoolAdmission,
                  let lease = admission.reserve(
                      accountDID: target.did,
                      maximumBytes: maximumBytes
                  ) else {
                throw PublicMutationFailure.unavailable
            }
            return (blobStore, mimeType, lease)
        }
        defer { lease.release() }
        let counter = PublicBlobUploadCounter()
        let body = request.body
        let reference = try await withAbsoluteRequestBodyDeadline(
            policy: capability.jsonWriteBodyPolicy,
            termination: context.jsonWriteBodyTermination
        ) {
            try await blobStore.putStreaming(
                namespace: .public,
                mimeType: mimeType,
                maximumBytes: maximumBytes
            ) { sink in
                var iterator = body.makeAsyncIterator()
                while let next = try await iterator.next() {
                    var buffer = next
                    try Task.checkCancellation()
                    let count = buffer.readableBytes
                    try counter.add(count, maximum: maximumBytes)
                    guard count > 0,
                          let bytes = buffer.readBytes(length: count) else {
                        continue
                    }
                    try await sink(Data(bytes))
                }
                guard counter.count > 0 else {
                    throw PublicMutationFailure.invalidRequest
                }
                guard declaredLength == counter.count else {
                    if await context.jsonWriteBodyTermination.wasTerminated() {
                        throw PublicMutationFailure.unavailable
                    }
                    throw PublicMutationFailure.invalidRequest
                }
            }
        }
        guard case .public = reference.namespace else {
            throw PublicMutationFailure.unavailable
        }
        let cid: CID
        do {
            cid = try CID.parse(reference.cid)
        } catch {
            throw PublicMutationFailure.unavailable
        }
        guard cid.string == reference.cid,
              cid.codec == .raw,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length else {
            throw PublicMutationFailure.unavailable
        }
        return .init(blob: Blob(
            type: "blob", ref: ATProtoLink(cid: cid), mimeType: mimeType,
            size: counter.count, cid: nil
        ))
    }

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
                let record = try PublicRepositoryRecordCodec.publicRecord(from: value.value, collection: path.collection)
                writes.append(.create(path: path, record: record))
            case let .comAtprotoRepoApplyWritesUpdate(value):
                let path = try PublicRepositoryPath(collection: value.collection.nsidString(), recordKey: value.rkey.value)
                let record = try PublicRepositoryRecordCodec.publicRecord(from: value.value, collection: path.collection)
                writes.append(.update(path: path, record: record, expectedRecordCID: nil))
            case let .comAtprotoRepoApplyWritesDelete(value):
                writes.append(.delete(path: try PublicRepositoryPath(collection: value.collection.nsidString(), recordKey: value.rkey.value), expectedRecordCID: nil))
            case .unexpected: throw PublicMutationFailure.invalidRequest
            }
        }
        try await validatePublicBlobLinks(in: writes, target: target)
        let committed = try await SwanPublicRepositoryMutationCoordinator.applyBatch(
            store: target.store, did: target.did,
            batch: try PublicRepositoryWriteBatch(writes: writes, expectedCommitCID: input.swapCommit),
            requestID: UUID().uuidString, bodyDigest: bodyDigest,
            signerProvider: capability.signerProvider
        )
        let results: [SwanPublicWire.ComAtprotoRepoApplyWrites.OutputResultsUnion] = try committed.recordResults.map { result in
            let uri: ATProtocolURI
            do {
                uri = try ATProtocolURI(uriString: "at://\(target.did)/\(result.path.mstKey)")
            } catch {
                // A coordinator/storage invariant failure must become a
                // bounded protocol error, never a process crash from a
                // request-derived path.
                throw PublicMutationFailure.unavailable
            }
            switch result.action {
            case .create:
                guard let recordCID = result.recordCID else {
                    throw PublicMutationFailure.unavailable
                }
                return .comAtprotoRepoApplyWritesCreateResult(
                    .init(
                        uri: uri,
                        cid: recordCID,
                        validationStatus: input.validate == nil ? nil : "valid"
                    )
                )
            case .update:
                guard let recordCID = result.recordCID else {
                    throw PublicMutationFailure.unavailable
                }
                return .comAtprotoRepoApplyWritesUpdateResult(
                    .init(
                        uri: uri,
                        cid: recordCID,
                        validationStatus: input.validate == nil ? nil : "valid"
                    )
                )
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
        try await validatePublicBlobLinks(in: [.create(path: path, record: record)], target: target)
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
        try await validatePublicBlobLinks(in: [.update(path: path, record: record, expectedRecordCID: nil)], target: target)
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
        let authorization = try await authorizedContext(request: request, method: method, path: path)
        guard case let .accountOAuth(subject, scopes) = authorization,
              scopes.contains("atproto") else { throw PublicMutationFailure.unauthorized }
        guard let target = try await capability.directory.publicRepositoryMutationTarget(selector: selector) else {
            throw PublicMutationFailure.notFound
        }
        guard target.status == .active, target.did == subject else { throw PublicMutationFailure.notFound }
        return target
    }

    private func authorizedSubject(request: Request, method: String, path: String) async throws -> String {
        let authorization = try await authorizedContext(request: request, method: method, path: path)
        guard case let .accountOAuth(subject, scopes) = authorization,
              scopes.contains("atproto") else { throw PublicMutationFailure.unauthorized }
        return subject
    }

    private func authorizedContext(request: Request, method: String, path: String) async throws -> AuthorizationContext {
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
        return authorization
    }

    private func validatePublicBlobLinks(
        in writes: [PublicRepositoryWrite],
        target: PublicRepositoryMutationTarget
    ) async throws {
        let records = writes.compactMap { write -> PublicRecord? in
            switch write {
            case let .create(_, record), let .update(_, record, _): return record
            case .delete: return nil
            }
        }
        let cids = records.flatMap(PublicRepositoryRecordCodec.publicBlobCIDs(in:))
        let typedReferences: [PublicTypedBlobReference]
        do {
            typedReferences = try records.flatMap {
                try PublicRepositoryRecordCodec.publicTypedBlobReferences(in: $0)
            }
        } catch {
            throw PublicMutationFailure.invalidRequest
        }
        guard !cids.isEmpty else { return }
        guard let blobStore = target.store as? any StreamingBlobStore else {
            throw PublicMutationFailure.unavailable
        }
        var seen = Set<String>()
        for cid in cids where seen.insert(cid.string).inserted {
            let metadata: PublicBlobMetadata?
            do {
                metadata = try await blobStore.publicBlobMetadata(cid: cid.string)
            } catch {
                throw PublicMutationFailure.unavailable
            }
            guard let metadata else { throw PublicMutationFailure.invalidRequest }
            for typed in typedReferences where typed.cid == cid {
                guard metadata.mimeType == typed.mimeType,
                      metadata.size == typed.size else {
                    throw PublicMutationFailure.invalidRequest
                }
            }
        }
    }
}

private func withPublicBlobUploadPreflightDrain<Value>(
    request: Request,
    context: SwanHTTPRequestContext,
    admission: PublicRepositoryJSONWriteAdmission,
    policy: SwanJSONWriteBodyPolicy,
    operation: () async throws -> Value
) async throws -> Value {
    do {
        return try await operation()
    } catch {
        do {
            try await drainRejectedRequestBody(
                request,
                admission: admission,
                policy: policy,
                termination: context.jsonWriteBodyTermination
            )
        } catch {
            throw PublicMutationFailure.unavailable
        }
        throw error
    }
}

func requiredPublicBlobContentLength(_ headers: HTTPFields) throws -> Int {
    let values = headers[values: .contentLength]
    guard values.count == 1,
          let value = values.first,
          !value.isEmpty,
          value.utf8.allSatisfy({ (48 ... 57).contains($0) }),
          value.first != "0",
          let length = Int(value),
          (1 ... maximumPublicBlobTransferBytes).contains(length) else {
        throw PublicMutationFailure.invalidRequest
    }
    return length
}

/// Shared with the public blob *read* route, which lives on the read surface
/// in `SwanPublicRepositoryReadXRPC.swift`. Upload and download must agree on
/// this bound or a blob could be accepted and then never served.
let maximumPublicBlobTransferBytes = 256 * 1024 * 1024

func registerPublicRepositoryMutationEndpoints(
    on router: Router<BasicRequestContext>,
    capability: SwanPublicRepositoryMutationCapability
) {
    let handlers = PublicMutationHandlers(capability: capability)
    let putPath: RouterPath = "/xrpc/com.atproto.repo.putRecord"
    let createPath: RouterPath = "/xrpc/com.atproto.repo.createRecord"
    let applyPath: RouterPath = "/xrpc/com.atproto.repo.applyWrites"
    let uploadPath: RouterPath = "/xrpc/com.atproto.repo.uploadBlob"
    let deletePath: RouterPath = "/xrpc/com.atproto.repo.deleteRecord"
    router.post(putPath) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoPutRecord.Input.self,
            capability: capability
        ) { input, digest in
            publicMutationJSON(
                .ok,
                try await handlers.put(input, bodyDigest: digest, request: request)
            )
        }
    }
    router.post(createPath) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoCreateRecord.Input.self,
            capability: capability
        ) { input, digest in
            publicMutationJSON(
                .ok,
                try await handlers.create(input, bodyDigest: digest, request: request)
            )
        }
    }
    router.post(applyPath) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoApplyWrites.Input.self,
            capability: capability
        ) { input, digest in
            publicMutationJSON(
                .ok,
                try await handlers.applyWrites(input, bodyDigest: digest, request: request)
            )
        }
    }
    router.post(uploadPath) { request, context async -> Response in
        do {
            return publicMutationJSON(
                .ok,
                try await handlers.uploadBlob(request, context: context)
            )
        } catch let failure as SwanRequestBodyCollectionFailure {
            return publicMutationResponse(
                failure == .unavailable ? .unavailable : .invalidRequest,
                authorizer: capability.authorizer
            )
        } catch let failure as PublicMutationFailure {
            return publicMutationResponse(failure, authorizer: capability.authorizer)
        } catch let error as SwanError {
            return publicMutationResponse(error)
        } catch let error as BlobQuotaError {
            return publicMutationResponse(error)
        } catch {
            return publicMutationError(.badRequest, "InvalidRequest")
        }
    }
    router.post(deletePath) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoDeleteRecord.Input.self,
            capability: capability
        ) { input, digest in
            publicMutationJSON(
                .ok,
                try await handlers.delete(input, bodyDigest: digest, request: request)
            )
        }
    }
    for path in [putPath, createPath, applyPath, uploadPath, deletePath] {
        for method: HTTPRequest.Method in [.get, .head, .put, .patch, .delete, .options, .connect, .trace] {
            router.on(path, method: method) { _, _ in publicMutationError(.notFound, "public_endpoint_unavailable") }
        }
    }
    // `com.atproto.sync.getBlob` is deliberately NOT registered here. It is a
    // read, and registering it in this block gated avatar and image serving
    // for the entire network behind `--enable-public-repository-mutations`.
    // It now lives in `registerPublicRepositoryReadEndpoints`.
}

private func publicMutationResponse(_ error: BlobQuotaError) -> Response {
    switch error {
    case .uniqueBytesExceeded, .referenceCountExceeded:
        return publicMutationError(.contentTooLarge, "AccountBlobQuotaExceeded")
    }
}

private func withPublicMutationInput<Value: Decodable>(
    _ request: Request,
    context: SwanHTTPRequestContext,
    as type: Value.Type,
    capability: SwanPublicRepositoryMutationCapability,
    operation: (Value, Data) async throws -> Response
) async -> Response {
    let contentTypes = request.headers[values: .contentType]
    guard contentTypes.count == 1,
          contentTypes[0].split(separator: ";", maxSplits: 1).first?.lowercased() == "application/json" else {
        context.jsonWriteBodyTermination.terminate()
        return publicMutationResponse(
            PublicMutationFailure.invalidRequest,
            authorizer: capability.authorizer
        )
    }
    guard acceptsPublicMutationContentLength(request.headers[values: .contentLength]) else {
        context.jsonWriteBodyTermination.terminate()
        return publicMutationResponse(
            PublicMutationFailure.invalidRequest,
            authorizer: capability.authorizer
        )
    }
    return await withAdmittedJSONWriteResponse(
        request.body,
        admission: capability.jsonWriteAdmission,
        policy: capability.jsonWriteBodyPolicy,
        maximumBytes: publicMutationMaximumJSONBytes,
        expectedBytes: request.headers[values: .contentLength].first.flatMap(Int.init),
        termination: context.jsonWriteBodyTermination
    ) { data in
        try StrictPermissionedWriteJSON.validate(data)
        return (
            try JSONDecoder().decode(Value.self, from: data),
            Data(SHA256.hash(data: data))
        )
    } operation: { admitted in
        try await operation(admitted.0, admitted.1)
    } errorResponse: { error in
        publicMutationResponse(error, capability: capability)
    }
}

func acceptsPublicMutationContentLength(_ values: [String]) -> Bool {
    guard values.count <= 1 else { return false }
    guard let value = values.first else { return true }
    guard !value.isEmpty,
          value.utf8.allSatisfy({ (48...57).contains($0) }),
          value.first != "0",
          let length = Int(value) else {
        return false
    }
    return length <= publicMutationMaximumJSONBytes
}

private func publicMutationResponse(
    _ error: any Error,
    capability: SwanPublicRepositoryMutationCapability
) -> Response {
    if let failure = error as? PublicMutationFailure {
        return publicMutationResponse(failure, authorizer: capability.authorizer)
    }
    if let failure = error as? SwanJSONWriteBodyCollectionFailure {
        return publicMutationResponse(failure)
    }
    if let failure = error as? PublicRepositoryMutationCoordinatorError {
        return publicMutationResponse(failure)
    }
    return publicMutationError(.badRequest, "InvalidRequest")
}

private func publicMutationResponse(
    _ failure: SwanJSONWriteBodyCollectionFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        publicMutationError(.badRequest, "InvalidRequest")
    case .unavailable:
        publicMutationError(.serviceUnavailable, "temporarily_unavailable")
    }
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

private func publicMutationResponse(_ error: SwanError) -> Response {
    switch error {
    case .unavailable, .conflict:
        return publicMutationError(.serviceUnavailable, "temporarily_unavailable")
    case .unauthorized, .expired:
        return publicMutationError(.unauthorized, "Unauthorized")
    case .invalidIdentifier, .invalidProfile, .malformed:
        return publicMutationError(.badRequest, "InvalidRequest")
    }
}

private func publicMutationResponse(
    _ failure: PublicRepositoryMutationCoordinatorError
) -> Response {
    switch failure {
    case .invalidSwap: return publicMutationError(.badRequest, "InvalidSwap")
    case .invalidBlobReference: return publicMutationError(.badRequest, "BlobNotFound")
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

/// Shared with the public blob read route on the read surface.
func safePublicBlobMIMEType(_ value: String?) -> String {
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
