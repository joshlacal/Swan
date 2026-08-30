import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanOAuth
import PetrelRepo
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
                admission: publicMutationRejectedDrainAdmission,
                policy: capability.jsonWriteBodyPolicy,
                termination: context.jsonWriteBodyTermination
            )
            throw PublicMutationFailure.invalidRequest
        }
        let (blobStore, mimeType, lease, subject) = try await withPublicBlobUploadPreflightDrain(
            request: request,
            context: context,
            admission: publicMutationRejectedDrainAdmission,
            policy: capability.jsonWriteBodyPolicy
        ) {
            let principal = try await authorizedPublicMutationPrincipal(
                request: request,
                path: "/xrpc/" + SwanPublicWire.ComAtprotoRepoUploadBlob.typeIdentifier,
                capability: capability
            )
            let subject = principal.subject
            guard let target = try await capability.directory.publicRepositoryMutationTarget(selector: subject),
                  target.did == subject,
                  target.status == .active,
                  let blobStore = target.store as? any StreamingBlobStore else {
                throw PublicMutationFailure.notFound
            }
            // The identity-admission fence runs before any body byte is
            // streamed: a suspended or failed-grace did:web identity cannot
            // consume the spool budget, and a store failure fails closed.
            do {
                try await capability.requireWriteAdmission(accountDID: subject, now: Date())
            } catch let failure as PublicMutationFailure {
                throw failure
            } catch {
                throw PublicMutationFailure.unavailable
            }
            let contentTypes = request.headers[values: .contentType]
            guard contentTypes.count <= 1 else {
                throw PublicMutationFailure.invalidRequest
            }
            let requestedMIMEType = contentTypes.first?.split(separator: ";", maxSplits: 1).first.map(String.init)
                ?? "application/octet-stream"
            let mimeType = safePublicBlobMIMEType(requestedMIMEType)
            // `assertBlob({mime: encoding})` — `repo/uploadBlob.ts:16`. Upstream
            // reads the mime from the Content-Type HEADER, never the body, and
            // so does this.
            //
            // The SANITIZED value is what is checked, not the raw header. That
            // is deliberate and it is the fail-closed direction: a malformed
            // header collapses to `application/octet-stream`, which is also what
            // gets recorded on the blob, so the grant is evaluated against the
            // mime the account will actually be storing. Checking the raw header
            // instead would let a client name `image/png`, be admitted by a
            // `blob:image/*` grant, and still store an octet-stream. It also
            // guarantees a concrete `type/subtype`, which `BlobPermission.matches`
            // requires before anything — not even `*/*` matches a non-concrete
            // request mime (`mime.test.ts:73-74`).
            try enforcingScope(
                route: "/xrpc/" + SwanPublicWire.ComAtprotoRepoUploadBlob.typeIdentifier,
                logger: context.logger,
                denial: PublicMutationFailure.unauthorized
            ) {
                try principal.permissions.requireBlob(.init(mime: mimeType))
            }
            guard let admission = capability.publicBlobSpoolAdmission,
                  let lease = admission.reserve(
                      accountDID: target.did,
                      maximumBytes: maximumBytes
                  ) else {
                throw PublicMutationFailure.unavailable
            }
            return (blobStore, mimeType, lease, subject)
        }
        defer { lease.release() }
        let counter = PublicBlobUploadCounter()
        let body = request.body
        let reference = try await withAbsoluteRequestBodyDeadline(
            policy: capability.jsonWriteBodyPolicy,
            termination: context.jsonWriteBodyTermination
        ) {
            // `uploadBlob` carries no namespace intent, so this one route also
            // receives every blob destined for a permissioned space. Staging
            // is what keeps those bytes out of the anonymous
            // `com.atproto.sync.getBlob` namespace until a commit says where
            // they belong; the commit that references them promotes them.
            try await blobStore.putStreaming(
                namespace: .staged,
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
        // The lifecycle state that authorized this request is up to 256 MiB
        // and one full body deadline stale by the time the blob is adopted.
        // Re-resolve before reporting a usable blob, so a deactivation that
        // landed mid-stream is not answered with success.
        //
        // The adopted bytes are deliberately left in place rather than
        // removed. `blob_namespace_references` carries one row per
        // `(cid, namespace_kind, space_uri)` with no reference count
        // (`Sources/SwanSQLite/SwanSQLite.swift:1041-1050`) and adoption is
        // `ON CONFLICT DO NOTHING` (`:7564-7572`), so `remove` cannot tell a
        // blob this request created from one an already-published record
        // shares by content address. Reclaiming here would destroy the latter.
        // Recorded in the L4 lane report as a maintainer decision.
        //
        // Merge note (2026-08-13): the blob lane's staged namespace changes
        // what "left in place" costs, without weakening the argument above.
        // The upload now lands on a `staged` edge rather than a `public` one,
        // and staged edges that no record promotes are reclaimed by that
        // lane's sweep — so the bytes this guard abandons are collected
        // rather than retained indefinitely, and they were never anonymously
        // fetchable while they sat here. The reference-count reasoning is
        // still why `remove` is not called; its deferred cost is now bounded
        // by the sweep instead of being permanent.
        guard let adopted = try await capability.directory
            .publicRepositoryMutationTarget(selector: subject),
            adopted.did == subject,
            adopted.status == .active else {
            throw PublicMutationFailure.notFound
        }
        do {
            // Re-fence identity admission at adoption: a suspension or grace
            // expiry that landed mid-stream must not be answered with success.
            try await capability.requireWriteAdmission(accountDID: subject, now: Date())
        } catch let failure as PublicMutationFailure {
            throw failure
        } catch {
            throw PublicMutationFailure.unavailable
        }
        guard case .staged = reference.namespace else {
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
        subject: String
    ) async throws -> SwanPublicWire.ComAtprotoRepoApplyWrites.Output {
        let target = try await mutationTarget(selector: input.repo.stringValue(), subject: subject)
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
        subject: String
    ) async throws -> SwanPublicWire.ComAtprotoRepoCreateRecord.Output {
        let target = try await mutationTarget(
            selector: input.repo.stringValue(), subject: subject
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
        subject: String
    ) async throws -> SwanPublicWire.ComAtprotoRepoPutRecord.Output {
        let target = try await mutationTarget(
            selector: input.repo.stringValue(), subject: subject
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
        subject: String
    ) async throws -> SwanPublicWire.ComAtprotoRepoDeleteRecord.Output {
        let target = try await mutationTarget(
            selector: input.repo.stringValue(), subject: subject
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

    /// Binds an already-authorized subject to the body-supplied repository
    /// selector. This half deliberately stays here: it is the only part of
    /// authorization that needs the decoded command, so it is also the only
    /// part that has to run after the body has been admitted and parsed.
    ///
    /// The durable identity-admission check also runs here: a suspended or
    /// failed-grace did:web identity denies every write, and a store/resolver
    /// failure fails closed (denies) rather than committing.
    private func mutationTarget(
        selector: String,
        subject: String
    ) async throws -> PublicRepositoryMutationTarget {
        guard let target = try await capability.directory.publicRepositoryMutationTarget(selector: selector) else {
            throw PublicMutationFailure.notFound
        }
        guard target.status == .active, target.did == subject else { throw PublicMutationFailure.notFound }
        do {
            try await capability.requireWriteAdmission(accountDID: subject, now: Date())
        } catch let failure as PublicMutationFailure {
            throw failure
        } catch {
            throw PublicMutationFailure.unavailable
        }
        return target
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
            // A record may reference a blob this account has staged but not
            // yet published — that is the ordinary upload-then-post flow, and
            // committing this record is what publishes it. The commit
            // transaction re-derives the same reachability under the storage
            // serialization boundary before it promotes anything.
            let metadata: PublicBlobMetadata?
            do {
                metadata = try await blobStore.uploadedBlobMetadata(cid: cid.string)
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

/// Header-only OAuth/DPoP admission for one fixed public write route.
///
/// It reads nothing but the `Authorization` and `DPoP` headers, which is what
/// lets every route run it *before* reserving a JSON write lease. It must run
/// exactly once per request: `OAuthDPoPProofValidator` durably claims the
/// proof's `jti` (`Sources/SwanOAuth/OAuthProofValidation.swift:117-119`), so
/// a second call for the same request is indistinguishable from a replay and
/// would deny every legitimate command.
private func authorizedPublicMutationPrincipal(
    request: Request,
    path: String,
    capability: SwanPublicRepositoryMutationCapability
) async throws -> AuthorizedPrincipal {
    let authorization: AuthorizationContext
    do {
        // Every route on this surface is registered with `post`; the fixed
        // method is the DPoP `htm` binding, never a request-derived value.
        authorization = try await capability.authorizer.authorize(
            request: request, method: "POST", fixedPath: path
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        throw failure == .nonceChallengeRequired ? PublicMutationFailure.nonce : .unauthorized
    } catch {
        throw PublicMutationFailure.unavailable
    }
    // PORTED (§6.5.10). This is the authorization FLOOR only — it establishes
    // that the caller holds an AT Protocol session at all. The per-method
    // predicates upstream spells `assertRepo({action, collection})` on
    // `repo/{createRecord.ts:64, putRecord.ts:82 AND :86, deleteRecord.ts:60,
    // applyWrites.ts:118}` and `assertBlob({mime: encoding})` on
    // `repo/uploadBlob.ts:16` CANNOT run here: `collection` lives in the
    // request body, and this function deliberately runs on headers alone so no
    // JSON write lease is reserved for an unauthenticated caller.
    //
    // So the permissions travel out with the subject and each route asserts
    // once it has decoded its own input. `uploadBlob` is the exception and
    // asserts from the Content-Type HEADER, which is the porting detail most
    // easily lost — never from the body.
    // OPT-IN for legacy sessions (§D3), the second of the two surfaces opened
    // on purpose: without it the client can read but not post.
    //
    // Each route still asserts `requireRepo`/`requireBlob` against whatever
    // permissions the principal carries, so an app-password session writes only
    // what its row grants while an account-password session writes what full
    // legacy authority grants.
    let subject: String
    let permissions: SwanScopePermissions
    switch authorization {
    case let .accountOAuth(oauthSubject, oauthPermissions):
        subject = oauthSubject
        permissions = oauthPermissions
    case let .accountLegacySession(legacySubject, legacyPermissions):
        subject = legacySubject
        permissions = legacyPermissions
    default:
        throw PublicMutationFailure.unauthorized
    }
    guard permissions.hasBaseATProtocolScope else { throw PublicMutationFailure.unauthorized }
    return AuthorizedPrincipal(subject: subject, permissions: permissions)
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

/// Installs the public write surface, filtered by the selected public route
/// surface.
///
/// `servedMethods` is required rather than defaulted for the same reason it is
/// on the read surface: these five handlers used to be installed on any
/// assembly that opted into public writes, whatever profile was selected, so a
/// narrower profile removed nothing.
func registerPublicRepositoryMutationEndpoints(
    on router: Router<BasicRequestContext>,
    capability: SwanPublicRepositoryMutationCapability,
    servedMethods: Set<String>
) {
    let handlers = PublicMutationHandlers(capability: capability)
    let putNSID = SwanPublicWire.ComAtprotoRepoPutRecord.typeIdentifier
    let createNSID = SwanPublicWire.ComAtprotoRepoCreateRecord.typeIdentifier
    let applyNSID = SwanPublicWire.ComAtprotoRepoApplyWrites.typeIdentifier
    let uploadNSID = SwanPublicWire.ComAtprotoRepoUploadBlob.typeIdentifier
    let deleteNSID = SwanPublicWire.ComAtprotoRepoDeleteRecord.typeIdentifier
    router.postIfServed(putNSID, in: servedMethods) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoPutRecord.Input.self,
            path: "/xrpc/\(putNSID)",
            capability: capability
        ) { input, digest, principal in
            try enforcingScope(
                route: "/xrpc/\(putNSID)",
                logger: context.logger,
                denial: PublicMutationFailure.unauthorized
            ) {
                // `putRecord.ts:82 AND :86` — BOTH actions, deliberately.
                // The route may create or update, and upstream demands both up
                // front rather than deciding after the swap check, so a grant
                // holding only one of them cannot reach it.
                let collection = input.collection.nsidString()
                try principal.permissions.requireRepo(.init(collection: collection, action: .create))
                try principal.permissions.requireRepo(.init(collection: collection, action: .update))
            }
            return publicMutationJSON(
                .ok,
                try await handlers.put(input, bodyDigest: digest, subject: principal.subject)
            )
        }
    }
    router.postIfServed(createNSID, in: servedMethods) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoCreateRecord.Input.self,
            path: "/xrpc/\(createNSID)",
            capability: capability
        ) { input, digest, principal in
            try enforcingScope(
                route: "/xrpc/\(createNSID)",
                logger: context.logger,
                denial: PublicMutationFailure.unauthorized
            ) {
                // `createRecord.ts:64`.
                try principal.permissions.requireRepo(
                    .init(collection: input.collection.nsidString(), action: .create)
                )
            }
            return publicMutationJSON(
                .ok,
                try await handlers.create(input, bodyDigest: digest, subject: principal.subject)
            )
        }
    }
    router.postIfServed(applyNSID, in: servedMethods) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoApplyWrites.Input.self,
            path: "/xrpc/\(applyNSID)",
            capability: capability
        ) { input, digest, principal in
            try enforcingScope(
                route: "/xrpc/\(applyNSID)",
                logger: context.logger,
                denial: PublicMutationFailure.unauthorized
            ) {
                // `applyWrites.ts:104-120` — PER WRITE, not per request.
                // Upstream groups the writes into one collection set per action
                // and asserts each (action, collection) pair, so a batch is
                // admitted only if EVERY write in it is individually granted.
                // An `.unexpected` member is not classifiable into an action and
                // so cannot be granted; it is left to the handler, which already
                // refuses it.
                for write in input.writes {
                    switch write {
                    case let .comAtprotoRepoApplyWritesCreate(value):
                        try principal.permissions.requireRepo(
                            .init(collection: value.collection.nsidString(), action: .create)
                        )
                    case let .comAtprotoRepoApplyWritesUpdate(value):
                        try principal.permissions.requireRepo(
                            .init(collection: value.collection.nsidString(), action: .update)
                        )
                    case let .comAtprotoRepoApplyWritesDelete(value):
                        try principal.permissions.requireRepo(
                            .init(collection: value.collection.nsidString(), action: .delete)
                        )
                    case .unexpected:
                        continue
                    }
                }
            }
            return publicMutationJSON(
                .ok,
                try await handlers.applyWrites(input, bodyDigest: digest, subject: principal.subject)
            )
        }
    }
    router.postIfServed(uploadNSID, in: servedMethods) { request, context async -> Response in
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
    router.postIfServed(deleteNSID, in: servedMethods) { request, context async -> Response in
        await withPublicMutationInput(
            request,
            context: context,
            as: SwanPublicWire.ComAtprotoRepoDeleteRecord.Input.self,
            path: "/xrpc/\(deleteNSID)",
            capability: capability
        ) { input, digest, principal in
            try enforcingScope(
                route: "/xrpc/\(deleteNSID)",
                logger: context.logger,
                denial: PublicMutationFailure.unauthorized
            ) {
                // `deleteRecord.ts:60`.
                try principal.permissions.requireRepo(
                    .init(collection: input.collection.nsidString(), action: .delete)
                )
            }
            return publicMutationJSON(
                .ok,
                try await handlers.delete(input, bodyDigest: digest, subject: principal.subject)
            )
        }
    }
    // Only installed routes claim their own verb; an unserved method must be
    // indistinguishable from one this build does not implement.
    for nsid in [putNSID, createNSID, applyNSID, uploadNSID, deleteNSID]
        where servedMethods.contains(nsid)
    {
        let path = RouterPath("/xrpc/\(nsid)")
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
    path: String,
    capability: SwanPublicRepositoryMutationCapability,
    operation: (Value, Data, AuthorizedPrincipal) async throws -> Response
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
    // Authorize on headers alone before any lease is reserved. Nothing in the
    // OAuth/DPoP check reads the body, so the old order bought nothing and
    // let an anonymous caller own one of eight shared JSON write leases for
    // the whole 30-second body deadline. `uploadBlob` above has always done
    // it this way.
    let principal: AuthorizedPrincipal
    do {
        principal = try await authorizedPublicMutationPrincipal(
            request: request,
            path: path,
            capability: capability
        )
    } catch {
        // Discard the refused body rather than resetting the connection, so a
        // client that sent a complete command keeps its keep-alive. The drain
        // deliberately charges a pool that no authorized command reserves.
        do {
            try await drainRejectedRequestBody(
                request,
                admission: publicMutationRejectedDrainAdmission,
                policy: capability.jsonWriteBodyPolicy,
                termination: context.jsonWriteBodyTermination
            )
        } catch {
            return publicMutationResponse(
                PublicMutationFailure.unavailable,
                authorizer: capability.authorizer
            )
        }
        return publicMutationResponse(error, capability: capability)
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
        try await operation(admitted.0, admitted.1, principal)
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
    case .quotaExceeded: return publicMutationError(.badRequest, "QuotaExceeded")
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
