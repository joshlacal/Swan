import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanAccounts
import SwanCore
import SwanPublicRepository
import SwanPublicWire
import SwanStorage
import Synchronization

/// Server-side diagnostics for the unauthenticated public read path. Stable
/// identifiers only — never payloads, credentials, or repository content.
private let publicReadDiagnosticLog = SwanLog(label: "swan.public-read")

/// Every method installed by the public read surface.
///
/// `com.atproto.identity.resolveHandle` belongs to this set: it is registered
/// from ``registerPublicRepositoryReadEndpoints`` alongside the repository
/// routes. It differs from the rest in needing a second capability — the
/// account control store — so membership alone does not mean a live route
/// exists. ``isInstalledPublicReadMethod(_:handleResolutionInstalled:)`` is the
/// predicate that knows the difference; nothing may consult this set directly.
private let publicReadNSIDs: Set<String> = [
    "com.atproto.identity.resolveHandle",
    "com.atproto.repo.describeRepo",
    "com.atproto.repo.getRecord",
    "com.atproto.repo.listRecords",
    "com.atproto.sync.getBlob",
    "com.atproto.sync.getLatestCommit",
    "com.atproto.sync.getRepo",
    "com.atproto.sync.getRepoStatus",
]

private let getBlobNSID = "com.atproto.sync.getBlob"

private let resolveHandleNSID = "com.atproto.identity.resolveHandle"

/// The response body budget for `resolveHandle`. Its output is one DID, and
/// `AccountControlIdentifiers` already bounds a DID at 2 KiB, so this is a
/// generous ceiling rather than a working limit. It exists so the encode path
/// carries an honest bound instead of inheriting the 16 MiB `listRecords`
/// default, and so the route never reserves a shared read lease it cannot use.
private let resolveHandleMaximumResponseBytes = 4 * 1_024

/// `resolveHandle`'s own admission, deliberately a separate instance from the
/// shared JSON read budget.
///
/// Separate, because reserving the multi-megabyte `listRecords` budget for a
/// one-DID response would let repository traffic starve the method every login
/// depends on. Bounded, because this is the only anonymous route with a path
/// into the single-connection control-database gate that OAuth, login, and
/// DPoP lookups also use: that gate is depth-1 and throws
/// `SwanError.unavailable` at the *next* caller once 128 waiters are queued, so
/// an unmetered anonymous route could deny login without presenting a
/// credential. Eight concurrent reads is exactly the ceiling anonymous traffic
/// already had through the shared read admission before this route existed.
///
/// The byte dimension is inert here — the initializer's floor is the
/// `listRecords` ceiling, and a 4 KiB reservation never approaches it. The
/// concurrency dimension is the operative bound.
let publicHandleResolutionAdmission = try! PublicRepositoryJSONReadAdmission(
    maximumConcurrentReads: 8,
    maximumReservedResponseBytes: PublicRepositoryJSONReadLimits
        .maximumListRecordsResponseBytes
)

/// Names an HTTP-layer guard that refuses a read after storage has already
/// answered. These are the 503 causes that never reach
/// `PublicReadUnavailableReason` because they are decided above the directory.
private enum PublicReadHandlerGuard: String {
    /// `describeRepo`: the admitted identity's `pdsOrigin` is not this service.
    case pdsOriginMismatch
    /// `listRecords`: the returned page violates its own ordering or cursor
    /// invariant.
    case listRecordsOrderingInvariant
    /// `getRepoStatus`: the account carries a status this build cannot render.
    case unknownAccountStatus
    /// A process-wide response-byte reservation was refused.
    case responseAdmissionExhausted
    /// The response could not be encoded, or exceeded its byte budget.
    case responseEncodingFailed
    /// `resolveHandle`: the account control store failed to answer the one
    /// handle lookup it is asked for. Distinct from every reason above because
    /// this route never consults the public read directory, so none of the
    /// generation-admission guards can possibly be the cause.
    case handleDirectoryUnavailable
    /// `getBlob`: the per-account/process blob streaming reservation was
    /// refused. Distinct from `responseAdmissionExhausted`, which names the
    /// JSON response-byte budget — a saturated blob budget and a saturated
    /// JSON budget call for different operator responses.
    case blobStreamAdmissionExhausted
    /// `getBlob`: the account's blob store failed to open a blob it reported
    /// as reachable.
    case blobStorageFailure
    /// `getBlob`: the opened blob declared a length outside the transfer bound
    /// this service will stream, or a length other than the one its metadata
    /// declared, so it is refused before a single byte leaves.
    case blobLengthOutOfBounds
    /// `getBlob`: the route's own request-body admission — the pool that
    /// bounds how many inbound streams may be proved empty at once — refused
    /// the reservation. Distinct from `blobStreamAdmissionExhausted`, which
    /// names the outbound transfer budget.
    case blobRequestBodyAdmissionExhausted
}

private enum PublicReadHandlerFailure: Error {
    case repoNotFound
    case recordNotFound
    case lifecycle(AccountControlStatus)
    case invalidRequest
    case unavailable(PublicReadHandlerGuard)
}

private struct PublicDescribeRepoHandler:
    SwanPublicWire.ComAtprotoRepoDescribeRepo.ServerHandler
{
    typealias Context = Request
    let directory: any PublicRepositoryReadDirectory
    let publicURL: URL

    func handle(
        parameters: SwanPublicWire.ComAtprotoRepoDescribeRepo.Parameters,
        input: Void,
        context: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoDescribeRepo.Output {
        let selector = parameters.repo.stringValue()
        let description: PublicRepositoryReadDescription
        switch try await directory.publicRepositoryDescriptionOutcome(
            selector: selector
        ) {
        case .notFound:
            throw PublicReadHandlerFailure.repoNotFound
        case let .lifecycle(status):
            throw PublicReadHandlerFailure.lifecycle(status.status)
        case let .active(resolved):
            description = resolved
        }
        guard publicReadOriginsMatch(
            description.identity.pdsOrigin, publicURL.absoluteString
        ) else {
            throw PublicReadHandlerFailure.unavailable(.pdsOriginMismatch)
        }
        let didDocument = try makePublicDIDDocument(
            id: description.did,
            handle: description.identity.canonicalHandle,
            signingDIDKey: description.identity.signingDIDKey,
            serviceEndpoint: description.identity.pdsOrigin
        )
        return .init(
            handle: try Handle(handleString: description.canonicalHandle),
            did: try DID(didString: description.did),
            didDoc: didDocument,
            collections: try description.collections.map(NSID.init(nsidString:)),
            handleIsCorrect: description.identity.handleIsCorrect
        )
    }
}

private struct PublicGetRecordHandler:
    SwanPublicWire.ComAtprotoRepoGetRecord.ServerHandler
{
    typealias Context = Request
    let directory: any PublicRepositoryReadDirectory

    func handle(
        parameters: SwanPublicWire.ComAtprotoRepoGetRecord.Parameters,
        input: Void,
        context: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoGetRecord.Output {
        let selector = parameters.repo.stringValue()
        let path = try PublicRepositoryPath(
            collection: parameters.collection.nsidString(),
            recordKey: parameters.rkey.value
        )
        let result: PublicRepositoryReadRecordResult
        switch try await directory.publicRepositoryRecordOutcome(
            selector: selector,
            path: path,
            expectedCID: parameters.cid
        ) {
        case .notFound:
            throw PublicReadHandlerFailure.repoNotFound
        case let .lifecycle(status):
            throw PublicReadHandlerFailure.lifecycle(status.status)
        case let .active(resolved):
            result = resolved
        }
        guard let record = result.record else {
            throw PublicReadHandlerFailure.recordNotFound
        }
        return .init(
            uri: try ATProtocolURI(
                uriString: "at://\(result.did)/\(path.mstKey)"
            ),
            cid: record.cid,
            value: try RepositoryMSTValidation.decodeRecordBlock(
                record.canonicalBytes,
                for: path
            )
        )
    }
}

private struct PublicListRecordsHandler:
    SwanPublicWire.ComAtprotoRepoListRecords.ServerHandler
{
    typealias Context = Request
    let directory: any PublicRepositoryReadDirectory

    func handle(
        parameters: SwanPublicWire.ComAtprotoRepoListRecords.Parameters,
        input: Void,
        context: Request
    ) async throws -> SwanPublicWire.ComAtprotoRepoListRecords.Output {
        let selector = parameters.repo.stringValue()
        let collection = parameters.collection.nsidString()
        let result: PublicRepositoryReadPageResult
        switch try await directory.publicRepositoryRecordsOutcome(
            selector: selector,
            collection: collection,
            limit: parameters.limit ?? 50,
            cursor: parameters.cursor,
            reverse: parameters.reverse ?? false
        ) {
        case .notFound:
            throw PublicReadHandlerFailure.repoNotFound
        case let .lifecycle(status):
            throw PublicReadHandlerFailure.lifecycle(status.status)
        case let .active(resolved):
            result = resolved
        }
        let page = result.page
        let limit = parameters.limit ?? 50
        let reverse = parameters.reverse ?? false
        let keys = page.records.map(\.path.recordKey)
        guard page.records.count <= limit,
              page.records.allSatisfy({ $0.path.collection == collection }),
              Set(keys).count == keys.count,
              zip(keys, keys.dropFirst()).allSatisfy({
                  reverse ? $0.0 < $0.1 : $0.0 > $0.1
              }),
              parameters.cursor.map({ cursor in
                  keys.allSatisfy { key in
                      reverse ? key > cursor : key < cursor
                  }
              }) ?? true,
              page.cursor == keys.last else {
            throw PublicReadHandlerFailure.unavailable(
                .listRecordsOrderingInvariant
            )
        }
        let records = try page.records.map {
            SwanPublicWire.ComAtprotoRepoListRecords.Record(
                uri: try ATProtocolURI(
                    uriString: "at://\(result.did)/\($0.path.mstKey)"
                ),
                cid: $0.cid,
                value: try RepositoryMSTValidation.decodeRecordBlock(
                    $0.canonicalBytes,
                    for: $0.path
                )
            )
        }
        return .init(cursor: page.cursor, records: records)
    }
}

private struct PublicLatestCommitHandler:
    SwanPublicWire.ComAtprotoSyncGetLatestCommit.ServerHandler
{
    typealias Context = Request
    let directory: any PublicRepositoryReadDirectory

    func handle(
        parameters: SwanPublicWire.ComAtprotoSyncGetLatestCommit.Parameters,
        input: Void,
        context: Request
    ) async throws -> SwanPublicWire.ComAtprotoSyncGetLatestCommit.Output {
        let selector = parameters.did.didString()
        let description: PublicRepositoryReadDescription
        switch try await directory.publicRepositoryDescriptionOutcome(
            selector: selector
        ) {
        case .notFound:
            throw PublicReadHandlerFailure.repoNotFound
        case let .lifecycle(status):
            throw PublicReadHandlerFailure.lifecycle(status.status)
        case let .active(resolved):
            description = resolved
        }
        return .init(
            cid: description.state.commitCID,
            rev: try TID(tidString: description.state.revision)
        )
    }
}

private struct PublicRepoStatusHandler:
    SwanPublicWire.ComAtprotoSyncGetRepoStatus.ServerHandler
{
    typealias Context = Request
    let directory: any PublicRepositoryReadDirectory

    func handle(
        parameters: SwanPublicWire.ComAtprotoSyncGetRepoStatus.Parameters,
        input: Void,
        context: Request
    ) async throws -> SwanPublicWire.ComAtprotoSyncGetRepoStatus.Output {
        guard let status = try await directory.publicRepositoryStatus(
            selector: parameters.did.didString()
        ) else { throw PublicReadHandlerFailure.repoNotFound }
        let publicStatus: String? = switch status.status {
        case .active: nil
        case .deactivated, .deleting, .deleted, .takendown, .suspended,
             .desynchronized, .throttled:
            status.status.rawValue
        case .unknown:
            throw PublicReadHandlerFailure.unavailable(.unknownAccountStatus)
        }
        return .init(
            did: try DID(didString: status.did),
            active: status.status == .active,
            status: publicStatus,
            rev: try status.revision.map(TID.init(tidString:))
        )
    }
}

/// Whether a live public read route is registered for this NSID, so a profile
/// that declares the method does not also install a 503 gate over it.
///
/// Callers have already established that a public repository read directory is
/// present. `resolveHandle` needs one capability more than that — the account
/// control store — and answering `true` for it without one would drop the
/// method's method-correct unavailable gate while registering no route to
/// replace it.
func isInstalledPublicReadMethod(
    _ nsid: String,
    handleResolutionInstalled: Bool
) -> Bool {
    guard publicReadNSIDs.contains(nsid) else { return false }
    return nsid != resolveHandleNSID || handleResolutionInstalled
}

/// The single storage question `com.atproto.identity.resolveHandle` is allowed
/// to ask, and the only reason the account control store reaches the
/// unauthenticated route surface at all.
///
/// The control store is a very wide type — credentials, recovery envelopes,
/// email delivery leases, key references. None of that may be reachable from an
/// anonymous request, so the store is held privately here and exactly one
/// projection escapes: an active account's DID, given its canonical handle.
/// This is an allow-list of one, not a store handed to a public handler that
/// promises to only call one method on it.
public struct SwanPublicHandleResolutionCapability: Sendable {
    private let controlStore: any AccountControlStore

    public init(controlStore: any AccountControlStore) {
        self.controlStore = controlStore
    }

    /// Resolves a *canonical* handle to a hosted, active account's DID.
    ///
    /// Only `.active` accounts resolve. A deactivated, suspended, taken-down,
    /// deleting, or deleted handle is reported exactly as an unhosted one is —
    /// the caller learns "not resolvable here", never which of those it was.
    /// That matches the rest of Swan's public surface and the reference PDS,
    /// whose `resolveHandle` likewise excludes deactivated and taken-down
    /// accounts.
    ///
    /// This performs no DNS, PLC, DID, or HTTP resolution: a handle this
    /// service does not host is simply unresolvable here.
    func activeDID(forCanonicalHandle handle: String) async throws -> String? {
        guard AccountControlIdentifiers.isCanonicalHandle(handle) else {
            return nil
        }
        guard let account = try await controlStore.account(
            canonicalHandle: handle
        ), account.status.authorizesAccount else { return nil }
        return account.did
    }
}

/// `com.atproto.identity.resolveHandle`'s entire output.
private struct PublicResolveHandleOutput: Encodable {
    let did: String
}

/// Installs the public read surface, filtered by the selected public route
/// surface.
///
/// `servedMethods` is required rather than defaulted. It used to be absent
/// entirely, which meant every one of these routes existed on any assembly that
/// had a read directory, whatever profile the operator selected — the selection
/// only added 503 gates and never removed a handler. A default here would
/// restore exactly that: the one production call site would keep working while
/// silently serving the full set again.
func registerPublicRepositoryReadEndpoints(
    on router: Router<BasicRequestContext>,
    directory: any PublicRepositoryReadDirectory,
    servedMethods: Set<String>,
    publicURL: URL,
    jsonReadAdmission: PublicRepositoryJSONReadAdmission = .processShared,
    handleResolution: SwanPublicHandleResolutionCapability? = nil,
    handleResolutionAdmission: PublicRepositoryJSONReadAdmission =
        publicHandleResolutionAdmission,
    blobStreamAdmission: PublicRepositorySpoolAdmission = .shared,
    blobRequestBodyAdmission: PublicRepositoryJSONWriteAdmission =
        .publicBlobReadProcessShared,
    blobRequestBodyPolicy: SwanJSONWriteBodyPolicy = .noRequestBodyDefault
) {
    let describeHandler = PublicDescribeRepoHandler(
        directory: directory, publicURL: publicURL
    )
    let getRecordHandler = PublicGetRecordHandler(directory: directory)
    let listRecordsHandler = PublicListRecordsHandler(directory: directory)
    let latestCommitHandler = PublicLatestCommitHandler(directory: directory)
    let repoStatusHandler = PublicRepoStatusHandler(directory: directory)

    router.getIfServed(
        "com.atproto.repo.describeRepo", in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, schema: describeRepoQuerySchema)
            guard let repo = query["repo"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = repo
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumListRecordsResponseBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: "com.atproto.repo.describeRepo",
                    selector: selector
                )
            }
            do {
                let output = try await describeHandler.handle(
                    parameters: try publicReadWireParameters {
                        .init(repo: try ATIdentifier(string: repo))
                    },
                    input: (),
                    context: request
                )
                return publicReadJSON(
                    .ok,
                    output,
                    maximumBytes: PublicRepositoryJSONReadLimits
                        .maximumListRecordsResponseBytes,
                    lease: lease,
                    method: "com.atproto.repo.describeRepo",
                    selector: selector
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: "com.atproto.repo.describeRepo",
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: "com.atproto.repo.describeRepo",
                selector: selector
            )
        }
    }

    router.getIfServed(
        "com.atproto.repo.getRecord", in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request,
                schema: getRecordQuerySchema
            )
            guard let repo = query["repo"],
                  let collectionQuery = query["collection"],
                  let recordKeyQuery = query["rkey"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = repo
            let path = try PublicRepositoryPath(
                collection: collectionQuery,
                recordKey: recordKeyQuery
            )
            let expectedCID = try query["cid"].map(publicReadCID)
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumGetRecordResponseBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: "com.atproto.repo.getRecord",
                    selector: selector
                )
            }
            do {
                let output = try await getRecordHandler.handle(
                    parameters: try publicReadWireParameters {
                        .init(
                            repo: try ATIdentifier(string: repo),
                            collection: try NSID(nsidString: path.collection),
                            rkey: try RecordKey(keyString: path.recordKey),
                            cid: expectedCID
                        )
                    },
                    input: (),
                    context: request
                )
                return publicReadJSON(
                    .ok,
                    output,
                    maximumBytes: PublicRepositoryJSONReadLimits
                        .maximumGetRecordResponseBytes,
                    lease: lease,
                    method: "com.atproto.repo.getRecord",
                    selector: selector
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: "com.atproto.repo.getRecord",
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch PublicRepositoryDomainError.invalidCollection,
                PublicRepositoryDomainError.invalidRecordKey,
                PublicRepositoryDomainError.pathTooLong {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: "com.atproto.repo.getRecord",
                selector: selector
            )
        }
    }

    router.getIfServed(
        "com.atproto.repo.listRecords", in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request,
                schema: listRecordsQuerySchema
            )
            guard let repo = query["repo"],
                  let collectionQuery = query["collection"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = repo
            _ = try PublicRepositoryPath(
                collection: collectionQuery,
                recordKey: "validation"
            )
            let limit = try query["limit"].map(publicReadLimit) ?? 50
            let reverse = try query["reverse"].map(publicReadBoolean) ?? false
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumListRecordsResponseBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: "com.atproto.repo.listRecords",
                    selector: selector
                )
            }
            do {
                let output = try await listRecordsHandler.handle(
                    parameters: try publicReadWireParameters {
                        .init(
                            repo: try ATIdentifier(string: repo),
                            collection: try NSID(nsidString: collectionQuery),
                            limit: limit,
                            cursor: query["cursor"],
                            reverse: reverse
                        )
                    },
                    input: (),
                    context: request
                )
                return publicReadJSON(
                    .ok,
                    output,
                    maximumBytes: PublicRepositoryJSONReadLimits
                        .maximumListRecordsResponseBytes,
                    lease: lease,
                    method: "com.atproto.repo.listRecords",
                    selector: selector
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: "com.atproto.repo.listRecords",
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidLimit,
                PublicRepositoryReadError.invalidCursor,
                PublicRepositoryReadError.invalidSelector,
                PublicRepositoryDomainError.invalidCollection,
                PublicRepositoryDomainError.invalidRecordKey,
                PublicRepositoryDomainError.pathTooLong {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: "com.atproto.repo.listRecords",
                selector: selector
            )
        }
    }

    router.getIfServed(
        "com.atproto.sync.getLatestCommit", in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, schema: getLatestCommitQuerySchema)
            guard let rawDID = query["did"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = rawDID
            let did: DID = try publicReadWireParameters {
                try DID(didString: rawDID)
            }
            // Same lease the JSON repo reads take, and for the same reason: a
            // cache miss or a drifted generation pin sends this call into a
            // full admission — a paginated walk of up to
            // `maximumGenerationIndexEntries` index rows, an MST projection
            // verify, and PLC `verifyGenesis`. Unleased, each ~50-byte
            // anonymous GET bought one of those, and this is one of the three
            // methods a relay calls against a PDS.
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumGetRecordResponseBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: "com.atproto.sync.getLatestCommit",
                    selector: selector
                )
            }
            do {
                let output = try await latestCommitHandler.handle(
                    parameters: try publicReadWireParameters {
                        .init(did: did)
                    },
                    input: (),
                    context: request
                )
                return publicReadJSON(
                    .ok,
                    output,
                    maximumBytes: PublicRepositoryJSONReadLimits
                        .maximumGetRecordResponseBytes,
                    lease: lease,
                    method: "com.atproto.sync.getLatestCommit",
                    selector: selector
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: "com.atproto.sync.getLatestCommit",
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: "com.atproto.sync.getLatestCommit",
                selector: selector
            )
        }
    }

    router.getIfServed(
        "com.atproto.sync.getRepoStatus", in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, schema: getRepoStatusQuerySchema)
            guard let rawDID = query["did"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = rawDID
            let did: DID = try publicReadWireParameters {
                try DID(didString: rawDID)
            }
            // Leased for the same reason as `getLatestCommit`, and more
            // urgently: `getRepoStatus` is one of the three XRPC methods
            // indigo's relay calls against a PDS, so this is the route network
            // traffic arrives on first.
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumGetRecordResponseBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: "com.atproto.sync.getRepoStatus",
                    selector: selector
                )
            }
            do {
                let output = try await repoStatusHandler.handle(
                    parameters: try publicReadWireParameters {
                        .init(did: did)
                    },
                    input: (),
                    context: request
                )
                return publicReadJSON(
                    .ok,
                    output,
                    maximumBytes: PublicRepositoryJSONReadLimits
                        .maximumGetRecordResponseBytes,
                    lease: lease,
                    method: "com.atproto.sync.getRepoStatus",
                    selector: selector
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: "com.atproto.sync.getRepoStatus",
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: "com.atproto.sync.getRepoStatus",
                selector: selector
            )
        }
    }

    router.getIfServed(
        "com.atproto.sync.getRepo", in: servedMethods
    ) { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request,
                schema: getRepoQuerySchema
            )
            guard query["since"] == nil else {
                return publicReadError(.badRequest, "InvalidRequest")
            }
            guard let rawDID = query["did"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = rawDID
            let did: DID = try publicReadWireParameters {
                try DID(didString: rawDID)
            }
            let car: PublicRepositoryReadCAR
            switch try await directory.publicRepositoryCAROutcome(
                selector: did.didString()
            ) {
            case .notFound:
                return publicReadError(.badRequest, "RepoNotFound")
            case let .lifecycle(status):
                return publicLifecycleError(status.status)
            case let .active(resolved):
                car = resolved
            }
            return publicRepositoryCARHTTPResponse(car)
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: "com.atproto.sync.getRepo",
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: "com.atproto.sync.getRepo",
                selector: selector
            )
        }
    }

    // `com.atproto.sync.getBlob` is a read, and it belongs here.
    //
    // It used to be registered inside the *mutation* endpoint block, so
    // `--enable-public-repository-mutations` was silently also the switch for
    // avatar and image serving: an operator who turned public writes off
    // turned every image this PDS hosts off for the whole network, with no
    // error and nothing in the journal. It is registered here now, from the
    // single condition that governs the rest of the public read surface.
    //
    // Like `resolveHandle` it needs no repository *generation*: a blob is
    // content-addressed and carries no MST revision, so it stays out of the
    // admission machinery the other routes depend on.
    router.getIfServed(getBlobNSID, in: servedMethods) { request, context async -> Response in
        switch await publicBlobRequestBody(
            request,
            context: context,
            admission: blobRequestBodyAdmission,
            policy: blobRequestBodyPolicy
        ) {
        case .absent:
            break
        case .present:
            return publicReadError(.badRequest, "InvalidRequest")
        case .unavailable:
            // The route's own inbound pool is saturated. Never a 400: the
            // caller's request is well formed and this is a capacity refusal.
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard
                    .blobRequestBodyAdmissionExhausted.rawValue,
                method: getBlobNSID,
                selector: nil
            )
        }
        let parameters: PublicBlobParameters
        do {
            parameters = try publicBlobParameters(request)
        } catch {
            return publicReadError(.badRequest, "InvalidRequest")
        }
        let target: PublicRepositoryReadBlobTarget
        do {
            switch try await directory.publicRepositoryBlobOutcome(
                did: parameters.did
            ) {
            case .notFound:
                return publicReadError(.badRequest, "RepoNotFound")
            case let .lifecycle(status):
                return publicLifecycleError(status.status)
            case let .active(resolved):
                // Defence in depth: the directory is asked for one exact DID,
                // and an implementation that answered with another account's
                // store would serve one account's blobs under another's name.
                guard resolved.did == parameters.did else {
                    return publicReadError(.badRequest, "RepoNotFound")
                }
                target = resolved
            }
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadUnavailable(
                error,
                method: getBlobNSID,
                selector: parameters.did
            )
        }
        // The blob's true length, read without opening or materializing a
        // body, so the transfer budget below is reserved for the bytes this
        // response will actually stream.
        //
        // Reserving the 256 MiB ceiling for every blob instead would make a
        // 5 KiB avatar cost a quarter of the per-account budget: two
        // concurrent image reads per account, four across the service, and
        // `com.atproto.sync.getRepo` starved out of the same pool. That bound
        // was inherited from the old mutation-surface route; this is the
        // network-facing image path now.
        let metadata: PublicBlobMetadata?
        do {
            metadata = try await target.store.publicBlobMetadata(
                cid: parameters.cid
            )
        } catch {
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard.blobStorageFailure.rawValue,
                method: getBlobNSID,
                selector: target.did
            )
        }
        guard let metadata else {
            return publicReadError(.notFound, "BlobNotFound")
        }
        guard metadata.size > 0,
              metadata.size <= maximumPublicBlobTransferBytes else {
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard.blobLengthOutOfBounds.rawValue,
                method: getBlobNSID,
                selector: target.did
            )
        }
        // Reserved before the store opens anything and released only when the
        // response writer finishes, so a stalled reader cannot hold bytes
        // outside the budget.
        guard let streamLease = blobStreamAdmission.reserve(
            accountDID: target.did,
            maximumBytes: metadata.size
        ) else {
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard
                    .blobStreamAdmissionExhausted.rawValue,
                method: getBlobNSID,
                selector: target.did
            )
        }
        let blob: PublicBlob?
        do {
            blob = try await target.store.publicBlob(cid: parameters.cid)
        } catch {
            streamLease.release()
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard.blobStorageFailure.rawValue,
                method: getBlobNSID,
                selector: target.did
            )
        }
        guard let blob else {
            streamLease.release()
            return publicReadError(.notFound, "BlobNotFound")
        }
        // A blob is content-addressed and immutable, so the opened body must
        // declare exactly the length the metadata did. Anything else means the
        // reservation does not cover the transfer, and the bytes do not leave.
        guard blob.body.contentLength == metadata.size else {
            streamLease.release()
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard.blobLengthOutOfBounds.rawValue,
                method: getBlobNSID,
                selector: target.did
            )
        }
        var headers: HTTPFields = [
            .contentType: safePublicBlobMIMEType(blob.mimeType),
            .cacheControl: "no-store",
        ]
        headers[.contentLength] = String(blob.body.contentLength)
        headers[HTTPField.Name("X-Content-Type-Options")!] = "nosniff"
        return Response(status: .ok, headers: headers, body: .init { writer in
            defer { streamLease.release() }
            try await blob.body.streamBody(maximumChunkBytes: 64 * 1_024) { chunk in
                try await writer.write(ByteBuffer(data: chunk))
            }
            try await writer.finish(nil)
        })
    }

    // Only the routes that were actually installed above claim their own verb.
    // A method the selected surface does not serve must look exactly like a
    // method this build does not implement — one 404 from the namespace guard,
    // not a wrong-method guard that quietly proves the endpoint is known here.
    for nsid in [
        "com.atproto.repo.describeRepo",
        "com.atproto.repo.getRecord",
        "com.atproto.repo.listRecords",
        "com.atproto.sync.getBlob",
        "com.atproto.sync.getLatestCommit",
        "com.atproto.sync.getRepo",
        "com.atproto.sync.getRepoStatus",
    ] where servedMethods.contains(nsid) {
        registerPublicReadWrongMethodGuards(
            on: router, path: RouterPath("/xrpc/\(nsid)")
        )
    }

    // Part of the public read surface, and registered from here so a server
    // that exposes no public reads exposes no anonymous handle->DID oracle
    // either. It still needs no *generation*: see below.
    //
    // `resolveHandle` appears in no public profile artifact's `endpoints`
    // array, so it reaches `servedMethods` through
    // `SwanPublicRouteSurface.outOfProfilePublicMethods` rather than through a
    // profile. That is deliberate and enumerated there: gating it on a profile
    // declaration instead would delete handle resolution from every deployment,
    // and no profile could ever restore it.
    if let handleResolution, servedMethods.contains(resolveHandleNSID) {
        registerPublicHandleResolutionEndpoint(
            on: router,
            capability: handleResolution,
            admission: handleResolutionAdmission
        )
    }
}

/// Unauthenticated `com.atproto.identity.resolveHandle`.
///
/// Registered from ``registerPublicRepositoryReadEndpoints``, but deliberately
/// independent of the read *directory* it is registered beside. Every other
/// route in this file has to admit a generation before it can answer, and on
/// 2026-08-12 a stale `PRAGMA data_version` pin made that admission fail
/// permanently. A handle lookup needs none of it: it reads one control row and
/// returns one DID. So it shares the read surface's *installation* — an
/// operator who exposes no public reads exposes no handle oracle — while
/// depending on none of the directory's health.
///
/// It reserves from ``publicHandleResolutionAdmission`` rather than the shared
/// JSON read budget: its response is one DID, so taking a multi-megabyte lease
/// would let `listRecords` traffic starve the method every login depends on,
/// while taking *no* lease would leave the control-database gate — the same one
/// OAuth and login queue on — reachable by unmetered anonymous traffic.
func registerPublicHandleResolutionEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanPublicHandleResolutionCapability,
    admission: PublicRepositoryJSONReadAdmission = publicHandleResolutionAdmission
) {
    router.get("/xrpc/\(resolveHandleNSID)") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, schema: resolveHandleQuerySchema)
            guard let rawHandle = query["handle"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            // Handles are case-insensitive on the wire and canonical in
            // storage, so fold before looking up. A handle that is not a
            // well-formed handle at all is a request fault, not a lookup miss.
            guard let canonicalHandle = try? AccountIdentifiers
                .canonicalHandle(rawHandle) else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = canonicalHandle
            // Taken before the control store is touched and held until the
            // response value exists, so the number of anonymous requests inside
            // the control-database gate at once is this admission's ceiling and
            // not the listener's connection limit. The body is built eagerly,
            // so the lease does not need to outlive the handler.
            guard let lease = admission.reserve(
                maximumResponseBytes: resolveHandleMaximumResponseBytes
            ) else {
                return publicReadUnavailable(
                    reason: PublicReadHandlerGuard
                        .responseAdmissionExhausted.rawValue,
                    method: resolveHandleNSID,
                    selector: selector
                )
            }
            defer { lease.release() }
            guard let did = try await capability.activeDID(
                forCanonicalHandle: canonicalHandle
            ) else {
                // The reference PDS answers an unhosted or non-active handle
                // with InvalidRequest, not 404, and callers depend on that.
                throw PublicReadHandlerFailure.invalidRequest
            }
            return publicReadJSON(
                .ok,
                PublicResolveHandleOutput(did: did),
                maximumBytes: resolveHandleMaximumResponseBytes,
                method: resolveHandleNSID,
                selector: canonicalHandle
            )
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(
                failure,
                method: resolveHandleNSID,
                selector: selector
            )
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            // Only the control store can fail here. Name it rather than let a
            // storage fault arrive in the journal as "unclassified".
            return publicReadUnavailable(
                reason: PublicReadHandlerGuard
                    .handleDirectoryUnavailable.rawValue,
                method: resolveHandleNSID,
                selector: selector
            )
        }
    }
    registerPublicReadWrongMethodGuards(
        on: router, path: "/xrpc/\(resolveHandleNSID)"
    )
}

/// A public read path answers its own verb and nothing else. Without these the
/// exact path would only claim GET, and a POST to it would fall through to a
/// wildcard guard — or, worse, to whatever lower-priority route exists.
private func registerPublicReadWrongMethodGuards(
    on router: Router<BasicRequestContext>,
    path: RouterPath
) {
    for method: HTTPRequest.Method in [
        .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ] {
        router.on(path, method: method) { _, _ -> Response in
            jsonResponseWithStatus(
                .notFound,
                body: ["error": "public_endpoint_unavailable"]
            )
        }
    }
}

/// The exact production HTTP body adapter, exposed package-wide so the large
/// streaming acceptance gate can drain it without HummingbirdTesting
/// aggregating the response into one ByteBuffer.
package func publicRepositoryCARHTTPResponse(
    _ car: PublicRepositoryReadCAR
) -> Response {
    Response(
        status: .ok,
        headers: [
            .contentType: "application/vnd.ipld.car",
            .cacheControl: "no-store",
        ],
        body: .init { writer in
            defer { car.spool.cleanup() }
            try await car.spool.stream { chunk in
                try await writer.write(ByteBuffer(data: chunk))
            }
            try await writer.finish(nil)
        }
    )
}

/// `com.atproto.sync.getBlob`'s entire request.
///
/// Both values are kept in their exact wire spelling after being proved
/// canonical, so the account the bytes are read from is the account the caller
/// literally named — never a re-encoding of it.
private struct PublicBlobParameters {
    let did: String
    let cid: String
}

/// Strict, canonical-only parsing for `getBlob`.
///
/// Anything short of an exactly-canonical DID and an exactly-canonical raw
/// sha-256 CID is a request fault. Accepting a re-encoding of either would
/// make two spellings address one blob, and the CID codec/multihash checks
/// keep a caller from asking for a repository block through the blob route.
private func publicBlobParameters(_ request: Request) throws -> PublicBlobParameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        schema: publicBlobQuerySchema
    )
    guard let rawDID = query["did"],
          rawDID.utf8.count <= 2_048,
          let did = try? DID(didString: rawDID),
          did.didString() == rawDID,
          let rawCID = query["cid"],
          rawCID.utf8.count <= 256,
          let cid = try? CID.parse(rawCID),
          cid.string == rawCID,
          cid.codec == .raw,
          cid.multihash.algorithm == Multihash.sha256Code,
          cid.multihash.length == Multihash.sha256Length,
          cid.multihash.digest.count == Int(Multihash.sha256Length) else {
        throw PublicReadHandlerFailure.invalidRequest
    }
    return PublicBlobParameters(did: rawDID, cid: rawCID)
}

/// What the inbound stream of an anonymous `getBlob` turned out to carry.
private enum PublicBlobRequestBody {
    /// Proved empty. The only case the route proceeds from.
    case absent
    /// A body was declared or delivered. A request fault: 400.
    case present
    /// The route's own inbound admission refused, or the body deadline
    /// expired. A capacity refusal, not a caller fault: 503.
    case unavailable
}

/// `getBlob` is a query and carries no body, and a request that carries one is
/// refused.
///
/// Two properties matter here beyond the refusal itself.
///
/// A body that is *declared* in the headers is refused from the headers alone,
/// before any lease is taken and without reading a byte. `Transfer-Encoding`
/// is the shape that mattered: it declares a body with no length, so the
/// generic collector could not reject it up front and instead admitted it and
/// waited out the body deadline.
///
/// The reservation used for everything else is this route's **own** pool, not
/// the shared JSON *write* pool. On the shared pool a handful of anonymous
/// unterminated GETs could hold every one of its eight leases and deny the
/// authenticated space, account-email, and preferences commands that reserve
/// from it — an anonymous read starving authenticated writes on a server with
/// public writes turned off.
private func publicBlobRequestBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    admission: PublicRepositoryJSONWriteAdmission,
    policy: SwanJSONWriteBodyPolicy
) async -> PublicBlobRequestBody {
    if request.headers[values: .transferEncoding].isEmpty == false
        || request.headers[values: .contentLength].contains(where: { $0 != "0" })
    {
        context.jsonWriteBodyTermination.terminate()
        return .present
    }
    do {
        let body = try await collectAdmittedRequestBody(
            request,
            mediaType: .unspecified,
            admission: admission,
            policy: policy,
            maximumBytes: 1,
            termination: context.jsonWriteBodyTermination
        )
        defer { withExtendedLifetime(body) {} }
        return body.readableBytes == 0 ? .absent : .present
    } catch SwanRequestBodyCollectionFailure.unavailable {
        return .unavailable
    } catch {
        return .present
    }
}

private let describeRepoQuerySchema = StrictQuerySchema(required: ["repo"])
private let getRecordQuerySchema = StrictQuerySchema(
    required: ["repo", "collection", "rkey"],
    optional: ["cid"]
)
private let listRecordsQuerySchema = StrictQuerySchema(
    required: ["repo", "collection"],
    optional: ["limit", "cursor", "reverse"]
)
private let getLatestCommitQuerySchema = StrictQuerySchema(required: ["did"])
private let getRepoStatusQuerySchema = StrictQuerySchema(required: ["did"])
private let getRepoQuerySchema = StrictQuerySchema(
    required: ["did"],
    optional: ["since"]
)
private let resolveHandleQuerySchema = StrictQuerySchema(required: ["handle"])
private let publicBlobQuerySchema = StrictQuerySchema(required: ["did", "cid"])

private func publicReadQuery(
    _ request: Request,
    schema: StrictQuerySchema
) throws -> [String: String] {
    do {
        return try strictAuthenticatedRecordQuery(
            request, schema: schema
        )
    } catch {
        throw PublicRepositoryReadError.invalidSelector
    }
}

private func publicReadWireParameters<Value>(
    _ construct: () throws -> Value
) throws -> Value {
    do {
        return try construct()
    } catch {
        throw PublicReadHandlerFailure.invalidRequest
    }
}

private func publicReadLimit(_ raw: String) throws -> Int {
    guard !raw.isEmpty,
          raw.utf8.allSatisfy({ (48...57).contains($0) }),
          let value = Int(raw),
          (1...100).contains(value) else {
        throw PublicRepositoryReadError.invalidLimit
    }
    return value
}

private func publicReadCID(_ raw: String) throws -> CID {
    do {
        let cid = try CID.parse(raw)
        try PublicRepositoryCID.validate(cid)
        return cid
    } catch {
        throw PublicRepositoryReadError.invalidSelector
    }
}

private func publicReadBoolean(_ raw: String) throws -> Bool {
    switch raw {
    case "true": true
    case "false": false
    default: throw PublicRepositoryReadError.invalidSelector
    }
}

private func publicLifecycleError(_ status: AccountControlStatus) -> Response {
    let code = switch status {
    case .deactivated: "RepoDeactivated"
    case .suspended: "RepoSuspended"
    case .takendown: "RepoTakendown"
    default: "RepoNotFound"
    }
    return publicReadError(.badRequest, code)
}

private func publicReadResponse(
    _ failure: PublicReadHandlerFailure,
    method: String,
    selector: String?
) -> Response {
    switch failure {
    case .repoNotFound:
        publicReadError(.badRequest, "RepoNotFound")
    case .recordNotFound:
        publicReadError(.badRequest, "RecordNotFound")
    case let .lifecycle(status):
        publicLifecycleError(status)
    case .invalidRequest:
        publicReadError(.badRequest, "InvalidRequest")
    case .unavailable:
        // Routed through the logging helper: a handler-level refusal is a 503
        // like any other and must not be the one that leaves no trace.
        publicReadUnavailable(failure, method: method, selector: selector)
    }
}

private func publicReadError(_ status: HTTPResponse.Status, _ code: String) -> Response {
    jsonResponseWithStatus(status, body: ["error": code])
}

/// Every public-read 503 on these routes leaves through here.
///
/// The response is byte-identical to what it has always been —
/// `503 {"error":"temporarily_unavailable"}`. What changes is that the guard
/// that refused the read is now written to the service journal. Three hours of
/// live 503s on 2026-08-12 produced zero journal lines, and diagnosing them
/// required copying the production databases to a laptop.
///
/// The selector is logged only when it is already a well-formed DID or handle,
/// so an arbitrary query value can never be reflected into the journal.
private func publicReadUnavailable(
    _ error: any Error,
    method: String,
    selector: String?
) -> Response {
    publicReadUnavailable(
        reason: publicReadDiagnosticToken(error),
        method: method,
        selector: selector
    )
}

/// The 503 exits that are decided rather than thrown — an admission reservation
/// refused, a response body that will not encode — name their guard directly.
private func publicReadUnavailable(
    reason: String,
    method: String,
    selector: String?
) -> Response {
    guard let suppressed = publicReadDiagnosticThrottle.admit(
        method: method, reason: reason
    ) else {
        return publicReadError(.serviceUnavailable, "temporarily_unavailable")
    }
    var fields = ["method": method, "reason": reason]
    if let selector,
       AccountControlIdentifiers.isDID(selector)
       || AccountControlIdentifiers.isCanonicalHandle(selector) {
        fields["selector"] = selector
    }
    if suppressed > 0 {
        fields["suppressedRepeats"] = String(suppressed)
    }
    publicReadDiagnosticJournalLines.withLock { $0 += 1 }
    publicReadDiagnosticLog.warning("public read unavailable", fields: fields)
    return publicReadError(.serviceUnavailable, "temporarily_unavailable")
}

/// Test seam: public-read 503 lines this module has written, counted at the one
/// site that writes them. Never read by production code — it exists so a route
/// test can assert that journal volume stops tracking request count, which is
/// invisible from a response body.
let publicReadDiagnosticJournalLines = Mutex(0)

/// One window per distinct public-read refusal, so journal volume tracks
/// distinct failures rather than inbound request rate.
///
/// Every 503 on these routes writes a `.warning`, and every one of these routes
/// is anonymous. A persistently unadmittable account therefore let any caller —
/// or a relay backfill retrying `getRepo` and `listRecords` — set the service
/// journal's growth rate directly, with no ceiling. That is a disk-fill path on
/// the production box, and it arrived through the very work that made these
/// refusals loud.
///
/// The information the line carries is the pair (method, reason): which route
/// refused and which guard refused it. Repeating that pair adds nothing, so the
/// first refusal in a window is journalled in full and the rest are counted,
/// with the count folded into the next window's line as `suppressedRepeats`. A
/// *new* pair is never delayed or dropped: a route or guard that has not been
/// seen in this window journals immediately, so a second, different failure
/// arriving during an ongoing one stays visible. The 503 itself is unaffected —
/// the client sees the same body on every request, journalled or not.
///
/// The key space is bounded by construction: `method` is a literal at each call
/// site and `reason` is a `PublicReadUnavailableReason` or a
/// `PublicReadHandlerGuard` raw value, so it cannot be grown by request input.
/// ``maximumKeys`` restates that as an invariant rather than an argument, and
/// declines to *track* rather than declining to log if it is ever reached: the
/// fallback is the unbounded-line behaviour that shipped before, which only a
/// build with hundreds of distinct guards could reach.
final class PublicReadDiagnosticThrottle: Sendable {
    private struct Window {
        var expiresAt: ContinuousClock.Instant
        var suppressed: Int
    }

    private let window: Duration
    private let maximumKeys: Int
    private let windows = Mutex([String: Window]())

    init(window: Duration, maximumKeys: Int = 512) {
        self.window = window
        self.maximumKeys = maximumKeys
    }

    /// The number of repeats to report alongside this line, or `nil` when the
    /// line must not be written because an identical one is already live.
    func admit(
        method: String,
        reason: String,
        now: ContinuousClock.Instant = .now
    ) -> Int? {
        let key = "\(method)|\(reason)"
        return windows.withLock { windows in
            if let live = windows[key], live.expiresAt > now {
                windows[key]?.suppressed += 1
                return nil
            }
            let suppressed = windows[key]?.suppressed ?? 0
            if windows[key] == nil, windows.count >= maximumKeys {
                windows = windows.filter { $0.value.expiresAt > now }
                guard windows.count < maximumKeys else { return 0 }
            }
            windows[key] = Window(
                expiresAt: now.advanced(by: window), suppressed: 0
            )
            return suppressed
        }
    }

    /// Test seam: forgets every window. Production has no reason to call this;
    /// a test does, because the throttle is process-wide and a window opened by
    /// one test would otherwise silence the next.
    func resetForTesting() {
        windows.withLock { $0 = [:] }
    }
}

/// How long one distinct (method, reason) refusal stays journalled-once.
///
/// Short enough that an operator watching a live incident sees the refusal
/// reappear at a readable cadence, long enough that a saturating anonymous
/// caller cannot push line rate past one per second per distinct failure.
private let publicReadDiagnosticWindow = Duration.seconds(1)

let publicReadDiagnosticThrottle = PublicReadDiagnosticThrottle(
    window: publicReadDiagnosticWindow
)

/// Names the guard behind one 503 for the journal line above.
///
/// Classification goes through
/// ``PublicRepositoryReadError/admissionFailureReason``, the same accessor the
/// storage layer journals and bounds with. ``unavailableReason`` answers `nil`
/// for `resourceLimitExceeded`, which carries no reason of its own, so this
/// site used to journal `reason=unclassified` for exactly the refusal the
/// storage layer had just journalled as `reason=projectionBoundExceeded` —
/// two lines naming one 503 differently, in the one function whose purpose is
/// that no 503 leaves unnamed.
///
/// Internal rather than private so the mapping can be asserted directly:
/// nothing about it reaches a response body, so a route test cannot see it.
func publicReadDiagnosticToken(_ error: any Error) -> String {
    if let reason = (error as? PublicRepositoryReadError)?
        .admissionFailureReason
    {
        return reason.rawValue
    }
    if case let PublicReadHandlerFailure.unavailable(guardName) = error {
        return guardName.rawValue
    }
    // A cancelled request is the caller hanging up, not a service failure.
    // Naming it keeps it out of the bucket that means "we do not know".
    if error is CancellationError { return "requestCancelled" }
    return "unclassified"
}

// Internal so the response-body lease lifetime can be regression-tested
// without requiring a real socket to stall its outbound writer.
func publicReadJSON(
    _ status: HTTPResponse.Status,
    _ value: some Encodable,
    maximumBytes: Int = PublicRepositoryJSONReadLimits
        .maximumListRecordsResponseBytes,
    lease: PublicRepositoryJSONReadLease? = nil,
    method: String = "unknown",
    selector: String? = nil
) -> Response {
    guard maximumBytes > 0,
          let data = try? SwanJSONEncoders.sortedNoEscaping.encode(value),
          data.count <= maximumBytes else {
        lease?.release()
        return publicReadUnavailable(
            reason: PublicReadHandlerGuard.responseEncodingFailed.rawValue,
            method: method,
            selector: selector
        )
    }
    if let lease {
        return Response(
            status: status,
            headers: [.contentType: "application/json", .cacheControl: "no-store"],
            body: .init(contentLength: data.count) { writer in
                defer { lease.release() }
                try await writer.write(ByteBuffer(data: data))
                try await writer.finish(nil)
            }
        )
    }
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

private enum DecodableValue {
    case string(String)
    case array([DecodableValue])
    case dictionary([String: DecodableValue])
}

private struct DecodableValueDecoder: Decoder {
    let value: DecodableValue
    var codingPath: [any CodingKey] = []
    var userInfo: [CodingUserInfoKey: Any] = [:]

    func container<Key: CodingKey>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> {
        guard case let .dictionary(dict) = value else {
            throw DecodingError.typeMismatch(
                [String: DecodableValue].self,
                .init(codingPath: codingPath, debugDescription: "Expected dictionary")
            )
        }
        return KeyedDecodingContainer(KeyedContainer<Key>(dict: dict, codingPath: codingPath))
    }

    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        guard case let .array(arr) = value else {
            throw DecodingError.typeMismatch(
                [DecodableValue].self,
                .init(codingPath: codingPath, debugDescription: "Expected array")
            )
        }
        return UnkeyedContainer(array: arr, codingPath: codingPath)
    }

    func singleValueContainer() throws -> SingleValueDecodingContainer {
        SingleContainer(value: value, codingPath: codingPath)
    }

    private struct KeyedContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
        let dict: [String: DecodableValue]
        var codingPath: [any CodingKey]
        var allKeys: [Key] { dict.keys.compactMap(Key.init(stringValue:)) }

        func contains(_ key: Key) -> Bool {
            dict[key.stringValue] != nil
        }

        func decodeNil(forKey key: Key) throws -> Bool {
            dict[key.stringValue] == nil
        }

        func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
            guard let val = dict[key.stringValue] else {
                throw DecodingError.keyNotFound(
                    key,
                    .init(codingPath: codingPath, debugDescription: "Missing key \(key.stringValue)")
                )
            }
            if type == String.self, case let .string(str) = val {
                return str as! T
            }
            return try T(from: DecodableValueDecoder(value: val, codingPath: codingPath + [key]))
        }

        func nestedContainer<NestedKey: CodingKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> {
            guard let val = dict[key.stringValue] else {
                throw DecodingError.keyNotFound(key, .init(codingPath: codingPath, debugDescription: "Missing key"))
            }
            return try DecodableValueDecoder(value: val, codingPath: codingPath + [key]).container(keyedBy: type)
        }

        func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
            guard let val = dict[key.stringValue] else {
                throw DecodingError.keyNotFound(key, .init(codingPath: codingPath, debugDescription: "Missing key"))
            }
            return try DecodableValueDecoder(value: val, codingPath: codingPath + [key]).unkeyedContainer()
        }

        func superDecoder() throws -> any Decoder {
            DecodableValueDecoder(value: .dictionary(dict), codingPath: codingPath)
        }

        func superDecoder(forKey key: Key) throws -> any Decoder {
            guard let val = dict[key.stringValue] else {
                throw DecodingError.keyNotFound(key, .init(codingPath: codingPath, debugDescription: "Missing key"))
            }
            return DecodableValueDecoder(value: val, codingPath: codingPath + [key])
        }
    }

    private struct UnkeyedContainer: UnkeyedDecodingContainer {
        let array: [DecodableValue]
        var codingPath: [any CodingKey]
        var count: Int? { array.count }
        var isAtEnd: Bool { currentIndex >= array.count }
        var currentIndex: Int = 0

        mutating func decodeNil() throws -> Bool { false }

        mutating func decode<T: Decodable>(_ type: T.Type) throws -> T {
            guard !isAtEnd else {
                throw DecodingError.valueNotFound(type, .init(codingPath: codingPath, debugDescription: "Unkeyed container is at end"))
            }
            let val = array[currentIndex]
            currentIndex += 1
            if type == String.self, case let .string(str) = val {
                return str as! T
            }
            return try T(from: DecodableValueDecoder(value: val, codingPath: codingPath))
        }

        mutating func nestedContainer<NestedKey: CodingKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> {
            guard !isAtEnd else {
                throw DecodingError.valueNotFound(Any.self, .init(codingPath: codingPath, debugDescription: "Unkeyed container is at end"))
            }
            let val = array[currentIndex]
            currentIndex += 1
            return try DecodableValueDecoder(value: val, codingPath: codingPath).container(keyedBy: type)
        }

        mutating func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
            guard !isAtEnd else {
                throw DecodingError.valueNotFound(Any.self, .init(codingPath: codingPath, debugDescription: "Unkeyed container is at end"))
            }
            let val = array[currentIndex]
            currentIndex += 1
            return try DecodableValueDecoder(value: val, codingPath: codingPath).unkeyedContainer()
        }

        mutating func superDecoder() throws -> any Decoder {
            DecodableValueDecoder(value: .array(array), codingPath: codingPath)
        }
    }

    private struct SingleContainer: SingleValueDecodingContainer {
        let value: DecodableValue
        var codingPath: [any CodingKey]

        func decodeNil() -> Bool { false }

        func decode<T: Decodable>(_ type: T.Type) throws -> T {
            if type == String.self, case let .string(str) = value {
                return str as! T
            }
            return try T(from: DecodableValueDecoder(value: value, codingPath: codingPath))
        }
    }
}

private func makePublicDIDDocument(
    id: String,
    handle: String,
    signingDIDKey: String,
    serviceEndpoint: String
) throws -> DIDDocument {
    let verificationType = switch try PLCDIDKeyCodec.decode(signingDIDKey) {
    case .p256:
        "EcdsaSecp256r1VerificationKey2019"
    case .secp256k1:
        "EcdsaSecp256k1VerificationKey2019"
    }
    let value: DecodableValue = .dictionary([
        "@context": .array([
            .string("https://www.w3.org/ns/did/v1"),
            .string("https://w3id.org/security/suites/ecdsa-2019/v1"),
        ]),
        "id": .string(id),
        "alsoKnownAs": .array([.string("at://\(handle)")]),
        "verificationMethod": .array([
            .dictionary([
                "id": .string("#atproto"),
                "type": .string(verificationType),
                "controller": .string(id),
                "publicKeyMultibase": .string(String(signingDIDKey.dropFirst("did:key:".count))),
            ]),
        ]),
        "service": .array([
            .dictionary([
                "id": .string("#atproto_pds"),
                "type": .string("AtprotoPersonalDataServer"),
                "serviceEndpoint": .string(serviceEndpoint),
            ]),
        ]),
    ])
    return try DIDDocument(from: DecodableValueDecoder(value: value))
}

private func publicReadOriginsMatch(_ lhs: String, _ rhs: String) -> Bool {
    func normalized(_ value: String) -> (String, String, Int)? {
        guard let components = URLComponents(string: value),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased(),
              components.path.isEmpty || components.path == "/",
              components.query == nil,
              components.fragment == nil else { return nil }
        let port = components.port ?? (scheme == "https" ? 443 : -1)
        return (scheme, host, port)
    }
    guard let left = normalized(lhs), let right = normalized(rhs) else {
        return false
    }
    return left == right
}

