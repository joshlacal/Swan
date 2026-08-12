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

/// Server-side diagnostics for the unauthenticated public read path. Stable
/// identifiers only — never payloads, credentials, or repository content.
private let publicReadDiagnosticLog = SwanLog(label: "swan.public-read")

private let publicReadNSIDs: Set<String> = [
    "com.atproto.repo.describeRepo",
    "com.atproto.repo.getRecord",
    "com.atproto.repo.listRecords",
    "com.atproto.sync.getLatestCommit",
    "com.atproto.sync.getRepo",
    "com.atproto.sync.getRepoStatus",
]

private enum PublicReadHandlerFailure: Error {
    case repoNotFound
    case recordNotFound
    case lifecycle(AccountControlStatus)
    case invalidRequest
    case unavailable
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
        ) else { throw PublicReadHandlerFailure.unavailable }
        let document = try PublicDIDDocument(
            id: description.did,
            handle: description.identity.canonicalHandle,
            signingDIDKey: description.identity.signingDIDKey,
            serviceEndpoint: description.identity.pdsOrigin
        )
        let didDocument = try JSONDecoder().decode(
            DIDDocument.self,
            from: JSONEncoder().encode(document)
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
            throw PublicReadHandlerFailure.unavailable
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
            throw PublicReadHandlerFailure.unavailable
        }
        return .init(
            did: try DID(didString: status.did),
            active: status.status == .active,
            status: publicStatus,
            rev: try status.revision.map(TID.init(tidString:))
        )
    }
}

func isInstalledPublicReadMethod(_ nsid: String) -> Bool {
    publicReadNSIDs.contains(nsid)
}

func registerPublicRepositoryReadEndpoints(
    on router: Router<BasicRequestContext>,
    directory: any PublicRepositoryReadDirectory,
    publicURL: URL,
    jsonReadAdmission: PublicRepositoryJSONReadAdmission = .processShared
) {
    let describeHandler = PublicDescribeRepoHandler(
        directory: directory, publicURL: publicURL
    )
    let getRecordHandler = PublicGetRecordHandler(directory: directory)
    let listRecordsHandler = PublicListRecordsHandler(directory: directory)
    let latestCommitHandler = PublicLatestCommitHandler(directory: directory)
    let repoStatusHandler = PublicRepoStatusHandler(directory: directory)

    router.get("/xrpc/com.atproto.repo.describeRepo") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, required: ["repo"])
            guard let repo = query["repo"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = repo
            guard let lease = jsonReadAdmission.reserve(
                maximumResponseBytes: PublicRepositoryJSONReadLimits
                    .maximumListRecordsResponseBytes
            ) else {
                return publicReadError(
                    .serviceUnavailable, "temporarily_unavailable"
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
                    lease: lease
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
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

    router.get("/xrpc/com.atproto.repo.getRecord") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request,
                required: ["repo", "collection", "rkey"],
                optional: ["cid"]
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
                return publicReadError(
                    .serviceUnavailable, "temporarily_unavailable"
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
                    lease: lease
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
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

    router.get("/xrpc/com.atproto.repo.listRecords") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request,
                required: ["repo", "collection"],
                optional: ["limit", "cursor", "reverse"]
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
                return publicReadError(
                    .serviceUnavailable, "temporarily_unavailable"
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
                    lease: lease
                )
            } catch {
                lease.release()
                throw error
            }
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
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

    router.get("/xrpc/com.atproto.sync.getLatestCommit") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, required: ["did"])
            guard let rawDID = query["did"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = rawDID
            let did: DID = try publicReadWireParameters {
                try DID(didString: rawDID)
            }
            let output = try await latestCommitHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(did: did)
                },
                input: (),
                context: request
            )
            return publicReadJSON(.ok, output)
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
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

    router.get("/xrpc/com.atproto.sync.getRepoStatus") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(request, required: ["did"])
            guard let rawDID = query["did"] else {
                throw PublicReadHandlerFailure.invalidRequest
            }
            selector = rawDID
            let did: DID = try publicReadWireParameters {
                try DID(didString: rawDID)
            }
            let output = try await repoStatusHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(did: did)
                },
                input: (),
                context: request
            )
            return publicReadJSON(.ok, output)
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
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

    router.get("/xrpc/com.atproto.sync.getRepo") { request, _ async -> Response in
        var selector: String?
        do {
            let query = try publicReadQuery(
                request, required: ["did"], optional: ["since"]
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
            return publicReadResponse(failure)
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

    for path: RouterPath in [
        "/xrpc/com.atproto.repo.describeRepo",
        "/xrpc/com.atproto.repo.getRecord",
        "/xrpc/com.atproto.repo.listRecords",
        "/xrpc/com.atproto.sync.getLatestCommit",
        "/xrpc/com.atproto.sync.getRepo",
        "/xrpc/com.atproto.sync.getRepoStatus",
    ] {
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

private func publicReadQuery(
    _ request: Request,
    required: Set<String>,
    optional: Set<String> = []
) throws -> [String: String] {
    do {
        return try strictAuthenticatedRecordQuery(
            request, required: required, optional: optional
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

private func publicReadResponse(_ failure: PublicReadHandlerFailure) -> Response {
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
        publicReadError(.serviceUnavailable, "temporarily_unavailable")
    }
}

private func publicReadError(_ status: HTTPResponse.Status, _ code: String) -> Response {
    jsonResponseWithStatus(status, body: ["error": code])
}

/// The single collapse point for every public-read 503.
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
    var fields = ["method": method]
    if let selector,
       AccountControlIdentifiers.isDID(selector)
       || AccountControlIdentifiers.isCanonicalHandle(selector) {
        fields["selector"] = selector
    }
    fields["reason"] =
        (error as? PublicRepositoryReadError)?.unavailableReason?.rawValue
        ?? "unclassified"
    publicReadDiagnosticLog.warning("public read unavailable", fields: fields)
    return publicReadError(.serviceUnavailable, "temporarily_unavailable")
}

// Internal so the response-body lease lifetime can be regression-tested
// without requiring a real socket to stall its outbound writer.
func publicReadJSON(
    _ status: HTTPResponse.Status,
    _ value: some Encodable,
    maximumBytes: Int = PublicRepositoryJSONReadLimits
        .maximumListRecordsResponseBytes,
    lease: PublicRepositoryJSONReadLease? = nil
) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard maximumBytes > 0,
          let data = try? encoder.encode(value),
          data.count <= maximumBytes else {
        lease?.release()
        return publicReadError(.serviceUnavailable, "temporarily_unavailable")
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

private struct PublicDIDDocument: Encodable {
    let context = [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ecdsa-2019/v1",
    ]
    let id: String
    let alsoKnownAs: [String]
    let verificationMethod: [PublicDIDVerificationMethod]
    let service: [PublicDIDService]

    init(
        id: String,
        handle: String,
        signingDIDKey: String,
        serviceEndpoint: String
    ) throws {
        self.id = id
        alsoKnownAs = ["at://\(handle)"]
        let verificationType = switch try PLCDIDKeyCodec.decode(
            signingDIDKey
        ) {
        case .p256:
            "EcdsaSecp256r1VerificationKey2019"
        case .secp256k1:
            "EcdsaSecp256k1VerificationKey2019"
        }
        verificationMethod = [.init(
            id: "#atproto",
            type: verificationType,
            controller: id,
            publicKeyMultibase: String(signingDIDKey.dropFirst("did:key:".count))
        )]
        service = [.init(
            id: "#atproto_pds",
            type: "AtprotoPersonalDataServer",
            serviceEndpoint: serviceEndpoint
        )]
    }

    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id, alsoKnownAs, verificationMethod, service
    }
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

private struct PublicDIDVerificationMethod: Encodable {
    let id: String
    let type: String
    let controller: String
    let publicKeyMultibase: String
}

private struct PublicDIDService: Encodable {
    let id: String
    let type: String
    let serviceEndpoint: String
}
