import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanPublicRepository
import SwanPublicWire
import SwanStorage

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
        guard let status = try await directory.publicRepositoryStatus(
            selector: selector
        ) else { throw PublicReadHandlerFailure.repoNotFound }
        guard status.status == .active else {
            throw PublicReadHandlerFailure.lifecycle(status.status)
        }
        guard let description = try await directory.describePublicRepository(
            selector: selector
        ) else { throw PublicReadHandlerFailure.unavailable }
        guard publicReadOriginsMatch(
            description.identity.pdsOrigin, publicURL.absoluteString
        ) else { throw PublicReadHandlerFailure.unavailable }
        let document = PublicDIDDocument(
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
        guard let record = try await directory.publicRepositoryRecord(
            selector: selector,
            path: path,
            expectedCID: parameters.cid
        ) else { throw PublicReadHandlerFailure.recordNotFound }
        guard let description = try await directory.describePublicRepository(
            selector: selector
        ), description.status == .active else {
            throw PublicReadHandlerFailure.unavailable
        }
        return .init(
            uri: try ATProtocolURI(
                uriString: "at://\(description.did)/\(path.mstKey)"
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
        let page = try await directory.listPublicRepositoryRecords(
            selector: selector,
            collection: collection,
            limit: parameters.limit ?? 50,
            cursor: parameters.cursor,
            reverse: parameters.reverse ?? false
        )
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
        guard let description = try await directory.describePublicRepository(
            selector: selector
        ), description.status == .active else {
            throw PublicReadHandlerFailure.unavailable
        }
        let records = try page.records.map {
            SwanPublicWire.ComAtprotoRepoListRecords.Record(
                uri: try ATProtocolURI(
                    uriString: "at://\(description.did)/\($0.path.mstKey)"
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
        guard let status = try await directory.publicRepositoryStatus(
            selector: selector
        ) else { throw PublicReadHandlerFailure.repoNotFound }
        guard status.status == .active else {
            throw PublicReadHandlerFailure.lifecycle(status.status)
        }
        guard let description = try await directory.describePublicRepository(
            selector: selector
        ) else { throw PublicReadHandlerFailure.unavailable }
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
        case .deactivated, .deleted, .takendown, .suspended,
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
    publicURL: URL
) {
    let describeHandler = PublicDescribeRepoHandler(
        directory: directory, publicURL: publicURL
    )
    let getRecordHandler = PublicGetRecordHandler(directory: directory)
    let listRecordsHandler = PublicListRecordsHandler(directory: directory)
    let latestCommitHandler = PublicLatestCommitHandler(directory: directory)
    let repoStatusHandler = PublicRepoStatusHandler(directory: directory)

    router.get("/xrpc/com.atproto.repo.describeRepo") { request, _ async -> Response in
        do {
            let query = try publicReadQuery(request, required: ["repo"])
            let output = try await describeHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(repo: try ATIdentifier(string: query["repo"]!))
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
            return publicReadError(.serviceUnavailable, "temporarily_unavailable")
        }
    }

    router.get("/xrpc/com.atproto.repo.getRecord") { request, _ async -> Response in
        do {
            let query = try publicReadQuery(
                request,
                required: ["repo", "collection", "rkey"],
                optional: ["cid"]
            )
            let path = try PublicRepositoryPath(
                collection: query["collection"]!,
                recordKey: query["rkey"]!
            )
            let expectedCID = try query["cid"].map(publicReadCID)
            let output = try await getRecordHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(
                        repo: try ATIdentifier(string: query["repo"]!),
                        collection: try NSID(nsidString: path.collection),
                        rkey: try RecordKey(keyString: path.recordKey),
                        cid: expectedCID
                    )
                },
                input: (),
                context: request
            )
            return publicReadJSON(.ok, output)
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch PublicRepositoryDomainError.invalidCollection,
                PublicRepositoryDomainError.invalidRecordKey,
                PublicRepositoryDomainError.pathTooLong {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadError(.serviceUnavailable, "temporarily_unavailable")
        }
    }

    router.get("/xrpc/com.atproto.repo.listRecords") { request, _ async -> Response in
        do {
            let query = try publicReadQuery(
                request,
                required: ["repo", "collection"],
                optional: ["limit", "cursor", "reverse"]
            )
            _ = try PublicRepositoryPath(
                collection: query["collection"]!,
                recordKey: "validation"
            )
            let limit = try query["limit"].map(publicReadLimit) ?? 50
            let reverse = try query["reverse"].map(publicReadBoolean) ?? false
            let output = try await listRecordsHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(
                        repo: try ATIdentifier(string: query["repo"]!),
                        collection: try NSID(nsidString: query["collection"]!),
                        limit: limit,
                        cursor: query["cursor"],
                        reverse: reverse
                    )
                },
                input: (),
                context: request
            )
            return publicReadJSON(.ok, output)
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
            return publicReadError(.serviceUnavailable, "temporarily_unavailable")
        }
    }

    router.get("/xrpc/com.atproto.sync.getLatestCommit") { request, _ async -> Response in
        do {
            let query = try publicReadQuery(request, required: ["did"])
            let output = try await latestCommitHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(did: try DID(didString: query["did"]!))
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
            return publicReadError(.serviceUnavailable, "temporarily_unavailable")
        }
    }

    router.get("/xrpc/com.atproto.sync.getRepoStatus") { request, _ async -> Response in
        do {
            let query = try publicReadQuery(request, required: ["did"])
            let output = try await repoStatusHandler.handle(
                parameters: try publicReadWireParameters {
                    .init(did: try DID(didString: query["did"]!))
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
            return publicReadError(.serviceUnavailable, "temporarily_unavailable")
        }
    }

    router.get("/xrpc/com.atproto.sync.getRepo") { request, _ async -> Response in
        do {
            let query = try publicReadQuery(
                request, required: ["did"], optional: ["since"]
            )
            guard query["since"] == nil else {
                return publicReadError(.badRequest, "InvalidRequest")
            }
            _ = try publicReadWireParameters {
                try DID(didString: query["did"]!)
            }
            guard let status = try await directory.publicRepositoryStatus(
                selector: query["did"]!
            ) else {
                return publicReadError(.badRequest, "RepoNotFound")
            }
            guard status.status == .active else {
                return publicLifecycleError(status.status)
            }
            guard let car = try await directory.publicRepositoryCAR(
                selector: query["did"]!
            ) else {
                return publicReadError(.badRequest, "RepoNotFound")
            }
            return publicRepositoryCARHTTPResponse(car)
        } catch let failure as PublicReadHandlerFailure {
            return publicReadResponse(failure)
        } catch PublicRepositoryReadError.invalidSelector {
            return publicReadError(.badRequest, "InvalidRequest")
        } catch {
            return publicReadError(.serviceUnavailable, "temporarily_unavailable")
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

private func publicReadJSON(_ status: HTTPResponse.Status, _ value: some Encodable) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard let data = try? encoder.encode(value) else {
        return publicReadError(.serviceUnavailable, "temporarily_unavailable")
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
    ) {
        self.id = id
        alsoKnownAs = ["at://\(handle)"]
        verificationMethod = [.init(
            id: "#atproto",
            type: "EcdsaSecp256r1VerificationKey2019",
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
