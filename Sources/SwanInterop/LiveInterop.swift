import AsyncHTTPClient
import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOHTTP1
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces

/// A bounded, redirect-free HTTP response used by the stateful interop
/// harness.  The body is present only for small JSON/XRPC responses; CAR and
/// blob responses use ``InteropHTTPClient.executeStreaming`` instead.
public struct InteropHTTPResponse: Sendable, Equatable {
    public let status: Int
    public let headers: [String: String]
    public let body: Data
    public let finalURL: URL?
    public let redirectCount: Int

    public init(
        status: Int,
        headers: [String: String],
        body: Data,
        finalURL: URL?,
        redirectCount: Int
    ) {
        self.status = status
        self.headers = Dictionary(uniqueKeysWithValues: headers.map {
            ($0.key.lowercased(), $0.value)
        })
        self.body = body
        self.finalURL = finalURL
        self.redirectCount = redirectCount
    }

    public func header(_ name: String) -> String? {
        headers[name.lowercased()]
    }
}

public enum InteropHTTPMethod: String, Sendable, Equatable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case delete = "DELETE"
    case patch = "PATCH"
}

public enum InteropHTTPError: Error, Sendable, Equatable {
    case invalidURL
    case responseTooLarge
    case unexpectedRedirect
    case unexpectedContentType
    case unexpectedStatus(Int)
    case transportFailure
    case fileFailure
}

/// The only authorization shapes accepted by the live runner.  This keeps
/// bearer material out of request summaries and prevents callers from
/// accidentally treating an account OAuth token as a space credential.
public enum InteropAuthorization: Sendable, Equatable {
    case none
    case dpop(accessToken: String, proof: String)
    case bearer(token: String)
    case service(token: String)
}

/// Optional per-request authorization used by live OAuth runs. A static
/// bearer/DPoP value is useful for reference fixtures, but Swan's resource
/// server binds DPoP proofs to the exact target and nonce. Keeping this as a
/// callback lets the runner mint a fresh proof without ever serializing the
/// token or private key into an artifact.
public typealias InteropAuthorizationProvider = @Sendable (
    InteropHTTPMethod, URL, Data?
) async throws -> InteropAuthorization

/// A small AsyncHTTPClient adapter with strict bounds and no redirect
/// following.  It is deliberately independent of the Hummingbird server so
/// the same client can drive Swan, the pinned TypeScript PDS, or a faultable
/// Toxiproxy route.
public final class InteropHTTPClient: @unchecked Sendable {
    public let baseURL: URL
    public let timeout: TimeInterval
    public let maximumResponseBytes: Int

    private let client: HTTPClient

    public init(
        baseURL: URL,
        timeout: TimeInterval = 15,
        maximumResponseBytes: Int = 2 * 1024 * 1024
    ) throws {
        guard Self.validBaseURL(baseURL),
              timeout > 0, timeout <= 120, timeout.isFinite,
              (1 ... 256 * 1024 * 1024).contains(maximumResponseBytes) else {
            throw SwanError.malformed("interop HTTP client bounds are invalid")
        }
        self.baseURL = baseURL
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
        client = HTTPClient(configuration: .init(
            redirectConfiguration: .disallow,
            timeout: .init(
                connect: .milliseconds(Int64(timeout * 1_000)),
                read: .milliseconds(Int64(timeout * 1_000))
            ),
            decompression: .disabled
        ))
    }

    deinit {
        client.shutdown { _ in }
    }

    public func execute(
        method: InteropHTTPMethod,
        path: String,
        headers: [String: String] = [:],
        body: Data? = nil,
        maximumResponseBytes: Int? = nil
    ) async throws -> InteropHTTPResponse {
        let url = try makeURL(path)
        guard body?.count ?? 0 <= 2 * 1024 * 1024 else {
            throw InteropHTTPError.responseTooLarge
        }
        let limit = maximumResponseBytes ?? self.maximumResponseBytes
        guard (1 ... 256 * 1024 * 1024).contains(limit) else {
            throw SwanError.malformed("interop response bound is invalid")
        }
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = nioMethod(method)
        request.headers = HTTPHeaders()
        for (name, value) in headers {
            request.headers.add(name: name, value: value)
        }
        if let body {
            request.body = .bytes(ByteBuffer(data: body))
        }

        let response: HTTPClientResponse
        do {
            response = try await client.execute(
                request,
                deadline: .now() + .milliseconds(Int64(timeout * 1_000))
            )
        } catch {
            throw InteropHTTPError.transportFailure
        }
        let collected: ByteBuffer
        do {
            collected = try await response.body.collect(upTo: limit)
        } catch {
            throw InteropHTTPError.responseTooLarge
        }
        let responseHeaders = response.headers.reduce(into: [String: String]()) { result, item in
            let name = item.name.lowercased()
            if let existing = result[name] {
                result[name] = existing + "," + item.value
            } else {
                result[name] = item.value
            }
        }
        let redirects = max(0, response.history.count - 1)
        guard redirects == 0 else { throw InteropHTTPError.unexpectedRedirect }
        return InteropHTTPResponse(
            status: Int(response.status.code),
            headers: responseHeaders,
            body: Data(buffer: collected),
            finalURL: response.url,
            redirectCount: redirects
        )
    }

    /// Streams a CAR/blob body directly to a caller-owned file.  At most one
    /// received NIO buffer is retained while writing; the response is never
    /// accumulated in memory.  A failed write removes the partial file.
    public func executeStreaming(
        method: InteropHTTPMethod,
        path: String,
        headers: [String: String] = [:],
        to destination: URL,
        maximumResponseBytes: Int
    ) async throws -> InteropHTTPResponse {
        guard (1 ... 256 * 1024 * 1024).contains(maximumResponseBytes) else {
            throw SwanError.malformed("interop streaming bound is invalid")
        }
        let url = try makeURL(path)
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = nioMethod(method)
        request.headers = HTTPHeaders()
        for (name, value) in headers {
            request.headers.add(name: name, value: value)
        }

        let response: HTTPClientResponse
        do {
            response = try await client.execute(
                request,
                deadline: .now() + .milliseconds(Int64(timeout * 1_000))
            )
        } catch {
            throw InteropHTTPError.transportFailure
        }
        let responseHeaders = response.headers.reduce(into: [String: String]()) { result, item in
            let name = item.name.lowercased()
            if let existing = result[name] {
                result[name] = existing + "," + item.value
            } else {
                result[name] = item.value
            }
        }
        let redirects = max(0, response.history.count - 1)
        guard redirects == 0 else { throw InteropHTTPError.unexpectedRedirect }

        let manager = FileManager.default
        guard manager.createFile(atPath: destination.path, contents: nil,
                                 attributes: [.posixPermissions: 0o600]) else {
            throw InteropHTTPError.fileFailure
        }
        let handle: FileHandle
        do {
            handle = try FileHandle(forWritingTo: destination)
        } catch {
            try? manager.removeItem(at: destination)
            throw InteropHTTPError.fileFailure
        }
        var received = 0
        do {
            for try await buffer in response.body {
                let count = buffer.readableBytes
                guard count <= maximumResponseBytes - received else {
                    throw InteropHTTPError.responseTooLarge
                }
                try handle.write(contentsOf: Data(buffer: buffer))
                received += count
            }
            try handle.close()
        } catch {
            try? handle.close()
            try? manager.removeItem(at: destination)
            if error is InteropHTTPError {
                throw error
            }
            throw InteropHTTPError.fileFailure
        }
        return InteropHTTPResponse(
            status: Int(response.status.code),
            headers: responseHeaders,
            body: Data(),
            finalURL: response.url,
            redirectCount: redirects
        )
    }

    private func makeURL(_ path: String) throws -> URL {
        guard !path.isEmpty,
              let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == baseURL.scheme?.lowercased(),
              components.host?.lowercased() == baseURL.host?.lowercased() else {
            throw InteropHTTPError.invalidURL
        }
        return url
    }

    private static func validBaseURL(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil else {
            return false
        }
        return true
    }

    private func nioMethod(_ method: InteropHTTPMethod) -> HTTPMethod {
        switch method {
        case .get: .GET
        case .post: .POST
        case .put: .PUT
        case .delete: .DELETE
        case .patch: .PATCH
        }
    }
}

/// Typed XRPC convenience methods layered over the bounded HTTP transport.
/// Generated wire models remain the preferred caller-facing types, while the
/// raw methods are useful for pinned-reference endpoints whose output is not
/// yet represented by a checked-in Swift declaration.
public struct InteropXRPCClient: Sendable {
    public let http: InteropHTTPClient

    public init(http: InteropHTTPClient) {
        self.http = http
    }

    public init(baseURL: URL, timeout: TimeInterval = 15) throws {
        self.init(http: try InteropHTTPClient(baseURL: baseURL, timeout: timeout))
    }

    public func query(
        _ nsid: String,
        query: [String: String] = [:],
        authorization: InteropAuthorization = .none,
        maximumResponseBytes: Int? = nil
    ) async throws -> InteropHTTPResponse {
        try await request(
            method: .get,
            nsid: nsid,
            query: query,
            body: nil,
            authorization: authorization,
            maximumResponseBytes: maximumResponseBytes
        )
    }

    public func procedure(
        _ nsid: String,
        body: Data,
        authorization: InteropAuthorization = .none,
        maximumResponseBytes: Int? = nil
    ) async throws -> InteropHTTPResponse {
        try await request(
            method: .post,
            nsid: nsid,
            query: [:],
            body: body,
            authorization: authorization,
            maximumResponseBytes: maximumResponseBytes
        )
    }

    public func query<Output: Decodable>(
        _ nsid: String,
        query: [String: String],
        authorization: InteropAuthorization = .none,
        as _: Output.Type
    ) async throws -> Output {
        let response = try await self.query(nsid, query: query, authorization: authorization)
        try requireJSONSuccess(response)
        return try StrictJSON.decode(Output.self, from: response.body)
    }

    public func procedure<Input: Encodable, Output: Decodable>(
        _ nsid: String,
        input: Input,
        authorization: InteropAuthorization = .none,
        as _: Output.Type
    ) async throws -> Output {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let body = try encoder.encode(input)
        let response = try await procedure(nsid, body: body, authorization: authorization)
        try requireJSONSuccess(response)
        return try StrictJSON.decode(Output.self, from: response.body)
    }

    public func stream(
        _ nsid: String,
        query: [String: String] = [:],
        authorization: InteropAuthorization = .none,
        to destination: URL,
        maximumResponseBytes: Int
    ) async throws -> InteropHTTPResponse {
        let path = try xrpcPath(nsid, query: query)
        var headers = ["Accept": "application/vnd.ipld.car, application/octet-stream, */*"]
        addAuthorization(authorization, to: &headers)
        return try await http.executeStreaming(
            method: .get,
            path: path,
            headers: headers,
            to: destination,
            maximumResponseBytes: maximumResponseBytes
        )
    }

    /// Returns the exact path used for an XRPC request. Callers that bind
    /// DPoP proofs to the request target should use this instead of rebuilding
    /// query encoding independently.
    public func xrpcPath(_ nsid: String, query: [String: String] = [:]) throws -> String {
        try makeXRPCPath(nsid, query: query)
    }

    private func request(
        method: InteropHTTPMethod,
        nsid: String,
        query: [String: String],
        body: Data?,
        authorization: InteropAuthorization,
        maximumResponseBytes: Int?
    ) async throws -> InteropHTTPResponse {
        let path = try makeXRPCPath(nsid, query: query)
        var headers = ["Accept": "application/json"]
        if body != nil { headers["Content-Type"] = "application/json" }
        addAuthorization(authorization, to: &headers)
        return try await http.execute(
            method: method,
            path: path,
            headers: headers,
            body: body,
            maximumResponseBytes: maximumResponseBytes
        )
    }

    private func makeXRPCPath(_ nsid: String, query: [String: String]) throws -> String {
        guard nsid.utf8.count <= 512,
              !nsid.isEmpty,
              nsid.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              !nsid.contains("/") && !nsid.contains("?") && !nsid.contains("#") else {
            throw SwanError.malformed("interop XRPC NSID is invalid")
        }
        var components = URLComponents()
        components.path = "/xrpc/\(nsid)"
        let items = query.keys.sorted().map { key in
            URLQueryItem(name: key, value: query[key] ?? "")
        }
        components.queryItems = items.isEmpty ? nil : items
        guard let string = components.string else { throw InteropHTTPError.invalidURL }
        return string
    }

    private func addAuthorization(
        _ authorization: InteropAuthorization,
        to headers: inout [String: String]
    ) {
        switch authorization {
        case .none:
            break
        case let .dpop(accessToken, proof):
            headers["Authorization"] = "DPoP " + accessToken
            headers["DPoP"] = proof
        case let .bearer(token), let .service(token):
            headers["Authorization"] = "Bearer " + token
        }
    }

    private func requireJSONSuccess(_ response: InteropHTTPResponse) throws {
        guard (200 ... 299).contains(response.status) else {
            throw InteropHTTPError.unexpectedStatus(response.status)
        }
        guard response.header("content-type")?.lowercased().contains("json") == true else {
            throw InteropHTTPError.unexpectedContentType
        }
    }
}

public struct InteropFixtureEvent: Codable, Sendable, Equatable {
    public let host: String
    public let method: String
    public let path: String
    public let status: Int
    public let requestBytes: Int
    public let responseBytes: Int
    public let responseSHA256: String
    public let responseError: String?

    public init(
        host: String,
        method: String,
        path: String,
        status: Int,
        requestBytes: Int,
        responseBytes: Int,
        responseSHA256: String,
        responseError: String? = nil
    ) {
        self.host = FixtureSanitizer.sanitize(host)
        self.method = FixtureSanitizer.sanitize(method)
        self.path = FixtureSanitizer.sanitize(path)
        self.status = status
        self.requestBytes = requestBytes
        self.responseBytes = responseBytes
        self.responseSHA256 = responseSHA256
        self.responseError = responseError.map(FixtureSanitizer.sanitize)
    }
}

/// Sanitized fixture recording for real HTTP runs.  It records hashes and
/// sizes, never request bodies, headers, credentials, DPoP proofs, or record
/// values.  The actor makes recording safe when scenario steps run in parallel.
public actor InteropFixtureRecorder {
    private var events: [InteropFixtureEvent] = []

    public init() {}

    public func record(
        host: String,
        method: String,
        path: String,
        requestBody: Data? = nil,
        response: InteropHTTPResponse
    ) {
        events.append(
            InteropFixtureEvent(
                host: host,
                method: method,
                path: FixtureSanitizer.path(path),
                status: response.status,
                requestBytes: requestBody?.count ?? 0,
                responseBytes: response.body.count,
                responseSHA256: Hex.encode(Data(SHA256.hash(data: response.body))),
                responseError: response.status >= 400 ? response.bodyErrorCode : nil
            )
        )
    }

    public func snapshot() -> [InteropFixtureEvent] {
        events
    }

    public func write(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(events).write(to: url, options: .atomic)
    }
}

/// A host plus its already-established authorization. Tokens and DPoP proofs
/// stay in this value only for the duration of a live run; artifacts contain
/// endpoint labels, statuses, sizes, and digests instead.
public struct LiveInteropHost: Sendable {
    public let label: String
    public let client: InteropXRPCClient
    public let authorization: InteropAuthorization
    public let authorizationProvider: InteropAuthorizationProvider?

    public init(
        label: String,
        client: InteropXRPCClient,
        authorization: InteropAuthorization = .none,
        authorizationProvider: InteropAuthorizationProvider? = nil
    ) {
        self.label = label
        self.client = client
        self.authorization = authorization
        self.authorizationProvider = authorizationProvider
    }
}

public struct LiveInteropPublicRoundTripArtifact: Codable, Sendable, Equatable {
    public let scenario: String
    public let profileID: String
    public let producer: String
    public let consumer: String
    public let putStatus: Int?
    public let readStatus: Int?
    public let putCID: String?
    public let readCID: String?
    public let putResponseSHA256: String?
    public let readResponseSHA256: String?
    public let converged: Bool
    public let status: String
    public let errorCode: String?
    public let fixturePolicy: String
    public let events: [InteropFixtureEvent]

    public init(
        scenario: String,
        producer: String,
        consumer: String,
        putStatus: Int?,
        readStatus: Int?,
        putCID: String?,
        readCID: String?,
        putResponseSHA256: String?,
        readResponseSHA256: String?,
        converged: Bool,
        status: String,
        errorCode: String?,
        events: [InteropFixtureEvent]
    ) {
        self.scenario = FixtureSanitizer.sanitize(["scenario": scenario])["scenario"] ?? "<redacted>"
        self.profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.producer = FixtureSanitizer.sanitize(["host": producer])["host"] ?? "<redacted>"
        self.consumer = FixtureSanitizer.sanitize(["host": consumer])["host"] ?? "<redacted>"
        self.putStatus = putStatus
        self.readStatus = readStatus
        self.putCID = putCID
        self.readCID = readCID
        self.putResponseSHA256 = putResponseSHA256
        self.readResponseSHA256 = readResponseSHA256
        self.converged = converged
        self.status = status
        self.errorCode = errorCode.map { FixtureSanitizer.sanitize(["error": $0])["error"] ?? "<redacted>" }
        self.fixturePolicy = "semantic-summary-only; no request bodies, record values, credentials, tokens, DPoP proofs, or personal selectors"
        self.events = events
    }
}

public struct LiveInteropPermissionedRoundTripArtifact: Codable, Sendable, Equatable {
    public let scenario: String
    public let profileID: String
    public let member: String
    public let authority: String
    public let credentialIssued: Bool
    public let writeStatus: Int?
    public let readStatus: Int?
    public let writeCID: String?
    public let readCID: String?
    public let writeResponseSHA256: String?
    public let readResponseSHA256: String?
    public let converged: Bool
    public let status: String
    public let errorCode: String?
    public let fixturePolicy: String
    public let events: [InteropFixtureEvent]

    public init(
        scenario: String,
        member: String,
        authority: String,
        credentialIssued: Bool,
        writeStatus: Int?,
        readStatus: Int?,
        writeCID: String?,
        readCID: String?,
        writeResponseSHA256: String?,
        readResponseSHA256: String?,
        converged: Bool,
        status: String,
        errorCode: String?,
        events: [InteropFixtureEvent]
    ) {
        self.scenario = FixtureSanitizer.sanitize(["scenario": scenario])["scenario"] ?? "<redacted>"
        self.profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.member = FixtureSanitizer.sanitize(["host": member])["host"] ?? "<redacted>"
        self.authority = FixtureSanitizer.sanitize(["host": authority])["host"] ?? "<redacted>"
        self.credentialIssued = credentialIssued
        self.writeStatus = writeStatus
        self.readStatus = readStatus
        self.writeCID = writeCID
        self.readCID = readCID
        self.writeResponseSHA256 = writeResponseSHA256
        self.readResponseSHA256 = readResponseSHA256
        self.converged = converged
        self.status = status
        self.errorCode = errorCode.map { FixtureSanitizer.sanitize(["error": $0])["error"] ?? "<redacted>" }
        self.fixturePolicy = "semantic-summary-only; no credentials, tokens, DPoP proofs, request bodies, record values, or personal selectors"
        self.events = events
    }
}

/// Stateful public-data interop that proves a write response and a subsequent
/// read response agree on the record CID. It is intentionally separate from
/// the older endpoint-probe runner: a probe can be useful diagnostically, but
/// this runner reports failure when data semantics do not converge.
public enum LiveInteropRunner {
    private struct RecordResponse: Decodable {
        let cid: String?
    }

    public static func publicPutAndRead(
        scenario: String,
        producer: LiveInteropHost,
        consumer: LiveInteropHost,
        repository: String,
        collection: String,
        rkey: String,
        putBody: Data,
        recorder: InteropFixtureRecorder? = nil
    ) async -> LiveInteropPublicRoundTripArtifact {
        let recorder = recorder ?? InteropFixtureRecorder()
        let putPath = "/xrpc/com.atproto.repo.putRecord"
        let getPath = "/xrpc/com.atproto.repo.getRecord"
        guard jsonFields(putBody, equalTo: [
            "repo": repository,
            "collection": collection,
            "rkey": rkey,
        ]) else {
            return await artifact(
                scenario: scenario, producer: producer, consumer: consumer,
                putStatus: nil, readStatus: nil, putCID: nil, readCID: nil,
                putDigest: nil, readDigest: nil, converged: false,
                errorCode: "InvalidRequest", recorder: recorder
            )
        }
        var putStatus: Int?
        var readStatus: Int?
        var putCID: String?
        var readCID: String?
        var putDigest: String?
        var readDigest: String?
        var errorCode: String?

        do {
            let authorization = try await authorization(
                for: producer,
                method: .post,
                path: putPath,
                body: putBody
            )
            let response = try await producer.client.procedure(
                "com.atproto.repo.putRecord",
                body: putBody,
                authorization: authorization
            )
            putStatus = response.status
            putDigest = responseDigest(response)
            await recorder.record(
                host: producer.label,
                method: "POST",
                path: putPath,
                requestBody: putBody,
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                errorCode = responseErrorCode(response)
                return await artifact(
                    scenario: scenario, producer: producer, consumer: consumer,
                    putStatus: putStatus, readStatus: nil, putCID: nil, readCID: nil,
                    putDigest: putDigest, readDigest: nil, converged: false,
                    errorCode: errorCode, recorder: recorder
                )
            }
            putCID = try StrictJSON.decode(RecordResponse.self, from: response.body).cid
            guard putCID != nil else {
                errorCode = "InvalidResponse"
                return await artifact(
                    scenario: scenario, producer: producer, consumer: consumer,
                    putStatus: putStatus, readStatus: nil, putCID: nil, readCID: nil,
                    putDigest: putDigest, readDigest: nil, converged: false,
                    errorCode: errorCode, recorder: recorder
                )
            }
        } catch {
            errorCode = liveErrorCode(error)
            return await artifact(
                scenario: scenario, producer: producer, consumer: consumer,
                putStatus: putStatus, readStatus: readStatus, putCID: nil, readCID: nil,
                putDigest: putDigest, readDigest: readDigest, converged: false,
                errorCode: errorCode, recorder: recorder
            )
        }

        do {
            let authorization = try await authorization(
                for: consumer,
                method: .get,
                path: try consumer.client.xrpcPath(
                    "com.atproto.repo.getRecord",
                    query: ["repo": repository, "collection": collection, "rkey": rkey]
                ),
                body: nil
            )
            let response = try await consumer.client.query(
                "com.atproto.repo.getRecord",
                query: ["repo": repository, "collection": collection, "rkey": rkey],
                authorization: authorization
            )
            readStatus = response.status
            readDigest = responseDigest(response)
            await recorder.record(
                host: consumer.label,
                method: "GET",
                path: getPath,
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                errorCode = responseErrorCode(response)
                return await artifact(
                    scenario: scenario, producer: producer, consumer: consumer,
                    putStatus: putStatus, readStatus: readStatus, putCID: putCID, readCID: nil,
                    putDigest: putDigest, readDigest: readDigest, converged: false,
                    errorCode: errorCode, recorder: recorder
                )
            }
            readCID = try StrictJSON.decode(RecordResponse.self, from: response.body).cid
        } catch {
            errorCode = liveErrorCode(error)
        }

        let converged = putCID != nil && putCID == readCID
        return await artifact(
            scenario: scenario, producer: producer, consumer: consumer,
            putStatus: putStatus, readStatus: readStatus, putCID: putCID, readCID: readCID,
            putDigest: putDigest, readDigest: readDigest, converged: converged,
            errorCode: converged ? nil : (errorCode ?? "CommitmentMismatch"), recorder: recorder
        )
    }

    /// Exercises the permissioned cross-host sequence without baking a
    /// particular authority placement into the runner: the member writes its
    /// repository with member OAuth/DPoP, mints a delegation, the authority
    /// exchanges it for a read credential, and that credential reads the
    /// member repository. Space credentials are intentionally read-only; the
    /// runner must not turn them into a write capability merely to make a
    /// round trip pass. The caller supplies the exact generated request
    /// bodies so this remains compatible with the pinned lexicon branch.
    public static func permissionedCreateAndRead(
        scenario: String,
        member: LiveInteropHost,
        authority: LiveInteropHost,
        broker: SpaceCredentialBroker,
        space: SpaceURI,
        createBody: Data,
        readQuery: [String: String],
        readHost: LiveInteropHost? = nil,
        clientAttestation: String? = nil,
        recorder: InteropFixtureRecorder? = nil
    ) async -> LiveInteropPermissionedRoundTripArtifact {
        let recorder = recorder ?? InteropFixtureRecorder()
        guard jsonFields(createBody, equalTo: [
            "space": space.rawValue,
            "repo": readQuery["repo"] ?? "",
            "collection": readQuery["collection"] ?? "",
            "rkey": readQuery["rkey"] ?? "",
        ]) else {
            return await permissionedArtifact(
                scenario: scenario, member: member, authority: authority,
                credentialIssued: false, writeStatus: nil, readStatus: nil,
                writeCID: nil, readCID: nil, writeDigest: nil, readDigest: nil,
                converged: false, errorCode: "InvalidRequest", recorder: recorder
            )
        }
        var credentialIssued = false
        var writeStatus: Int?
        var readStatus: Int?
        var writeCID: String?
        var readCID: String?
        var writeDigest: String?
        var readDigest: String?
        var errorCode: String?
        do {
            let credential = try await broker.exchange(
                space: space,
                memberAuthorization: member.authorization,
                clientAttestation: clientAttestation,
                recorder: recorder,
                memberAuthorizationProvider: member.authorizationProvider,
                memberLabel: member.label,
                authorityLabel: authority.label
            )
            credentialIssued = !credential.isEmpty
            guard credentialIssued else { throw InteropHTTPError.unexpectedStatus(502) }
            // The proposal's space credential authorizes reads only. The
            // repository write is therefore made by the member account using
            // the same fresh OAuth/DPoP provider used to mint its delegation.
            let writePath = "/xrpc/com.atproto.space.createRecord"
            let memberWriteAuthorization = try await authorization(
                for: member,
                method: .post,
                path: writePath,
                body: createBody
            )
            let write = try await member.client.procedure(
                "com.atproto.space.createRecord",
                body: createBody,
                authorization: memberWriteAuthorization
            )
            writeStatus = write.status
            writeDigest = responseDigest(write)
            await recorder.record(
                host: member.label,
                method: "POST",
                path: writePath,
                requestBody: createBody,
                response: write
            )
            guard (200 ... 299).contains(write.status) else {
                errorCode = responseErrorCode(write)
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: nil, writeCID: nil, readCID: nil,
                    writeDigest: writeDigest, readDigest: nil,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            writeCID = try StrictJSON.decode(RecordResponse.self, from: write.body).cid
            guard writeCID != nil else {
                errorCode = "InvalidResponse"
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: nil, writeCID: nil, readCID: nil,
                    writeDigest: writeDigest, readDigest: nil,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            let credentialAuthorization = InteropAuthorization.bearer(token: credential)
            // A space credential is presented to the repository host.  In a
            // local laboratory the authority may also host the member repo,
            // which is the historical default.  Cross-implementation runs
            // must be able to select the member host explicitly so the test
            // proves that the pinned TypeScript PDS can verify and serve a
            // Swan-issued credential rather than accidentally reading a
            // second local copy from the authority.
            let repositoryHost = readHost ?? authority
            let read = try await repositoryHost.client.query(
                "com.atproto.space.getRecord",
                query: readQuery,
                authorization: credentialAuthorization
            )
            readStatus = read.status
            readDigest = responseDigest(read)
            await recorder.record(
                host: repositoryHost.label,
                method: "GET",
                path: "/xrpc/com.atproto.space.getRecord",
                response: read
            )
            guard (200 ... 299).contains(read.status) else {
                errorCode = responseErrorCode(read)
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: readStatus, writeCID: writeCID, readCID: nil,
                    writeDigest: writeDigest, readDigest: readDigest,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            readCID = try StrictJSON.decode(RecordResponse.self, from: read.body).cid
            guard readCID != nil else {
                errorCode = "InvalidResponse"
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: readStatus, writeCID: writeCID, readCID: nil,
                    writeDigest: writeDigest, readDigest: readDigest,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            let converged = writeCID == readCID
            return await permissionedArtifact(
                scenario: scenario, member: member, authority: authority,
                credentialIssued: credentialIssued, writeStatus: writeStatus,
                readStatus: readStatus, writeCID: writeCID, readCID: readCID,
                writeDigest: writeDigest, readDigest: readDigest,
                converged: converged, errorCode: nil, recorder: recorder
            )
        } catch {
            errorCode = liveErrorCode(error)
            return await permissionedArtifact(
                scenario: scenario, member: member, authority: authority,
                credentialIssued: credentialIssued, writeStatus: writeStatus,
                readStatus: readStatus, writeCID: writeCID, readCID: readCID,
                writeDigest: writeDigest, readDigest: readDigest,
                converged: false, errorCode: errorCode, recorder: recorder
            )
        }
    }

    private static func artifact(
        scenario: String,
        producer: LiveInteropHost,
        consumer: LiveInteropHost,
        putStatus: Int?,
        readStatus: Int?,
        putCID: String?,
        readCID: String?,
        putDigest: String?,
        readDigest: String?,
        converged: Bool,
        errorCode: String?,
        recorder: InteropFixtureRecorder
    ) async -> LiveInteropPublicRoundTripArtifact {
        LiveInteropPublicRoundTripArtifact(
            scenario: scenario,
            producer: producer.label,
            consumer: consumer.label,
            putStatus: putStatus,
            readStatus: readStatus,
            putCID: putCID,
            readCID: readCID,
            putResponseSHA256: putDigest,
            readResponseSHA256: readDigest,
            converged: converged,
            status: converged ? "passed" : "failed",
            errorCode: errorCode,
            events: await recorder.snapshot()
        )
    }

    private static func permissionedArtifact(
        scenario: String,
        member: LiveInteropHost,
        authority: LiveInteropHost,
        credentialIssued: Bool,
        writeStatus: Int?,
        readStatus: Int?,
        writeCID: String?,
        readCID: String?,
        writeDigest: String?,
        readDigest: String?,
        converged: Bool,
        errorCode: String?,
        recorder: InteropFixtureRecorder
    ) async -> LiveInteropPermissionedRoundTripArtifact {
        LiveInteropPermissionedRoundTripArtifact(
            scenario: scenario,
            member: member.label,
            authority: authority.label,
            credentialIssued: credentialIssued,
            writeStatus: writeStatus,
            readStatus: readStatus,
            writeCID: writeCID,
            readCID: readCID,
            writeResponseSHA256: writeDigest,
            readResponseSHA256: readDigest,
            converged: converged,
            status: converged ? "passed" : "failed",
            errorCode: errorCode,
            events: await recorder.snapshot()
        )
    }

    private static func authorization(
        for host: LiveInteropHost,
        method: InteropHTTPMethod,
        path: String,
        body: Data?,
        fallback: InteropAuthorization? = nil
    ) async throws -> InteropAuthorization {
        guard let provider = host.authorizationProvider else {
            return fallback ?? host.authorization
        }
        guard let target = URL(string: path, relativeTo: host.client.http.baseURL)?.absoluteURL else {
            throw InteropHTTPError.invalidURL
        }
        return try await provider(method, target, body)
    }

    private static func jsonFields(_ body: Data, equalTo expected: [String: String]) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return false
        }
        return expected.allSatisfy { key, value in
            (object[key] as? String) == value
        }
    }
}

private func responseDigest(_ response: InteropHTTPResponse) -> String {
    Hex.encode(Data(SHA256.hash(data: response.body)))
}

private func responseErrorCode(_ response: InteropHTTPResponse) -> String? {
    guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
        return nil
    }
    return (object["error"] as? String).map { FixtureSanitizer.sanitize(["error": $0])["error"] ?? "<redacted>" }
}

private func liveErrorCode(_ error: Error) -> String {
    switch error {
    case let error as InteropHTTPError:
        switch error {
        case .invalidURL: return "InvalidURL"
        case .responseTooLarge: return "ResponseTooLarge"
        case .unexpectedRedirect: return "UnexpectedRedirect"
        case .unexpectedContentType: return "UnexpectedContentType"
        case let .unexpectedStatus(status): return "HTTP\(status)"
        case .transportFailure: return "TransportFailure"
        case .fileFailure: return "FileFailure"
        }
    default:
        return "InteropFailure"
    }
}

private extension InteropHTTPResponse {
    var bodyErrorCode: String? {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return nil
        }
        return (object["error"] as? String).map(FixtureSanitizer.sanitize)
    }
}

/// A compact, durable consumer state used by the live matrix.  It validates
/// CID/value correspondence and the LtHash commitment before publishing a
/// new state, so a bad or reordered response leaves the last good snapshot
/// unchanged.
public actor SpaceReplica {
    public struct State: Sendable, Equatable {
        public let revision: UInt64
        public let records: [SpaceRecord]
        public let ltHash: Data
        public let commitment: Data
    }

    public enum Error: Swift.Error, Sendable, Equatable {
        case wrongRepository
        case revisionGap
        case staleRevision
        case invalidCID
        case missingDelete
        case commitmentMismatch
        case emptyOperation
    }

    private let space: SpaceURI
    private let author: String
    private var records: [SpaceRecordURI: SpaceRecord] = [:]
    private var revision: UInt64 = 0
    private var ltHash = LtHash()

    public init(space: SpaceURI, author: String) throws {
        guard (try? DID(didString: author)) != nil else {
            throw SwanError.invalidIdentifier("replica author")
        }
        self.space = space
        self.author = author
    }

    public func state() -> State {
        State(
            revision: revision,
            records: records.values.sorted { $0.uri.rawValue < $1.uri.rawValue },
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment
        )
    }

    public func apply(_ entries: [InteropRepositoryOperation]) throws -> State {
        guard !entries.isEmpty else { throw Error.emptyOperation }
        var nextRecords = records
        var nextRevision = revision
        var nextHash = ltHash
        for entry in entries {
            guard entry.uri.space == space, entry.uri.author == author else { throw Error.wrongRepository }
            guard entry.revision == nextRevision + 1 else {
                throw entry.revision <= nextRevision ? Error.staleRevision : Error.revisionGap
            }
            switch entry.value {
            case let .some(value):
                guard CID.fromDAGCBOR(value).string == entry.cid else { throw Error.invalidCID }
                if let old = nextRecords[entry.uri] {
                    nextHash.remove(element: Self.element(for: old))
                }
                let record = SpaceRecord(
                    uri: entry.uri,
                    value: value,
                    cid: entry.cid,
                    revision: entry.revision
                )
                nextRecords[entry.uri] = record
                nextHash.add(element: Self.element(for: record))
            case .none:
                guard let old = nextRecords.removeValue(forKey: entry.uri) else {
                    throw Error.missingDelete
                }
                nextHash.remove(element: Self.element(for: old))
            }
            guard nextHash.commitment == entry.commitment else { throw Error.commitmentMismatch }
            nextRevision = entry.revision
        }
        records = nextRecords
        revision = nextRevision
        ltHash = nextHash
        return state()
    }

    public func replace(
        revision: UInt64,
        records replacement: [SpaceRecord],
        commitment: Data
    ) throws -> State {
        var replacementMap: [SpaceRecordURI: SpaceRecord] = [:]
        var replacementHash = LtHash()
        for record in replacement {
            guard record.uri.space == space, record.uri.author == author,
                  CID.fromDAGCBOR(record.value).string == record.cid,
                  replacementMap[record.uri] == nil else {
                throw Error.invalidCID
            }
            replacementMap[record.uri] = record
            replacementHash.add(element: Self.element(for: record))
        }
        guard replacementHash.commitment == commitment else { throw Error.commitmentMismatch }
        self.records = replacementMap
        self.revision = revision
        self.ltHash = replacementHash
        return state()
    }

    private static func element(for record: SpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
    }
}

public struct InteropRepositoryOperation: Sendable, Equatable {
    public let revision: UInt64
    public let uri: SpaceRecordURI
    public let cid: String
    public let value: Data?
    public let commitment: Data

    public init(
        revision: UInt64,
        uri: SpaceRecordURI,
        cid: String,
        value: Data?,
        commitment: Data
    ) {
        self.revision = revision
        self.uri = uri
        self.cid = cid
        self.value = value
        self.commitment = commitment
    }
}

/// Applies an incremental page and then verifies the fresh reader-specific
/// commit envelope.  The terminal verification occurs before the caller can
/// use the resulting state as a convergence assertion.
public struct IncrementalSynchronizer: Sendable {
    public let replica: SpaceReplica

    public init(replica: SpaceReplica) {
        self.replica = replica
    }

    public func apply(
        _ entries: [InteropRepositoryOperation],
        terminalCommit: SpaceCommitEnvelope,
        publicKey: P256.Signing.PublicKey
    ) async throws -> SpaceReplica.State {
        let state = try await replica.apply(entries)
        guard terminalCommit.context.space == entries[0].uri.space,
              terminalCommit.context.author == entries[0].uri.author,
              try SpaceCommitCodec.verifyContextSignature(terminalCommit, publicKey: publicKey),
              SpaceCommitCodec.verifyContentBinding(terminalCommit),
              terminalCommit.commitment == state.commitment else {
            throw SpaceReplica.Error.commitmentMismatch
        }
        return state
    }
}

/// Consumes a streamed Swan two-root CAR through a bounded temporary spool.
/// Verification is delegated to the same proposal-0016 decoder used by the
/// server; the returned recovery is safe to install only after all roots,
/// record CIDs, context signature, content binding, and LtHash checks pass.
public struct SwanCARConsumer: Sendable {
    public let maximumBytes: Int

    public init(maximumBytes: Int = 256 * 1024 * 1024) throws {
        guard (1 ... 256 * 1024 * 1024).contains(maximumBytes) else {
            throw SwanError.malformed("CAR consumer bound is invalid")
        }
        self.maximumBytes = maximumBytes
    }

    public func verify(
        fileURL: URL,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey
    ) throws -> VerifiedSpaceCARRecovery {
        let data = try boundedFileData(fileURL)
        return try SpaceCARCodec.verifyRecovery(
            data,
            space: space,
            author: author,
            publicKey: publicKey
        )
    }

    public func streamAndVerify(
        client: InteropXRPCClient,
        query: [String: String],
        authorization: InteropAuthorization,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey,
        spoolURL: URL
    ) async throws -> VerifiedSpaceCARRecovery {
        _ = try await client.stream(
            "com.atproto.space.getRepo",
            query: query,
            authorization: authorization,
            to: spoolURL,
            maximumResponseBytes: maximumBytes
        )
        return try verify(fileURL: spoolURL, space: space, author: author, publicKey: publicKey)
    }

    private func boundedFileData(_ url: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber,
              size.intValue <= maximumBytes else {
            throw InteropHTTPError.responseTooLarge
        }
        do {
            return try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw InteropHTTPError.fileFailure
        }
    }
}

/// The credential exchange is kept as a named seam so the real matrix can
/// record the delegation issuer and authority separately without exposing
/// either token in an artifact.  The concrete HTTP calls use strict raw JSON
/// decoding because the pinned TypeScript branch can add fields to these
/// small output objects without changing the wire contract.
public struct SpaceCredentialBroker: Sendable {
    public let member: InteropXRPCClient
    public let authority: InteropXRPCClient

    public init(member: InteropXRPCClient, authority: InteropXRPCClient) {
        self.member = member
        self.authority = authority
    }

    public func exchange(
        space: SpaceURI,
        memberAuthorization: InteropAuthorization,
        delegationAuthorization: InteropAuthorization? = nil,
        clientAttestation: String? = nil,
        recorder: InteropFixtureRecorder? = nil,
        memberAuthorizationProvider: InteropAuthorizationProvider? = nil,
        memberLabel: String = "member",
        authorityLabel: String = "authority"
    ) async throws -> String {
        let delegationPath = try member.xrpcPath(
            "com.atproto.space.getDelegationToken",
            query: ["space": space.rawValue]
        )
        let effectiveMemberAuthorization: InteropAuthorization
        if let memberAuthorizationProvider,
           let target = URL(string: delegationPath, relativeTo: member.http.baseURL)?.absoluteURL {
            effectiveMemberAuthorization = try await memberAuthorizationProvider(
                .get, target, nil
            )
        } else {
            effectiveMemberAuthorization = memberAuthorization
        }
        let delegation = try await member.query(
            "com.atproto.space.getDelegationToken",
            query: ["space": space.rawValue],
            authorization: effectiveMemberAuthorization
        )
        await recorder?.record(
            host: memberLabel,
            method: "GET",
            path: "/xrpc/com.atproto.space.getDelegationToken",
            response: delegation
        )
        try requireJSONSuccess(delegation)
        let delegationObject = try StrictJSON.decode(TokenResponse.self, from: delegation.body)
        let credentialAuthorization = delegationAuthorization ?? .bearer(token: delegationObject.token)
        let input = CredentialRequest(space: space.rawValue, clientAttestation: clientAttestation)
        let inputBody = try encode(input)
        let credential = try await authority.procedure(
            "com.atproto.space.getSpaceCredential",
            body: inputBody,
            authorization: credentialAuthorization
        )
        await recorder?.record(
            host: authorityLabel,
            method: "POST",
            path: "/xrpc/com.atproto.space.getSpaceCredential",
            requestBody: inputBody,
            response: credential
        )
        try requireJSONSuccess(credential)
        return try StrictJSON.decode(TokenResponse.self, from: credential.body).token
    }

    private struct TokenResponse: Decodable {
        let token: String
        private enum CodingKeys: String, CodingKey {
            case token
            case credential
        }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            if let token = try values.decodeIfPresent(String.self, forKey: .token) {
                self.token = token
            } else {
                self.token = try values.decode(String.self, forKey: .credential)
            }
        }
    }

    private struct CredentialRequest: Encodable {
        let space: String
        let clientAttestation: String?
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    private func requireJSONSuccess(_ response: InteropHTTPResponse) throws {
        guard (200 ... 299).contains(response.status),
              response.header("content-type")?.lowercased().contains("json") == true else {
            throw InteropHTTPError.unexpectedStatus(response.status)
        }
    }
}

private func requireJSONSuccess(_ response: InteropHTTPResponse) throws {
    guard (200 ... 299).contains(response.status),
          response.header("content-type")?.lowercased().contains("json") == true else {
        throw InteropHTTPError.unexpectedStatus(response.status)
    }
}

private extension FixtureSanitizer {
    static func sanitize(_ value: String) -> String {
        FixtureSanitizer.sanitize(["value": value])["value"] ?? "<redacted>"
    }

    static func path(_ value: String) -> String {
        guard var components = URLComponents(string: value),
              !components.path.isEmpty else {
            return "<invalid-path>"
        }
        // XRPC query values can contain DIDs, handles, record keys, and
        // selectors. Keep only the endpoint path and sorted parameter names.
        let names = Set(components.queryItems?.map(\.name) ?? []).sorted()
        components.query = nil
        let path = components.path
        guard !names.isEmpty else { return path }
        return path + "?keys=" + names.joined(separator: ",")
    }
}
