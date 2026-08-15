import AsyncHTTPClient
import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOHTTP1
import NIOSSL
import Petrel
import SwanCore
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage
import SwanSpacesWire

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

/// A bounded request seam for deterministic interop tests. Production callers
/// use AsyncHTTPClient; tests can provide a transport that records the exact
/// target, headers, and body while returning pinned wire responses without
/// opening a socket.
public typealias InteropHTTPExecuteHandler = @Sendable (
    InteropHTTPMethod, URL, [String: String], Data?, Int
) async throws -> InteropHTTPResponse

/// A small AsyncHTTPClient adapter with strict bounds and no redirect
/// following.  It is deliberately independent of the Hummingbird server so
/// the same client can drive Swan, the pinned TypeScript PDS, or a faultable
/// Toxiproxy route.
public final class InteropHTTPClient: @unchecked Sendable {
    public let baseURL: URL
    public let timeout: TimeInterval
    public let maximumResponseBytes: Int
    /// File-backed CAR/blob responses may be larger than JSON responses. The
    /// limit remains finite and is enforced one received buffer at a time.
    public let maximumStreamingResponseBytes: Int

    private let client: HTTPClient
    private let executeHandler: InteropHTTPExecuteHandler?

    public init(
        baseURL: URL,
        timeout: TimeInterval = 15,
        maximumResponseBytes: Int = 2 * 1024 * 1024,
        maximumStreamingResponseBytes: Int = 512 * 1024 * 1024,
        additionalTrustRootFile: URL? = nil,
        executeHandler: InteropHTTPExecuteHandler? = nil
    ) throws {
        guard Self.validBaseURL(baseURL),
              timeout > 0, timeout <= 120, timeout.isFinite,
              (1 ... 256 * 1024 * 1024).contains(maximumResponseBytes),
              (1 ... 512 * 1024 * 1024).contains(maximumStreamingResponseBytes) else {
            throw SwanError.malformed("interop HTTP client bounds are invalid")
        }
        self.baseURL = baseURL
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
        self.maximumStreamingResponseBytes = maximumStreamingResponseBytes
        self.executeHandler = executeHandler
        var configuration = HTTPClient.Configuration(
            redirectConfiguration: .disallow,
            timeout: .init(
                connect: .milliseconds(Int64(timeout * 1_000)),
                read: .milliseconds(Int64(timeout * 1_000))
            ),
            decompression: .disabled
        )
        if let additionalTrustRootFile {
            let path = additionalTrustRootFile.standardizedFileURL.path
            guard FileManager.default.fileExists(atPath: path),
                  let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  (attributes[.type] as? FileAttributeType) == .typeRegular else {
                throw SwanError.malformed("interop TLS trust root is unavailable")
            }
            var tls = TLSConfiguration.makeClientConfiguration()
            tls.additionalTrustRoots = [.file(path)]
            configuration.tlsConfiguration = tls
        }
        client = HTTPClient(configuration: configuration)
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
        if let executeHandler {
            let response = try await executeHandler(method, url, headers, body, limit)
            guard response.body.count <= limit else {
                throw InteropHTTPError.responseTooLarge
            }
            guard response.redirectCount == 0 else {
                throw InteropHTTPError.unexpectedRedirect
            }
            return response
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
        guard (1 ... self.maximumStreamingResponseBytes).contains(maximumResponseBytes) else {
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
                _ = try InteropStreamingBodyChunker.drain(buffer) {
                    try handle.write(contentsOf: $0)
                }
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
              let baseComponents = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == baseURL.scheme?.lowercased(),
              components.host?.lowercased() == baseURL.host?.lowercased(),
              components.port == baseComponents.port,
              components.user == nil,
              components.password == nil,
              components.fragment == nil else {
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

enum InteropStreamingBodyChunker {
    static let maximumChunkBytes = 64 * 1_024

    /// AsyncHTTPClient does not promise a maximum size for each yielded
    /// ByteBuffer. Slice it before bridging to Foundation so one unusually
    /// large network buffer cannot become an equally large transient Data.
    static func drain(
        _ receivedBuffer: ByteBuffer,
        consume: (Data) throws -> Void
    ) throws -> Int {
        var buffer = receivedBuffer
        let originalCount = buffer.readableBytes
        while buffer.readableBytes > 0 {
            let count = min(maximumChunkBytes, buffer.readableBytes)
            guard let chunk = buffer.readData(length: count),
                  chunk.count == count else {
                throw InteropHTTPError.fileFailure
            }
            try consume(chunk)
        }
        return originalCount
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

    public init(
        baseURL: URL,
        timeout: TimeInterval = 15,
        additionalTrustRootFile: URL? = nil
    ) throws {
        self.init(http: try InteropHTTPClient(
            baseURL: baseURL,
            timeout: timeout,
            additionalTrustRootFile: additionalTrustRootFile
        ))
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

    /// Bounded binary XRPC procedure used by the public blob interop slice.
    /// The live fixture runner intentionally keeps request bodies small; the
    /// production HTTP upload route has its own streaming staging path.
    public func binaryProcedure(
        _ nsid: String,
        body: Data,
        contentType: String,
        authorization: InteropAuthorization = .none,
        maximumResponseBytes: Int? = nil
    ) async throws -> InteropHTTPResponse {
        guard body.count <= 2 * 1024 * 1024 else {
            throw InteropHTTPError.responseTooLarge
        }
        let path = try makeXRPCPath(nsid, query: [:])
        var headers = [
            "Accept": "application/json",
            "Content-Type": contentType,
        ]
        addAuthorization(authorization, to: &headers)
        return try await http.execute(
            method: .post,
            path: path,
            headers: headers,
            body: body,
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
        self.host = FixtureSanitizer.safeIdentifier(host)
        self.method = FixtureSanitizer.httpMethod(method)
        self.path = FixtureSanitizer.path(path)
        self.status = status
        self.requestBytes = requestBytes
        self.responseBytes = responseBytes
        self.responseSHA256 =
            FixtureSanitizer.canonicalSHA256Hex(responseSHA256) ?? "<redacted>"
        self.responseError = responseError.map(FixtureSanitizer.errorCode)
    }

    private enum CodingKeys: String, CodingKey {
        case host
        case method
        case path
        case status
        case requestBytes
        case responseBytes
        case responseSHA256
        case responseError
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            host: try container.decode(String.self, forKey: .host),
            method: try container.decode(String.self, forKey: .method),
            path: try container.decode(String.self, forKey: .path),
            status: try container.decode(Int.self, forKey: .status),
            requestBytes: try container.decode(Int.self, forKey: .requestBytes),
            responseBytes: try container.decode(Int.self, forKey: .responseBytes),
            responseSHA256: try container.decode(
                String.self,
                forKey: .responseSHA256
            ),
            responseError: try container.decodeIfPresent(
                String.self,
                forKey: .responseError
            )
        )
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
                path: path,
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
    /// Optional operator-pinned key for verifying permissioned repository
    /// commits returned by this host. A missing key is an intentional
    /// fail-closed condition when an incremental sync assertion is requested.
    public let permissionedCommitVerificationKey: PermissionedDataJWTVerificationKey?

    public init(
        label: String,
        client: InteropXRPCClient,
        authorization: InteropAuthorization = .none,
        authorizationProvider: InteropAuthorizationProvider? = nil,
        permissionedCommitVerificationKey: PermissionedDataJWTVerificationKey? = nil
    ) {
        self.label = label
        self.client = client
        self.authorization = authorization
        self.authorizationProvider = authorizationProvider
        self.permissionedCommitVerificationKey = permissionedCommitVerificationKey
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
    public let blobUploadStatus: Int?
    public let blobDownloadStatus: Int?
    public let blobCID: String?
    public let blobBytes: Int?
    public let blobVerified: Bool?
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
        blobUploadStatus: Int? = nil,
        blobDownloadStatus: Int? = nil,
        blobCID: String? = nil,
        blobBytes: Int? = nil,
        blobVerified: Bool? = nil,
        converged: Bool,
        status: String,
        errorCode: String?,
        events: [InteropFixtureEvent]
    ) {
        self.scenario = FixtureSanitizer.safeIdentifier(scenario)
        self.profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.producer = FixtureSanitizer.safeIdentifier(producer)
        self.consumer = FixtureSanitizer.safeIdentifier(consumer)
        self.putStatus = putStatus
        self.readStatus = readStatus
        self.putCID = canonicalInteropCID(putCID, codec: .dagCBOR)
        self.readCID = canonicalInteropCID(readCID, codec: .dagCBOR)
        self.putResponseSHA256 =
            FixtureSanitizer.canonicalSHA256Hex(putResponseSHA256)
        self.readResponseSHA256 =
            FixtureSanitizer.canonicalSHA256Hex(readResponseSHA256)
        self.blobUploadStatus = blobUploadStatus
        self.blobDownloadStatus = blobDownloadStatus
        self.blobCID = canonicalInteropCID(blobCID, codec: .raw)
        self.blobBytes = blobBytes
        self.blobVerified = blobVerified
        self.converged = converged
        self.status = FixtureSanitizer.artifactStatus(status)
        self.errorCode = errorCode.map(FixtureSanitizer.errorCode)
        self.fixturePolicy = "semantic-summary-only; no request bodies, record values, credentials, tokens, DPoP proofs, or personal selectors"
        self.events = events
    }

    private enum CodingKeys: String, CodingKey {
        case scenario
        case profileID
        case producer
        case consumer
        case putStatus
        case readStatus
        case putCID
        case readCID
        case putResponseSHA256
        case readResponseSHA256
        case blobUploadStatus
        case blobDownloadStatus
        case blobCID
        case blobBytes
        case blobVerified
        case converged
        case status
        case errorCode
        case fixturePolicy
        case events
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            scenario: try container.decode(String.self, forKey: .scenario),
            producer: try container.decode(String.self, forKey: .producer),
            consumer: try container.decode(String.self, forKey: .consumer),
            putStatus: try container.decodeIfPresent(Int.self, forKey: .putStatus),
            readStatus: try container.decodeIfPresent(Int.self, forKey: .readStatus),
            putCID: try container.decodeIfPresent(String.self, forKey: .putCID),
            readCID: try container.decodeIfPresent(String.self, forKey: .readCID),
            putResponseSHA256: try container.decodeIfPresent(
                String.self,
                forKey: .putResponseSHA256
            ),
            readResponseSHA256: try container.decodeIfPresent(
                String.self,
                forKey: .readResponseSHA256
            ),
            blobUploadStatus: try container.decodeIfPresent(
                Int.self,
                forKey: .blobUploadStatus
            ),
            blobDownloadStatus: try container.decodeIfPresent(
                Int.self,
                forKey: .blobDownloadStatus
            ),
            blobCID: try container.decodeIfPresent(String.self, forKey: .blobCID),
            blobBytes: try container.decodeIfPresent(Int.self, forKey: .blobBytes),
            blobVerified: try container.decodeIfPresent(
                Bool.self,
                forKey: .blobVerified
            ),
            converged: try container.decode(Bool.self, forKey: .converged),
            status: try container.decode(String.self, forKey: .status),
            errorCode: try container.decodeIfPresent(String.self, forKey: .errorCode),
            events: try container.decode([InteropFixtureEvent].self, forKey: .events)
        )
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
    public let syncStatus: Int?
    public let syncOpsCount: Int?
    public let syncOperationCID: String?
    /// Revision of the operation that matched the write CID. This makes the
    /// incremental page an explicit state-transition witness, rather than an
    /// endpoint-success probe.
    public let syncOperationRevision: String?
    /// Hex-encoded LtHash commitment reconstructed from the terminal page.
    public let syncCommitment: String?
    /// Revision bound into the verified signed terminal commitment.
    public let syncCommitRevision: String?
    public let syncCommitVerified: Bool?
    /// Whether the incremental-sync response included record values.  The
    /// pinned TypeScript branch currently has an ambiguous SQLite query when
    /// values are requested; callers can explicitly exercise its supported
    /// metadata-only form with `excludeValues=true` and this field keeps that
    /// limitation visible in the sanitized artifact.
    public let syncValuesIncluded: Bool?
    public let fullCARStatus: Int?
    public let fullCARRecordCount: Int?
    public let fullCARCommitment: String?
    /// Canonical TID from the signed full-CAR commit context. This is retained
    /// so a commitment that recurs at a later state cannot make an older CAR
    /// look current.
    public let fullCARWireRevision: String?
    /// True only when the fully verified CAR index contains the exact
    /// collection/rkey -> CID produced and read by this round trip. The path
    /// itself is intentionally not persisted in the artifact.
    public let fullCARExpectedRecordVerified: Bool?
    public let fullCARVerified: Bool?
    /// Permissioned blob transfer evidence, when the live fixture requested a
    /// blob upload. The blob is uploaded with the member's OAuth capability
    /// and fetched from the selected repository host with the read-only space
    /// credential; only status, CID, byte count, and a digest check leave the
    /// runner.
    public let blobUploadStatus: Int?
    public let blobDownloadStatus: Int?
    public let blobCID: String?
    public let blobBytes: Int?
    public let blobVerified: Bool?
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
        syncStatus: Int? = nil,
        syncOpsCount: Int? = nil,
        syncOperationCID: String? = nil,
        syncOperationRevision: String? = nil,
        syncCommitment: String? = nil,
        syncCommitRevision: String? = nil,
        syncCommitVerified: Bool? = nil,
        syncValuesIncluded: Bool? = nil,
        fullCARStatus: Int? = nil,
        fullCARRecordCount: Int? = nil,
        fullCARCommitment: String? = nil,
        fullCARWireRevision: String? = nil,
        fullCARExpectedRecordVerified: Bool? = nil,
        fullCARVerified: Bool? = nil,
        blobUploadStatus: Int? = nil,
        blobDownloadStatus: Int? = nil,
        blobCID: String? = nil,
        blobBytes: Int? = nil,
        blobVerified: Bool? = nil,
        converged: Bool,
        status: String,
        errorCode: String?,
        events: [InteropFixtureEvent]
    ) {
        self.scenario = FixtureSanitizer.safeIdentifier(scenario)
        self.profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.member = FixtureSanitizer.safeIdentifier(member)
        self.authority = FixtureSanitizer.safeIdentifier(authority)
        self.credentialIssued = credentialIssued
        self.writeStatus = writeStatus
        self.readStatus = readStatus
        self.writeCID = canonicalInteropCID(writeCID, codec: .dagCBOR)
        self.readCID = canonicalInteropCID(readCID, codec: .dagCBOR)
        self.writeResponseSHA256 =
            FixtureSanitizer.canonicalSHA256Hex(writeResponseSHA256)
        self.readResponseSHA256 =
            FixtureSanitizer.canonicalSHA256Hex(readResponseSHA256)
        self.syncStatus = syncStatus
        self.syncOpsCount = syncOpsCount
        self.syncOperationCID = canonicalInteropCID(
            syncOperationCID,
            codec: .dagCBOR
        )
        self.syncOperationRevision = canonicalInteropTID(
            syncOperationRevision
        )
        self.syncCommitment =
            FixtureSanitizer.canonicalSHA256Hex(syncCommitment)
        self.syncCommitRevision = canonicalInteropTID(syncCommitRevision)
        self.syncCommitVerified = syncCommitVerified
        self.syncValuesIncluded = syncValuesIncluded
        self.fullCARStatus = fullCARStatus
        self.fullCARRecordCount = fullCARRecordCount
        self.fullCARCommitment =
            FixtureSanitizer.canonicalSHA256Hex(fullCARCommitment)
        self.fullCARWireRevision = canonicalInteropTID(fullCARWireRevision)
        self.fullCARExpectedRecordVerified = fullCARExpectedRecordVerified
        self.fullCARVerified = fullCARVerified
        self.blobUploadStatus = blobUploadStatus
        self.blobDownloadStatus = blobDownloadStatus
        self.blobCID = canonicalInteropCID(blobCID, codec: .raw)
        self.blobBytes = blobBytes
        self.blobVerified = blobVerified
        self.converged = converged
        self.status = FixtureSanitizer.artifactStatus(status)
        self.errorCode = errorCode.map(FixtureSanitizer.errorCode)
        self.fixturePolicy = "semantic-summary-only; no credentials, tokens, DPoP proofs, request bodies, record values, or personal selectors"
        self.events = events
    }

    private enum CodingKeys: String, CodingKey {
        case scenario
        case profileID
        case member
        case authority
        case credentialIssued
        case writeStatus
        case readStatus
        case writeCID
        case readCID
        case writeResponseSHA256
        case readResponseSHA256
        case syncStatus
        case syncOpsCount
        case syncOperationCID
        case syncOperationRevision
        case syncCommitment
        case syncCommitRevision
        case syncCommitVerified
        case syncValuesIncluded
        case fullCARStatus
        case fullCARRecordCount
        case fullCARCommitment
        case fullCARWireRevision
        case fullCARExpectedRecordVerified
        case fullCARVerified
        case blobUploadStatus
        case blobDownloadStatus
        case blobCID
        case blobBytes
        case blobVerified
        case converged
        case status
        case errorCode
        case fixturePolicy
        case events
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            scenario: try container.decode(String.self, forKey: .scenario),
            member: try container.decode(String.self, forKey: .member),
            authority: try container.decode(String.self, forKey: .authority),
            credentialIssued: try container.decode(
                Bool.self,
                forKey: .credentialIssued
            ),
            writeStatus: try container.decodeIfPresent(
                Int.self,
                forKey: .writeStatus
            ),
            readStatus: try container.decodeIfPresent(Int.self, forKey: .readStatus),
            writeCID: try container.decodeIfPresent(String.self, forKey: .writeCID),
            readCID: try container.decodeIfPresent(String.self, forKey: .readCID),
            writeResponseSHA256: try container.decodeIfPresent(
                String.self,
                forKey: .writeResponseSHA256
            ),
            readResponseSHA256: try container.decodeIfPresent(
                String.self,
                forKey: .readResponseSHA256
            ),
            syncStatus: try container.decodeIfPresent(Int.self, forKey: .syncStatus),
            syncOpsCount: try container.decodeIfPresent(
                Int.self,
                forKey: .syncOpsCount
            ),
            syncOperationCID: try container.decodeIfPresent(
                String.self,
                forKey: .syncOperationCID
            ),
            syncOperationRevision: try container.decodeIfPresent(
                String.self,
                forKey: .syncOperationRevision
            ),
            syncCommitment: try container.decodeIfPresent(
                String.self,
                forKey: .syncCommitment
            ),
            syncCommitRevision: try container.decodeIfPresent(
                String.self,
                forKey: .syncCommitRevision
            ),
            syncCommitVerified: try container.decodeIfPresent(
                Bool.self,
                forKey: .syncCommitVerified
            ),
            syncValuesIncluded: try container.decodeIfPresent(
                Bool.self,
                forKey: .syncValuesIncluded
            ),
            fullCARStatus: try container.decodeIfPresent(
                Int.self,
                forKey: .fullCARStatus
            ),
            fullCARRecordCount: try container.decodeIfPresent(
                Int.self,
                forKey: .fullCARRecordCount
            ),
            fullCARCommitment: try container.decodeIfPresent(
                String.self,
                forKey: .fullCARCommitment
            ),
            fullCARWireRevision: try container.decodeIfPresent(
                String.self,
                forKey: .fullCARWireRevision
            ),
            fullCARExpectedRecordVerified: try container.decodeIfPresent(
                Bool.self,
                forKey: .fullCARExpectedRecordVerified
            ),
            fullCARVerified: try container.decodeIfPresent(
                Bool.self,
                forKey: .fullCARVerified
            ),
            blobUploadStatus: try container.decodeIfPresent(
                Int.self,
                forKey: .blobUploadStatus
            ),
            blobDownloadStatus: try container.decodeIfPresent(
                Int.self,
                forKey: .blobDownloadStatus
            ),
            blobCID: try container.decodeIfPresent(String.self, forKey: .blobCID),
            blobBytes: try container.decodeIfPresent(Int.self, forKey: .blobBytes),
            blobVerified: try container.decodeIfPresent(
                Bool.self,
                forKey: .blobVerified
            ),
            converged: try container.decode(Bool.self, forKey: .converged),
            status: try container.decode(String.self, forKey: .status),
            errorCode: try container.decodeIfPresent(String.self, forKey: .errorCode),
            events: try container.decode([InteropFixtureEvent].self, forKey: .events)
        )
    }
}

/// The deliberately narrow artifact for a member-authorized, write-only
/// `space.applyWrites` advancement.  It contains no record material or peer
/// identity: the signed terminal revision is the only durable witness needed
/// by the recovery acceptance harness.
public struct PermissionedWriteOnlyApplyWritesArtifact: Codable, Sendable, Equatable {
    public let scenario: String
    public let profileID: String
    public let fixturePolicy: String
    public let applyStatus: Int?
    public let witnessStatus: Int?
    public let terminalRevision: String?
    public let operationCount: Int?
    public let responseDigest: String?
    public let status: String
    public let errorCode: String?

    public init(
        scenario: String,
        applyStatus: Int?,
        witnessStatus: Int?,
        terminalRevision: String?,
        operationCount: Int?,
        responseDigest: String?,
        status: String,
        errorCode: String?
    ) {
        self.scenario = FixtureSanitizer.safeIdentifier(scenario)
        self.profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.fixturePolicy = "summary-only-digests-and-signed-terminal-revision"
        self.applyStatus = applyStatus.flatMap { (100 ... 599).contains($0) ? $0 : nil }
        self.witnessStatus = witnessStatus.flatMap { (100 ... 599).contains($0) ? $0 : nil }
        self.terminalRevision = canonicalInteropTID(terminalRevision)
        self.operationCount = operationCount.flatMap { (1 ... 100).contains($0) ? $0 : nil }
        self.responseDigest = FixtureSanitizer.canonicalSHA256Hex(responseDigest)
        self.status = FixtureSanitizer.artifactStatus(status)
        self.errorCode = errorCode.map(FixtureSanitizer.errorCode)
    }
}

/// Sanitized proof that either an incremental retention gap selected full-CAR
/// recovery or an explicitly enabled compatibility fallback selected it, an
/// existing durable receiver head was CAS-replaced by a newer archive, and a
/// deliberately corrupted retry could not replace that head. Repository and
/// receiver identifiers, space URIs, request IDs, verifier fingerprints, raw
/// LtHash state, credentials, and record values are deliberately absent.
public struct PermissionedRecoveryAcceptanceArtifact:
    Encodable, Sendable, Equatable
{
    public let scenario: String
    public let profileID: String
    public let gapStatus: Int?
    public let gapErrorCode: String?
    /// True only when the caller explicitly enabled the compatibility path
    /// for a source that returned a successful listRepoOps response without
    /// the protocol's retention-gap error. This is never retention-gap proof.
    public let gapFallbackUsed: Bool
    public let priorHeadGeneration: UInt64?
    public let priorHeadRevision: String?
    public let priorCommitment: String?
    public let replacementHeadGeneration: UInt64?
    public let replacementHeadRevision: String?
    public let replacementCommitment: String?
    public let replacementRecordCount: Int?
    public let replacementCASAdvanced: Bool
    public let corruptionRejected: Bool
    public let corruptErrorCode: String?
    public let finalHeadGeneration: UInt64?
    public let finalHeadRevision: String?
    public let finalCommitment: String?
    public let lastValidHeadPreserved: Bool
    public let status: String
    public let errorCode: String?
    public let fixturePolicy: String

    public init(
        scenario: String,
        gapStatus: Int?,
        gapErrorCode: String?,
        gapFallbackUsed: Bool = false,
        priorHeadGeneration: UInt64?,
        priorHeadRevision: String?,
        priorCommitment: String?,
        replacementHeadGeneration: UInt64?,
        replacementHeadRevision: String?,
        replacementCommitment: String?,
        replacementRecordCount: Int?,
        replacementCASAdvanced: Bool,
        corruptionRejected: Bool,
        corruptErrorCode: String?,
        finalHeadGeneration: UInt64?,
        finalHeadRevision: String?,
        finalCommitment: String?,
        lastValidHeadPreserved: Bool,
        status: String,
        errorCode: String?
    ) {
        self.scenario = FixtureSanitizer.safeIdentifier(scenario)
        profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.gapStatus = gapStatus.flatMap {
            (100 ... 599).contains($0) ? $0 : nil
        }
        self.gapErrorCode = gapErrorCode.map(FixtureSanitizer.errorCode)
        self.gapFallbackUsed = gapFallbackUsed
        self.priorHeadGeneration = priorHeadGeneration.flatMap {
            $0 > 0 && $0 <= UInt64(Int.max) ? $0 : nil
        }
        self.priorHeadRevision = canonicalInteropTID(priorHeadRevision)
        self.priorCommitment = FixtureSanitizer.canonicalSHA256Hex(
            priorCommitment
        )
        self.replacementHeadGeneration = replacementHeadGeneration.flatMap {
            $0 > 0 && $0 <= UInt64(Int.max) ? $0 : nil
        }
        self.replacementHeadRevision = canonicalInteropTID(replacementHeadRevision)
        self.replacementCommitment = FixtureSanitizer.canonicalSHA256Hex(
            replacementCommitment
        )
        self.replacementRecordCount = replacementRecordCount.flatMap {
            $0 >= 0 ? $0 : nil
        }
        self.replacementCASAdvanced = replacementCASAdvanced
        self.corruptionRejected = corruptionRejected
        self.corruptErrorCode = corruptErrorCode.map(
            FixtureSanitizer.errorCode
        )
        self.finalHeadGeneration = finalHeadGeneration.flatMap {
            $0 > 0 && $0 <= UInt64(Int.max) ? $0 : nil
        }
        self.finalHeadRevision = canonicalInteropTID(finalHeadRevision)
        self.finalCommitment = FixtureSanitizer.canonicalSHA256Hex(
            finalCommitment
        )
        self.lastValidHeadPreserved = lastValidHeadPreserved
        self.status = FixtureSanitizer.artifactStatus(status)
        self.errorCode = errorCode.map(FixtureSanitizer.errorCode)
        fixturePolicy = "semantic-summary-only; no DIDs, space URIs, paths, request identities, verifier material, credentials, tokens, DPoP proofs, record values, or raw LtHash state"
    }
}

/// Stable secret-free error projection for recovery acceptance artifacts. No
/// arbitrary `Error` description, peer body, selector, URL, or database path
/// crosses this boundary.
public enum PermissionedRecoveryFailureCode {
    public static func code(for error: Error) -> String {
        switch error {
        case let recovery as PermissionedRemoteReplicaRecoveryError:
            switch recovery {
            case .invalidBinding: return "RecoveryInvalidBinding"
            case .invalidTimestamp: return "RecoveryInvalidTimestamp"
            case .receiverMismatch: return "RecoveryReceiverMismatch"
            case .unknownSession: return "RecoveryUnknownSession"
            case .expiredSession: return "RecoveryExpiredSession"
            case .importInProgress: return "RecoveryImportInProgress"
            case .poisonedSession: return "RecoveryPoisonedSession"
            case .conflictingRequestReuse:
                return "RecoveryConflictingRequestReuse"
            case .bindingMismatch: return "RecoveryBindingMismatch"
            case .verificationRequired:
                return "RecoveryVerificationRequired"
            case .invalidStatus: return "RecoveryInvalidStatus"
            case .duplicateIndexEntry: return "CARDuplicateIndexEntry"
            case .duplicateBlockConflict: return "CARBlockCIDMismatch"
            case .invalidChunk: return "RecoveryInvalidChunk"
            case .incompleteBlock: return "RecoveryIncompleteBlock"
            case .corruptStaging: return "RecoveryCorruptStaging"
            case .corruptReplica: return "RecoveryCorruptReplica"
            case .targetCASConflict: return "RecoveryCASConflict"
            case .staleRecovery: return "RecoveryStale"
            case .equivocation: return "RecoveryEquivocation"
            case .freshnessMismatch: return "RecoveryFreshnessMismatch"
            }
        case let streaming as SpaceCARStreamingError:
            return spaceCARStreamingErrorCode(streaming)
        case is InteropHTTPError:
            return liveErrorCode(error)
        default:
            return "RecoveryFailed"
        }
    }

    /// The acceptance command injects exactly one mutation after a complete
    /// download: it flips the final payload byte. Only a local block-CID
    /// mismatch proves that this mutation reached the verifier. Transport,
    /// authentication, timeout, and unrelated storage errors must not be
    /// counted as corruption rejection evidence.
    public static func isInjectedFinalByteCorruptionRejection(
        _ error: Error
    ) -> Bool {
        code(for: error) == "CARBlockCIDMismatch"
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

    private struct BlobResponse: Decodable {
        struct BlobValue: Decodable {
            struct Link: Decodable {
                let link: String

                private enum CodingKeys: String, CodingKey {
                    case link = "$link"
                }
            }

            let ref: Link?
            let cid: String?
        }

        let blob: BlobValue
    }

    static func canonicalRecordCID(from body: Data) -> String? {
        guard let response = try? StrictJSON.decode(
            RecordResponse.self,
            from: body
        ) else {
            return nil
        }
        return canonicalInteropCID(response.cid, codec: .dagCBOR)
    }

    static func canonicalBlobCID(from body: Data) -> String? {
        guard let response = try? StrictJSON.decode(
            BlobResponse.self,
            from: body
        ) else {
            return nil
        }
        let candidates = [response.blob.ref?.link, response.blob.cid]
            .compactMap { $0 }
        guard candidates.count == 1 else {
            return nil
        }
        return canonicalInteropCID(candidates[0], codec: .raw)
    }

    private struct PermissionedSyncResult: Sendable {
        let status: Int?
        let opsCount: Int?
        let operationCID: String?
        let operationRevision: String?
        let commitment: String?
        let commitRevision: String?
        let commitVerified: Bool?
        let valuesIncluded: Bool?
        let errorCode: String?

        static let notRequested = Self(
            status: nil, opsCount: nil, operationCID: nil,
            operationRevision: nil, commitment: nil, commitRevision: nil,
            commitVerified: nil, valuesIncluded: nil, errorCode: nil
        )
    }

    private struct PermissionedCARResult: Sendable {
        let status: Int?
        let recordCount: Int?
        let commitment: String?
        let wireRevision: String?
        let expectedRecordVerified: Bool?
        let verified: Bool?
        let errorCode: String?

        static let notRequested = Self(
            status: nil, recordCount: nil, commitment: nil,
            wireRevision: nil, expectedRecordVerified: nil,
            verified: nil, errorCode: nil
        )
    }

    private struct PermissionedBlobResult: Sendable {
        let uploadStatus: Int?
        let downloadStatus: Int?
        let cid: String?
        let byteCount: Int?
        let verified: Bool?
        let errorCode: String?

        static let notRequested = Self(
            uploadStatus: nil, downloadStatus: nil, cid: nil,
            byteCount: nil, verified: nil, errorCode: nil
        )
    }

    private struct PublicBlobResult: Sendable {
        let uploadStatus: Int?
        let downloadStatus: Int?
        let cid: String?
        let byteCount: Int?
        let verified: Bool?
        let errorCode: String?

        static let notRequested = Self(
            uploadStatus: nil, downloadStatus: nil, cid: nil,
            byteCount: nil, verified: nil, errorCode: nil
        )
    }

    public static func publicPutAndRead(
        scenario: String,
        producer: LiveInteropHost,
        consumer: LiveInteropHost,
        repository: String,
        collection: String,
        rkey: String,
        putBody: Data,
        blobBody: Data? = nil,
        recorder: InteropFixtureRecorder? = nil
    ) async -> LiveInteropPublicRoundTripArtifact {
        let recorder = recorder ?? InteropFixtureRecorder()
        let putPath = "/xrpc/com.atproto.repo.putRecord"
        let getPath = "/xrpc/com.atproto.repo.getRecord"
        let materializedBody: Data
        if let bodyText = String(data: putBody, encoding: .utf8),
           bodyText.contains("{{REPOSITORY_DID}}") {
            materializedBody = Data(
                bodyText.replacingOccurrences(of: "{{REPOSITORY_DID}}", with: repository).utf8
            )
        } else {
            materializedBody = putBody
        }
        guard jsonFields(materializedBody, equalTo: [
            "repo": repository,
            "collection": collection,
            "rkey": rkey,
        ]) else {
            return await artifact(
                scenario: scenario, producer: producer, consumer: consumer,
                putStatus: nil, readStatus: nil, putCID: nil, readCID: nil,
                putDigest: nil, readDigest: nil,
                converged: false,
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
        var blobResult = PublicBlobResult.notRequested
        var putRequestBody = materializedBody

        if let blobBody {
            blobResult = await uploadPublicBlob(
                producer: producer,
                body: blobBody,
                recorder: recorder
            )
            guard blobResult.errorCode == nil,
                  let blobCID = blobResult.cid,
                  let bodyText = String(data: materializedBody, encoding: .utf8),
                  bodyText.contains(blobCID) || bodyText.contains("{{BLOB_CID}}") else {
                return await artifact(
                    scenario: scenario, producer: producer, consumer: consumer,
                    putStatus: nil, readStatus: nil, putCID: nil, readCID: nil,
                    putDigest: nil, readDigest: nil, blobResult: blobResult,
                    converged: false,
                    errorCode: blobResult.errorCode ?? "BlobReferenceMissing",
                    recorder: recorder
                )
            }
            if bodyText.contains("{{BLOB_CID}}") {
                putRequestBody = Data(
                    bodyText.replacingOccurrences(of: "{{BLOB_CID}}", with: blobCID).utf8
                )
            }
        }

        do {
            let authorization = try await authorization(
                for: producer,
                method: .post,
                path: putPath,
                body: putRequestBody
            )
            let response = try await producer.client.procedure(
                "com.atproto.repo.putRecord",
                body: putRequestBody,
                authorization: authorization
            )
            putStatus = response.status
            putDigest = responseDigest(response)
            await recorder.record(
                host: producer.label,
                method: "POST",
                path: putPath,
                requestBody: putRequestBody,
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                errorCode = responseErrorCode(response)
                return await artifact(
                    scenario: scenario, producer: producer, consumer: consumer,
                    putStatus: putStatus, readStatus: nil, putCID: nil, readCID: nil,
                    putDigest: putDigest, readDigest: nil, blobResult: blobResult,
                    converged: false,
                    errorCode: errorCode, recorder: recorder
                )
            }
            putCID = canonicalRecordCID(from: response.body)
            guard putCID != nil else {
                errorCode = "InvalidResponse"
                return await artifact(
                    scenario: scenario, producer: producer, consumer: consumer,
                    putStatus: putStatus, readStatus: nil, putCID: nil, readCID: nil,
                    putDigest: putDigest, readDigest: nil, blobResult: blobResult,
                    converged: false,
                    errorCode: errorCode, recorder: recorder
                )
            }
        } catch {
            errorCode = liveErrorCode(error)
            return await artifact(
                scenario: scenario, producer: producer, consumer: consumer,
                putStatus: putStatus, readStatus: readStatus, putCID: nil, readCID: nil,
                putDigest: putDigest, readDigest: readDigest, blobResult: blobResult,
                converged: false,
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
                    putDigest: putDigest, readDigest: readDigest, blobResult: blobResult,
                    converged: false,
                    errorCode: errorCode, recorder: recorder
                )
            }
            readCID = canonicalRecordCID(from: response.body)
            if readCID == nil {
                errorCode = "InvalidResponse"
            }
        } catch {
            errorCode = liveErrorCode(error)
        }

        if let blobBody, let blobCID = blobResult.cid {
            blobResult = await downloadPublicBlob(
                consumer: consumer,
                repository: repository,
                cid: blobCID,
                expectedBody: blobBody,
                uploadStatus: blobResult.uploadStatus,
                recorder: recorder
            )
        }
        let converged = putCID != nil && putCID == readCID
            && blobResult.errorCode == nil
        return await artifact(
            scenario: scenario, producer: producer, consumer: consumer,
            putStatus: putStatus, readStatus: readStatus, putCID: putCID, readCID: readCID,
            putDigest: putDigest, readDigest: readDigest, blobResult: blobResult,
            converged: converged,
            errorCode: converged ? nil : (errorCode ?? blobResult.errorCode ?? "CommitmentMismatch"), recorder: recorder
        )
    }

    private static func uploadPublicBlob(
        producer: LiveInteropHost,
        body: Data,
        recorder: InteropFixtureRecorder
    ) async -> PublicBlobResult {
        let path = "/xrpc/com.atproto.repo.uploadBlob"
        do {
            let authorization = try await authorization(
                for: producer,
                method: .post,
                path: path,
                body: body
            )
            let response = try await producer.client.binaryProcedure(
                "com.atproto.repo.uploadBlob",
                body: body,
                contentType: "application/octet-stream",
                authorization: authorization
            )
            await recorder.record(
                host: producer.label,
                method: "POST",
                path: path,
                requestBody: body,
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return PublicBlobResult(
                    uploadStatus: response.status, downloadStatus: nil,
                    cid: nil, byteCount: nil, verified: false,
                    errorCode: responseErrorCode(response) ?? "HTTP\(response.status)"
                )
            }
            guard let cid = canonicalBlobCID(from: response.body) else {
                return PublicBlobResult(
                    uploadStatus: response.status, downloadStatus: nil,
                    cid: nil, byteCount: body.count, verified: false,
                    errorCode: "InvalidBlobResponse"
                )
            }
            guard cid == CID.fromBlob(body).string else {
                return PublicBlobResult(
                    uploadStatus: response.status, downloadStatus: nil,
                    cid: cid, byteCount: body.count, verified: false,
                    errorCode: "BlobCIDMismatch"
                )
            }
            return PublicBlobResult(
                uploadStatus: response.status, downloadStatus: nil,
                cid: cid, byteCount: body.count, verified: nil, errorCode: nil
            )
        } catch {
            return PublicBlobResult(
                uploadStatus: nil, downloadStatus: nil, cid: nil,
                byteCount: nil, verified: false, errorCode: liveErrorCode(error)
            )
        }
    }

    private static func uploadPermissionedBlob(
        member: LiveInteropHost,
        body: Data,
        recorder: InteropFixtureRecorder
    ) async -> PermissionedBlobResult {
        let path = "/xrpc/com.atproto.repo.uploadBlob"
        do {
            let authorization = try await authorization(
                for: member,
                method: .post,
                path: path,
                body: body
            )
            let response = try await member.client.binaryProcedure(
                "com.atproto.repo.uploadBlob",
                body: body,
                contentType: "application/octet-stream",
                authorization: authorization
            )
            await recorder.record(
                host: member.label,
                method: "POST",
                path: path,
                requestBody: body,
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return PermissionedBlobResult(
                    uploadStatus: response.status, downloadStatus: nil,
                    cid: nil, byteCount: nil, verified: false,
                    errorCode: responseErrorCode(response) ?? "HTTP\(response.status)"
                )
            }
            guard let cid = canonicalBlobCID(from: response.body) else {
                return PermissionedBlobResult(
                    uploadStatus: response.status, downloadStatus: nil,
                    cid: nil, byteCount: body.count, verified: false,
                    errorCode: "InvalidBlobResponse"
                )
            }
            guard cid == CID.fromBlob(body).string else {
                return PermissionedBlobResult(
                    uploadStatus: response.status, downloadStatus: nil,
                    cid: cid, byteCount: body.count, verified: false,
                    errorCode: "BlobCIDMismatch"
                )
            }
            return PermissionedBlobResult(
                uploadStatus: response.status, downloadStatus: nil,
                cid: cid, byteCount: body.count, verified: nil, errorCode: nil
            )
        } catch {
            return PermissionedBlobResult(
                uploadStatus: nil, downloadStatus: nil, cid: nil,
                byteCount: nil, verified: false, errorCode: liveErrorCode(error)
            )
        }
    }

    private static func downloadPermissionedBlob(
        repositoryHost: LiveInteropHost,
        space: SpaceURI,
        repository: String,
        cid: String,
        expectedBody: Data,
        uploadStatus: Int?,
        authorization: InteropAuthorization,
        recorder: InteropFixtureRecorder
    ) async -> PermissionedBlobResult {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "swan-permissioned-blob-\(UUID().uuidString).blob")
        defer { try? FileManager.default.removeItem(at: url) }
        do {
            let query = [
                "space": space.rawValue,
                "repo": repository,
                "cid": cid,
            ]
            let response = try await repositoryHost.client.stream(
                "com.atproto.space.getBlob",
                query: query,
                authorization: authorization,
                to: url,
                maximumResponseBytes: 256 * 1024 * 1024
            )
            await recorder.record(
                host: repositoryHost.label,
                method: "GET",
                path: "/xrpc/com.atproto.space.getBlob",
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return PermissionedBlobResult(
                    uploadStatus: uploadStatus, downloadStatus: response.status,
                    cid: cid, byteCount: nil, verified: false,
                    errorCode: responseErrorCode(response) ?? "HTTP\(response.status)"
                )
            }
            guard cid == CID.fromBlob(expectedBody).string else {
                return PermissionedBlobResult(
                    uploadStatus: uploadStatus, downloadStatus: response.status,
                    cid: cid, byteCount: nil, verified: false,
                    errorCode: "BlobCIDMismatch"
                )
            }
            let received = try fileDigest(url)
            let expectedDigest = Hex.encode(SHA256.hash(data: expectedBody))
            let verified = received.bytes == expectedBody.count
                && received.digest == expectedDigest
            return PermissionedBlobResult(
                uploadStatus: uploadStatus, downloadStatus: response.status,
                cid: cid, byteCount: received.bytes, verified: verified,
                errorCode: verified ? nil : "BlobMismatch"
            )
        } catch {
            return PermissionedBlobResult(
                uploadStatus: uploadStatus, downloadStatus: nil, cid: cid,
                byteCount: nil, verified: false, errorCode: liveErrorCode(error)
            )
        }
    }

    private static func downloadPublicBlob(
        consumer: LiveInteropHost,
        repository: String,
        cid: String,
        expectedBody: Data,
        uploadStatus: Int?,
        recorder: InteropFixtureRecorder
    ) async -> PublicBlobResult {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "swan-public-blob-\(UUID().uuidString).blob")
        defer { try? FileManager.default.removeItem(at: url) }
        do {
            let path = try consumer.client.xrpcPath(
                "com.atproto.sync.getBlob",
                query: ["did": repository, "cid": cid]
            )
            let authorization = try await authorization(
                for: consumer,
                method: .get,
                path: path,
                body: nil
            )
            let response = try await consumer.client.stream(
                "com.atproto.sync.getBlob",
                query: ["did": repository, "cid": cid],
                authorization: authorization,
                to: url,
                maximumResponseBytes: 256 * 1024 * 1024
            )
            await recorder.record(
                host: consumer.label,
                method: "GET",
                path: "/xrpc/com.atproto.sync.getBlob",
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return PublicBlobResult(
                    uploadStatus: uploadStatus, downloadStatus: response.status,
                    cid: cid, byteCount: nil, verified: false,
                    errorCode: "HTTP\(response.status)"
                )
            }
            guard cid == CID.fromBlob(expectedBody).string else {
                return PublicBlobResult(
                    uploadStatus: uploadStatus, downloadStatus: response.status,
                    cid: cid, byteCount: nil, verified: false,
                    errorCode: "BlobCIDMismatch"
                )
            }
            guard response.header("content-type")?.lowercased()
                .contains("application/octet-stream") == true else {
                return PublicBlobResult(
                    uploadStatus: uploadStatus, downloadStatus: response.status,
                    cid: cid, byteCount: nil, verified: false,
                    errorCode: "UnexpectedContentType"
                )
            }
            let received = try fileDigest(url)
            let expectedDigest = Hex.encode(SHA256.hash(data: expectedBody))
            let verified = received.bytes == expectedBody.count
                && received.digest == expectedDigest
            return PublicBlobResult(
                uploadStatus: uploadStatus, downloadStatus: response.status,
                cid: cid, byteCount: received.bytes, verified: verified,
                errorCode: verified ? nil : "BlobMismatch"
            )
        } catch {
            return PublicBlobResult(
                uploadStatus: uploadStatus, downloadStatus: nil, cid: cid,
                byteCount: nil, verified: false, errorCode: liveErrorCode(error)
            )
        }
    }

    private static func fileDigest(_ url: URL) throws -> (bytes: Int, digest: String) {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var digest = SHA256()
        var count = 0
        while let chunk = try handle.read(upToCount: 64 * 1_024), !chunk.isEmpty {
            count += chunk.count
            digest.update(data: chunk)
        }
        return (count, Hex.encode(Data(digest.finalize())))
    }

    /// Advances a member repository using exactly the pinned applyWrites
    /// request shape. This intentionally does not construct an authority host,
    /// mint a space credential, or read a record: recovery needs a source-side
    /// advancement while the receiver remains stale. A metadata-only query uses
    /// the same member OAuth/DPoP session for a signed terminal witness.
    public static func permissionedWriteOnlyApplyWrites(
        scenario: String,
        member: LiveInteropHost,
        space: SpaceURI,
        repository: String,
        body: Data,
        recorder: InteropFixtureRecorder? = nil
    ) async -> PermissionedWriteOnlyApplyWritesArtifact {
        let recorder = recorder ?? InteropFixtureRecorder()
        guard let operationCount = pinnedApplyWritesOperationCount(
            body,
            space: space,
            repository: repository
        ) else {
            return PermissionedWriteOnlyApplyWritesArtifact(
                scenario: scenario, applyStatus: nil, witnessStatus: nil, terminalRevision: nil,
                operationCount: nil, responseDigest: nil, status: "failed",
                errorCode: "InvalidRequest"
            )
        }

        let writePath = "/xrpc/com.atproto.space.applyWrites"
        do {
            let writeAuthorization = try await authorization(
                for: member, method: .post, path: writePath, body: body
            )
            let write = try await member.client.procedure(
                "com.atproto.space.applyWrites",
                body: body,
                authorization: writeAuthorization
            )
            let digest = responseDigest(write)
            await recorder.record(
                host: member.label, method: "POST", path: writePath,
                requestBody: body, response: write
            )
            guard (200 ... 299).contains(write.status) else {
                return PermissionedWriteOnlyApplyWritesArtifact(
                    scenario: scenario, applyStatus: write.status, witnessStatus: nil,
                    terminalRevision: nil, operationCount: operationCount,
                    responseDigest: digest, status: "failed",
                    errorCode: responseErrorCode(write) ?? "HTTP\(write.status)"
                )
            }
            let output = try StrictJSON.decode(
                ComAtprotoSpaceApplyWrites.Output.self,
                from: write.body
            )
            guard let expectedURIs = pinnedApplyWritesExpectedURIs(
                      body, space: space, repository: repository
                  ),
                  let resultCIDs = applyWritesResultCIDs(
                      output, expectedURIs: expectedURIs
                  ),
                  resultCIDs.count == operationCount else {
                return PermissionedWriteOnlyApplyWritesArtifact(
                    scenario: scenario, applyStatus: write.status, witnessStatus: nil,
                    terminalRevision: nil, operationCount: operationCount,
                    responseDigest: digest, status: "failed",
                    errorCode: "InvalidResponse"
                )
            }
            let witness = await verifyTerminalApplyWritesWitness(
                member: member,
                space: space,
                repository: repository,
                expectedResultCIDs: resultCIDs,
                recorder: recorder
            )
            return PermissionedWriteOnlyApplyWritesArtifact(
                scenario: scenario, applyStatus: write.status, witnessStatus: witness.status,
                terminalRevision: witness.revision,
                operationCount: operationCount, responseDigest: digest,
                status: witness.verified ? "passed" : "failed",
                errorCode: witness.errorCode
            )
        } catch {
            return PermissionedWriteOnlyApplyWritesArtifact(
                scenario: scenario, applyStatus: nil, witnessStatus: nil, terminalRevision: nil,
                operationCount: operationCount, responseDigest: nil,
                status: "failed", errorCode: liveErrorCode(error)
            )
        }
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
        blobBody: Data? = nil,
        readHost: LiveInteropHost? = nil,
        verifyIncrementalSync: Bool = false,
        includeIncrementalValues: Bool = true,
        verifyFullCAR: Bool = false,
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
        var syncResult = PermissionedSyncResult.notRequested
        var fullCARResult = PermissionedCARResult.notRequested
        var blobResult = PermissionedBlobResult.notRequested
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
            var writeBody = createBody
            if let blobBody {
                blobResult = await uploadPermissionedBlob(
                    member: member,
                    body: blobBody,
                    recorder: recorder
                )
                guard blobResult.errorCode == nil,
                      let blobCID = blobResult.cid,
                      let bodyText = String(data: createBody, encoding: .utf8),
                      bodyText.contains(blobCID) || bodyText.contains("{{BLOB_CID}}") else {
                    return await permissionedArtifact(
                        scenario: scenario, member: member, authority: authority,
                        credentialIssued: credentialIssued, writeStatus: nil,
                        readStatus: nil, writeCID: nil, readCID: nil,
                        writeDigest: nil, readDigest: nil,
                        blobResult: blobResult,
                        converged: false,
                        errorCode: blobResult.errorCode ?? "BlobReferenceMissing",
                        recorder: recorder
                    )
                }
                if bodyText.contains("{{BLOB_CID}}") {
                    writeBody = Data(
                        bodyText.replacingOccurrences(
                            of: "{{BLOB_CID}}", with: blobCID
                        ).utf8
                    )
                }
            }
            guard jsonFields(writeBody, equalTo: [
                "space": space.rawValue,
                "repo": readQuery["repo"] ?? "",
                "collection": readQuery["collection"] ?? "",
                "rkey": readQuery["rkey"] ?? "",
            ]) else {
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: nil,
                    readStatus: nil, writeCID: nil, readCID: nil,
                    writeDigest: nil, readDigest: nil,
                    blobResult: blobResult,
                    converged: false, errorCode: "InvalidRequest", recorder: recorder
                )
            }
            let memberWriteAuthorization = try await authorization(
                for: member,
                method: .post,
                path: writePath,
                body: writeBody
            )
            let write = try await member.client.procedure(
                "com.atproto.space.createRecord",
                body: writeBody,
                authorization: memberWriteAuthorization
            )
            writeStatus = write.status
            writeDigest = responseDigest(write)
            await recorder.record(
                host: member.label,
                method: "POST",
                path: writePath,
                requestBody: writeBody,
                response: write
            )
            guard (200 ... 299).contains(write.status) else {
                errorCode = responseErrorCode(write)
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: nil, writeCID: nil, readCID: nil,
                    writeDigest: writeDigest, readDigest: nil,
                    blobResult: blobResult,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            writeCID = canonicalRecordCID(from: write.body)
            guard writeCID != nil else {
                errorCode = "InvalidResponse"
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: nil, writeCID: nil, readCID: nil,
                    writeDigest: writeDigest, readDigest: nil,
                    blobResult: blobResult,
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
                    blobResult: blobResult,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            readCID = canonicalRecordCID(from: read.body)
            guard readCID != nil else {
                errorCode = "InvalidResponse"
                return await permissionedArtifact(
                    scenario: scenario, member: member, authority: authority,
                    credentialIssued: credentialIssued, writeStatus: writeStatus,
                    readStatus: readStatus, writeCID: writeCID, readCID: nil,
                    writeDigest: writeDigest, readDigest: readDigest,
                    blobResult: blobResult,
                    converged: false, errorCode: errorCode, recorder: recorder
                )
            }
            if let blobBody, let blobCID = blobResult.cid {
                blobResult = await downloadPermissionedBlob(
                    repositoryHost: repositoryHost,
                    space: space,
                    repository: readQuery["repo"] ?? "",
                    cid: blobCID,
                    expectedBody: blobBody,
                    uploadStatus: blobResult.uploadStatus,
                    authorization: credentialAuthorization,
                    recorder: recorder
                )
            }
            if verifyIncrementalSync {
                syncResult = await verifyPermissionedListRepoOps(
                    repositoryHost: repositoryHost,
                    space: space,
                    author: readQuery["repo"] ?? "",
                    expectedCID: writeCID,
                    authorization: credentialAuthorization,
                    includeValues: includeIncrementalValues,
                    recorder: recorder
                )
            }
            if verifyFullCAR {
                fullCARResult = await verifyPermissionedGetRepo(
                    repositoryHost: repositoryHost,
                    space: space,
                    author: readQuery["repo"] ?? "",
                    collection: readQuery["collection"],
                    rkey: readQuery["rkey"],
                    expectedCID: writeCID == readCID ? writeCID : nil,
                    authorization: credentialAuthorization,
                    recorder: recorder
                )
            }
            let converged = permissionedEvidenceConverged(
                writeCID: writeCID,
                readCID: readCID,
                verifyIncrementalSync: verifyIncrementalSync,
                syncResult: syncResult,
                verifyFullCAR: verifyFullCAR,
                fullCARResult: fullCARResult,
                blobRequested: blobBody != nil,
                blobResult: blobResult
            )
            let evidenceError = syncResult.errorCode
                ?? fullCARResult.errorCode
                ?? (converged ? nil : "EvidenceMismatch")
            return await permissionedArtifact(
                scenario: scenario, member: member, authority: authority,
                credentialIssued: credentialIssued, writeStatus: writeStatus,
                readStatus: readStatus, writeCID: writeCID, readCID: readCID,
                writeDigest: writeDigest, readDigest: readDigest,
                syncResult: syncResult,
                fullCARResult: fullCARResult,
                blobResult: blobResult,
                converged: converged,
                errorCode: evidenceError,
                recorder: recorder
            )
        } catch {
            errorCode = liveErrorCode(error)
            return await permissionedArtifact(
                scenario: scenario, member: member, authority: authority,
                credentialIssued: credentialIssued, writeStatus: writeStatus,
                readStatus: readStatus, writeCID: writeCID, readCID: readCID,
                writeDigest: writeDigest, readDigest: readDigest,
                syncResult: syncResult,
                fullCARResult: fullCARResult,
                blobResult: blobResult,
                converged: false, errorCode: errorCode, recorder: recorder
            )
        }
    }

    /// Performs a live, caller-bound full-CAR recovery into a receiver's
    /// durable per-account database. The source provider obtains the signed
    /// current-head witness and CAR from the configured host; the SQLite
    /// orchestrator verifies and publishes only an authenticated replacement.
    /// This is kept separate from the summary-only round-trip artifact so a
    /// caller must deliberately provide the receiver database and request
    /// identity rather than silently turning a read probe into an install.
    public static func recoverPermissionedRepository(
        target: PermissionedRemoteReplicaTarget,
        requestID: String,
        sourceHost: LiveInteropHost,
        receiverDatabase: SQLiteAccountDatabase,
        profileID: String = OfflineProtocolProfileVerifier.stableProfileID,
        expiresAt: Int64,
        temporaryDirectory: URL = FileManager.default.temporaryDirectory,
        spoolAdmission: PublicRepositorySpoolAdmission,
        limits: SpaceCARRecoveryLimits = .standard,
        sourceFault: PermissionedRemoteReplicaSourceFault = .none,
        publicationAuthorization:
            @escaping PermissionedRemoteReplicaRecoveryOrchestrator
            .PublicationAuthorization,
        now: @escaping @Sendable () -> Int64 = {
            Int64(Date().timeIntervalSince1970)
        }
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        let provider = try PermissionedRemoteReplicaHTTPSourceProvider(
            host: sourceHost,
            temporaryDirectory: temporaryDirectory,
            spoolAdmission: spoolAdmission,
            limits: limits,
            fault: sourceFault
        )
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: receiverDatabase,
            now: now,
            publicationAuthorization: publicationAuthorization
        )
        return try await orchestrator.recover(
            target: target,
            requestID: requestID,
            provider: provider,
            profileID: profileID,
            expiresAt: expiresAt,
            limits: limits
        )
    }

    private struct TerminalApplyWritesWitness: Sendable {
        let status: Int?
        let revision: String?
        let verified: Bool
        let errorCode: String?
    }

    /// Verifies the terminal context only. A retention-bounded listRepoOps
    /// response is deliberately not a complete LtHash witness, so this never
    /// recomputes a commitment from its truncated operation page.
    private static func verifyTerminalApplyWritesWitness(
        member: LiveInteropHost,
        space: SpaceURI,
        repository: String,
        expectedResultCIDs: [String],
        recorder: InteropFixtureRecorder
    ) async -> TerminalApplyWritesWitness {
        guard (try? DID(didString: repository)) != nil,
              !expectedResultCIDs.isEmpty,
              expectedResultCIDs.allSatisfy({ canonicalInteropCID($0, codec: .dagCBOR) != nil })
        else {
            return TerminalApplyWritesWitness(
                status: nil, revision: nil, verified: false,
                errorCode: "InvalidRequest"
            )
        }
        let query = [
            "excludeValues": "true",
            "limit": "100",
            "repo": repository,
            "space": space.rawValue,
        ]
        do {
            let path = try member.client.xrpcPath(
                "com.atproto.space.listRepoOps", query: query
            )
            let authorization = try await authorization(
                for: member, method: .get, path: path, body: nil
            )
            let response = try await member.client.query(
                "com.atproto.space.listRepoOps", query: query,
                authorization: authorization
            )
            await recorder.record(
                host: member.label, method: "GET",
                path: "/xrpc/com.atproto.space.listRepoOps", response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return TerminalApplyWritesWitness(
                    status: response.status, revision: nil, verified: false,
                    errorCode: responseErrorCode(response) ?? "HTTP\(response.status)"
                )
            }
            let output = try StrictJSON.decode(
                ComAtprotoSpaceListRepoOps.Output.self,
                from: response.body
            )
            guard !output.ops.isEmpty,
                  output.ops.allSatisfy({ $0.value == nil }),
                  let commit = output.commit,
                  commit.ver == 1,
                  commit.rev == output.ops.last?.rev,
                  canonicalInteropTID(commit.rev.toString()) != nil,
                  commit.hash.data.count == 32,
                  commit.ikm.data.count == 32,
                  commit.sig.data.count == 64,
                  commit.mac.data.count == 32 else {
                return TerminalApplyWritesWitness(
                    status: response.status, revision: nil, verified: false,
                    errorCode: "InvalidCommit"
                )
            }
            // Retention can discard the first create in a three-write batch.
            // The final two result CIDs must remain visible, which identifies
            // this terminal batch without claiming the page reconstructs state.
            let retainedResultCIDs = Set(expectedResultCIDs.suffix(2))
            let visibleCIDs = Set(output.ops.compactMap { $0.cid?.string })
            guard retainedResultCIDs.isSubset(of: visibleCIDs) else {
                return TerminalApplyWritesWitness(
                    status: response.status, revision: commit.rev.toString(), verified: false,
                    errorCode: "OperationMismatch"
                )
            }
            let context = try SpaceCommitContext(
                space: space, author: repository, rev: commit.rev.toString(), ikm: commit.ikm.data
            )
            let envelope = SpaceCommitEnvelope(
                ver: commit.ver, context: context, contextSignature: commit.sig.data,
                contentBinding: commit.mac.data, commitment: commit.hash.data
            )
            guard SpaceCommitCodec.verifyContentBinding(envelope) else {
                return TerminalApplyWritesWitness(
                    status: response.status, revision: commit.rev.toString(), verified: false,
                    errorCode: "ContentBindingMismatch"
                )
            }
            guard let key = member.permissionedCommitVerificationKey else {
                return TerminalApplyWritesWitness(
                    status: response.status, revision: commit.rev.toString(), verified: false,
                    errorCode: "MissingCommitKey"
                )
            }
            let algorithm: String = switch key {
            case .p256: "ES256"
            case .secp256k1PublicKey: "ES256K"
            }
            guard try key.verify(
                signature: commit.sig.data,
                signingInput: try SpaceCommitCodec.contextSigningBytes(context),
                algorithm: algorithm
            ) else {
                return TerminalApplyWritesWitness(
                    status: response.status, revision: commit.rev.toString(), verified: false,
                    errorCode: "ContextSignatureMismatch"
                )
            }
            return TerminalApplyWritesWitness(
                status: response.status, revision: commit.rev.toString(), verified: true,
                errorCode: nil
            )
        } catch {
            return TerminalApplyWritesWitness(
                status: nil, revision: nil, verified: false,
                errorCode: liveErrorCode(error)
            )
        }
    }

    private static func applyWritesResultCIDs(
        _ output: ComAtprotoSpaceApplyWrites.Output,
        expectedURIs: [String]
    ) -> [String]? {
        guard let results = output.results else { return nil }
        guard results.count == expectedURIs.count else { return nil }
        let cids = zip(results, expectedURIs).compactMap { result, expectedURI -> String? in
            switch result {
            case let .comAtprotoSpaceApplyWritesCreateResult(value):
                guard value.uri.uriString() == expectedURI else { return nil }
                return value.cid.string
            case .comAtprotoSpaceApplyWritesUpdateResult,
                 .comAtprotoSpaceApplyWritesDeleteResult:
                return nil
            case .unexpected:
                return nil
            }
        }
        guard cids.count == results.count,
              cids.allSatisfy({ canonicalInteropCID($0, codec: .dagCBOR) != nil }) else {
            return nil
        }
        return cids
    }

    private static func pinnedApplyWritesExpectedURIs(
        _ body: Data,
        space: SpaceURI,
        repository: String
    ) -> [String]? {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let writes = object["writes"] as? [[String: Any]],
              writes.allSatisfy({
                  ($0["collection"] as? String) != nil && ($0["rkey"] as? String) != nil
              }) else {
            return nil
        }
        return writes.compactMap { write in
            guard let collection = write["collection"] as? String,
                  let rkey = write["rkey"] as? String else { return nil }
            return "\(space.rawValue)/\(repository)/\(collection)/\(rkey)"
        }
    }

    /// Pure admission check shared by the CLI and live runner. StrictJSON
    /// rejects duplicate keys and hostile nesting before any OAuth secret is
    /// read; generated Input decoding pins the wire contract.
    public static func pinnedApplyWritesOperationCount(
        _ body: Data,
        space: SpaceURI,
        repository: String
    ) -> Int? {
        guard (1 ... 2 * 1024 * 1024).contains(body.count),
              (try? DID(didString: repository)) != nil,
              let decoded = try? StrictJSON.decode(
                  ComAtprotoSpaceApplyWrites.Input.self,
                  from: body
              ),
              decoded.space.uriString() == space.rawValue,
              decoded.repo.didString() == repository,
              decoded.writes.allSatisfy({
                  if case .comAtprotoSpaceApplyWritesCreate = $0 { return true }
                  return false
              }),
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              Set(object.keys) == ["space", "repo", "writes"],
              object["space"] as? String == space.rawValue,
              object["repo"] as? String == repository,
              let writes = object["writes"] as? [[String: Any]],
              (1 ... 100).contains(writes.count) else {
            return nil
        }
        let requiredWriteKeys: Set<String> = ["$type", "collection", "rkey", "value"]
        guard writes.allSatisfy({ write in
            Set(write.keys) == requiredWriteKeys
                && write["$type"] as? String == "com.atproto.space.applyWrites#create"
                && (try? NSID(nsidString: write["collection"] as? String ?? "")) != nil
                && (try? RecordKey(keyString: write["rkey"] as? String ?? "")) != nil
                && write["value"] is [String: Any]
        }) else {
            return nil
        }
        return writes.count
    }

    private static func verifyPermissionedListRepoOps(
        repositoryHost: LiveInteropHost,
        space: SpaceURI,
        author: String,
        expectedCID: String?,
        authorization: InteropAuthorization,
        includeValues: Bool,
        recorder: InteropFixtureRecorder
    ) async -> PermissionedSyncResult {
        guard let expectedCID else {
            return PermissionedSyncResult(
                status: nil, opsCount: nil, operationCID: nil,
                operationRevision: nil, commitment: nil, commitRevision: nil,
                commitVerified: false, valuesIncluded: includeValues,
                errorCode: "InvalidResponse"
            )
        }
        var query: [String: String] = [
            "space": space.rawValue,
            "repo": author,
            // The pinned TypeScript implementation emits its signed commit
            // on a short terminal page. A fresh disposable repo is below this
            // bound, so the response is also a complete hash witness.
            "limit": "100",
        ]
        if !includeValues {
            query["excludeValues"] = "true"
        }
        do {
            let response = try await repositoryHost.client.query(
                "com.atproto.space.listRepoOps",
                query: query,
                authorization: authorization
            )
            await recorder.record(
                host: repositoryHost.label,
                method: "GET",
                path: "/xrpc/com.atproto.space.listRepoOps",
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: nil, operationCID: nil,
                    operationRevision: nil, commitment: nil, commitRevision: nil,
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: responseErrorCode(response) ?? "HTTP\(response.status)"
                )
            }
            let output = try StrictJSON.decode(
                ComAtprotoSpaceListRepoOps.Output.self,
                from: response.body
            )
            guard output.cursor == nil,
                  !output.ops.isEmpty,
                  case let operationRevisions = output.ops.map(\.rev),
                  zip(operationRevisions, operationRevisions.dropFirst()).allSatisfy({
                      $0.0 <= $0.1
                  }) else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: output.ops.first?.cid?.string,
                    operationRevision: output.ops.first?.rev.toString(),
                    commitment: nil, commitRevision: output.commit?.rev.toString(),
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "InvalidOperation"
                )
            }
            let operation = output.ops.first(where: { $0.cid?.string == expectedCID })
            guard let operation else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: output.ops.first?.cid?.string,
                    operationRevision: output.ops.first?.rev.toString(),
                    commitment: nil, commitRevision: nil,
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "OperationMismatch"
                )
            }
            guard let commit = output.commit else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: operation.cid?.string,
                    operationRevision: operation.rev.toString(),
                    commitment: nil, commitRevision: nil,
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "CommitMissing"
                )
            }
            guard commit.ver == 1,
                  commit.rev == output.ops.last?.rev,
                  commit.hash.data.count == 32,
                  commit.ikm.data.count == 32,
                  commit.sig.data.count == 64,
                  commit.mac.data.count == 32 else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: operation.cid?.string,
                    operationRevision: operation.rev.toString(),
                    commitment: nil, commitRevision: commit.rev.toString(),
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "InvalidCommit"
                )
            }
            var lthash = LtHash()
            for entry in output.ops {
                if let value = entry.value {
                    guard let cid = entry.cid,
                          let canonicalValue = try? canonicalInteropRecordValue(value),
                          CID.fromDAGCBOR(canonicalValue) == cid else {
                        return PermissionedSyncResult(
                            status: response.status, opsCount: output.ops.count,
                            operationCID: operation.cid?.string,
                            operationRevision: operation.rev.toString(),
                            commitment: nil, commitRevision: commit.rev.toString(),
                            commitVerified: false, valuesIncluded: includeValues,
                            errorCode: "ValueCIDMismatch"
                        )
                    }
                } else if includeValues, entry.cid != nil {
                    return PermissionedSyncResult(
                        status: response.status, opsCount: output.ops.count,
                        operationCID: operation.cid?.string,
                        operationRevision: operation.rev.toString(),
                        commitment: nil, commitRevision: commit.rev.toString(),
                        commitVerified: false, valuesIncluded: includeValues,
                        errorCode: "ValueMissing"
                    )
                }
                guard let cid = entry.cid?.string else {
                    guard entry.value == nil else {
                        return PermissionedSyncResult(
                            status: response.status, opsCount: output.ops.count,
                            operationCID: operation.cid?.string,
                            operationRevision: operation.rev.toString(),
                            commitment: nil, commitRevision: commit.rev.toString(),
                            commitVerified: false, valuesIncluded: includeValues,
                            errorCode: "InvalidOperation"
                        )
                    }
                    guard let previous = entry.prev?.string else {
                        return PermissionedSyncResult(
                            status: response.status, opsCount: output.ops.count,
                            operationCID: operation.cid?.string,
                            operationRevision: operation.rev.toString(),
                            commitment: nil, commitRevision: commit.rev.toString(),
                            commitVerified: false, valuesIncluded: includeValues,
                            errorCode: "InvalidOperation"
                        )
                    }
                    lthash.remove(element: "\(entry.collection)/\(entry.rkey)/\(previous)")
                    continue
                }
                if let previous = entry.prev?.string {
                    lthash.remove(element: "\(entry.collection)/\(entry.rkey)/\(previous)")
                }
                lthash.add(element: "\(entry.collection)/\(entry.rkey)/\(cid)")
            }
            guard lthash.commitment == commit.hash.data else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: operation.cid?.string,
                    operationRevision: operation.rev.toString(),
                    commitment: Hex.encode(commit.hash.data), commitRevision: commit.rev.toString(),
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "CommitmentMismatch"
                )
            }
            let context = try SpaceCommitContext(
                space: space,
                author: author,
                rev: commit.rev.toString(),
                ikm: commit.ikm.data
            )
            let envelope = SpaceCommitEnvelope(
                ver: commit.ver,
                context: context,
                contextSignature: commit.sig.data,
                contentBinding: commit.mac.data,
                commitment: commit.hash.data
            )
            guard SpaceCommitCodec.verifyContentBinding(envelope) else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: operation.cid?.string,
                    operationRevision: operation.rev.toString(),
                    commitment: Hex.encode(commit.hash.data), commitRevision: commit.rev.toString(),
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "ContentBindingMismatch"
                )
            }
            guard let key = repositoryHost.permissionedCommitVerificationKey else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: operation.cid?.string,
                    operationRevision: operation.rev.toString(),
                    commitment: Hex.encode(commit.hash.data), commitRevision: commit.rev.toString(),
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "MissingCommitKey"
                )
            }
            let algorithm: String = switch key {
            case .p256: "ES256"
            case .secp256k1PublicKey: "ES256K"
            }
            guard try key.verify(
                signature: commit.sig.data,
                signingInput: try SpaceCommitCodec.contextSigningBytes(context),
                algorithm: algorithm
            ) else {
                return PermissionedSyncResult(
                    status: response.status, opsCount: output.ops.count,
                    operationCID: operation.cid?.string,
                    operationRevision: operation.rev.toString(),
                    commitment: Hex.encode(commit.hash.data), commitRevision: commit.rev.toString(),
                    commitVerified: false, valuesIncluded: includeValues,
                    errorCode: "ContextSignatureMismatch"
                )
            }
            return PermissionedSyncResult(
                status: response.status, opsCount: output.ops.count,
                operationCID: operation.cid?.string,
                operationRevision: operation.rev.toString(),
                commitment: Hex.encode(commit.hash.data), commitRevision: commit.rev.toString(),
                commitVerified: true, valuesIncluded: includeValues, errorCode: nil
            )
        } catch {
            return PermissionedSyncResult(
                status: nil, opsCount: nil, operationCID: nil,
                operationRevision: nil, commitment: nil, commitRevision: nil,
                commitVerified: false, valuesIncluded: includeValues,
                errorCode: liveErrorCode(error)
            )
        }
    }

    private static func verifyPermissionedGetRepo(
        repositoryHost: LiveInteropHost,
        space: SpaceURI,
        author: String,
        collection: String?,
        rkey: String?,
        expectedCID: String?,
        authorization: InteropAuthorization,
        recorder: InteropFixtureRecorder
    ) async -> PermissionedCARResult {
        guard let collection,
              let rkey,
              let expectedCID,
              let parsedCID = try? CID.parse(expectedCID),
              let recordURI = try? SpaceRecordURI(
                  space: space,
                  author: author,
                  collection: collection,
                  rkey: rkey
              )
        else {
            return PermissionedCARResult(
                status: nil, recordCount: nil, commitment: nil,
                wireRevision: nil, expectedRecordVerified: false,
                verified: false, errorCode: "InvalidExpectedRecord"
            )
        }
        let expectedEntry = SpaceCARRecoveryIndexEntry(
            path: "\(recordURI.collection)/\(recordURI.rkey)",
            cid: parsedCID
        )
        guard let key = repositoryHost.permissionedCommitVerificationKey else {
            return PermissionedCARResult(
                status: nil, recordCount: nil, commitment: nil,
                wireRevision: nil, expectedRecordVerified: false,
                verified: false, errorCode: "MissingCommitKey"
            )
        }
        let spoolURL = FileManager.default.temporaryDirectory
            .appending(path: "swan-permissioned-recovery-\(UUID().uuidString).car")
        defer { try? FileManager.default.removeItem(at: spoolURL) }
        do {
            let response = try await repositoryHost.client.stream(
                "com.atproto.space.getRepo",
                query: ["space": space.rawValue, "repo": author],
                authorization: authorization,
                to: spoolURL,
                maximumResponseBytes: 256 * 1024 * 1024
            )
            await recorder.record(
                host: repositoryHost.label,
                method: "GET",
                path: "/xrpc/com.atproto.space.getRepo",
                response: response
            )
            guard (200 ... 299).contains(response.status) else {
                return PermissionedCARResult(
                    status: response.status, recordCount: nil, commitment: nil,
                    wireRevision: nil, expectedRecordVerified: false,
                    verified: false, errorCode: responseErrorCode(response) ?? "HTTP\(response.status)"
                )
            }
            guard response.header("content-type")?.lowercased()
                .contains("application/vnd.ipld.car") == true else {
                return PermissionedCARResult(
                    status: response.status, recordCount: nil, commitment: nil,
                    wireRevision: nil, expectedRecordVerified: false,
                    verified: false, errorCode: "UnexpectedContentType"
                )
            }
            let recovery = try await SwanCARConsumer().verifyStreaming(
                fileURL: spoolURL,
                space: space,
                author: author,
                verificationKey: key,
                expectedEntries: [expectedEntry]
            )
            return PermissionedCARResult(
                status: response.status,
                recordCount: recovery.recordCount,
                commitment: Hex.encode(recovery.commitment),
                wireRevision: recovery.wireRevision.toString(),
                expectedRecordVerified:
                    recovery.verifiedExpectedWitnessCount == 1,
                verified: true,
                errorCode: nil
            )
        } catch {
            return PermissionedCARResult(
                status: nil, recordCount: nil, commitment: nil,
                wireRevision: nil, expectedRecordVerified: false,
                verified: false, errorCode: liveErrorCode(error)
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
        blobResult: PublicBlobResult = .notRequested,
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
            blobUploadStatus: blobResult.uploadStatus,
            blobDownloadStatus: blobResult.downloadStatus,
            blobCID: blobResult.cid,
            blobBytes: blobResult.byteCount,
            blobVerified: blobResult.verified,
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
        syncResult: PermissionedSyncResult = .notRequested,
        fullCARResult: PermissionedCARResult = .notRequested,
        blobResult: PermissionedBlobResult = .notRequested,
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
            syncStatus: syncResult.status,
            syncOpsCount: syncResult.opsCount,
            syncOperationCID: syncResult.operationCID,
            syncOperationRevision: syncResult.operationRevision,
            syncCommitment: syncResult.commitment,
            syncCommitRevision: syncResult.commitRevision,
            syncCommitVerified: syncResult.commitVerified,
            syncValuesIncluded: syncResult.valuesIncluded,
            fullCARStatus: fullCARResult.status,
            fullCARRecordCount: fullCARResult.recordCount,
            fullCARCommitment: fullCARResult.commitment,
            fullCARWireRevision: fullCARResult.wireRevision,
            fullCARExpectedRecordVerified:
                fullCARResult.expectedRecordVerified,
            fullCARVerified: fullCARResult.verified,
            blobUploadStatus: blobResult.uploadStatus,
            blobDownloadStatus: blobResult.downloadStatus,
            blobCID: blobResult.cid,
            blobBytes: blobResult.byteCount,
            blobVerified: blobResult.verified,
            converged: converged,
            status: converged ? "passed" : "failed",
            errorCode: errorCode,
            events: await recorder.snapshot()
        )
    }

    /// Computes the permissioned result from semantic evidence, not endpoint
    /// reachability. A recurrent LtHash commitment is insufficient when both
    /// synchronization forms are requested: their signed terminal TIDs must
    /// identify the exact same repository state.
    private static func permissionedEvidenceConverged(
        writeCID: String?,
        readCID: String?,
        verifyIncrementalSync: Bool,
        syncResult: PermissionedSyncResult,
        verifyFullCAR: Bool,
        fullCARResult: PermissionedCARResult,
        blobRequested: Bool,
        blobResult: PermissionedBlobResult
    ) -> Bool {
        guard let writeCID, writeCID == readCID else { return false }

        if verifyIncrementalSync {
            guard syncResult.status.map({ (200 ... 299).contains($0) }) == true,
                  (syncResult.opsCount ?? 0) > 0,
                  syncResult.operationCID == writeCID,
                  canonicalInteropTID(syncResult.commitRevision) != nil,
                  !(syncResult.commitment?.isEmpty ?? true),
                  syncResult.commitVerified == true,
                  syncResult.errorCode == nil
            else {
                return false
            }
        }

        if verifyFullCAR {
            guard fullCARResult.status.map({ (200 ... 299).contains($0) }) == true,
                  (fullCARResult.recordCount ?? 0) > 0,
                  !(fullCARResult.commitment?.isEmpty ?? true),
                  canonicalInteropTID(fullCARResult.wireRevision) != nil,
                  fullCARResult.expectedRecordVerified == true,
                  fullCARResult.verified == true,
                  fullCARResult.errorCode == nil
            else {
                return false
            }
        }

        if verifyIncrementalSync, verifyFullCAR {
            guard syncResult.commitment == fullCARResult.commitment,
                  canonicalInteropTID(syncResult.commitRevision)
                    == canonicalInteropTID(fullCARResult.wireRevision)
            else {
                return false
            }
        }

        if blobRequested {
            guard blobResult.uploadStatus.map({ (200 ... 299).contains($0) }) == true,
                  blobResult.downloadStatus.map({ (200 ... 299).contains($0) }) == true,
                  blobResult.verified == true,
                  (blobResult.byteCount ?? 0) > 0,
                  blobResult.errorCode == nil else {
                return false
            }
        }

        return true
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

private func canonicalInteropRecordValue(_ record: ATProtocolValueContainer) throws -> Data {
    let cborValue = try record.toCBORValue()
    guard cborValue is OrderedCBORMap || cborValue is [String: Any] else {
        throw SwanError.malformed("incremental record value is not a map")
    }
    let bytes = try DAGCBOR.encodeValue(cborValue)
    _ = try CARRepository.decodeRecordCBOR(bytes)
    return bytes
}

private func responseErrorCode(_ response: InteropHTTPResponse) -> String? {
    guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
        return nil
    }
    return (object["error"] as? String).map(FixtureSanitizer.errorCode)
}

/// Returns only the canonical lowercase base32 spelling for the expected
/// content class. `CID.parse` intentionally accepts uppercase base32 input;
/// fixture and request boundaries must not.
private func canonicalInteropCID(
    _ rawValue: String?,
    codec: CIDCodec
) -> String? {
    guard let rawValue,
          rawValue.utf8.count <= 100,
          let cid = try? CID.parse(rawValue),
          cid.codec == codec,
          cid.string == rawValue else {
        return nil
    }
    return cid.string
}

/// Returns only the canonical fixed-alphabet TID spelling. Artifacts never
/// retain arbitrary peer-provided revision text.
private func canonicalInteropTID(_ rawValue: String?) -> String? {
    guard let rawValue,
          let tid = try? TID(tidString: rawValue)
    else {
        return nil
    }
    return tid.toString()
}

private func liveErrorCode(_ error: Error) -> String {
    if let error = error as? SpaceCARStreamingError {
        // Keep CAR failures actionable in sanitized lab artifacts without
        // exposing the response body, record values, or peer-selected paths.
        return spaceCARStreamingErrorCode(error)
    }
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

private func spaceCARStreamingErrorCode(_ error: SpaceCARStreamingError) -> String {
    switch error {
    case .invalidLimits: return "CARInvalidLimits"
    case .invalidChunk: return "CARInvalidChunk"
    case .byteLimitExceeded: return "CARByteLimitExceeded"
    case .malformedVarint: return "CARMalformedVarint"
    case .nonCanonicalVarint: return "CARNonCanonicalVarint"
    case .malformedHeader: return "CARMalformedHeader"
    case .invalidRootCount: return "CARInvalidRootCount"
    case .unsupportedVersion: return "CARUnsupportedVersion"
    case .malformedFrame: return "CARMalformedFrame"
    case .invalidCID: return "CARInvalidCID"
    case .blockCIDMismatch: return "CARBlockCIDMismatch"
    case .commitBodyLimitExceeded: return "CARCommitBodyLimitExceeded"
    case .recordBodyLimitExceeded: return "CARRecordBodyLimitExceeded"
    case .commitDidNotVerify: return "CARCommitDidNotVerify"
    case .malformedIndex: return "CARMalformedIndex"
    case .nonCanonicalIndex: return "CARNonCanonicalIndex"
    case .duplicateIndexEntry: return "CARDuplicateIndexEntry"
    case .indexEntryLimitExceeded: return "CARIndexEntryLimitExceeded"
    case .uniqueBlockLimitExceeded: return "CARUniqueBlockLimitExceeded"
    case .invalidRecordOrder: return "CARInvalidRecordOrder"
    case .invalidRecordValue: return "CARInvalidRecordValue"
    case .unindexedBlocks: return "CARUnindexedBlocks"
    case .invalidExpectedWitness: return "CARInvalidExpectedWitness"
    case .expectedWitnessMismatch: return "CARExpectedWitnessMismatch"
    case .commitmentMismatch: return "CARCommitmentMismatch"
    case .stagingUnavailable: return "CARStagingUnavailable"
    }
}

private extension InteropHTTPResponse {
    var bodyErrorCode: String? {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return nil
        }
        return (object["error"] as? String).map(FixtureSanitizer.errorCode)
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
        case invalidWireRevision
        case terminalRevisionMismatch
    }

    private let space: SpaceURI
    private let author: String
    private var records: [SpaceRecordURI: SpaceRecord] = [:]
    private var revision: UInt64 = 0
    private var ltHash = LtHash()

    private struct PreparedState {
        let records: [SpaceRecordURI: SpaceRecord]
        let revision: UInt64
        let ltHash: LtHash
    }

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
        let prepared = try prepare(entries)
        install(prepared)
        return state()
    }

    /// Applies a page only after its reader-specific terminal envelope has
    /// verified against the candidate state. Keeping preparation and install
    /// in one actor turn prevents a bad terminal commit from advancing the
    /// last-good replica before verification fails.
    public func applyAndVerify(
        _ entries: [InteropRepositoryOperation],
        terminalCommit: SpaceCommitEnvelope,
        publicKey: P256.Signing.PublicKey
    ) throws -> State {
        let prepared = try prepare(entries)
        guard let first = entries.first, let last = entries.last,
              terminalCommit.context.space == first.uri.space,
              terminalCommit.context.author == first.uri.author,
              terminalCommit.context.rev == last.wireRevision else {
            throw Error.terminalRevisionMismatch
        }
        guard try SpaceCommitCodec.verifyContextSignature(terminalCommit, publicKey: publicKey),
              SpaceCommitCodec.verifyContentBinding(terminalCommit),
              terminalCommit.commitment == prepared.ltHash.commitment else {
            throw Error.commitmentMismatch
        }
        install(prepared)
        return state()
    }

    private func prepare(_ entries: [InteropRepositoryOperation]) throws -> PreparedState {
        guard !entries.isEmpty else { throw Error.emptyOperation }
        var nextRecords = records
        var nextRevision = revision
        var nextHash = ltHash
        for entry in entries {
            guard entry.uri.space == space, entry.uri.author == author else { throw Error.wrongRepository }
            guard (try? TID(tidString: entry.wireRevision)) != nil else {
                throw Error.invalidWireRevision
            }
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
        return PreparedState(records: nextRecords, revision: nextRevision, ltHash: nextHash)
    }

    private func install(_ prepared: PreparedState) {
        records = prepared.records
        revision = prepared.revision
        ltHash = prepared.ltHash
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
    public let wireRevision: String
    public let uri: SpaceRecordURI
    public let cid: String
    public let value: Data?
    public let commitment: Data

    public init(
        revision: UInt64,
        wireRevision: String,
        uri: SpaceRecordURI,
        cid: String,
        value: Data?,
        commitment: Data
    ) {
        self.revision = revision
        self.wireRevision = wireRevision
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
        try await replica.applyAndVerify(
            entries,
            terminalCommit: terminalCommit,
            publicKey: publicKey
        )
    }
}

/// Consumes a Swan two-root CAR. Live interop uses the asynchronous streaming
/// methods, which retain at most one one-MiB record value and a 64-KiB source
/// chunk while the DRISL map lives in an owner-only disposable SQLite index.
/// The synchronous methods remain for small/offline fixtures that need record
/// values and are explicitly bounded by `maximumBytes`.
public struct SwanCARConsumer: Sendable {
    public let maximumBytes: Int
    public let maximumRecordBytes: Int
    private let stagingDirectory: URL

    public init(
        maximumBytes: Int = 256 * 1024 * 1024,
        maximumRecordBytes: Int = 1 * 1_024 * 1_024,
        stagingDirectory: URL = FileManager.default.temporaryDirectory
    ) throws {
        guard (1 ... SpaceCARRecoveryLimits.absoluteMaximumCARBytes)
            .contains(maximumBytes),
            (1 ... SpaceCARRecoveryLimits.absoluteMaximumRecordBytes)
                .contains(maximumRecordBytes)
        else {
            throw SwanError.malformed("CAR consumer bound is invalid")
        }
        self.maximumBytes = maximumBytes
        self.maximumRecordBytes = maximumRecordBytes
        self.stagingDirectory = stagingDirectory
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

    public func verify(
        fileURL: URL,
        space: SpaceURI,
        author: String,
        verificationKey: PermissionedDataJWTVerificationKey
    ) throws -> VerifiedSpaceCARRecovery {
        let data = try boundedFileData(fileURL)
        let algorithm: String = switch verificationKey {
        case .p256: "ES256"
        case .secp256k1PublicKey: "ES256K"
        }
        return try SpaceCARCodec.verifyRecovery(
            data,
            space: space,
            author: author,
            contextSignatureVerifier: { envelope in
                try verificationKey.verify(
                    signature: envelope.contextSignature,
                    signingInput: try SpaceCommitCodec.contextSigningBytes(envelope.context),
                    algorithm: algorithm
                )
            }
        )
    }

    public func verifyStreaming(
        fileURL: URL,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey,
        expectedEntries: [SpaceCARRecoveryIndexEntry] = []
    ) async throws -> VerifiedStreamingSpaceCARRecovery {
        try await verifyStreaming(
            fileURL: fileURL,
            space: space,
            author: author,
            expectedEntries: expectedEntries,
            contextSignatureVerifier: {
                try SpaceCommitCodec.verifyContextSignature(
                    $0,
                    publicKey: publicKey
                )
            }
        )
    }

    public func verifyStreaming(
        fileURL: URL,
        space: SpaceURI,
        author: String,
        verificationKey: PermissionedDataJWTVerificationKey,
        expectedEntries: [SpaceCARRecoveryIndexEntry] = []
    ) async throws -> VerifiedStreamingSpaceCARRecovery {
        let algorithm: String = switch verificationKey {
        case .p256: "ES256"
        case .secp256k1PublicKey: "ES256K"
        }
        return try await verifyStreaming(
            fileURL: fileURL,
            space: space,
            author: author,
            expectedEntries: expectedEntries,
            contextSignatureVerifier: { envelope in
                try verificationKey.verify(
                    signature: envelope.contextSignature,
                    signingInput: try SpaceCommitCodec.contextSigningBytes(
                        envelope.context
                    ),
                    algorithm: algorithm
                )
            }
        )
    }

    public func streamAndVerify(
        client: InteropXRPCClient,
        query: [String: String],
        authorization: InteropAuthorization,
        space: SpaceURI,
        author: String,
        publicKey: P256.Signing.PublicKey,
        spoolURL: URL,
        expectedEntries: [SpaceCARRecoveryIndexEntry] = []
    ) async throws -> VerifiedStreamingSpaceCARRecovery {
        defer { try? FileManager.default.removeItem(at: spoolURL) }
        _ = try await client.stream(
            "com.atproto.space.getRepo",
            query: query,
            authorization: authorization,
            to: spoolURL,
            maximumResponseBytes: maximumBytes
        )
        return try await verifyStreaming(
            fileURL: spoolURL,
            space: space,
            author: author,
            publicKey: publicKey,
            expectedEntries: expectedEntries
        )
    }

    private func verifyStreaming(
        fileURL: URL,
        space: SpaceURI,
        author: String,
        expectedEntries: [SpaceCARRecoveryIndexEntry],
        contextSignatureVerifier: @escaping @Sendable (
            SpaceCommitEnvelope
        ) throws -> Bool
    ) async throws -> VerifiedStreamingSpaceCARRecovery {
        let source: FileSpaceCARRecoverySource
        do {
            source = try FileSpaceCARRecoverySource(fileURL: fileURL)
        } catch {
            throw InteropHTTPError.fileFailure
        }
        let index: SQLiteSpaceCARRecoveryIndex
        do {
            index = try await SQLiteSpaceCARRecoveryIndex.create(
                temporaryParentURL: stagingDirectory
            )
        } catch {
            await source.close()
            throw error
        }
        do {
            let result = try await SpaceCARCodec.verifyStreamingRecovery(
                from: source,
                space: space,
                author: author,
                contextSignatureVerifier: contextSignatureVerifier,
                index: index,
                expectedEntries: expectedEntries,
                limits: try SpaceCARRecoveryLimits(
                    maximumCARBytes: maximumBytes,
                    maximumRecordBytes: maximumRecordBytes
                )
            )
            await source.close()
            await index.cleanup()
            return result
        } catch {
            await source.close()
            await index.cleanup()
            throw error
        }
    }

    private func boundedFileData(_ url: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber,
              size.intValue <= maximumBytes else {
            throw InteropHTTPError.responseTooLarge
        }
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            throw InteropHTTPError.fileFailure
        }
        defer { try? handle.close() }
        var output = Data()
        output.reserveCapacity(size.intValue)
        do {
            while let chunk = try handle.read(
                upToCount: SpaceCARRecoveryLimits.maximumChunkBytes
            ), !chunk.isEmpty {
                guard chunk.count <= maximumBytes - output.count else {
                    throw InteropHTTPError.responseTooLarge
                }
                output.append(chunk)
            }
        } catch let error as InteropHTTPError {
            throw error
        } catch {
            throw InteropHTTPError.fileFailure
        }
        return output
    }
}

private actor FileSpaceCARRecoverySource: SpaceCARRecoveryByteSource {
    private var handle: FileHandle?

    init(fileURL: URL) throws {
        handle = try FileHandle(forReadingFrom: fileURL)
    }

    func read(maximumBytes: Int) throws -> Data? {
        guard let handle else {
            throw InteropHTTPError.fileFailure
        }
        return try handle.read(upToCount: maximumBytes)
    }

    func close() {
        guard let handle else { return }
        self.handle = nil
        try? handle.close()
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
        let queryItems = components.queryItems ?? []
        let names = Set(queryItems.map(\.name)).sorted()
        components.query = nil
        let path = components.path
        // Fixture events are XRPC probe summaries, never a record of a local
        // resource.  Reject arbitrary paths so an owner-only file path cannot
        // become an artifact merely because a caller supplied it as `path`.
        guard path.hasPrefix("/xrpc/"),
              path.dropFirst("/xrpc/".count).allSatisfy({
                  $0.isLetter || $0.isNumber || $0 == "." || $0 == "-"
              }) else {
            return "<invalid-path>"
        }
        if queryItems.count == 1,
           queryItems[0].name == "keys",
           let summarizedKeys = queryItems[0].value,
           (1 ... 256).contains(summarizedKeys.utf8.count),
           summarizedKeys.allSatisfy({
               $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == ","
           }) {
            return path + "?keys=" + summarizedKeys
        }
        guard !names.isEmpty else { return path }
        return path + "?keys=" + names.joined(separator: ",")
    }
}
