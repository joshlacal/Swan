import Foundation
import Hummingbird
import Logging
import NIOCore
import SwanAccounts
import SwanCore
import SwanStorage

/// The only literal listener addresses permitted for Swan's alpha operator
/// surface. Host names, wildcard addresses, reverse proxies, and Unix sockets
/// deliberately have no representation here.
public enum SwanManagementBindAddress: String, Sendable, Equatable {
    case ipv4Loopback = "127.0.0.1"
    case ipv6Loopback = "::1"
}

public enum SwanManagementHTTPConfigurationError: Error, Sendable, Equatable {
    case invalidBindAddress
    case invalidPort
}

/// Configuration for the *separate* loopback management application. This is
/// not a prefix or middleware on Swan's public router.
public struct SwanManagementHTTPConfiguration: Sendable, Equatable {
    public let bindAddress: SwanManagementBindAddress
    public let port: Int

    public init(bindAddress: SwanManagementBindAddress, port: Int) throws {
        guard (1 ... 65_535).contains(port) else {
            throw SwanManagementHTTPConfigurationError.invalidPort
        }
        self.bindAddress = bindAddress
        self.port = port
    }

    /// This explicit literal parser is used by `swan serve`; accepting a
    /// `String` without this validation would make it too easy to accidentally
    /// bind an operator credential listener to a public interface.
    public init(bindAddressLiteral: String, port: Int) throws {
        guard let bindAddress = SwanManagementBindAddress(rawValue: bindAddressLiteral) else {
            throw SwanManagementHTTPConfigurationError.invalidBindAddress
        }
        try self.init(bindAddress: bindAddress, port: port)
    }
}

/// Captures the actual peer socket address before routing. It never reads
/// forwarded/host headers, so a reverse proxy cannot assert loopback identity.
public struct SwanManagementRequestContext: RequestContext, RemoteAddressRequestContext {
    public var coreContext: CoreRequestContextStorage
    public let remoteAddress: SocketAddress?

    public init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
        remoteAddress = source.channel.remoteAddress
    }

    public var maxUploadSize: Int { SwanManagementHTTPServer.maximumJSONBytes }
}

/// Defense-in-depth peer verification for an already loopback-bound listener.
/// An unavailable address fails closed so direct-router tests cannot accidentally
/// stand in for a real local TCP peer.
public enum SwanManagementPeerPolicy {
    public static func permits(_ remoteAddress: SocketAddress?) -> Bool {
        switch remoteAddress?.ipAddress {
        case "127.0.0.1", "::1": true
        default: false
        }
    }
}

/// A narrow authenticated operator API. It uses `AccountOperatorService` and
/// `AccountControlStore` exclusively; no raw control.sqlite tables or account
/// private material are exposed here.
public struct SwanManagementHTTPServer: Sendable {
    public static let maximumJSONBytes = 8 * 1024

    public let configuration: SwanManagementHTTPConfiguration
    private let accounts: AccountOperatorService
    private let operatorSecretVerifier: OperatorSecretVerifier

    public init(
        configuration: SwanManagementHTTPConfiguration,
        controlStore: any AccountControlStore,
        operatorSecretVerifier: OperatorSecretVerifier
    ) {
        self.configuration = configuration
        accounts = AccountOperatorService(store: controlStore)
        self.operatorSecretVerifier = operatorSecretVerifier
    }

    /// The management router has its own request context and is never merged
    /// into `SwanHTTPServer.buildRouter()`.
    public func buildRouter() -> Router<SwanManagementRequestContext> {
        let router = Router(context: SwanManagementRequestContext.self)
        let accounts = accounts
        let verifier = operatorSecretVerifier

        router.get("/v1/accounts") { request, context async -> Response in
            guard authorize(request: request, context: context, verifier: verifier) != nil else {
                return managementError(.unauthorized)
            }
            do {
                let view = try await accounts.show(try accountLookup(from: request))
                return managementJSON(.ok, view)
            } catch {
                return managementError(status(for: error))
            }
        }

        router.post("/v1/accounts/deactivate") { request, context async -> Response in
            guard let authorization = authorize(request: request, context: context, verifier: verifier) else {
                return managementError(.unauthorized)
            }
            do {
                let input: ManagementDIDRequest = try await decodeManagementJSON(from: request)
                let view = try await accounts.deactivate(did: input.did, authorization: authorization)
                return managementJSON(.ok, view)
            } catch {
                return managementError(status(for: error))
            }
        }

        router.post("/v1/accounts/reactivate") { request, context async -> Response in
            guard let authorization = authorize(request: request, context: context, verifier: verifier) else {
                return managementError(.unauthorized)
            }
            do {
                let input: ManagementDIDRequest = try await decodeManagementJSON(from: request)
                let view = try await accounts.reactivate(did: input.did, authorization: authorization)
                return managementJSON(.ok, view)
            } catch {
                return managementError(status(for: error))
            }
        }

        router.post("/v1/accounts/delete") { request, context async -> Response in
            guard let authorization = authorize(request: request, context: context, verifier: verifier) else {
                return managementError(.unauthorized)
            }
            do {
                let input: ManagementDeleteRequest = try await decodeManagementJSON(from: request)
                let view = try await accounts.delete(
                    did: input.did,
                    tombstoneReason: input.tombstoneReason,
                    exportReference: input.exportReference,
                    authorization: authorization
                )
                return managementJSON(.ok, view)
            } catch {
                return managementError(status(for: error))
            }
        }

        // Make wrong verbs and unknown management paths return the same small,
        // no-store JSON closure as every other management error. The public
        // router intentionally has no corresponding fallback.
        registerMethodGuards(on: router, verifier: verifier)
        registerUnknownManagementGuards(on: router)
        return router
    }

    public func buildApplication(logger: Logger) -> some ApplicationProtocol {
        Application(
            router: buildRouter(),
            configuration: .init(
                address: .hostname(configuration.bindAddress.rawValue, port: configuration.port),
                serverName: "swan-management"
            ),
            logger: logger
        )
    }
}

private enum ManagementRequestError: Error {
    case malformed
    case payloadTooLarge
}

private struct ManagementDIDRequest: Decodable {
    let did: String

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: ManagementCodingKey.self)
        try validateKeys(container, allowed: ["did"])
        did = try container.decode(String.self, forKey: .init("did"))
        guard !did.isEmpty, did.utf8.count <= 2_048 else { throw ManagementRequestError.malformed }
    }
}

private struct ManagementDeleteRequest: Decodable {
    let did: String
    let tombstoneReason: String?
    let exportReference: String?

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: ManagementCodingKey.self)
        try validateKeys(container, allowed: ["did", "tombstoneReason", "exportReference"])
        did = try container.decode(String.self, forKey: .init("did"))
        tombstoneReason = try container.decodeIfPresent(String.self, forKey: .init("tombstoneReason"))
        exportReference = try container.decodeIfPresent(String.self, forKey: .init("exportReference"))
        guard !did.isEmpty, did.utf8.count <= 2_048,
              tombstoneReason.map({ !$0.isEmpty && $0.utf8.count <= 1_024 }) ?? true,
              exportReference.map({ $0.utf8.count == 71 }) ?? true else {
            throw ManagementRequestError.malformed
        }
    }
}

private struct ManagementCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int? = nil

    init(_ stringValue: String) {
        self.stringValue = stringValue
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        return nil
    }
}

private func validateKeys(
    _ container: KeyedDecodingContainer<ManagementCodingKey>,
    allowed: Set<String>
) throws {
    guard Set(container.allKeys.map(\.stringValue)).isSubset(of: allowed) else {
        throw ManagementRequestError.malformed
    }
}

private func authorize(
    request: Request,
    context: SwanManagementRequestContext,
    verifier: OperatorSecretVerifier
) -> AccountOperatorAuthorization? {
    guard SwanManagementPeerPolicy.permits(context.remoteAddress),
          let bearerValue = managementBearerValue(from: request.headers),
          let authorization = try? verifier.authorize(bearerValue: bearerValue) else {
        return nil
    }
    return authorization
}

private func managementBearerValue(from headers: HTTPFields) -> String? {
    let values = headers[values: .authorization]
    guard values.count == 1 else { return nil }
    let value = values[0]
    guard value.hasPrefix("Bearer "), value.utf8.count <= SwanManagementHTTPServer.maximumJSONBytes else {
        return nil
    }
    let token = String(value.dropFirst("Bearer ".count))
    guard !token.isEmpty, !token.contains(where: { $0 == " " || $0 == "\t" || $0 == "," }) else {
        return nil
    }
    return token
}

private func accountLookup(from request: Request) throws -> AccountOperatorLookup {
    guard let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 4_096,
          let separator = query.firstIndex(of: "=") else {
        throw ManagementRequestError.malformed
    }
    let key = String(query[..<separator])
    let encodedValue = String(query[query.index(after: separator)...])
    guard !encodedValue.contains("&"),
          let value = encodedValue.removingPercentEncoding,
          !value.isEmpty else {
        throw ManagementRequestError.malformed
    }
    switch key {
    case "did": return .did(value)
    case "handle": return .handle(value)
    default: throw ManagementRequestError.malformed
    }
}

private func decodeManagementJSON<Value: Decodable>(from request: Request) async throws -> Value {
    guard let contentType = request.headers[.contentType],
          contentType.split(separator: ";", maxSplits: 1).first?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "application/json" else {
        throw ManagementRequestError.malformed
    }
    let contentLengths = request.headers[values: .contentLength]
    guard contentLengths.count <= 1 else { throw ManagementRequestError.malformed }
    if let declaredLength = contentLengths.first {
        guard let value = Int(declaredLength), value >= 0 else { throw ManagementRequestError.malformed }
        guard value <= SwanManagementHTTPServer.maximumJSONBytes else {
            throw ManagementRequestError.payloadTooLarge
        }
    }
    let buffer: ByteBuffer
    do {
        buffer = try await request.body.collect(upTo: SwanManagementHTTPServer.maximumJSONBytes)
    } catch is NIOTooManyBytesError {
        throw ManagementRequestError.payloadTooLarge
    } catch {
        throw ManagementRequestError.malformed
    }
    guard buffer.readableBytes > 0,
          let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) else {
        throw ManagementRequestError.malformed
    }
    do {
        return try JSONDecoder().decode(Value.self, from: Data(bytes))
    } catch let error as ManagementRequestError {
        throw error
    } catch {
        throw ManagementRequestError.malformed
    }
}

private func registerMethodGuards(
    on router: Router<SwanManagementRequestContext>,
    verifier: OperatorSecretVerifier
) {
    let routes: [(RouterPath, Set<HTTPRequest.Method>)] = [
        ("/v1/accounts", [.get]),
        ("/v1/accounts/deactivate", [.post]),
        ("/v1/accounts/reactivate", [.post]),
        ("/v1/accounts/delete", [.post]),
    ]
    let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
    for (path, allowed) in routes {
        for method in methods where !allowed.contains(method) {
            router.on(path, method: method) { request, context -> Response in
                guard authorize(request: request, context: context, verifier: verifier) != nil else {
                    return managementError(.unauthorized)
                }
                return managementError(.methodNotAllowed)
            }
        }
    }
}

private func registerUnknownManagementGuards(on router: Router<SwanManagementRequestContext>) {
    let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
    for method in methods {
        router.on("/v1/*", method: method) { _, _ -> Response in
            managementError(.notFound)
        }
    }
}

private func status(for error: any Error) -> HTTPResponse.Status {
    switch error {
    case is ManagementRequestError:
        if case ManagementRequestError.payloadTooLarge = error {
            return .contentTooLarge
        }
        return .badRequest
    case let error as AccountOperatorError where error == .unknownAccount:
        return .notFound
    case is AccountControlStoreError, is SwanError:
        return .badRequest
    default:
        return .internalServerError
    }
}

private func managementJSON(_ status: HTTPResponse.Status, _ body: AccountOperatorView) -> Response {
    let data = (try? AccountOperatorJSON.render(body)) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

private func managementError(_ status: HTTPResponse.Status) -> Response {
    struct ErrorBody: Encodable { let error: String }
    let code = switch status {
    case .badRequest: "invalid_request"
    case .unauthorized: "unauthorized"
    case .notFound: "not_found"
    case .contentTooLarge: "request_too_large"
    case .methodNotAllowed: "method_not_allowed"
    default: "internal_error"
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(ErrorBody(error: code))) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
