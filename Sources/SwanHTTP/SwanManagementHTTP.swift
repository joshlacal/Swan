import Foundation
import Hummingbird
import HummingbirdCore
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
    case invalidMaximumConnections
    case invalidIdleTimeout
}

/// Configuration for the *separate* loopback management application. This is
/// not a prefix or middleware on Swan's public router.
public struct SwanManagementHTTPConfiguration: Sendable, Equatable {
    public let bindAddress: SwanManagementBindAddress
    public let port: Int
    public let maximumConnections: Int
    public let idleTimeoutSeconds: Int

    public init(
        bindAddress: SwanManagementBindAddress,
        port: Int,
        maximumConnections: Int = 32,
        idleTimeoutSeconds: Int = 15
    ) throws {
        guard (1 ... 65_535).contains(port) else {
            throw SwanManagementHTTPConfigurationError.invalidPort
        }
        guard maximumConnections > 0 else {
            throw SwanManagementHTTPConfigurationError.invalidMaximumConnections
        }
        guard idleTimeoutSeconds > 0 else {
            throw SwanManagementHTTPConfigurationError.invalidIdleTimeout
        }
        self.bindAddress = bindAddress
        self.port = port
        self.maximumConnections = maximumConnections
        self.idleTimeoutSeconds = idleTimeoutSeconds
    }

    /// This explicit literal parser is used by `swan serve`; accepting a
    /// `String` without this validation would make it too easy to accidentally
    /// bind an operator credential listener to a public interface.
    public init(
        bindAddressLiteral: String,
        port: Int,
        maximumConnections: Int = 32,
        idleTimeoutSeconds: Int = 15
    ) throws {
        guard let bindAddress = SwanManagementBindAddress(rawValue: bindAddressLiteral) else {
            throw SwanManagementHTTPConfigurationError.invalidBindAddress
        }
        try self.init(
            bindAddress: bindAddress,
            port: port,
            maximumConnections: maximumConnections,
            idleTimeoutSeconds: idleTimeoutSeconds
        )
    }
}

/// Captures the actual peer socket address before routing. It never reads
/// forwarded/host headers, so a reverse proxy cannot assert loopback identity.
public struct SwanManagementRequestContext: RequestContext, RemoteAddressRequestContext {
    public var coreContext: CoreRequestContextStorage
    public let remoteAddress: SocketAddress?
    private let requestChannel: any Channel
    private let bodyTerminationState: SwanJSONWriteBodyTerminationState

    public init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
        remoteAddress = source.channel.remoteAddress
        requestChannel = source.channel
        bodyTerminationState = SwanJSONWriteBodyTerminationState()
    }

    public var maxUploadSize: Int { SwanManagementHTTPServer.maximumJSONBytes }

    var requestBodyTermination: SwanJSONWriteBodyTerminationHandle {
        SwanJSONWriteBodyTerminationHandle({
            bodyTerminationState.markTerminated()
            requestChannel.pipeline.context(handlerType: SwanJSONWriteBodyDrainHandler.self)
                .whenComplete { result in
                    switch result {
                    case .success:
                        requestChannel.pipeline.fireUserInboundEventTriggered(
                            SwanJSONWriteBodyDrainEvent()
                        )
                    case .failure:
                        requestChannel.close(mode: .input, promise: nil)
                    }
                }
        }, state: { bodyTerminationState.value })
    }
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

public enum SwanManagementFirehoseSyncError: Error, Sendable, Equatable {
    case inactiveAccount
    case unavailable
}

public struct SwanManagementFirehoseSyncInput: Sendable, Equatable {
    public let did: String
    public let requestID: String

    public init(did: String, requestID: String) {
        self.did = did
        self.requestID = requestID
    }
}

public struct SwanManagementFirehoseSyncResult: Sendable, Equatable, Encodable {
    public let did: String
    public let requestId: String
    public let status: String

    public init(did: String, requestId: String, status: String = "accepted") {
        self.did = did
        self.requestId = requestId
        self.status = status
    }
}

public protocol SwanManagementFirehoseSyncing: Sendable {
    func sync(
        _ input: SwanManagementFirehoseSyncInput
    ) async throws -> SwanManagementFirehoseSyncResult
}

public protocol SwanManagementLiveAccountChecking: Sendable {
    func containsLiveAccount(did: String) async throws -> Bool
}

/// Executes the operator sync inside the serving process so SQLite's WAL has
/// one process owner. The request UUID is the emitter's durable source key;
/// an exact HTTP retry therefore converges through the outbox's uniqueness
/// constraint and returns the same acknowledgement.
public actor SwanManagementFirehoseSyncRuntime: SwanManagementFirehoseSyncing {
    private let controlStore: any AccountControlStore
    private let liveAccounts: any SwanManagementLiveAccountChecking
    private let emitter: any PublicLifecycleEventEmitting

    public init(
        controlStore: any AccountControlStore,
        liveAccounts: any SwanManagementLiveAccountChecking,
        emitter: any PublicLifecycleEventEmitting
    ) {
        self.controlStore = controlStore
        self.liveAccounts = liveAccounts
        self.emitter = emitter
    }

    public func sync(
        _ input: SwanManagementFirehoseSyncInput
    ) async throws -> SwanManagementFirehoseSyncResult {
        guard AccountControlIdentifiers.isDID(input.did),
              input.requestID.utf8.count == 36,
              UUID(uuidString: input.requestID)?.uuidString.lowercased()
                == input.requestID else {
            throw SwanManagementFirehoseSyncError.inactiveAccount
        }
        do {
            guard let account = try await controlStore.account(did: input.did),
                  account.status.authorizesAccount,
                  try await liveAccounts.containsLiveAccount(did: input.did) else {
                throw SwanManagementFirehoseSyncError.inactiveAccount
            }
            try await emitter.emitManualSync(
                did: input.did,
                requestUUID: input.requestID,
                now: Date()
            )
            return .init(did: input.did, requestId: input.requestID)
        } catch let error as SwanManagementFirehoseSyncError {
            throw error
        } catch let error as AccountControlStoreError {
            if case .invalidTransition = error {
                throw SwanManagementFirehoseSyncError.inactiveAccount
            }
            throw SwanManagementFirehoseSyncError.unavailable
        } catch {
            throw SwanManagementFirehoseSyncError.unavailable
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
    private let plcProvisioning: (any SwanManagementPLCProvisioning)?
    private let firehoseSync: (any SwanManagementFirehoseSyncing)?
    private let requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    private let rejectedBodyAdmission: SwanRequestBodyAdmissionConfiguration

    public init(
        configuration: SwanManagementHTTPConfiguration,
        controlStore: any AccountControlStore,
        operatorSecretVerifier: OperatorSecretVerifier,
        plcProvisioning: (any SwanManagementPLCProvisioning)? = nil,
        firehoseSync: (any SwanManagementFirehoseSyncing)? = nil,
        permanentDeletionCoordinator:
            (any AccountPermanentDeletionCoordinating)? = nil,
        lifecycleEmitter: (any PublicLifecycleEventEmitting)? = nil,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission = .managementProcessShared,
        rejectedBodyAdmission: PublicRepositoryJSONWriteAdmission = .managementRejectedProcessShared,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy = .productionDefault
    ) {
        self.configuration = configuration
        accounts = AccountOperatorService(
            store: controlStore,
            permanentDeletionCoordinator:
                permanentDeletionCoordinator,
            lifecycleEmitter: lifecycleEmitter
        )
        self.operatorSecretVerifier = operatorSecretVerifier
        self.plcProvisioning = plcProvisioning
        self.firehoseSync = firehoseSync
        requestBodyAdmission = .init(
            admission: jsonWriteAdmission,
            policy: jsonWriteBodyPolicy
        )
        self.rejectedBodyAdmission = .init(
            admission: rejectedBodyAdmission,
            policy: jsonWriteBodyPolicy
        )
    }

    /// The management router has its own request context and is never merged
    /// into `SwanHTTPServer.buildRouter()`.
    public func buildRouter() -> Router<SwanManagementRequestContext> {
        let router = Router(context: SwanManagementRequestContext.self)
        let accounts = accounts
        let verifier = operatorSecretVerifier
        let plcProvisioning = plcProvisioning
        let firehoseSync = firehoseSync
        let requestBodyAdmission = requestBodyAdmission
        let rejectedBodyAdmission = rejectedBodyAdmission

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
                if let failure = await drainManagementRejectedBody(
                    request, context: context,
                    requestBodyAdmission: rejectedBodyAdmission
                ) { return failure }
                return managementError(.unauthorized)
            }
            do {
                let input: ManagementDIDRequest = try await decodeManagementJSON(
                    from: request, context: context,
                    requestBodyAdmission: requestBodyAdmission)
                let view = try await accounts.deactivate(did: input.did, authorization: authorization)
                return managementJSON(.ok, view)
            } catch {
                return managementError(status(for: error))
            }
        }

        router.post("/v1/accounts/reactivate") { request, context async -> Response in
            guard let authorization = authorize(request: request, context: context, verifier: verifier) else {
                if let failure = await drainManagementRejectedBody(
                    request, context: context,
                    requestBodyAdmission: rejectedBodyAdmission
                ) { return failure }
                return managementError(.unauthorized)
            }
            do {
                let input: ManagementDIDRequest = try await decodeManagementJSON(
                    from: request, context: context,
                    requestBodyAdmission: requestBodyAdmission)
                let view = try await accounts.reactivate(did: input.did, authorization: authorization)
                return managementJSON(.ok, view)
            } catch {
                return managementError(status(for: error))
            }
        }

        router.post("/v1/accounts/delete") { request, context async -> Response in
            guard let authorization = authorize(request: request, context: context, verifier: verifier) else {
                if let failure = await drainManagementRejectedBody(
                    request, context: context,
                    requestBodyAdmission: rejectedBodyAdmission
                ) { return failure }
                return managementError(.unauthorized)
            }
            do {
                let input: ManagementDeleteRequest = try await decodeManagementJSON(
                    from: request, context: context,
                    requestBodyAdmission: requestBodyAdmission)
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

        if let plcProvisioning {
            router.post("/v1/accounts/plc/prepare") { request, context async -> Response in
                guard authorize(request: request, context: context, verifier: verifier) != nil else {
                    if let failure = await drainManagementRejectedBody(
                        request, context: context,
                        requestBodyAdmission: rejectedBodyAdmission
                    ) { return failure }
                    return managementError(.unauthorized)
                }
                do {
                    let requestBody: ManagementPLCPrepareRequest =
                        try await decodeManagementJSON(
                            from: request, context: context,
                            requestBodyAdmission: requestBodyAdmission)
                    let input = try requestBody.validatedInput()
                    let result = try await plcProvisioning.prepare(input)
                    return managementJSON(.ok, result)
                } catch {
                    return managementError(status(for: error))
                }
            }

            router.post("/v1/accounts/plc/activate") { request, context async -> Response in
                guard authorize(request: request, context: context, verifier: verifier) != nil else {
                    if let failure = await drainManagementRejectedBody(
                        request, context: context,
                        requestBodyAdmission: rejectedBodyAdmission
                    ) { return failure }
                    return managementError(.unauthorized)
                }
                    do {
                        let requestBody: ManagementPLCActivateRequest =
                            try await decodeManagementJSON(
                                from: request, context: context,
                                requestBodyAdmission: requestBodyAdmission)
                        let input = try requestBody.validatedInput()
                        let result = try await plcProvisioning.activate(input)
                        return managementJSON(.ok, result)
                    } catch {
                        return managementError(status(for: error))
                    }
            }
        } else {
            // Keep disabled provisioning indistinguishable from any other
            // unavailable management path while retaining the management
            // listener's no-store error closure.
            registerDisabledPLCProvisioningGuards(on: router)
        }

        if let firehoseSync {
            router.post("/v1/firehose/sync") { request, context async -> Response in
                guard authorize(request: request, context: context, verifier: verifier) != nil else {
                    if let failure = await drainManagementRejectedBody(
                        request, context: context,
                        requestBodyAdmission: rejectedBodyAdmission
                    ) { return failure }
                    return managementError(.unauthorized)
                }
                do {
                    let requestBody: ManagementFirehoseSyncRequest =
                        try await decodeManagementJSON(
                            from: request, context: context,
                            requestBodyAdmission: requestBodyAdmission
                        )
                    return managementJSON(
                        .ok,
                        try await firehoseSync.sync(requestBody.validatedInput())
                    )
                } catch {
                    return managementError(status(for: error))
                }
            }
        } else {
            registerDisabledManagementFirehoseSyncGuards(on: router)
        }

        // Make wrong verbs and unknown management paths return the same small,
        // no-store JSON closure as every other management error. The public
        // router intentionally has no corresponding fallback.
        registerMethodGuards(
            on: router,
            verifier: verifier,
            plcProvisioningEnabled: plcProvisioning != nil,
            firehoseSyncEnabled: firehoseSync != nil
        )
        registerUnknownManagementGuards(on: router)
        return router
    }

    public func buildApplication(logger: Logger) -> some ApplicationProtocol {
        let applicationConfiguration = ApplicationConfiguration(
            address: .hostname(
                configuration.bindAddress.rawValue,
                port: configuration.port
            ),
            serverName: "swan-management",
            availableConnectionsDelegate: MaximumAvailableConnections(
                configuration.maximumConnections,
                logger: logger
            )
        )
        return Application(
            router: buildRouter(),
            server: .http1(
                configuration: .init(
                    additionalChannelHandlers: [SwanJSONWriteBodyDrainHandler(
                        timeout: requestBodyAdmission.policy.totalBodyTimeout + .milliseconds(50)
                    )],
                    idleTimeout: .seconds(
                        Int64(configuration.idleTimeoutSeconds)
                    )
                )
            ),
            configuration: applicationConfiguration,
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

private struct ManagementFirehoseSyncRequest: Decodable {
    let did: String
    let requestID: String

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: ManagementCodingKey.self)
        try validateKeys(container, allowed: ["did", "requestId"])
        did = try container.decode(String.self, forKey: .init("did"))
        requestID = try container.decode(String.self, forKey: .init("requestId"))
    }

    func validatedInput() throws -> SwanManagementFirehoseSyncInput {
        guard AccountControlIdentifiers.isDID(did),
              requestID.utf8.count == 36,
              UUID(uuidString: requestID)?.uuidString.lowercased() == requestID else {
            throw ManagementRequestError.malformed
        }
        return .init(did: did, requestID: requestID)
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

private struct ManagementPLCPrepareRequest: Decodable {
    let requestID: String
    let handle: String
    let pdsOrigin: String
    let repositoryRevision: String
    let plcOrigin: String?
    let plcLaboratory: Bool
    let plcReferenceCompatibility: String?

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: ManagementCodingKey.self)
        try validateKeys(container, allowed: [
            "requestId", "handle", "pdsOrigin", "repositoryRevision",
            "plcOrigin", "plcLaboratory", "plcReferenceCompatibility",
        ])
        requestID = try container.decode(String.self, forKey: .init("requestId"))
        handle = try container.decode(String.self, forKey: .init("handle"))
        pdsOrigin = try container.decode(String.self, forKey: .init("pdsOrigin"))
        repositoryRevision = try container.decode(String.self, forKey: .init("repositoryRevision"))
        plcOrigin = try container.decodeIfPresent(String.self, forKey: .init("plcOrigin"))
        plcLaboratory = try container.decodeIfPresent(Bool.self, forKey: .init("plcLaboratory"))
            ?? false
        plcReferenceCompatibility = try container.decodeIfPresent(
            String.self,
            forKey: .init("plcReferenceCompatibility")
        )
    }

    func validatedInput() throws -> SwanManagementPLCPrepareInput {
        let pdsURL = try validatedHTTPSOrigin(pdsOrigin)
        let plcConfiguration = try validatedPLCConfiguration(
            origin: plcOrigin,
            laboratory: plcLaboratory,
            compatibility: plcReferenceCompatibility,
            allowsCompatibility: true
        )
        guard !requestID.isEmpty, requestID.utf8.count <= 128,
              !handle.isEmpty, handle.utf8.count <= 2_048,
              !repositoryRevision.isEmpty, repositoryRevision.utf8.count <= 128 else {
            throw ManagementRequestError.malformed
        }
        return .init(
            requestID: requestID,
            handle: handle,
            pdsOrigin: pdsURL,
            repositoryRevision: repositoryRevision,
            plcConfiguration: plcConfiguration
        )
    }
}

private struct ManagementPLCActivateRequest: Decodable {
    let requestID: String
    let password: String
    let plcOrigin: String?
    let plcLaboratory: Bool
    let plcReferenceCompatibility: String?
    let handleLaboratoryOrigin: String?

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: ManagementCodingKey.self)
        try validateKeys(container, allowed: [
            "requestId", "password", "plcOrigin", "plcLaboratory",
            "plcReferenceCompatibility", "handleLaboratoryOrigin",
        ])
        requestID = try container.decode(String.self, forKey: .init("requestId"))
        password = try container.decode(String.self, forKey: .init("password"))
        plcOrigin = try container.decodeIfPresent(String.self, forKey: .init("plcOrigin"))
        plcLaboratory = try container.decodeIfPresent(Bool.self, forKey: .init("plcLaboratory"))
            ?? false
        plcReferenceCompatibility = try container.decodeIfPresent(
            String.self,
            forKey: .init("plcReferenceCompatibility")
        )
        handleLaboratoryOrigin = try container.decodeIfPresent(
            String.self,
            forKey: .init("handleLaboratoryOrigin")
        )
    }

    func validatedInput() throws -> SwanManagementPLCActivateInput {
        guard !requestID.isEmpty, requestID.utf8.count <= 128,
              !password.isEmpty, password.utf8.count <= 4 * 1_024,
              !password.utf8.contains(0) else {
            throw ManagementRequestError.malformed
        }
        let plcConfiguration = try validatedPLCConfiguration(
            origin: plcOrigin,
            laboratory: plcLaboratory,
            compatibility: plcReferenceCompatibility,
            allowsCompatibility: true
        )
        let handlePolicy: ATHandleResolutionPolicy
        if plcLaboratory {
            guard let handleLaboratoryOrigin,
                  let origin = URL(string: handleLaboratoryOrigin) else {
                throw ManagementRequestError.malformed
            }
            handlePolicy = try ATHandleResolutionPolicy.laboratory(origin: origin)
        } else {
            guard handleLaboratoryOrigin == nil else {
                throw ManagementRequestError.malformed
            }
            handlePolicy = try ATHandleResolutionPolicy.production()
        }
        return .init(
            requestID: requestID,
            password: password,
            plcConfiguration: plcConfiguration,
            handlePolicy: handlePolicy
        )
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

private func validatedHTTPSOrigin(_ rawValue: String) throws -> URL {
    guard rawValue.utf8.count <= 4_096,
          let url = URL(string: rawValue),
          let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          components.scheme?.lowercased() == "https",
          let host = components.host,
          !host.isEmpty,
          components.user == nil,
          components.password == nil,
          components.query == nil,
          components.fragment == nil,
          components.path.isEmpty || components.path == "/",
          components.port == nil || components.port == 443 else {
        throw ManagementRequestError.malformed
    }
    do {
        let canonical = try PLCATProfile.canonicalPDSOrigin(url)
        guard let result = URL(string: canonical) else {
            throw ManagementRequestError.malformed
        }
        return result
    } catch {
        throw ManagementRequestError.malformed
    }
}

private func validatedPLCConfiguration(
    origin rawOrigin: String?,
    laboratory: Bool,
    compatibility rawCompatibility: String?,
    allowsCompatibility: Bool
) throws -> PLCClientConfiguration {
    do {
        let originText = rawOrigin
            ?? PLCClientConfiguration.defaultProductionOrigin.absoluteString
        guard originText.utf8.count <= 4_096,
              let origin = URL(string: originText) else {
            throw ManagementRequestError.malformed
        }
        let compatibility: PLCSubmitSuccessResponsePolicy
        switch rawCompatibility {
        case nil:
            compatibility = .strict
        case PLCSubmitSuccessResponsePolicy.didPLCServer001.rawValue:
            guard allowsCompatibility, laboratory else {
                throw ManagementRequestError.malformed
            }
            compatibility = .didPLCServer001
        case .some:
            throw ManagementRequestError.malformed
        }
        if laboratory {
            return try .laboratory(
                origin: origin,
                submitSuccessResponsePolicy: compatibility
            )
        }
        guard compatibility == .strict else {
            throw ManagementRequestError.malformed
        }
        return try .production(origin: origin)
    } catch is ManagementRequestError {
        throw ManagementRequestError.malformed
    } catch {
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

private func decodeManagementJSON<Value: Decodable>(
    from request: Request,
    context: SwanManagementRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> Value {
    let buffer: SwanAdmittedRequestBody
    do {
        buffer = try await collectAdmittedRequestBody(
            request,
            mediaType: .json,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: SwanManagementHTTPServer.maximumJSONBytes,
            termination: context.requestBodyTermination
        )
    } catch let failure as SwanRequestBodyCollectionFailure {
        switch failure {
        case .invalidRequest:
            throw ManagementRequestError.malformed
        case .payloadTooLarge:
            throw ManagementRequestError.payloadTooLarge
        case .unavailable:
            throw SwanError.unavailable("request body unavailable")
        }
    } catch {
        throw ManagementRequestError.malformed
    }
    defer { withExtendedLifetime(buffer) {} }
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

private func drainManagementRejectedBody(
    _ request: Request,
    context: SwanManagementRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response? {
    do {
        try await drainRejectedRequestBody(
            request,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            termination: context.requestBodyTermination
        )
        return nil
    } catch {
        return managementError(.serviceUnavailable)
    }
}

private func registerMethodGuards(
    on router: Router<SwanManagementRequestContext>,
    verifier: OperatorSecretVerifier,
    plcProvisioningEnabled: Bool,
    firehoseSyncEnabled: Bool
) {
    var routes: [(RouterPath, Set<HTTPRequest.Method>)] = [
        ("/v1/accounts", [.get]),
        ("/v1/accounts/deactivate", [.post]),
        ("/v1/accounts/reactivate", [.post]),
        ("/v1/accounts/delete", [.post]),
    ]
    if plcProvisioningEnabled {
        routes.append(("/v1/accounts/plc/prepare", [.post]))
        routes.append(("/v1/accounts/plc/activate", [.post]))
    }
    if firehoseSyncEnabled {
        routes.append(("/v1/firehose/sync", [.post]))
    }
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

private func registerDisabledManagementFirehoseSyncGuards(
    on router: Router<SwanManagementRequestContext>
) {
    let methods: [HTTPRequest.Method] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ]
    for method in methods {
        router.on("/v1/firehose/sync", method: method) { _, _ -> Response in
            managementError(.notFound)
        }
    }
}

private func registerDisabledPLCProvisioningGuards(
    on router: Router<SwanManagementRequestContext>
) {
    let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
    for path: RouterPath in ["/v1/accounts/plc/prepare", "/v1/accounts/plc/activate"] {
        for method in methods {
            router.on(path, method: method) { _, _ -> Response in
                managementError(.notFound)
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
        router.on("/v1/*/*", method: method) { _, _ -> Response in
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
    case let error as AccountOperatorError
        where error == .permanentDeletionUnavailable:
        return .serviceUnavailable
    case let error as PLCAccountPreparationError:
        return error == .unavailable ? .serviceUnavailable : .badRequest
    case let error as PLCAccountActivationError:
        return error == .unavailable ? .serviceUnavailable : .badRequest
    case let error as SwanManagementFirehoseSyncError:
        return error == .unavailable ? .serviceUnavailable : .badRequest
    case let error as SwanError:
        if case .unavailable = error { return .serviceUnavailable }
        return .badRequest
    case is AccountControlStoreError:
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

private func managementJSON(
    _ status: HTTPResponse.Status,
    _ body: some Encodable
) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
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
    case .serviceUnavailable: "temporarily_unavailable"
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
