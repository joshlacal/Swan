import AsyncHTTPClient
import Foundation
import NIOCore
import Petrel
import SwanCore

public enum PLCHTTPMethod: String, Sendable, Equatable {
    case get = "GET"
    case post = "POST"
}

public struct PLCHTTPRequest: Sendable, Equatable {
    public let method: PLCHTTPMethod
    public let url: URL
    public let headers: [String: String]
    public let body: Data?
    public let timeout: TimeInterval
    public let maximumResponseBytes: Int

    public init(
        method: PLCHTTPMethod,
        url: URL,
        headers: [String: String],
        body: Data?,
        timeout: TimeInterval,
        maximumResponseBytes: Int
    ) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
    }
}

public struct PLCHTTPResponse: Sendable, Equatable {
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
}

public protocol PLCHTTPTransport: Sendable {
    func execute(_ request: PLCHTTPRequest) async throws -> PLCHTTPResponse
}

public final class AsyncHTTPClientPLCTransport: PLCHTTPTransport, @unchecked Sendable {
    private let client: HTTPClient
    private let maximumTimeout: TimeInterval

    public init(maximumTimeout: TimeInterval = 10) throws {
        guard maximumTimeout > 0, maximumTimeout <= 30, maximumTimeout.isFinite else {
            throw SwanError.malformed("PLC HTTP transport timeout is invalid")
        }
        self.maximumTimeout = maximumTimeout
        client = HTTPClient(configuration: .init(
            redirectConfiguration: .disallow,
            timeout: .init(
                connect: .milliseconds(Int64(maximumTimeout * 1_000)),
                read: .milliseconds(Int64(maximumTimeout * 1_000))
            ),
            decompression: .disabled
        ))
    }

    deinit {
        client.shutdown { _ in }
    }

    public func execute(_ request: PLCHTTPRequest) async throws -> PLCHTTPResponse {
        guard request.timeout > 0,
              request.timeout <= maximumTimeout,
              request.timeout.isFinite,
              (1 ... 1_048_576).contains(request.maximumResponseBytes),
              request.body?.count ?? 0 <= 32 * 1_024 else {
            throw SwanError.malformed("PLC HTTP request bounds are invalid")
        }
        var outgoing = HTTPClientRequest(url: request.url.absoluteString)
        outgoing.method = request.method == .get ? .GET : .POST
        for (name, value) in request.headers {
            outgoing.headers.add(name: name, value: value)
        }
        if let body = request.body {
            outgoing.body = .bytes(ByteBuffer(data: body))
        }
        let deadline = NIODeadline.now() + .milliseconds(Int64(request.timeout * 1_000))
        let response: HTTPClientResponse
        do {
            response = try await client.execute(outgoing, deadline: deadline)
        } catch {
            throw SwanError.unavailable("PLC HTTP request failed")
        }
        let body: ByteBuffer
        do {
            body = try await response.body.collect(upTo: request.maximumResponseBytes)
        } catch {
            throw SwanError.unavailable("PLC HTTP response exceeded its bound")
        }
        let headers = response.headers.reduce(into: [String: String]()) { output, header in
            let name = header.name.lowercased()
            if output[name] == nil {
                output[name] = header.value
            } else {
                output[name, default: ""].append(",\(header.value)")
            }
        }
        return PLCHTTPResponse(
            status: Int(response.status.code),
            headers: headers,
            body: Data(buffer: body),
            finalURL: response.url,
            redirectCount: response.history.count
        )
    }
}

public struct PLCClientConfiguration: Sendable, Equatable {
    public static let defaultProductionOrigin = URL(string: "https://plc.directory")!

    public let origin: URL
    public let timeout: TimeInterval
    public let maximumStateBytes: Int
    public let maximumAuditBytes: Int
    public let maximumSubmitResponseBytes: Int

    private init(
        origin: URL,
        laboratory: Bool,
        timeout: TimeInterval,
        maximumStateBytes: Int,
        maximumAuditBytes: Int,
        maximumSubmitResponseBytes: Int
    ) throws {
        guard timeout > 0, timeout <= 30, timeout.isFinite,
              (1 ... 1_048_576).contains(maximumStateBytes),
              (1 ... 1_048_576).contains(maximumAuditBytes),
              (1 ... 1_048_576).contains(maximumSubmitResponseBytes) else {
            throw SwanError.malformed("PLC client bounds are invalid")
        }
        self.origin = try Self.validateOrigin(origin, laboratory: laboratory)
        self.timeout = timeout
        self.maximumStateBytes = maximumStateBytes
        self.maximumAuditBytes = maximumAuditBytes
        self.maximumSubmitResponseBytes = maximumSubmitResponseBytes
    }

    public static func production(
        origin: URL = defaultProductionOrigin,
        timeout: TimeInterval = 5,
        maximumStateBytes: Int = 256 * 1_024,
        maximumAuditBytes: Int = 512 * 1_024,
        maximumSubmitResponseBytes: Int = 64 * 1_024
    ) throws -> Self {
        try .init(
            origin: origin,
            laboratory: false,
            timeout: timeout,
            maximumStateBytes: maximumStateBytes,
            maximumAuditBytes: maximumAuditBytes,
            maximumSubmitResponseBytes: maximumSubmitResponseBytes
        )
    }

    public static func laboratory(
        origin: URL,
        timeout: TimeInterval = 5,
        maximumStateBytes: Int = 256 * 1_024,
        maximumAuditBytes: Int = 512 * 1_024,
        maximumSubmitResponseBytes: Int = 64 * 1_024
    ) throws -> Self {
        try .init(
            origin: origin,
            laboratory: true,
            timeout: timeout,
            maximumStateBytes: maximumStateBytes,
            maximumAuditBytes: maximumAuditBytes,
            maximumSubmitResponseBytes: maximumSubmitResponseBytes
        )
    }

    private static func validateOrigin(_ origin: URL, laboratory: Bool) throws -> URL {
        guard let components = URLComponents(url: origin, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/" else {
            throw SwanError.malformed("PLC directory must be configured as an origin")
        }
        if laboratory {
            guard scheme == "http", plcIsLoopbackLiteral(host),
                  let port = components.port, (1_024 ... 65_535).contains(port) else {
                throw SwanError.malformed("PLC laboratory origin must be an HTTP literal-loopback origin")
            }
        } else {
            guard scheme == "https", !plcIsLoopbackLiteral(host),
                  components.port == nil || components.port == 443 else {
                throw SwanError.malformed("PLC production origin must use HTTPS on port 443")
            }
        }
        var canonical = components
        canonical.path = ""
        guard let result = canonical.url, !result.absoluteString.hasSuffix("/") else {
            throw SwanError.malformed("PLC directory origin is malformed")
        }
        return result
    }
}

public struct PLCDocumentData: Sendable, Equatable {
    public let did: String
    public let rotationKeys: [String]
    public let verificationMethods: [String: String]
    public let alsoKnownAs: [String]
    public let services: [String: PLCService]
}

public struct PLCAuditEntry: Sendable, Equatable {
    public let did: String
    public let operation: PLCSignedOperation
    public let cid: String
    public let nullified: Bool
    public let createdAt: String
}

public protocol PLCClient: Sendable {
    func submit(did: String, operation: PLCSignedOperation) async throws
    func fetchState(did: String) async throws -> PLCDocumentData
    func fetchAudit(did: String) async throws -> [PLCAuditEntry]
}

public struct PLCDirectoryClient: PLCClient, Sendable {
    public let configuration: PLCClientConfiguration
    private let transport: any PLCHTTPTransport

    public init(
        configuration: PLCClientConfiguration,
        transport: any PLCHTTPTransport
    ) throws {
        self.configuration = configuration
        self.transport = transport
    }

    public init(configuration: PLCClientConfiguration) throws {
        self.configuration = configuration
        transport = try AsyncHTTPClientPLCTransport(maximumTimeout: configuration.timeout)
    }

    public func submit(did: String, operation: PLCSignedOperation) async throws {
        try PLCOperationCodec.validateCanonicalDID(did)
        if operation.prev == nil {
            try PLCOperationCodec.verifyGenesis(operation, expectedDID: did)
        } else {
            // This proves structural/canonical constraints without pretending
            // to know the previous operation's authorized rotation keys.
            let reparsed = try PLCOperationCodec.decodeSignedJSON(operation.canonicalJSON)
            guard reparsed == operation else {
                throw SwanError.malformed("PLC operation is not canonical")
            }
        }
        let request = PLCHTTPRequest(
            method: .post,
            url: try endpoint(did: did, suffix: []),
            headers: [
                "accept": "application/json",
                "content-type": "application/json",
            ],
            body: try operation.canonicalJSON,
            timeout: configuration.timeout,
            maximumResponseBytes: configuration.maximumSubmitResponseBytes
        )
        let response = try await transport.execute(request)
        try validateResponse(response, for: request, permitsEmptyBody: true)
    }

    public func fetchState(did: String) async throws -> PLCDocumentData {
        try PLCOperationCodec.validateCanonicalDID(did)
        let request = PLCHTTPRequest(
            method: .get,
            url: try endpoint(did: did, suffix: ["data"]),
            headers: ["accept": "application/json"],
            body: nil,
            timeout: configuration.timeout,
            maximumResponseBytes: configuration.maximumStateBytes
        )
        let response = try await transport.execute(request)
        try validateResponse(response, for: request, permitsEmptyBody: false)
        let state = try decodeState(response.body, expectedDID: did)
        let audit = try await fetchAudit(did: did)
        guard let activeTerminal = audit.last(where: { !$0.nullified }),
              let regular = activeTerminal.operation.regular,
              state.rotationKeys == regular.rotationKeys,
              state.verificationMethods == regular.verificationMethods,
              state.alsoKnownAs == regular.alsoKnownAs,
              state.services == regular.services else {
            throw SwanError.unauthorized("PLC document data does not match its audit log")
        }
        return state
    }

    public func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        try PLCOperationCodec.validateCanonicalDID(did)
        let request = PLCHTTPRequest(
            method: .get,
            url: try endpoint(did: did, suffix: ["log", "audit"]),
            headers: ["accept": "application/json"],
            body: nil,
            timeout: configuration.timeout,
            maximumResponseBytes: configuration.maximumAuditBytes
        )
        let response = try await transport.execute(request)
        try validateResponse(response, for: request, permitsEmptyBody: false)
        return try decodeAndVerifyAudit(response.body, expectedDID: did)
    }

    private func endpoint(did: String, suffix: [String]) throws -> URL {
        try PLCOperationCodec.validateCanonicalDID(did)
        var url = configuration.origin.appendingPathComponent(did, isDirectory: false)
        for component in suffix {
            url.appendPathComponent(component, isDirectory: false)
        }
        guard url.host == configuration.origin.host,
              url.scheme == configuration.origin.scheme,
              url.port == configuration.origin.port,
              url.query == nil,
              url.fragment == nil else {
            throw SwanError.malformed("PLC request URL is invalid")
        }
        return url
    }

    private func validateResponse(
        _ response: PLCHTTPResponse,
        for request: PLCHTTPRequest,
        permitsEmptyBody: Bool
    ) throws {
        guard response.redirectCount == 0,
              response.finalURL == request.url else {
            throw SwanError.unauthorized("PLC directory redirects are forbidden")
        }
        guard (200 ... 299).contains(response.status) else {
            throw SwanError.unavailable("PLC directory returned a non-success status")
        }
        guard response.body.count <= request.maximumResponseBytes else {
            throw SwanError.unavailable("PLC directory response exceeded its bound")
        }
        if permitsEmptyBody, response.body.isEmpty {
            return
        }
        guard let contentType = response.headers["content-type"],
              contentType.split(separator: ";", maxSplits: 1).first?
              .trimmingCharacters(in: .whitespacesAndNewlines)
              .lowercased() == "application/json" else {
            throw SwanError.malformed("PLC directory response is not JSON")
        }
    }

    private func decodeState(_ data: Data, expectedDID: String) throws -> PLCDocumentData {
        try StrictJSON.validate(data)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == [
                  "did", "rotationKeys", "verificationMethods", "alsoKnownAs", "services",
              ],
              let did = object["did"] as? String,
              did == expectedDID,
              let rotationKeys = object["rotationKeys"] as? [String],
              let verificationMethods = object["verificationMethods"] as? [String: String],
              let alsoKnownAs = object["alsoKnownAs"] as? [String],
              let rawServices = object["services"] as? [String: Any] else {
            throw SwanError.malformed("PLC document data is malformed")
        }
        var services = [String: PLCService]()
        for (name, raw) in rawServices {
            guard let value = raw as? [String: Any],
                  Set(value.keys) == ["type", "endpoint"],
                  let type = value["type"] as? String,
                  let endpoint = value["endpoint"] as? String else {
                throw SwanError.malformed("PLC document service is malformed")
            }
            services[name] = .init(type: type, endpoint: endpoint)
        }
        // Reuse regular-operation validation for every state field and key.
        _ = try PLCUnsignedRegularOperation(
            rotationKeys: rotationKeys,
            verificationMethods: verificationMethods,
            alsoKnownAs: alsoKnownAs,
            services: services,
            prev: nil
        )
        return .init(
            did: did,
            rotationKeys: rotationKeys,
            verificationMethods: verificationMethods,
            alsoKnownAs: alsoKnownAs,
            services: services
        )
    }

    private func decodeAndVerifyAudit(_ data: Data, expectedDID: String) throws -> [PLCAuditEntry] {
        try StrictJSON.validate(data)
        guard let rawEntries = try JSONSerialization.jsonObject(with: data) as? [[String: Any]],
              !rawEntries.isEmpty,
              rawEntries.count <= 10_000 else {
            throw SwanError.malformed("PLC audit log is malformed")
        }
        struct ValidatedEntry {
            let entry: PLCAuditEntry
            let createdAt: Date
        }

        var entries = [ValidatedEntry]()
        var seenCIDs = Set<String>()
        var previousCreatedAt: Date?
        for raw in rawEntries {
            guard Set(raw.keys) == ["did", "operation", "cid", "nullified", "createdAt"],
                  let did = raw["did"] as? String,
                  did == expectedDID,
                  let operationObject = raw["operation"],
                  JSONSerialization.isValidJSONObject(operationObject),
                  let cidText = raw["cid"] as? String,
                  raw["nullified"] is Bool,
                  let createdAt = raw["createdAt"] as? String,
                  let createdAtDate = canonicalTimestampDate(createdAt),
                  previousCreatedAt.map({ createdAtDate >= $0 }) ?? true else {
                throw SwanError.malformed("PLC audit entry is malformed")
            }
            let operationData = try JSONSerialization.data(
                withJSONObject: operationObject,
                options: [.sortedKeys]
            )
            let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
            let cid = try CID.parse(cidText)
            guard cid.string == cidText,
                  cid.codec == .dagCBOR,
                  cid.multihash.algorithm == Multihash.sha256Code,
                  cid.multihash.length == Multihash.sha256Length,
                  try operation.cid.string == cidText,
                  seenCIDs.insert(cidText).inserted else {
                throw SwanError.unauthorized("PLC audit operation CID is invalid")
            }
            let entry = PLCAuditEntry(
                did: did,
                operation: operation,
                cid: cidText,
                nullified: false,
                createdAt: createdAt
            )
            if entries.isEmpty {
                guard operation.prev == nil else {
                    throw SwanError.unauthorized("PLC audit does not start with genesis")
                }
                try PLCOperationCodec.verifyGenesis(operation, expectedDID: expectedDID)
            } else if operation.prev == nil {
                throw SwanError.unauthorized("PLC audit contains multiple genesis operations")
            }
            entries.append(.init(entry: entry, createdAt: createdAtDate))
            previousCreatedAt = createdAtDate
        }

        var activeIndices = [0]
        for proposedIndex in entries.indices.dropFirst() {
            let proposed = entries[proposedIndex]
            guard let proposedPrev = proposed.entry.operation.prev,
                  let parentPosition = activeIndices.firstIndex(where: {
                      entries[$0].entry.cid == proposedPrev
                  }),
                  let parentOperation = entries[activeIndices[parentPosition]]
                  .entry.operation.regular else {
                throw SwanError.unauthorized("PLC audit operation prev is not active")
            }
            let rotationKeys = parentOperation.rotationKeys
            if parentPosition == activeIndices.count - 1 {
                _ = try PLCOperationCodec.verify(
                    proposed.entry.operation,
                    authorizedRotationKeys: rotationKeys
                )
                activeIndices.append(proposedIndex)
                continue
            }

            let firstDisputed = entries[activeIndices[parentPosition + 1]]
            let disputedSignerIndex = try PLCOperationCodec.verify(
                firstDisputed.entry.operation,
                authorizedRotationKeys: rotationKeys
            )
            guard disputedSignerIndex > 0 else {
                throw SwanError.unauthorized(
                    "PLC recovery cannot supersede an equal-authority operation"
                )
            }
            _ = try PLCOperationCodec.verify(
                proposed.entry.operation,
                authorizedRotationKeys: Array(rotationKeys[..<disputedSignerIndex])
            )
            let recoveryAge = proposed.createdAt.timeIntervalSince(firstDisputed.createdAt)
            guard recoveryAge >= 0, recoveryAge <= 72 * 60 * 60 else {
                throw SwanError.unauthorized("PLC recovery exceeds the 72-hour window")
            }
            activeIndices.removeSubrange((parentPosition + 1)...)
            activeIndices.append(proposedIndex)
        }

        let activeCIDs = Set(activeIndices.map { entries[$0].entry.cid })
        return entries.map { validated in
            PLCAuditEntry(
                did: validated.entry.did,
                operation: validated.entry.operation,
                cid: validated.entry.cid,
                nullified: !activeCIDs.contains(validated.entry.cid),
                createdAt: validated.entry.createdAt
            )
        }
    }

    private func canonicalTimestampDate(_ value: String) -> Date? {
        let bytes = Array(value.utf8)
        guard bytes.count == 24,
              bytes[4] == UInt8(ascii: "-"),
              bytes[7] == UInt8(ascii: "-"),
              bytes[10] == UInt8(ascii: "T"),
              bytes[13] == UInt8(ascii: ":"),
              bytes[16] == UInt8(ascii: ":"),
              bytes[19] == UInt8(ascii: "."),
              bytes[23] == UInt8(ascii: "Z"),
              bytes.enumerated().allSatisfy({ index, byte in
                  [4, 7, 10, 13, 16, 19, 23].contains(index) ||
                      (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
              }) else {
            return nil
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        guard let date = formatter.date(from: value), formatter.string(from: date) == value else {
            return nil
        }
        return date
    }
}

private func plcIsLoopbackLiteral(_ host: String) -> Bool {
    let canonical = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    if canonical == "::1" { return true }
    let parts = canonical.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4,
          let first = UInt8(parts[0]),
          parts.allSatisfy({ part in
              guard let value = UInt8(part) else { return false }
              return String(value) == part
          }) else {
        return false
    }
    return first == 127
}
