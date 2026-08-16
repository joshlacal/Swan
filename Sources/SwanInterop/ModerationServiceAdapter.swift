import Foundation
import Crypto
import SwanCore

public struct ModerationTransportRequest: Sendable, Equatable {
    public let host: String
    public let pinnedPeer: String
    public let path: String
    public let body: Data
    public let maximumResponseBytes: Int
    public let subject: String
    public let details: String?
}

public struct ModerationReportRequest: Sendable, Equatable {
    public let subject: String
    public let reason: String
    public var reasonType: String { reason }
    public let details: String?

    public init(subject: String, reason: String, details: String? = nil) {
        self.subject = subject
        self.reason = reason
        self.details = details
    }
}

public struct ModerationTransportResponse: Sendable, Equatable {
    public let status: Int
    public let body: Data
    public let peer: String

    public init(status: Int, body: Data, peer: String) {
        self.status = status
        self.body = body
        self.peer = peer
    }
}

public protocol ModerationTransport: Sendable {
    func send(_ request: ModerationTransportRequest) async throws -> ModerationTransportResponse
}

public enum ModerationServiceAdapterError: Error, Sendable, Equatable {
    case invalidConfiguration
    case invalidReport
    case responseTooLarge
    case peerMismatch
    case rejected
}

public struct ModerationReportResult: Sendable, Equatable {
    public let accepted: Bool
    public let status: Int
    public let output: Data
}

/// Bounded moderation delivery. Subject and details are sent only as
/// correlation values produced by a deployment-provided keyed HMAC; unlike a
/// plain hash this is not guessable from a public DID or short report text.
/// The trusted moderation transport receives the typed envelope and is solely
/// responsible for resolving those correlations. Raw values never enter logs.
public struct ModerationServiceAdapter: Sendable {
    private let transport: any ModerationTransport
    private let allowedHost: String
    private let pinnedPeer: String
    private let maximumBodyBytes: Int
    private let correlationKey: SymmetricKey
    private let correlationKeyID: String
    private let correlationKeyVersion: Int
    private let maximumResponseBytes = 16 * 1_024

    public init(transport: any ModerationTransport, allowedHost: String, pinnedPeer: String, maximumBodyBytes: Int = 64 * 1_024, correlationKeyID: String, correlationKeyVersion: Int, correlationKey: Data) throws {
        guard !allowedHost.isEmpty, !pinnedPeer.isEmpty, (64...1_024 * 1_024).contains(maximumBodyBytes), (1...128).contains(correlationKeyID.utf8.count), correlationKeyVersion > 0, correlationKey.count >= 32, Set(correlationKey).count >= 4 else {
            throw ModerationServiceAdapterError.invalidConfiguration
        }
        self.transport = transport
        self.allowedHost = allowedHost
        self.pinnedPeer = pinnedPeer
        self.maximumBodyBytes = maximumBodyBytes
        self.correlationKey = SymmetricKey(data: correlationKey)
        self.correlationKeyID = correlationKeyID
        self.correlationKeyVersion = correlationKeyVersion
    }

    public func submit(_ request: ModerationReportRequest) async throws -> ModerationReportResult {
        guard (1...128).contains(request.reason.utf8.count),
              request.reason.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }),
              !request.subject.isEmpty,
              request.subject.utf8.count <= 512,
              request.details.map({ $0.utf8.count <= maximumBodyBytes }) ?? true else {
            throw ModerationServiceAdapterError.invalidReport
        }
        let envelope = try JSONEncoder().encode(RedactedReport(
            subjectCorrelation: correlation(for: request.subject),
            reason: request.reason,
            detailsCorrelation: request.details.map { correlation(for: $0) },
            keyID: correlationKeyID,
            keyVersion: correlationKeyVersion
        ))
        guard envelope.count <= maximumBodyBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        let response = try await transport.send(.init(host: allowedHost, pinnedPeer: pinnedPeer, path: "/reports", body: envelope, maximumResponseBytes: maximumResponseBytes, subject: request.subject, details: request.details))
        guard response.peer == pinnedPeer else { throw ModerationServiceAdapterError.peerMismatch }
        guard response.body.count <= maximumResponseBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        guard (200...299).contains(response.status) else { throw ModerationServiceAdapterError.rejected }
        return .init(accepted: true, status: response.status, output: response.body)
    }

    private func correlation(for value: String) -> String {
        Hex.encode(HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: correlationKey))
    }

    private struct RedactedReport: Codable {
        let subjectCorrelation: String
        let reason: String
        let detailsCorrelation: String?
        let schema: String
        let keyID: String
        let keyVersion: Int

        init(subjectCorrelation: String, reason: String, detailsCorrelation: String?, keyID: String, keyVersion: Int) {
            self.subjectCorrelation = subjectCorrelation
            self.reason = reason
            self.detailsCorrelation = detailsCorrelation
            self.keyID = keyID
            self.keyVersion = keyVersion
            schema = "swan.moderation.report.v1"
        }
    }
}
