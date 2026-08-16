import Foundation

public struct ModerationReportRequest: Sendable, Equatable {
    public let subject: String
    public let reason: String
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
    func send(host: String, peer: String, path: String, body: Data, maximumResponseBytes: Int) async throws -> ModerationTransportResponse
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
}

/// Bounded moderation delivery. The adapter deliberately sends a redacted
/// category-only envelope: provider payloads, subject identifiers, and free
/// text never cross the service boundary or enter logs.
public struct ModerationServiceAdapter: Sendable {
    private let transport: any ModerationTransport
    private let allowedHost: String
    private let pinnedPeer: String
    private let maximumBodyBytes: Int
    private let maximumResponseBytes = 16 * 1_024

    public init(transport: any ModerationTransport, allowedHost: String, pinnedPeer: String, maximumBodyBytes: Int = 64 * 1_024) throws {
        guard !allowedHost.isEmpty, !pinnedPeer.isEmpty, (64...1_024 * 1_024).contains(maximumBodyBytes) else {
            throw ModerationServiceAdapterError.invalidConfiguration
        }
        self.transport = transport
        self.allowedHost = allowedHost
        self.pinnedPeer = pinnedPeer
        self.maximumBodyBytes = maximumBodyBytes
    }

    public func submit(_ request: ModerationReportRequest) async throws -> ModerationReportResult {
        guard (1...128).contains(request.reason.utf8.count),
              request.reason.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }),
              !request.subject.isEmpty,
              request.subject.utf8.count <= 512,
              request.details.map({ $0.utf8.count <= maximumBodyBytes }) ?? true else {
            throw ModerationServiceAdapterError.invalidReport
        }
        let envelope = try JSONEncoder().encode(RedactedReport(reason: request.reason))
        guard envelope.count <= maximumBodyBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        let response = try await transport.send(
            host: allowedHost,
            peer: pinnedPeer,
            path: "/reports",
            body: envelope,
            maximumResponseBytes: maximumResponseBytes
        )
        guard response.peer == pinnedPeer else { throw ModerationServiceAdapterError.peerMismatch }
        guard response.body.count <= maximumResponseBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        guard (200...299).contains(response.status) else { throw ModerationServiceAdapterError.rejected }
        return .init(accepted: true, status: response.status)
    }

    private struct RedactedReport: Codable {
        let reason: String
        let schema: String

        init(reason: String) {
            self.reason = reason
            schema = "swan.moderation.report.v1"
        }
    }
}
