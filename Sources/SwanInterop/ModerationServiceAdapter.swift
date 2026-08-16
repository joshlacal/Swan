import Foundation
import Crypto
import SwanCore
import SwanAccounts
import Petrel
import SwanPublicRepository

public struct ModerationTransportRequest: Sendable, Equatable {
    public let host: String
    public let pinnedPeer: String
    public let path: String
    public let body: Data
    public let maximumResponseBytes: Int
    public let subject: ModerationSubject
    public let details: String?
}

public enum ModerationSubject: Sendable, Equatable, Codable {
    case repoRef(did: String)
    case strongRef(uri: String, cid: String)

    enum CodingKeys: String, CodingKey { case type = "$type", did, uri, cid }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "com.atproto.admin.defs#repoRef": self = .repoRef(did: try c.decode(String.self, forKey: .did))
        case "com.atproto.repo.strongRef": self = .strongRef(uri: try c.decode(String.self, forKey: .uri), cid: try c.decode(String.self, forKey: .cid))
        default: throw DecodingError.dataCorruptedError(forKey: .type, in: c, debugDescription: "unknown moderation subject")
        }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .repoRef(let did): try c.encode("com.atproto.admin.defs#repoRef", forKey: .type); try c.encode(did, forKey: .did)
        case .strongRef(let uri, let cid): try c.encode("com.atproto.repo.strongRef", forKey: .type); try c.encode(uri, forKey: .uri); try c.encode(cid, forKey: .cid)
        }
    }
}

public struct ModerationReportRequest: Sendable, Equatable {
    public let subject: ModerationSubject
    public let reasonType: String
    public let reason: String?
    public let details: String?

    public init(subject: ModerationSubject, reasonType: String, reason: String? = nil, details: String? = nil) {
        self.subject = subject
        self.reasonType = reasonType
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
    case invalidOutput
}

public struct ModerationReportResult: Sendable, Equatable {
    public let accepted: Bool
    public let status: Int
    public let output: Data
    public let reportedBy: String?
}

/// Bounded moderation delivery. Subject and details are sent only as
/// correlation values produced by a deployment-provided keyed HMAC. The
/// trusted moderation transport also receives the typed subject/details over
/// its pinned channel; HMAC values are for log correlation only and are not a
/// privacy transformation for public identifiers.
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
        guard (1...256).contains(request.reasonType.utf8.count),
              request.reasonType.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." || $0 == "/" || $0 == "#" }),
              request.reason.map({ $0.utf8.count <= 512 }) ?? true,
              request.details.map({ $0.utf8.count <= maximumBodyBytes }) ?? true,
              valid(subject: request.subject) else {
            throw ModerationServiceAdapterError.invalidReport
        }
        let envelope = try JSONEncoder().encode(TypedReport(reasonType: request.reasonType, subject: request.subject, reason: request.reason))
        guard envelope.count <= maximumBodyBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        let response = try await transport.send(.init(host: allowedHost, pinnedPeer: pinnedPeer, path: "/reports", body: envelope, maximumResponseBytes: maximumResponseBytes, subject: request.subject, details: request.details))
        guard response.peer == pinnedPeer else { throw ModerationServiceAdapterError.peerMismatch }
        guard response.body.count <= maximumResponseBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        guard (200...299).contains(response.status) else { throw ModerationServiceAdapterError.rejected }
        guard let output = try? JSONDecoder().decode(ModerationReportOutput.self, from: response.body), output.reasonType == request.reasonType, output.subject == request.subject else { throw ModerationServiceAdapterError.invalidOutput }
        return .init(accepted: true, status: response.status, output: response.body, reportedBy: output.reportedBy)
    }

    private func correlation(for value: String) -> String {
        Hex.encode(HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: correlationKey))
    }

    private func valid(subject: ModerationSubject) -> Bool {
        switch subject {
        case .repoRef(let did): return did.hasPrefix("did:") && (try? AccountIdentifiers.validateDID(did)) != nil
        case .strongRef(let uri, let cid):
            guard uri.hasPrefix("at://"), uri.utf8.count <= 2_048, let parsed = try? CID.parse(cid), (try? PublicRepositoryCID.validate(parsed)) != nil else { return false }
            return true
        }
    }

    private struct TypedReport: Codable { let reasonType: String; let subject: ModerationSubject; let reason: String? }
    public struct ModerationReportOutput: Codable, Sendable, Equatable { public let id: String; public let reasonType: String; public let subject: ModerationSubject; public let reportedBy: String; public let createdAt: String }

    private struct RedactedReport: Codable {
        let subjectCorrelation: String
        let reason: String?
        let reasonType: String
        let detailsCorrelation: String?
        let schema: String
        let keyID: String
        let keyVersion: Int

        init(subjectCorrelation: String, reason: String?, reasonType: String, detailsCorrelation: String?, keyID: String, keyVersion: Int) {
            self.subjectCorrelation = subjectCorrelation
            self.reason = reason
            self.reasonType = reasonType
            self.detailsCorrelation = detailsCorrelation
            self.keyID = keyID
            self.keyVersion = keyVersion
            schema = "swan.moderation.report.v1"
        }
    }
}
