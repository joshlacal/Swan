import Foundation
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
    public let modTool: ModerationModTool?

    public init(subject: ModerationSubject, reasonType: String, reason: String? = nil, details: String? = nil, modTool: ModerationModTool? = nil) {
        self.subject = subject
        self.reasonType = reasonType
        self.reason = reason
        self.details = details
        self.modTool = modTool
    }
}

public struct ModerationModTool: Codable, Sendable, Equatable {
    public let name: String
    public let meta: [String: String]?

    public init(name: String, meta: [String: String]? = nil) {
        self.name = name
        self.meta = meta
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

/// Bounded moderation delivery. The typed subject and optional details are sent
/// over the injected trusted, peer-pinned transport. This adapter makes no
/// claim that public identifiers are hidden or transformed for privacy.
public struct ModerationServiceAdapter: Sendable {
    /// Pinned from com.atproto.moderation.defs#reasonType. Unknown lexicon
    /// values fail closed until this set is deliberately regenerated.
    public static let knownReasonTypes: Set<String> = [
        "com.atproto.moderation.defs#reasonSpam",
        "com.atproto.moderation.defs#reasonViolation",
        "com.atproto.moderation.defs#reasonMisleading",
        "com.atproto.moderation.defs#reasonSexual",
        "com.atproto.moderation.defs#reasonRude",
        "com.atproto.moderation.defs#reasonOther",
        "com.atproto.moderation.defs#reasonAppeal",
        "tools.ozone.report.defs#reasonAppeal",
        "tools.ozone.report.defs#reasonOther",
        "tools.ozone.report.defs#reasonViolenceAnimal",
        "tools.ozone.report.defs#reasonViolenceThreats",
        "tools.ozone.report.defs#reasonViolenceGraphicContent",
        "tools.ozone.report.defs#reasonViolenceGlorification",
        "tools.ozone.report.defs#reasonViolenceExtremistContent",
        "tools.ozone.report.defs#reasonViolenceTrafficking",
        "tools.ozone.report.defs#reasonViolenceOther",
        "tools.ozone.report.defs#reasonSexualAbuseContent",
        "tools.ozone.report.defs#reasonSexualNCII",
        "tools.ozone.report.defs#reasonSexualDeepfake",
        "tools.ozone.report.defs#reasonSexualAnimal",
        "tools.ozone.report.defs#reasonSexualUnlabeled",
        "tools.ozone.report.defs#reasonSexualOther",
        "tools.ozone.report.defs#reasonChildSafetyCSAM",
        "tools.ozone.report.defs#reasonChildSafetyGroom",
        "tools.ozone.report.defs#reasonChildSafetyPrivacy",
        "tools.ozone.report.defs#reasonChildSafetyHarassment",
        "tools.ozone.report.defs#reasonChildSafetyOther",
        "tools.ozone.report.defs#reasonHarassmentTroll",
        "tools.ozone.report.defs#reasonHarassmentTargeted",
        "tools.ozone.report.defs#reasonHarassmentHateSpeech",
        "tools.ozone.report.defs#reasonHarassmentDoxxing",
        "tools.ozone.report.defs#reasonHarassmentOther",
        "tools.ozone.report.defs#reasonMisleadingBot",
        "tools.ozone.report.defs#reasonMisleadingImpersonation",
        "tools.ozone.report.defs#reasonMisleadingSpam",
        "tools.ozone.report.defs#reasonMisleadingScam",
        "tools.ozone.report.defs#reasonMisleadingElections",
        "tools.ozone.report.defs#reasonMisleadingOther",
        "tools.ozone.report.defs#reasonRuleSiteSecurity",
        "tools.ozone.report.defs#reasonRuleProhibitedSales",
        "tools.ozone.report.defs#reasonRuleBanEvasion",
        "tools.ozone.report.defs#reasonRuleOther",
        "tools.ozone.report.defs#reasonSelfHarmContent",
        "tools.ozone.report.defs#reasonSelfHarmED",
        "tools.ozone.report.defs#reasonSelfHarmStunts",
        "tools.ozone.report.defs#reasonSelfHarmSubstances",
        "tools.ozone.report.defs#reasonSelfHarmOther",
    ]
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
        guard Self.knownReasonTypes.contains(request.reasonType),
              request.reason.map({ $0.count <= 2_000 && $0.utf8.count <= 20_000 }) ?? true,
              request.details.map({ $0.utf8.count <= maximumBodyBytes }) ?? true,
              request.modTool.map(valid(modTool:)) ?? true,
              valid(subject: request.subject) else {
            throw ModerationServiceAdapterError.invalidReport
        }
        let envelope = try JSONEncoder().encode(TypedReport(reasonType: request.reasonType, subject: request.subject, reason: request.reason, modTool: request.modTool))
        guard envelope.count <= maximumBodyBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        let response = try await transport.send(.init(host: allowedHost, pinnedPeer: pinnedPeer, path: "/reports", body: envelope, maximumResponseBytes: maximumResponseBytes, subject: request.subject, details: request.details))
        guard response.peer == pinnedPeer else { throw ModerationServiceAdapterError.peerMismatch }
        guard response.body.count <= maximumResponseBytes else { throw ModerationServiceAdapterError.responseTooLarge }
        guard (200...299).contains(response.status) else { throw ModerationServiceAdapterError.rejected }
        guard let output = try? JSONDecoder().decode(ModerationReportOutput.self, from: response.body), output.id > 0,
              output.reasonType == request.reasonType, output.subject == request.subject, output.reason == request.reason,
              (try? AccountIdentifiers.validateDID(output.reportedBy)) != nil,
              ISO8601DateFormatter().date(from: output.createdAt) != nil else { throw ModerationServiceAdapterError.invalidOutput }
        return .init(accepted: true, status: response.status, output: response.body, reportedBy: output.reportedBy)
    }

    private func valid(subject: ModerationSubject) -> Bool {
        switch subject {
        case .repoRef(let did): return did.hasPrefix("did:") && (try? AccountIdentifiers.validateDID(did)) != nil
        case .strongRef(let uri, let cid):
            guard uri.hasPrefix("at://"), uri.utf8.count <= 2_048, let parsed = try? CID.parse(cid), (try? PublicRepositoryCID.validate(parsed)) != nil else { return false }
            return true
        }
    }

    private func valid(modTool: ModerationModTool) -> Bool {
        guard (1...256).contains(modTool.name.utf8.count),
              !modTool.name.utf8.contains(0),
              (modTool.meta?.count ?? 0) <= 32 else { return false }
        return modTool.meta?.allSatisfy {
            (1...128).contains($0.key.utf8.count) && $0.value.utf8.count <= 2_048
                && !$0.key.utf8.contains(0) && !$0.value.utf8.contains(0)
        } ?? true
    }

    private struct TypedReport: Codable { let reasonType: String; let subject: ModerationSubject; let reason: String?; let modTool: ModerationModTool? }
    public struct ModerationReportOutput: Codable, Sendable, Equatable { public let id: Int; public let reasonType: String; public let subject: ModerationSubject; public let reason: String?; public let reportedBy: String; public let createdAt: String }
}
