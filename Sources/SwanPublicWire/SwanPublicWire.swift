import Foundation

public enum PublicXRPCMethodKind: String, Sendable, Codable {
    case query
    case procedure
}

public struct PublicXRPCMethodDescriptor: Sendable, Codable, Equatable {
    public let nsid: String
    public let kind: PublicXRPCMethodKind
    public let inputEncoding: String?
    public let outputEncoding: String?
    public let declaredErrors: [String]

    public init(
        nsid: String,
        kind: PublicXRPCMethodKind,
        inputEncoding: String?,
        outputEncoding: String?,
        declaredErrors: [String]
    ) {
        self.nsid = nsid
        self.kind = kind
        self.inputEncoding = inputEncoding
        self.outputEncoding = outputEncoding
        self.declaredErrors = declaredErrors
    }
}

public enum PublicDataTesting20260727 {
    public static let profileID = "public-data-testing-2026-07-27"

    public static let methods: [PublicXRPCMethodDescriptor] = [
        .init(nsid: "com.atproto.repo.applyWrites", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["InvalidSwap"]),
        .init(nsid: "com.atproto.repo.createRecord", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["InvalidSwap"]),
        .init(nsid: "com.atproto.repo.deleteRecord", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["InvalidSwap"]),
        .init(nsid: "com.atproto.repo.describeRepo", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: []),
        .init(nsid: "com.atproto.repo.getRecord", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["RecordNotFound"]),
        .init(nsid: "com.atproto.repo.listRecords", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: []),
        .init(nsid: "com.atproto.repo.putRecord", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["InvalidSwap"]),
        .init(nsid: "com.atproto.repo.uploadBlob", kind: .procedure, inputEncoding: "*/*", outputEncoding: "application/json", declaredErrors: []),
        .init(nsid: "com.atproto.sync.getBlob", kind: .query, inputEncoding: nil, outputEncoding: "*/*", declaredErrors: ["BlobNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.sync.getLatestCommit", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.sync.getRepo", kind: .query, inputEncoding: nil, outputEncoding: "application/vnd.ipld.car", declaredErrors: ["RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.sync.getRepoStatus", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["RepoNotFound"]),
    ]
}
