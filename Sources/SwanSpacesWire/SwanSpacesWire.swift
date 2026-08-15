import Foundation
import SwanCore

/// Profile-level descriptors supplement the checked-in Petrel output under
/// `Generated/`. They give Swan a compact complete-coverage registry without
/// forcing routing code to switch over arbitrary endpoint strings.
public struct SpaceDeclarationDescriptor: Sendable, Codable, Equatable {
    public let nsid: String
    public let keyType: String
    public let name: String
    public let collections: [String]
}

public enum XRPCMethodKind: String, Sendable, Codable {
    case query
    case procedure
    case subscription
}

public struct XRPCMethodDescriptor: Sendable, Codable, Equatable {
    public let nsid: String
    public let kind: XRPCMethodKind
    public let inputEncoding: String?
    public let outputEncoding: String?
    public let declaredErrors: [String]
}

public enum PermissionedData0016 {
    public static let profileID = "permissioned-data-0016-2026-08-15"

    /// Mechanically transcribed bootstrap registry from the profile's verified
    /// lexicon manifest. Petrel's opt-in server-contract generation replaces
    /// this file after the isolated generator prerequisite is accepted.
    public static let methods: [XRPCMethodDescriptor] = [
        .init(nsid: "com.atproto.space.applyWrites", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "RecordNotFound", "RecordAlreadyExists"]),
        .init(nsid: "com.atproto.space.createRecord", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "RecordAlreadyExists"]),
        .init(nsid: "com.atproto.space.deleteRecord", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceNotFound"]),
        .init(nsid: "com.atproto.space.getBlob", kind: .query, inputEncoding: nil, outputEncoding: "*/*", declaredErrors: ["BlobNotFound", "SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.getDelegationToken", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: []),
        .init(nsid: "com.atproto.space.getLatestCommit", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.getRecord", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["RecordNotFound", "SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.getRepo", kind: .query, inputEncoding: nil, outputEncoding: "application/vnd.ipld.car", declaredErrors: ["SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.getSpaceCredential", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "SpaceDeleted", "UserNotAuthorized", "AppNotAuthorized", "NotAuthorized", "InvalidDelegationToken", "InvalidClientAttestation"]),
        .init(nsid: "com.atproto.space.listBlobs", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.listRecords", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.listRepoOps", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated"]),
        .init(nsid: "com.atproto.space.listRepos", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound"]),
        .init(nsid: "com.atproto.space.listSpaces", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: []),
        .init(nsid: "com.atproto.space.notifySpaceDeleted", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: []),
        .init(nsid: "com.atproto.space.notifyWrite", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: []),
        .init(nsid: "com.atproto.space.putRecord", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceNotFound"]),
        .init(nsid: "com.atproto.space.registerNotify", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceNotFound", "ServiceNotResolvable"]),
        .init(nsid: "com.atproto.space.unregisterNotify", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["SpaceNotFound"]),
        .init(nsid: "com.atproto.simplespace.addMember", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["SpaceNotFound", "NotSpaceOwner"]),
        .init(nsid: "com.atproto.simplespace.checkUserAccess", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: []),
        .init(nsid: "com.atproto.simplespace.createSpace", kind: .procedure, inputEncoding: "application/json", outputEncoding: "application/json", declaredErrors: ["SpaceAlreadyExists", "UnsupportedPolicy", "UnsupportedAppAccess"]),
        .init(nsid: "com.atproto.simplespace.deleteSpace", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["SpaceNotFound", "NotSpaceOwner"]),
        .init(nsid: "com.atproto.simplespace.getSpace", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound"]),
        .init(nsid: "com.atproto.simplespace.listMembers", kind: .query, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: ["SpaceNotFound"]),
        .init(nsid: "com.atproto.simplespace.removeMember", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["SpaceNotFound", "NotSpaceOwner"]),
        .init(nsid: "com.atproto.simplespace.updateSpace", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["SpaceNotFound", "NotSpaceOwner", "UnsupportedPolicy", "UnsupportedAppAccess"]),
    ]
}

public protocol XRPCServerRequestContext: Sendable {}

public protocol XRPCServerHandler: Sendable {
    associatedtype Context: XRPCServerRequestContext
    associatedtype Input: Sendable
    associatedtype Output: Sendable
    func handle(_ input: Input, context: Context) async throws -> Output
}
