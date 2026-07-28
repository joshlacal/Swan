import Foundation
import Testing
@testable import SwanPublicWire

@Suite("Swan public wire profile")
struct SwanPublicWireTests {
    @Test
    func profileIsFiniteOrderedAndExact() throws {
        let methods = PublicDataTesting20260727.methods
        let expected: [PublicXRPCMethodDescriptor] = [
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
        #expect(methods.count == 12)
        #expect(Set(methods.map(\.nsid)).count == methods.count)
        #expect(methods == expected)

        struct Profile: Decodable {
            let id: String
            let endpoints: [String]
        }
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let profile = try JSONDecoder().decode(
            Profile.self,
            from: Data(contentsOf: root.appending(path: "Profiles/public-data-testing-2026-07-27.json"))
        )
        #expect(profile.id == PublicDataTesting20260727.profileID)
        #expect(profile.endpoints == expected.map(\.nsid))
    }
}

private struct ApplyWritesSentinel: ComAtprotoRepoApplyWrites.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoRepoApplyWrites.Input, context: Int) async throws
        -> ComAtprotoRepoApplyWrites.Output { fatalError() }
}
private struct CreateRecordSentinel: ComAtprotoRepoCreateRecord.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoRepoCreateRecord.Input, context: Int) async throws
        -> ComAtprotoRepoCreateRecord.Output { fatalError() }
}
private struct DeleteRecordSentinel: ComAtprotoRepoDeleteRecord.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoRepoDeleteRecord.Input, context: Int) async throws
        -> ComAtprotoRepoDeleteRecord.Output { fatalError() }
}
private struct DescribeRepoSentinel: ComAtprotoRepoDescribeRepo.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoRepoDescribeRepo.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoRepoDescribeRepo.Output { fatalError() }
}
private struct GetRecordSentinel: ComAtprotoRepoGetRecord.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoRepoGetRecord.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoRepoGetRecord.Output { fatalError() }
}
private struct ListRecordsSentinel: ComAtprotoRepoListRecords.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoRepoListRecords.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoRepoListRecords.Output { fatalError() }
}
private struct PutRecordSentinel: ComAtprotoRepoPutRecord.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoRepoPutRecord.Input, context: Int) async throws
        -> ComAtprotoRepoPutRecord.Output { fatalError() }
}
private struct UploadBlobSentinel: ComAtprotoRepoUploadBlob.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoRepoUploadBlob.Input, context: Int) async throws
        -> ComAtprotoRepoUploadBlob.Output { fatalError() }
}
private struct GetBlobSentinel: ComAtprotoSyncGetBlob.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoSyncGetBlob.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoSyncGetBlob.Output { fatalError() }
}
private struct GetLatestCommitSentinel: ComAtprotoSyncGetLatestCommit.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoSyncGetLatestCommit.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoSyncGetLatestCommit.Output { fatalError() }
}
private struct GetRepoSentinel: ComAtprotoSyncGetRepo.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoSyncGetRepo.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoSyncGetRepo.Output { fatalError() }
}
private struct GetRepoStatusSentinel: ComAtprotoSyncGetRepoStatus.ServerHandler {
    typealias Context = Int
    func handle(parameters: ComAtprotoSyncGetRepoStatus.Parameters, input: Void, context: Int) async throws
        -> ComAtprotoSyncGetRepoStatus.Output { fatalError() }
}
