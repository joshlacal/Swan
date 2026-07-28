import Testing
@testable import SwanPublicWire

@Suite("Swan public wire profile")
struct SwanPublicWireTests {
    @Test
    func profileIsFiniteAndOrdered() {
        let methods = PublicDataTesting20260727.methods
        let expected = [
            "com.atproto.repo.applyWrites", "com.atproto.repo.createRecord",
            "com.atproto.repo.deleteRecord", "com.atproto.repo.describeRepo",
            "com.atproto.repo.getRecord", "com.atproto.repo.listRecords",
            "com.atproto.repo.putRecord", "com.atproto.repo.uploadBlob",
            "com.atproto.sync.getBlob", "com.atproto.sync.getLatestCommit",
            "com.atproto.sync.getRepo", "com.atproto.sync.getRepoStatus",
        ]
        #expect(methods.count == 12)
        #expect(Set(methods.map(\.nsid)).count == methods.count)
        #expect(methods.map(\.nsid) == expected)
        #expect(methods.allSatisfy { !($0.outputEncoding?.isEmpty ?? false) })
        #expect(methods.first?.declaredErrors == ["InvalidSwap"])
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
