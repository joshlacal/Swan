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

    @Test
    func successorProfileKeepsDefinitionsSeparateFromEndpointContracts() throws {
        let methods = PublicDataTesting20260730.methods
        let expectedLexicons = [
            "com.atproto.repo.applyWrites",
            "com.atproto.repo.createRecord",
            "com.atproto.repo.defs",
            "com.atproto.repo.deleteRecord",
            "com.atproto.repo.describeRepo",
            "com.atproto.repo.getRecord",
            "com.atproto.repo.listRecords",
            "com.atproto.repo.putRecord",
            "com.atproto.repo.uploadBlob",
            "com.atproto.server.confirmEmail",
            "com.atproto.server.requestEmailConfirmation",
            "com.atproto.server.requestEmailUpdate",
            "com.atproto.server.requestPasswordReset",
            "com.atproto.server.resetPassword",
            "com.atproto.server.updateEmail",
            "com.atproto.sync.defs",
            "com.atproto.sync.getBlob",
            "com.atproto.sync.getLatestCommit",
            "com.atproto.sync.getRepo",
            "com.atproto.sync.getRepoStatus",
        ]

        struct Profile: Decodable {
            let id: String
            let lexicons: [String]
            let endpoints: [String]
        }
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let profile = try JSONDecoder().decode(
            Profile.self,
            from: Data(contentsOf: root.appending(path: "Profiles/public-data-testing-2026-07-30.json"))
        )

        #expect(profile.id == PublicDataTesting20260730.profileID)
        #expect(profile.lexicons == expectedLexicons)
        #expect(profile.lexicons.count == 20)
        #expect(Set(profile.lexicons).count == 20)
        #expect(profile.endpoints == methods.map(\.nsid))
        #expect(profile.endpoints.count == 18)
        #expect(Set(profile.endpoints).count == 18)
        #expect(!profile.endpoints.contains("com.atproto.repo.defs"))
        #expect(!profile.endpoints.contains("com.atproto.sync.defs"))
    }

    @Test
    func testPublicDataTesting20260805IncludesSubscribeReposSubscription() throws {
        let methods = PublicDataTesting20260805.methods
        #expect(methods.count == 19)
        #expect(Set(methods.map(\.nsid)).count == methods.count)

        let subscribeRepos = methods.last
        #expect(subscribeRepos?.nsid == "com.atproto.sync.subscribeRepos")
        #expect(subscribeRepos?.kind == .subscription)
        #expect(subscribeRepos?.inputEncoding == nil)
        #expect(subscribeRepos?.outputEncoding == nil)
        #expect(subscribeRepos?.declaredErrors == ["FutureCursor", "ConsumerTooSlow"])

        let generatedDescriptor = ComAtprotoSyncSubscribeRepos.endpointDescriptor
        #expect(generatedDescriptor.nsid == "com.atproto.sync.subscribeRepos")
        #expect(generatedDescriptor.kind == "subscription")
        #expect(generatedDescriptor.inputEncoding == nil)
        #expect(generatedDescriptor.outputEncoding == nil)
        #expect(generatedDescriptor.declaredErrors == ["FutureCursor", "ConsumerTooSlow"])

        struct Profile: Decodable {
            let id: String
            let lexicons: [String]
            let endpoints: [String]
        }
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let profile = try JSONDecoder().decode(
            Profile.self,
            from: Data(contentsOf: root.appending(path: "Profiles/public-data-testing-2026-08-05.json"))
        )

        #expect(profile.id == PublicDataTesting20260805.profileID)
        #expect(profile.lexicons.count == 21)
        #expect(Set(profile.lexicons).count == 21)
        #expect(profile.lexicons.last == "com.atproto.sync.subscribeRepos")
        #expect(profile.endpoints == methods.map(\.nsid))
        #expect(profile.endpoints.count == 19)
        #expect(Set(profile.endpoints).count == 19)
    }

    @Test
    func successorProfileAddsExactAccountEmailMethodDescriptors() {
        let accountEmailMethods = Array(PublicDataTesting20260730.methods[8...13])
        #expect(accountEmailMethods == [
            .init(nsid: "com.atproto.server.confirmEmail", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["AccountNotFound", "ExpiredToken", "InvalidToken", "InvalidEmail"]),
            .init(nsid: "com.atproto.server.requestEmailConfirmation", kind: .procedure, inputEncoding: nil, outputEncoding: nil, declaredErrors: []),
            .init(nsid: "com.atproto.server.requestEmailUpdate", kind: .procedure, inputEncoding: nil, outputEncoding: "application/json", declaredErrors: []),
            .init(nsid: "com.atproto.server.requestPasswordReset", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: []),
            .init(nsid: "com.atproto.server.resetPassword", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["ExpiredToken", "InvalidToken"]),
            .init(nsid: "com.atproto.server.updateEmail", kind: .procedure, inputEncoding: "application/json", outputEncoding: nil, declaredErrors: ["ExpiredToken", "InvalidToken", "TokenRequired"]),
        ])

        assertDescriptor(
            ComAtprotoServerConfirmEmail.endpointDescriptor,
            nsid: "com.atproto.server.confirmEmail",
            input: "application/json",
            output: nil,
            errors: ["AccountNotFound", "ExpiredToken", "InvalidToken", "InvalidEmail"]
        )
        assertDescriptor(
            ComAtprotoServerRequestEmailConfirmation.endpointDescriptor,
            nsid: "com.atproto.server.requestEmailConfirmation",
            input: nil,
            output: nil,
            errors: []
        )
        assertDescriptor(
            ComAtprotoServerRequestEmailUpdate.endpointDescriptor,
            nsid: "com.atproto.server.requestEmailUpdate",
            input: nil,
            output: "application/json",
            errors: []
        )
        assertDescriptor(
            ComAtprotoServerRequestPasswordReset.endpointDescriptor,
            nsid: "com.atproto.server.requestPasswordReset",
            input: "application/json",
            output: nil,
            errors: []
        )
        assertDescriptor(
            ComAtprotoServerResetPassword.endpointDescriptor,
            nsid: "com.atproto.server.resetPassword",
            input: "application/json",
            output: nil,
            errors: ["ExpiredToken", "InvalidToken"]
        )
        assertDescriptor(
            ComAtprotoServerUpdateEmail.endpointDescriptor,
            nsid: "com.atproto.server.updateEmail",
            input: "application/json",
            output: nil,
            errors: ["ExpiredToken", "InvalidToken", "TokenRequired"]
        )
    }

    @Test
    func accountEmailGeneratedInputsOutputsAndErrorsAreExact() {
        let confirmation = ComAtprotoServerConfirmEmail.Input(email: "person@example.com", token: "123456")
        #expect(confirmation.email == "person@example.com")
        #expect(confirmation.token == "123456")
        #expect(ComAtprotoServerConfirmEmail.Error.allCasesForTesting == [
            "AccountNotFound", "ExpiredToken", "InvalidToken", "InvalidEmail",
        ])

        let emailUpdate = ComAtprotoServerRequestEmailUpdate.Output(tokenRequired: true)
        #expect(emailUpdate.tokenRequired)

        let updatedEmail = ComAtprotoServerUpdateEmail.Input(
            email: "new@example.com",
            emailAuthFactor: true,
            token: "654321"
        )
        #expect(updatedEmail.email == "new@example.com")
        #expect(updatedEmail.emailAuthFactor == true)
        #expect(updatedEmail.token == "654321")
        #expect(ComAtprotoServerUpdateEmail.Error.allCasesForTesting == [
            "ExpiredToken", "InvalidToken", "TokenRequired",
        ])

        let resetRequest = ComAtprotoServerRequestPasswordReset.Input(email: "person@example.com")
        #expect(resetRequest.email == "person@example.com")

        let reset = ComAtprotoServerResetPassword.Input(token: "123456", password: "new password")
        #expect(reset.token == "123456")
        #expect(reset.password == "new password")
        #expect(ComAtprotoServerResetPassword.Error.allCasesForTesting == [
            "ExpiredToken", "InvalidToken",
        ])
    }
}

private extension ComAtprotoServerConfirmEmail.Error {
    static var allCasesForTesting: [String] {
        [
            Self.accountNotFound.rawValue,
            Self.expiredToken.rawValue,
            Self.invalidToken.rawValue,
            Self.invalidEmail.rawValue,
        ]
    }
}

private extension ComAtprotoServerResetPassword.Error {
    static var allCasesForTesting: [String] {
        [
            Self.expiredToken.rawValue,
            Self.invalidToken.rawValue,
        ]
    }
}

private extension ComAtprotoServerUpdateEmail.Error {
    static var allCasesForTesting: [String] {
        [
            Self.expiredToken.rawValue,
            Self.invalidToken.rawValue,
            Self.tokenRequired.rawValue,
        ]
    }
}

private func assertDescriptor<Descriptor>(
    _ descriptor: Descriptor,
    nsid: String,
    input: String?,
    output: String?,
    errors: [String],
    sourceLocation: SourceLocation = #_sourceLocation
) where Descriptor: PublicWireDescriptor {
    #expect(descriptor.nsid == nsid, sourceLocation: sourceLocation)
    #expect(descriptor.kind == "procedure", sourceLocation: sourceLocation)
    #expect(descriptor.inputEncoding == input, sourceLocation: sourceLocation)
    #expect(descriptor.outputEncoding == output, sourceLocation: sourceLocation)
    #expect(descriptor.declaredErrors == errors, sourceLocation: sourceLocation)
}

private protocol PublicWireDescriptor {
    var nsid: String { get }
    var kind: String { get }
    var inputEncoding: String? { get }
    var outputEncoding: String? { get }
    var declaredErrors: [String] { get }
}

extension ComAtprotoServerConfirmEmail.XRPCMethodDescriptor: PublicWireDescriptor {}
extension ComAtprotoServerRequestEmailConfirmation.XRPCMethodDescriptor: PublicWireDescriptor {}
extension ComAtprotoServerRequestEmailUpdate.XRPCMethodDescriptor: PublicWireDescriptor {}
extension ComAtprotoServerRequestPasswordReset.XRPCMethodDescriptor: PublicWireDescriptor {}
extension ComAtprotoServerResetPassword.XRPCMethodDescriptor: PublicWireDescriptor {}
extension ComAtprotoServerUpdateEmail.XRPCMethodDescriptor: PublicWireDescriptor {}

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
private struct ConfirmEmailSentinel: ComAtprotoServerConfirmEmail.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoServerConfirmEmail.Input, context: Int) async throws {}
}
private struct RequestEmailConfirmationSentinel: ComAtprotoServerRequestEmailConfirmation.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: Void, context: Int) async throws {}
}
private struct RequestEmailUpdateSentinel: ComAtprotoServerRequestEmailUpdate.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: Void, context: Int) async throws
        -> ComAtprotoServerRequestEmailUpdate.Output { fatalError() }
}
private struct RequestPasswordResetSentinel: ComAtprotoServerRequestPasswordReset.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoServerRequestPasswordReset.Input, context: Int) async throws {}
}
private struct ResetPasswordSentinel: ComAtprotoServerResetPassword.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoServerResetPassword.Input, context: Int) async throws {}
}
private struct UpdateEmailSentinel: ComAtprotoServerUpdateEmail.ServerHandler {
    typealias Context = Int
    func handle(parameters: Void, input: ComAtprotoServerUpdateEmail.Input, context: Int) async throws {}
}
