import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import SwanAccounts
import SwanSQLite
import XCTest

final class PLCAccountPreparationCLITests: XCTestCase {
    private let requestID = "prepare-plc-test-001"
    private let handle = "alice.example.com"
    private let pdsOrigin = "https://pds.example.com"
    private let revision = "3lqby3xuo4k2a"

    func testRealPLCTransportPreservesRequestedFinalURLWithoutRedirects() async throws {
        let server = try TestPLCDirectory(submitBody: Data("OK".utf8))
        defer { server.shutdown() }
        let url = URL(
            string: "http://127.0.0.1:\(server.port)/did:plc:abcdefghijklmnopqrstuvwx/log/audit"
        )!
        let transport = try AsyncHTTPClientPLCTransport()
        let response = try await transport.execute(.init(
            method: .get,
            url: url,
            headers: ["accept": "application/json"],
            body: nil,
            timeout: 5,
            maximumResponseBytes: 1024
        ))
        XCTAssertEqual(response.status, 404)
        XCTAssertEqual(response.redirectCount, 0)
        XCTAssertEqual(response.finalURL, url)
    }

    func testExplicitPinnedLabCompatibilityIsIdempotentSanitizedAndPending() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let server = try TestPLCDirectory(submitBody: Data("OK".utf8))
        defer { server.shutdown() }

        let first = try runPrepare(
            fixture: fixture,
            server: server,
            compatibility: "did-plc-server-0.0.1"
        )
        XCTAssertEqual(first.status, 0, "\(first.error) submit-count=\(server.submitCount)")
        let firstJSON = try decode(first.output)
        XCTAssertEqual(firstJSON["requestID"] as? String, requestID)
        XCTAssertEqual(firstJSON["canonicalHandle"] as? String, handle)
        XCTAssertEqual(firstJSON["pdsOrigin"] as? String, pdsOrigin)
        XCTAssertEqual(firstJSON["repositoryRevision"] as? String, revision)
        XCTAssertNotNil(firstJSON["did"] as? String)
        XCTAssertNotNil(firstJSON["plcOperationCID"] as? String)
        XCTAssertNotNil(firstJSON["publicGenesisCommitCID"] as? String)
        XCTAssertEqual(Set(firstJSON.keys), [
            "requestID", "did", "canonicalHandle", "pdsOrigin",
            "repositoryRevision", "plcOperationCID", "publicGenesisCommitCID",
        ])
        XCTAssertEqual(server.submitCount, 1)

        let retry = try runPrepare(
            fixture: fixture,
            server: server,
            compatibility: "did-plc-server-0.0.1"
        )
        XCTAssertEqual(retry.status, 0, retry.error)
        XCTAssertEqual(try decode(retry.output) as NSDictionary, firstJSON as NSDictionary)
        XCTAssertEqual(server.submitCount, 1)

        let did = try XCTUnwrap(firstJSON["did"] as? String)
        let control = try await SQLiteControlDatabase(dataDirectory: fixture.data)
        let activeAccount = try await control.account(did: did)
        XCTAssertNil(activeAccount)
        try await control.close()

        let mismatch = try runPrepare(
            fixture: fixture,
            server: server,
            compatibility: "did-plc-server-0.0.1",
            handle: "mallory.example.com"
        )
        XCTAssertNotEqual(mismatch.status, 0)
        XCTAssertTrue(mismatch.output.isEmpty)
        XCTAssertFalse(mismatch.error.contains(fixture.operatorSecret))
        XCTAssertFalse(mismatch.error.contains(fixture.encodedKEK))
        XCTAssertEqual(server.submitCount, 1)

        for rendered in [first.output, retry.output, first.error, retry.error] {
            XCTAssertFalse(rendered.contains(fixture.operatorSecret))
            XCTAssertFalse(rendered.contains(fixture.encodedKEK))
            XCTAssertFalse(rendered.contains(fixture.operatorSecretFile.path))
            XCTAssertFalse(rendered.contains(fixture.kekFile.path))
        }
        try assertPersistedData(
            under: fixture.data,
            excludes: [
                Data(fixture.operatorSecret.utf8),
                Data(fixture.encodedKEK.utf8),
                fixture.rawKEK,
            ]
        )
    }

    func testStrictLabRejectsPinnedPlainTextAndNeverPersistsResponseBody() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let server = try TestPLCDirectory(submitBody: Data("OK".utf8))
        defer { server.shutdown() }

        let result = try runPrepare(fixture: fixture, server: server, compatibility: nil)
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertEqual(server.submitCount, 1)
        XCTAssertFalse(result.error.contains("OK"))

        let control = try await SQLiteControlDatabase(dataDirectory: fixture.data)
        let intents = try await control.plcAccountPreparationIntent(requestID: requestID)
        let did = try XCTUnwrap(intents?.did)
        let activeAccount = try await control.account(did: did)
        XCTAssertNil(activeAccount)
        try await control.close()
    }

    func testResponseBodyAndSecretsAreNotProjectedOrPersistedOnFailure() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let responseSentinel = "PLC-RESPONSE-BODY-MUST-NOT-PERSIST-5D6831"
        let server = try TestPLCDirectory(submitBody: Data(responseSentinel.utf8))
        defer { server.shutdown() }

        let result = try runPrepare(
            fixture: fixture,
            server: server,
            compatibility: "did-plc-server-0.0.1"
        )
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertFalse(result.error.contains(responseSentinel))
        try assertPersistedData(
            under: fixture.data,
            excludes: [
                Data(responseSentinel.utf8),
                Data(fixture.operatorSecret.utf8),
                Data(fixture.encodedKEK.utf8),
                fixture.rawKEK,
            ]
        )
    }

    func testInvalidCompatibilityFlagsFailBeforeStorageMutation() throws {
        let cases: [(laboratory: Bool, compatibility: String?, plcOrigin: String)] = [
            (true, "another-policy", "http://127.0.0.1:2582"),
            (false, "did-plc-server-0.0.1", "https://plc.directory"),
            (false, nil, "http://127.0.0.1:2582"),
            (true, "did-plc-server-0.0.1", "https://plc.directory"),
        ]

        for configuration in cases {
            let fixture = try Fixture()
            defer { fixture.remove() }
            let result = try runPrepare(
                fixture: fixture,
                plcOrigin: configuration.plcOrigin,
                laboratory: configuration.laboratory,
                compatibility: configuration.compatibility
            )
            XCTAssertNotEqual(result.status, 0)
            XCTAssertTrue(result.output.isEmpty)
            XCTAssertFalse(
                FileManager.default.fileExists(
                    atPath: fixture.data.appending(path: "control.sqlite").path
                )
            )
        }
    }

    func testMalformedPDSOriginFailsBeforeStorageMutation() throws {
        for malformed in [
            "http://pds.example.com",
            "https://pds.example.com/path",
            "https://user@pds.example.com",
        ] {
            let fixture = try Fixture()
            defer { fixture.remove() }
            let result = try runPrepare(
                fixture: fixture,
                plcOrigin: "https://plc.directory",
                laboratory: false,
                compatibility: nil,
                pdsOrigin: malformed
            )
            XCTAssertNotEqual(result.status, 0)
            XCTAssertTrue(result.output.isEmpty)
            XCTAssertFalse(
                FileManager.default.fileExists(
                    atPath: fixture.data.appending(path: "control.sqlite").path
                )
            )
        }
    }

    private func runPrepare(
        fixture: Fixture,
        server: TestPLCDirectory? = nil,
        plcOrigin: String? = nil,
        laboratory: Bool = true,
        compatibility: String?,
        handle: String? = nil,
        pdsOrigin: String? = nil
    ) throws -> ProcessResult {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        let selectedPLCOrigin: String
        if let plcOrigin {
            selectedPLCOrigin = plcOrigin
        } else {
            selectedPLCOrigin = "http://127.0.0.1:\(try XCTUnwrap(server?.port))"
        }
        var arguments = [
            "account", "prepare-plc",
            "--data-directory", fixture.data.path,
            "--request-id", requestID,
            "--handle", handle ?? self.handle,
            "--pds-origin", pdsOrigin ?? self.pdsOrigin,
            "--repository-revision", revision,
            "--plc-origin", selectedPLCOrigin,
            "--operator-secret-file", fixture.operatorSecretFile.path,
            "--account-kek-file", fixture.kekFile.path,
            "--account-kek-id", "test-primary",
            "--account-key-directory", fixture.data.appending(path: "account-keys").path,
        ]
        if laboratory { arguments.append("--plc-laboratory") }
        if let compatibility {
            arguments.append(contentsOf: ["--plc-reference-compatibility", compatibility])
        }
        process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "SWAN_OPERATOR_SECRET")
        environment.removeValue(forKey: "SWAN_ACCOUNT_KEK")
        process.environment = environment
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        return ProcessResult(
            status: process.terminationStatus,
            output: String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            error: String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        )
    }

    private func executableURL() -> URL? {
        let testBundleProduct = Bundle(for: PLCAccountPreparationCLITests.self)
            .bundleURL
            .deletingLastPathComponent()
            .appending(path: "swan")
        if FileManager.default.isExecutableFile(atPath: testBundleProduct.path) {
            return testBundleProduct
        }
        let testExecutable = URL(fileURLWithPath: CommandLine.arguments[0])
            .resolvingSymlinksInPath()
        let adjacentProduct = testExecutable
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "swan")
        if FileManager.default.isExecutableFile(atPath: adjacentProduct.path) {
            return adjacentProduct
        }
        let bundleProducts = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundled = bundleProducts.appending(path: "swan")
        if FileManager.default.isExecutableFile(atPath: bundled.path) { return bundled }
        let packageRoot = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let ordinary = packageRoot.appending(path: ".build/debug/swan")
        return FileManager.default.isExecutableFile(atPath: ordinary.path) ? ordinary : nil
    }

    private func decode(_ output: String) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any]
        )
    }

    private func assertPersistedData(under root: URL, excludes needles: [Data]) throws {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: []
        ) else {
            XCTFail("unable to enumerate persisted data")
            return
        }
        for case let file as URL in enumerator {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }
            let data = try Data(contentsOf: file)
            for needle in needles {
                XCTAssertNil(data.range(of: needle), "secret material persisted in \(file.lastPathComponent)")
            }
        }
    }
}

private struct ProcessResult {
    let status: Int32
    let output: String
    let error: String
}

private final class Fixture {
    let root: URL
    let data: URL
    let secrets: URL
    let operatorSecretFile: URL
    let kekFile: URL
    let operatorSecret = "operator-secret-MUST-NOT-PERSIST-71D9"
    let rawKEK: Data
    let encodedKEK: String

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPLCPrepareCLI-\(UUID().uuidString)")
        data = root.appending(path: "data")
        secrets = root.appending(path: "mounted-secrets")
        operatorSecretFile = secrets.appending(path: "operator")
        kekFile = secrets.appending(path: "account-kek")
        rawKEK = Data(repeating: 0xD7, count: 32)
        encodedKEK = Self.base64URLEncoded(rawKEK)
        try FileManager.default.createDirectory(at: data, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: secrets, withIntermediateDirectories: true)
        for directory in [root, data, secrets] {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )
        }
        try Data((operatorSecret + "\n").utf8).write(to: operatorSecretFile)
        try Data((encodedKEK + "\n").utf8).write(to: kekFile)
        for file in [operatorSecretFile, kekFile] {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: file.path
            )
        }
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }

    private static func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private final class TestPLCDirectory {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let state: TestPLCState

    var port: Int { channel.localAddress!.port! }
    var submitCount: Int { state.submitCount }

    init(submitBody: Data) throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sharedState = TestPLCState(submitBody: submitBody)
        state = sharedState
        channel = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 8)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(TestPLCHandler(state: sharedState))
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .bind(host: "127.0.0.1", port: 0)
            .wait()
    }

    func shutdown() {
        try? channel.close().wait()
        try? group.syncShutdownGracefully()
    }
}

private final class TestPLCState: @unchecked Sendable {
    private let lock = NSLock()
    private let submitBody: Data
    private var audit: Data?
    private var document: Data?
    private var count = 0

    init(submitBody: Data) {
        self.submitBody = submitBody
    }

    var submitCount: Int {
        locked { count }
    }

    func submit(did: String, operationData: Data) throws -> Data {
        let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
        let rawOperation = try JSONSerialization.jsonObject(with: operationData)
        guard let operationObject = rawOperation as? [String: Any],
              let rotationKeys = operationObject["rotationKeys"],
              let verificationMethods = operationObject["verificationMethods"],
              let alsoKnownAs = operationObject["alsoKnownAs"],
              let services = operationObject["services"] else {
            throw TestPLCError.malformedOperation
        }
        let body = try JSONSerialization.data(withJSONObject: [[
            "did": did,
            "operation": rawOperation,
            "cid": try operation.cid.string,
            "nullified": false,
            "createdAt": "2026-07-27T12:00:00.000Z",
        ]], options: [.sortedKeys])
        let document = try JSONSerialization.data(withJSONObject: [
            "did": did,
            "rotationKeys": rotationKeys,
            "verificationMethods": verificationMethods,
            "alsoKnownAs": alsoKnownAs,
            "services": services,
        ], options: [.sortedKeys])
        locked {
            count += 1
            audit = body
            self.document = document
        }
        return submitBody
    }

    func currentAudit() -> Data? {
        locked { audit }
    }

    func currentDocument() -> Data? {
        locked { document }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    private enum TestPLCError: Error {
        case malformedOperation
    }
}

private final class TestPLCHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let state: TestPLCState
    private var head: HTTPRequestHead?
    private var body = Data()

    init(state: TestPLCState) {
        self.state = state
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            self.head = head
            body.removeAll(keepingCapacity: true)
        case let .body(buffer):
            body.append(contentsOf: buffer.readableBytesView)
        case .end:
            respond(context: context)
        }
    }

    private func respond(context: ChannelHandlerContext) {
        guard let head else {
            write(status: .badRequest, body: Data(), contentType: nil, context: context)
            return
        }
        let components = head.uri.split(separator: "/", omittingEmptySubsequences: true)
        guard let did = components.first.map(String.init), did.hasPrefix("did:plc:") else {
            write(status: .notFound, body: Data(), contentType: nil, context: context)
            return
        }
        if head.method == .POST, components.count == 1 {
            do {
                let response = try state.submit(did: did, operationData: body)
                write(
                    status: .ok,
                    body: response,
                    contentType: "text/plain; charset=utf-8",
                    context: context
                )
            } catch {
                write(status: .badRequest, body: Data(), contentType: nil, context: context)
            }
        } else if head.method == .GET,
                  components.count == 3,
                  components[1] == "log",
                  components[2] == "audit",
                  let audit = state.currentAudit() {
            write(
                status: .ok,
                body: audit,
                contentType: "application/json; charset=utf-8",
                context: context
            )
        } else if head.method == .GET,
                  components.count == 2,
                  components[1] == "data",
                  let document = state.currentDocument() {
            write(
                status: .ok,
                body: document,
                contentType: "application/json; charset=utf-8",
                context: context
            )
        } else {
            write(status: .notFound, body: Data(), contentType: nil, context: context)
        }
    }

    private func write(
        status: HTTPResponseStatus,
        body: Data,
        contentType: String?,
        context: ChannelHandlerContext
    ) {
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: String(body.count))
        if let contentType { headers.add(name: "content-type", value: contentType) }
        headers.add(name: "connection", value: "close")
        context.write(
            wrapOutboundOut(.head(.init(version: .http1_1, status: status, headers: headers))),
            promise: nil
        )
        if !body.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: body.count)
            buffer.writeBytes(body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
}
