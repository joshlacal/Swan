import Foundation
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
@testable import SwanAccounts
import SwanCore
@testable import SwanHTTP
import SwanSQLite
import SwanStorage
import XCTest

final class ManagementPLCProvisioningRuntimeHTTPTests: XCTestCase {
    func testConcreteRuntimeSingleFlightForcesRealOverlappingActivation() async throws {
        let plc = try ManagementPLCDirectoryFixture()
        defer { plc.shutdown() }
        let fixture = try await ConcreteManagementFixture(plc: plc)
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        do {
            let plcOrigin = try XCTUnwrap(URL(
                string: "http://127.0.0.1:\(plc.port)"
            ))
            let plcConfiguration = try PLCClientConfiguration.laboratory(
                origin: plcOrigin,
                submitSuccessResponsePolicy: .didPLCServer001
            )
            let handlePolicy = try ATHandleResolutionPolicy.laboratory(
                origin: plcOrigin
            )
            let prepared = try await fixture.runtime.prepare(.init(
                requestID: fixture.requestID,
                handle: "alice.test",
                pdsOrigin: try XCTUnwrap(URL(string: "https://pds.example")),
                repositoryRevision: "3lqby3xuo4k2a",
                plcConfiguration: plcConfiguration
            ))
            let activation = SwanManagementPLCActivateInput(
                requestID: fixture.requestID,
                password: fixture.password,
                plcConfiguration: plcConfiguration,
                handlePolicy: handlePolicy
            )

            plc.armAuditResponseBarrier()
            defer { plc.releaseAuditResponseBarrier() }
            async let first = fixture.runtime.activate(activation)
            guard try await plc.waitForAuditResponseBarrier() else {
                XCTFail("first activation never reached the forced network overlap")
                plc.releaseAuditResponseBarrier()
                _ = try? await first
                try await fixture.close()
                return
            }

            async let second = fixture.runtime.activate(activation)
            guard try await Self.waitForActivationWaiters(
                runtime: fixture.runtime,
                requestID: fixture.requestID,
                count: 2
            ) else {
                XCTFail("second activation did not join the in-flight attempt")
                plc.releaseAuditResponseBarrier()
                _ = try? await (first, second)
                try await fixture.close()
                return
            }

            let mismatched = SwanManagementPLCActivateInput(
                requestID: fixture.requestID,
                password: fixture.password + "-different",
                plcConfiguration: plcConfiguration,
                handlePolicy: handlePolicy
            )
            do {
                _ = try await fixture.runtime.activate(mismatched)
                XCTFail("different input must not join an in-flight request ID")
            } catch let error as PLCAccountActivationError {
                XCTAssertEqual(error, .conflict)
            }

            plc.releaseAuditResponseBarrier()
            let (firstResult, secondResult) = try await (first, second)
            XCTAssertEqual(firstResult, secondResult)
            XCTAssertEqual(firstResult.did, prepared.did)
            XCTAssertEqual(firstResult.status, "active")
            XCTAssertTrue(firstResult.recovered)
            let remainingWaiters = await fixture.runtime
                .activationWaiterCountForTesting(
                    requestID: fixture.requestID
                )
            XCTAssertEqual(remainingWaiters, 0)
            try await fixture.liveDirectory.requireActivePreopenedAccount(prepared.did)
            let active = try await fixture.control.account(did: prepared.did)
            XCTAssertEqual(active?.status, .active)
            let recoveryCount = try await fixture.liveDirectory
                .notificationRecoveryDatabases().count
            XCTAssertEqual(recoveryCount, 1)

            try await fixture.close()
        } catch {
            plc.releaseAuditResponseBarrier()
            try? await fixture.close()
            throw error
        }
    }

    func testConcreteManagementRoutesPrepareActivateRetryAndAdmitWithoutRestart() async throws {
        let plc = try ManagementPLCDirectoryFixture()
        defer { plc.shutdown() }
        let fixture = try await ConcreteManagementFixture(plc: plc)
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "ConcreteManagementPLCProvisioningHTTPTests")
            )
            let capture = ManagementHTTPTestCapture()
            try await app.test(.live) { client in
                for _ in 0 ..< 2 {
                    try await client.execute(
                        uri: "/v1/accounts/plc/prepare",
                        method: .post,
                        headers: fixture.authorizationHeaders,
                        body: ByteBuffer(data: fixture.prepareBody)
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                        let body = Data(buffer: response.body)
                        let object = try JSONDecoder().decode(
                            ManagementPreparedResponse.self,
                            from: body
                        )
                        try await capture.recordPrepared(object, body: body)
                    }
                }
                XCTAssertEqual(plc.submitCount, 1)
                let did = try await capture.requiredPrepared().did
                let pendingAccount = try await fixture.control.account(did: did)
                XCTAssertNil(pendingAccount)

                let conflictingPrepare = try Self.prepareBody(
                    requestID: fixture.requestID,
                    handle: "mallory.test",
                    plcPort: plc.port
                )
                try await client.execute(
                    uri: "/v1/accounts/plc/prepare",
                    method: .post,
                    headers: fixture.authorizationHeaders,
                    body: ByteBuffer(data: conflictingPrepare)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    await capture.append(Data(buffer: response.body))
                }
                let accountAfterConflict = try await fixture.control.account(did: did)
                XCTAssertNil(accountAfterConflict)
                XCTAssertEqual(plc.submitCount, 1)

                // Exact HTTP retries remain successful after the preparation
                // opener transfers lifecycle ownership.
                for _ in 0 ..< 2 {
                    try await client.execute(
                        uri: "/v1/accounts/plc/activate",
                        method: .post,
                        headers: fixture.authorizationHeaders,
                        body: ByteBuffer(data: fixture.activateBody)
                    ) { response in
                        let body = Data(buffer: response.body)
                        XCTAssertEqual(
                            response.status,
                            .ok,
                            String(data: body, encoding: .utf8) ?? "<non-UTF8 body>"
                        )
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                        let object = try JSONDecoder().decode(
                            ManagementActivatedResponse.self,
                            from: body
                        )
                        XCTAssertEqual(object.did, did)
                        XCTAssertEqual(object.status, "active")
                        XCTAssertTrue(object.recovered)
                        try await capture.recordActivation(object, body: body)
                    }
                }
                XCTAssertEqual(plc.submitCount, 1)
                let activeAccount = try await fixture.control.account(did: did)
                XCTAssertEqual(activeAccount?.status, .active)

                // The public resource process directory was bootstrapped while
                // the inventory was empty. Successful management activation
                // must therefore make this authorization gate pass immediately
                // in this same process, without another bootstrap or restart.
                try await fixture.liveDirectory.requireActivePreopenedAccount(did)
                let recoveryCount = try await fixture.liveDirectory
                    .notificationRecoveryDatabases().count
                XCTAssertEqual(recoveryCount, 1)
            }

            try Self.assertNoProjection(
                renderedBodies: await capture.bodies,
                persistedUnder: fixture.data,
                sentinels: fixture.secretSentinels + [
                    Data(ManagementPLCFixtureState.responseBodySentinel.utf8),
                    Data(ManagementPLCFixtureState.proofBodySentinel.utf8),
                ]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testConcreteManagementRouteFailuresNeverActivateOrPersistRemoteBodies() async throws {
        let remoteSentinel = "PLC-RESPONSE-BODY-MUST-NOT-PERSIST-5D6831"
        let plc = try ManagementPLCDirectoryFixture(submitBody: Data(remoteSentinel.utf8))
        defer { plc.shutdown() }
        let fixture = try await ConcreteManagementFixture(plc: plc)
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "ConcreteManagementPLCFailureHTTPTests")
            )
            let capture = ManagementHTTPTestCapture()
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/v1/accounts/plc/prepare",
                    method: .post,
                    headers: fixture.authorizationHeaders,
                    body: ByteBuffer(data: fixture.prepareBody)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    await capture.append(Data(buffer: response.body))
                }
            }
            XCTAssertEqual(plc.submitCount, 1)
            let intent = try await fixture.control.plcAccountPreparationIntent(
                requestID: fixture.requestID
            )
            if let did = intent?.did {
                let account = try await fixture.control.account(did: did)
                XCTAssertNil(account)
            }
            try Self.assertNoProjection(
                renderedBodies: await capture.bodies,
                persistedUnder: fixture.data,
                sentinels: fixture.secretSentinels + [Data(remoteSentinel.utf8)]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testConcreteManagementActivationRejectsBadHandleProofWithoutActiveAccount() async throws {
        let plc = try ManagementPLCDirectoryFixture()
        defer { plc.shutdown() }
        let fixture = try await ConcreteManagementFixture(plc: plc)
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "ConcreteManagementPLCHandleFailureHTTPTests")
            )
            let capture = ManagementHTTPTestCapture()
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/v1/accounts/plc/prepare",
                    method: .post,
                    headers: fixture.authorizationHeaders,
                    body: ByteBuffer(data: fixture.prepareBody)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = Data(buffer: response.body)
                    let prepared = try JSONDecoder().decode(
                        ManagementPreparedResponse.self,
                        from: body
                    )
                    try await capture.recordPrepared(prepared, body: body)
                }
                let did = try await capture.requiredPrepared().did
                plc.setWellKnownResponse(.body(
                    Data(ManagementPLCFixtureState.proofBodySentinel.utf8)
                ))
                try await client.execute(
                    uri: "/v1/accounts/plc/activate",
                    method: .post,
                    headers: fixture.authorizationHeaders,
                    body: ByteBuffer(data: fixture.activateBody)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    await capture.append(Data(buffer: response.body))
                }
                let account = try await fixture.control.account(did: did)
                XCTAssertNil(account)
                do {
                    try await fixture.liveDirectory.requireActivePreopenedAccount(did)
                    XCTFail("failed activation must not enter the live account directory")
                } catch let error as SwanError {
                    guard case .unauthorized = error else {
                        return XCTFail("expected unauthorized, got \(error)")
                    }
                }
            }
            try Self.assertNoProjection(
                renderedBodies: await capture.bodies,
                persistedUnder: fixture.data,
                sentinels: fixture.secretSentinels + [
                    Data(ManagementPLCFixtureState.responseBodySentinel.utf8),
                    Data(ManagementPLCFixtureState.proofBodySentinel.utf8),
                ]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    fileprivate static func prepareBody(
        requestID: String,
        handle: String,
        plcPort: Int
    ) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "requestId": requestID,
            "handle": handle,
            "pdsOrigin": "https://pds.example",
            "repositoryRevision": "3lqby3xuo4k2a",
            "plcOrigin": "http://127.0.0.1:\(plcPort)",
            "plcLaboratory": true,
            "plcReferenceCompatibility": "did-plc-server-0.0.1",
        ], options: [.sortedKeys])
    }

    private static func waitForActivationWaiters(
        runtime: SwanManagementPLCProvisioningRuntime,
        requestID: String,
        count: Int,
        timeout: Duration = .seconds(5)
    ) async throws -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if await runtime.activationWaiterCountForTesting(
                requestID: requestID
            ) == count {
                return true
            }
            try await Task.sleep(for: .milliseconds(1))
        }
        return await runtime.activationWaiterCountForTesting(
            requestID: requestID
        ) == count
    }

    private static func assertNoProjection(
        renderedBodies: [Data],
        persistedUnder root: URL,
        sentinels: [Data]
    ) throws {
        for body in renderedBodies {
            for sentinel in sentinels {
                XCTAssertNil(body.range(of: sentinel), "sentinel projected by management HTTP")
            }
        }
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: []
        ) else {
            XCTFail("unable to enumerate persisted management state")
            return
        }
        for case let file as URL in enumerator {
            guard try file.resourceValues(forKeys: [.isRegularFileKey])
                .isRegularFile == true else { continue }
            let data = try Data(contentsOf: file)
            for sentinel in sentinels {
                XCTAssertNil(
                    data.range(of: sentinel),
                    "sentinel persisted in \(file.lastPathComponent)"
                )
            }
        }
    }
}

private final class ConcreteManagementFixture: @unchecked Sendable {
    let root: URL
    let data: URL
    let requestID = "management-concrete-r1"
    let operatorSecret = "operator-secret-MUST-NOT-PERSIST-71D9"
    let password = "password-MUST-NOT-PERSIST-E28AC7"
    let rawKEK = Data(repeating: 0xD7, count: 32)
    let control: SQLiteControlDatabase
    let liveDirectory: SQLitePreMigratedAccountDirectory
    let runtime: SwanManagementPLCProvisioningRuntime
    let server: SwanManagementHTTPServer
    let prepareBody: Data
    let activateBody: Data

    var authorizationHeaders: HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "Bearer \(operatorSecret)"
        headers[.contentType] = "application/json; charset=utf-8"
        return headers
    }

    var secretSentinels: [Data] {
        [
            Data(operatorSecret.utf8),
            Data(password.utf8),
            rawKEK,
            Data(rawKEK.base64EncodedString().utf8),
        ]
    }

    init(plc: ManagementPLCDirectoryFixture) async throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanConcreteManagementHTTP-\(UUID().uuidString)")
        data = root.appending(path: "data")
        let mountedSecrets = root.appending(path: "mounted-secrets")
        let keyRoot = data.appending(path: "keys")
        try FileManager.default.createDirectory(
            at: mountedSecrets,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let operatorFile = mountedSecrets.appending(path: "operator")
        try Data((operatorSecret + "\n").utf8).write(to: operatorFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: operatorFile.path
        )
        control = try await SQLiteControlDatabase(dataDirectory: data)
        liveDirectory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: data,
            controlStore: control,
            publicIdentityVerifier: SwanPublicPLCGenesisVerifier()
        )
        let keyStore = try FileAccountKeyStore(
            root: keyRoot,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "test-primary",
                activeKey: rawKEK
            )
        )
        runtime = try SwanManagementPLCProvisioningRuntime(
            controlDatabase: control,
            dataDirectory: data,
            keyStore: keyStore,
            liveAccountDirectory: liveDirectory
        )
        server = SwanManagementHTTPServer(
            configuration: try SwanManagementHTTPConfiguration(
                bindAddressLiteral: "127.0.0.1",
                port: 3001
            ),
            controlStore: control,
            operatorSecretVerifier: try OperatorSecretResolver.loadVerifier(
                secretFile: operatorFile
            ),
            plcProvisioning: runtime
        )
        prepareBody = try ManagementPLCProvisioningRuntimeHTTPTests.prepareBody(
            requestID: requestID,
            handle: "alice.test",
            plcPort: plc.port
        )
        activateBody = try JSONSerialization.data(withJSONObject: [
            "requestId": requestID,
            "password": password,
            "plcOrigin": "http://127.0.0.1:\(plc.port)",
            "plcLaboratory": true,
            "plcReferenceCompatibility": "did-plc-server-0.0.1",
            "handleLaboratoryOrigin": "http://127.0.0.1:\(plc.port)",
        ], options: [.sortedKeys])
    }

    func close() async throws {
        try await runtime.close()
        try await liveDirectory.close()
        try await control.close()
    }
}

private struct ManagementPreparedResponse: Codable, Sendable, Equatable {
    let requestId: String
    let did: String
    let canonicalHandle: String
    let pdsOrigin: String
    let repositoryRevision: String
    let plcOperationCID: String
    let publicGenesisCommitCID: String
}

private struct ManagementActivatedResponse: Codable, Sendable, Equatable {
    let did: String
    let canonicalHandle: String
    let status: String
    let publicGenesisCommitCID: String
    let publicGenesisRevision: String
    let recovered: Bool
}

private actor ManagementHTTPTestCapture {
    private(set) var bodies: [Data] = []
    private var prepared: ManagementPreparedResponse?
    private var activation: ManagementActivatedResponse?

    func append(_ body: Data) {
        bodies.append(body)
    }

    func recordPrepared(_ response: ManagementPreparedResponse, body: Data) throws {
        bodies.append(body)
        if let prepared, prepared != response {
            throw ManagementHTTPTestCaptureError.nonIdempotentResponse
        }
        prepared = response
    }

    func recordActivation(_ response: ManagementActivatedResponse, body: Data) throws {
        bodies.append(body)
        if let activation, activation != response {
            throw ManagementHTTPTestCaptureError.nonIdempotentResponse
        }
        activation = response
    }

    func requiredPrepared() throws -> ManagementPreparedResponse {
        guard let prepared else {
            throw ManagementHTTPTestCaptureError.missingResponse
        }
        return prepared
    }
}

private enum ManagementHTTPTestCaptureError: Error {
    case missingResponse
    case nonIdempotentResponse
}
