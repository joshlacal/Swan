import Crypto
import Foundation
import SwanAccounts
import SwanSQLite
import SwanStorage
import XCTest

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class ServeLocalSpaceInteropCLITests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testSpaceKeyOptionsRequireExplicitOptInWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let secret = root.appending(path: "mounted-kek")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: secret)

        let result = try runServe(
            data: data,
            arguments: ["--space-account-kek-file", secret.path]
        )

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertFalse(result.error.contains(secret.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testLocalInteropRejectsCleartextAndMissingNotificationConfigWithoutLeakingPaths() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let secret = root.appending(path: "mounted-kek")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: secret)

        let cleartext = try runServe(data: data, arguments: [
            "--enable-local-space-interop",
            "--space-account-kek-file", secret.path,
            "--public-url", "http://127.0.0.1:3000",
        ])
        XCTAssertNotEqual(cleartext.status, 0)
        XCTAssertTrue(cleartext.output.isEmpty)
        XCTAssertFalse(cleartext.error.contains(secret.path))

        let missing = try runServe(data: data, arguments: [
            "--enable-local-space-interop",
            "--space-account-kek-file", secret.path,
            "--notification-config", root.appending(path: "notification.json").path,
        ])
        XCTAssertNotEqual(missing.status, 0)
        XCTAssertTrue(missing.output.isEmpty)
        XCTAssertFalse(missing.error.contains(secret.path))
        XCTAssertFalse(missing.error.contains(root.path))
    }

    func testCompleteLocalInteropAndNotificationDeliveryStartsTogether() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let kek = Data(repeating: 0x61, count: 32)
        let keyStore = try FileAccountKeyStore(
            root: data.appending(path: "keys"),
            configuration: try .init(activeKeyID: "mixed", activeKey: kek)
        )
        let provisioned = try await AccountKeyProvisioner(keyStore: keyStore)
            .provisionInitial(accountDID: did)
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        _ = try await control.createAccount(try .init(
            did: did,
            canonicalHandle: "mixed.example.com",
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(
                purpose: .signing,
                generation: provisioned.signingReference.generation
            ),
            rotationKey: .init(
                purpose: .rotation,
                generation: provisioned.rotationReference.generation
            ),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        ))
        let database = try await SQLiteAccountDatabase(dataDirectory: data, did: did)
        try await database.close()
        try await control.close()

        let mountedKEK = root.appending(path: "mounted-kek")
        // Mounted KEKs use their URL-safe base64 text representation.
        try protectedWrite(Data(base64URLEncoded(kek).utf8), to: mountedKEK)
        let notification = root.appending(path: "notification.json")
        let configuration: [String: Any] = [
            "credentialPublicKeys": [],
            "delegationPublicKeys": [],
            "servicePublicKeys": [],
            "authorityDestinations": [[
                "key": did,
                "endpoint": "http://localhost:3000",
                "audience": "did:web:configured-managing.example",
                "finalPeer": "127.0.0.1",
            ]],
            "registrationDestinations": [],
            "recipientServiceBindings": [[
                "serviceIdentity": "did:web:configured-recipient.example",
                "recipientAccount": did,
            ]],
            "managingServiceAudience": "did:web:configured-managing.example",
        ]
        try JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys])
            .write(to: notification)

        let result = try runServeUntilStarted(data: data, arguments: [
            "--host", "127.0.0.1",
            "--port", "0",
            "--public-url", "https://swan.example",
            "--enable-local-space-interop",
            "--space-account-kek-file", mountedKEK.path,
            "--space-account-kek-id", "mixed",
            "--space-account-key-directory", data.appending(path: "keys").path,
            "--notification-config", notification.path,
            "--enable-notification-delivery",
            "--oauth-allow-metadata-ip", "127.0.0.1",
        ])

        XCTAssertTrue(result.started, result.error)
        XCTAssertFalse(result.error.contains(root.path))
    }

    func testNotificationDeliveryRejectsPartialFlagAndKeyConfigurations() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let missingConfiguration = try runServe(
            data: root.appending(path: "missing-config-data"),
            arguments: ["--enable-notification-delivery"]
        )
        XCTAssertNotEqual(missingConfiguration.status, 0)
        XCTAssertTrue(
            missingConfiguration.error.contains(
                "--enable-notification-delivery requires --notification-config"
            )
        )

        let keyWithoutDelivery = try runServe(
            data: root.appending(path: "key-without-delivery-data"),
            arguments: ["--notification-account-kek-id", "partial"]
        )
        XCTAssertNotEqual(keyWithoutDelivery.status, 0)
        XCTAssertTrue(
            keyWithoutDelivery.error.contains(
                "notification account options require --enable-notification-delivery"
            )
        )
        XCTAssertFalse(missingConfiguration.error.contains(root.path))
        XCTAssertFalse(keyWithoutDelivery.error.contains(root.path))
    }

    func testLocalInteropRejectsBroadlyReadableMountedKEKBeforeServing() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let keyDirectory = root.appending(path: "keys")
        try FileManager.default.createDirectory(
            at: keyDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let secret = root.appending(path: "mounted-kek")
        try Data(repeating: 0x41, count: 43).write(to: secret)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: secret.path)

        let result = try runServe(data: data, arguments: [
            "--enable-local-space-interop",
            "--public-url", "https://swan.example",
            "--space-account-kek-file", secret.path,
            "--space-account-key-directory", keyDirectory.path,
        ])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertFalse(result.error.contains(secret.path))
    }

    func testLocalInteropRejectsInactiveAccountBeforeServing() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let keyDirectory = root.appending(path: "keys")
        try FileManager.default.createDirectory(
            at: keyDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let secret = root.appending(path: "mounted-kek")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: secret)

        let control = try await SQLiteControlDatabase(dataDirectory: data)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "alice.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
            )
        )
        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date()
        )
        try await control.close()

        let result = try runServe(data: data, arguments: [
            "--enable-local-space-interop",
            "--public-url", "https://swan.example",
            "--space-account-kek-file", secret.path,
            "--space-account-key-directory", keyDirectory.path,
        ])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertFalse(result.error.contains(secret.path))
        XCTAssertFalse(result.error.contains(keyDirectory.path))
        XCTAssertFalse(result.error.contains("argon2"))
    }

    func testOAuthServerKeyCanBeLoadedFromFileAndRejectsAmbiguousSource() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let keyFile = root.appending(path: "oauth-server-key")
        let envKey = base64URLEncoded(Data(repeating: 0xAA, count: 32))
        try protectedWrite(Data(repeating: 0x5A, count: 43), to: keyFile)

        let fileResult = try runServe(
            data: data,
            arguments: ["--oauth-server-key-file", keyFile.path],
            environment: ["SWAN_OAUTH_SERVER_KEY": envKey]
        )
        XCTAssertNotEqual(fileResult.status, 0)
        XCTAssertTrue(fileResult.output.isEmpty)
        XCTAssertTrue(fileResult.error.contains("oauth-server-key source is ambiguous"))
        XCTAssertFalse(fileResult.error.contains(keyFile.path))
        XCTAssertFalse(fileResult.error.contains(root.path))
    }

    func testOAuthServerKeyFileRequiresSecureOwnerOnlyFile() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let keyFile = root.appending(path: "oauth-server-key")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: keyFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: keyFile.path)

        let result = try runServe(
            data: data,
            arguments: ["--oauth-server-key-file", keyFile.path],
            environment: [:]
        )
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertFalse(result.error.contains(keyFile.path))
        XCTAssertTrue(result.error.contains("oauth-server-key"))
    }

    private func runServe(
        data: URL,
        arguments: [String],
        environment: [String: String]? = nil
    ) throws -> ProcessResult {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["serve", "--data-directory", data.path] + arguments
        var processEnvironment = ProcessInfo.processInfo.environment
        processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY")
        processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY_FILE")
        if let environment {
            for (key, value) in environment {
                processEnvironment[key] = value
            }
            if environment.isEmpty {
                processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY")
            } else if environment["SWAN_OAUTH_SERVER_KEY"] == nil {
                processEnvironment["SWAN_OAUTH_SERVER_KEY"] = base64URLEncoded(
                    Data(repeating: 0x5A, count: 32)
                )
            }
        } else {
            processEnvironment["SWAN_OAUTH_SERVER_KEY"] = base64URLEncoded(
                Data(repeating: 0x5A, count: 32)
            )
        }
        process.environment = processEnvironment
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        return .init(
            status: process.terminationStatus,
            output: String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            error: String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        )
    }

    private func runServeUntilStarted(
        data: URL,
        arguments: [String]
    ) throws -> StartedProcessResult {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["serve", "--data-directory", data.path] + arguments
        var environment = ProcessInfo.processInfo.environment
        environment["SWAN_OAUTH_SERVER_KEY"] = base64URLEncoded(
            Data(repeating: 0x5A, count: 32)
        )
        process.environment = environment

        let outputURL = data.deletingLastPathComponent()
            .appending(path: "serve-output-\(UUID().uuidString)")
        let errorURL = data.deletingLastPathComponent()
            .appending(path: "serve-error-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: outputURL.path, contents: Data())
        FileManager.default.createFile(atPath: errorURL.path, contents: Data())
        let output = try FileHandle(forWritingTo: outputURL)
        let error = try FileHandle(forWritingTo: errorURL)
        defer {
            try? output.close()
            try? error.close()
        }
        process.standardOutput = output
        process.standardError = error
        try process.run()

        let deadline = Date().addingTimeInterval(10)
        var started = false
        while Date() < deadline {
            let rendered = String(
                decoding: (try? Data(contentsOf: errorURL)) ?? Data(),
                as: UTF8.self
            )
            if rendered.contains("Server started and listening") {
                started = true
                break
            }
            if !process.isRunning { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            // This test models the crash boundary required by the delivery
            // runtime. Recovery is proven separately after reopening the same
            // account database.
            _ = kill(process.processIdentifier, SIGKILL)
            process.waitUntilExit()
        }
        try output.synchronize()
        try error.synchronize()
        return .init(
            started: started,
            output: String(decoding: try Data(contentsOf: outputURL), as: UTF8.self),
            error: String(decoding: try Data(contentsOf: errorURL), as: UTF8.self)
        )
    }

    private func executableURL() -> URL? {
        let packageRoot = URL(filePath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let executable = packageRoot.appending(path: ".build/debug/swan")
        return FileManager.default.isExecutableFile(atPath: executable.path) ? executable : nil
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanServeLocalSpaceCLI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func protectedWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct ProcessResult {
    let status: Int32
    let output: String
    let error: String
}

private struct StartedProcessResult {
    let started: Bool
    let output: String
    let error: String
}
