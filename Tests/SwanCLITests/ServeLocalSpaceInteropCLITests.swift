import Crypto
import Foundation
import Petrel
import PetrelCrypto
import PetrelPLC
import PetrelRepo
import SwanAccounts
import SwanCore
import SwanHTTP
import SwanInterop
import SwanOAuth
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

    func testPublicMutationKeyOptionsRequireSeparateExplicitOptIn() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let secret = root.appending(path: "mounted-kek")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: secret)

        let result = try runServe(
            data: data,
            arguments: ["--public-account-kek-file", secret.path]
        )

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertFalse(result.error.contains(secret.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testMalformedDefaultHostFailsAsValidationInsteadOfCrashing() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")

        let result = try runServe(
            data: data,
            arguments: ["--host", "%"]
        )

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains("valid default public URL"),
            "unexpected validation output: \(result.error)"
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testSpaceOplogRetentionRejectsZeroBeforeCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")

        let result = try runServe(
            data: data,
            arguments: ["--space-oplog-retention", "0"]
        )

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--space-oplog-retention must be from 1 through 1000000"
            ),
            result.error
        )
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
        let signing = P256.Signing.PrivateKey()
        let rotation = P256.Signing.PrivateKey()
        let pdsOrigin = URL(string: "https://swan.example")!
        let unsignedOperation = try PLCATProfile.regularOperation(
            handle: "mixed.example.com",
            signingPublicKey: signing.publicKey,
            rotationPublicKeys: [rotation.publicKey],
            pdsOrigin: pdsOrigin,
            prev: nil
        )
        let operation = try PLCOperationCodec.sign(
            .regular(unsignedOperation),
            using: rotation
        )
        let localDID = try PLCOperationCodec.genesisDID(for: operation)
        let signingReference = try AccountKeyReference(
            accountDID: localDID,
            purpose: .signing,
            generation: 1
        )
        let rotationReference = try AccountKeyReference(
            accountDID: localDID,
            purpose: .rotation,
            generation: 1
        )
        try await keyStore.createBatch([
            try AccountKeyMaterial(reference: signingReference, key: signing.rawRepresentation),
            try AccountKeyMaterial(reference: rotationReference, key: rotation.rawRepresentation),
        ])
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        let revision = "3jzfcijpj2z2a"
        let publicGenesis = try PublicRepositoryGenesisCodec.create(
            did: localDID,
            revision: revision,
            signingKey: signing
        )
        let operationCID = try operation.cid.string
        let requestID = "serve-local-interop"
        let operationFacts = try PLCAccountPreparationOperationFacts(
            signingDIDKey: try XCTUnwrap(
                operation.regular?.verificationMethods["atproto"]
            ),
            rotationDIDKey: try XCTUnwrap(operation.regular?.rotationKeys.first),
            signature: try XCTUnwrap(operation.regular?.signature)
        )
        let journal = try PLCAccountPreparationJournal(
            requestID: requestID,
            canonicalHandle: "mixed.example.com",
            pdsOrigin: pdsOrigin.absoluteString,
            repositoryRevision: revision,
            operation: operationFacts,
            signingKey: try AccountControlKeyReference(
                purpose: .signing,
                generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation,
                generation: 1
            ),
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        let intent = try PLCAccountPreparationIntent(
            requestID: requestID,
            did: localDID,
            canonicalHandle: "mixed.example.com",
            pdsOrigin: pdsOrigin.absoluteString,
            repositoryRevision: revision,
            operationCID: operationCID,
            stage: .keysStored
        )
        _ = try await control.reservePLCAccountPreparationIntent(intent)
        _ = try await control.advancePLCAccountPreparationIntent(
            requestID: requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled
        )
        _ = try await control.advancePLCAccountPreparationIntent(
            requestID: requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending
        )
        _ = try await control.advancePLCAccountPreparationIntent(
            requestID: requestID,
            expectedStage: .submissionPending,
            to: .submitted
        )
        _ = try await control.createAccount(try .init(
            did: localDID,
            canonicalHandle: "mixed.example.com",
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(
                purpose: .signing,
                generation: 1
            ),
            rotationKey: .init(
                purpose: .rotation,
                generation: 1
            ),
            publicGenesisCommitCID: publicGenesis.commitCID.string,
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        ))
        let database = try await SQLiteAccountDatabase(dataDirectory: data, did: localDID)
        _ = try await database.installPublicRepositoryGenesis(
            publicGenesis,
            signingPublicKey: signing.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        _ = try await database.installPLCAccountPreparationJournal(journal)
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: publicGenesis.commitCID.string
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: requestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
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
                "key": localDID,
                "endpoint": "http://localhost:3000",
                "audience": "did:web:configured-managing.example",
                "finalPeer": "127.0.0.1",
            ]],
            "registrationDestinations": [],
            "recipientServiceBindings": [[
                "serviceIdentity": "did:web:configured-recipient.example",
                "recipientAccount": localDID,
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
            "--enable-oauth-authorization-server",
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

    func testMetadataFetchOptionsRejectInapplicableAndNonliteralModes() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let inapplicableIP = try runServe(
            data: root.appending(path: "inapplicable-ip"),
            arguments: ["--oauth-allow-metadata-ip", "127.0.0.1"]
        )
        XCTAssertNotEqual(inapplicableIP.status, 0)
        XCTAssertTrue(inapplicableIP.output.isEmpty)
        XCTAssertTrue(
            inapplicableIP.error.contains(
                "--oauth-allow-metadata-ip requires "
                    + "--enable-oauth-authorization-server or "
                    + "--enable-local-space-interop"
            )
        )

        let nonliteralIP = try runServe(
            data: root.appending(path: "nonliteral-ip"),
            arguments: [
                "--enable-oauth-authorization-server",
                "--public-url", "https://swan.example",
                "--oauth-allow-metadata-ip", "metadata.example",
            ]
        )
        XCTAssertNotEqual(nonliteralIP.status, 0)
        XCTAssertTrue(nonliteralIP.output.isEmpty)
        XCTAssertTrue(
            nonliteralIP.error.contains(
                "--oauth-allow-metadata-ip must be a literal IPv4 or IPv6 address"
            )
        )

        let inapplicableLocalhost = try runServe(
            data: root.appending(path: "inapplicable-localhost"),
            arguments: ["--oauth-allow-localhost-development-client"]
        )
        XCTAssertNotEqual(inapplicableLocalhost.status, 0)
        XCTAssertTrue(inapplicableLocalhost.output.isEmpty)
        XCTAssertTrue(
            inapplicableLocalhost.error.contains(
                "--oauth-allow-localhost-development-client requires "
                    + "--enable-oauth-authorization-server"
            )
        )
        for result in [inapplicableIP, nonliteralIP, inapplicableLocalhost] {
            XCTAssertFalse(result.error.contains(root.path))
        }
    }

    func testLoginTrustedProxyPeersRequireStrictLiteralIPsBeforeCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        for (index, literal) in [
            "caddy",
            "172.30.0.2:3000",
            "[2001:db8::2]",
            "172.30.0.2,172.30.0.3",
            "2001:db8::2%en0",
        ].enumerated() {
            let data = root.appending(path: "invalid-\(index)")
            let result = try runServe(
                data: data,
                arguments: [
                    "--login-trusted-proxy-peer",
                    literal,
                ]
            )

            XCTAssertNotEqual(result.status, 0, literal)
            XCTAssertTrue(result.output.isEmpty, literal)
            XCTAssertTrue(
                result.error.contains(
                    "--login-trusted-proxy-peer must be a literal IPv4 or IPv6 address"
                ),
                "\(literal): \(result.error)"
            )
            XCTAssertFalse(result.error.contains(root.path), literal)
            XCTAssertFalse(FileManager.default.fileExists(atPath: data.path), literal)
        }
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

    func testOAuthServerKeyRequiresMountedFileAndRejectsEnvironment() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let envKey = base64URLEncoded(Data(repeating: 0xAA, count: 32))

        // Environment-only secret supply must be rejected
        let envResult = try runServe(
            data: data,
            arguments: [],
            environment: ["SWAN_OAUTH_SERVER_KEY": envKey]
        )
        XCTAssertNotEqual(envResult.status, 0)
        XCTAssertTrue(envResult.output.isEmpty)
        XCTAssertTrue(envResult.error.contains("--oauth-server-key-file"))
        XCTAssertFalse(envResult.error.contains(envKey))
        XCTAssertFalse(envResult.error.contains(root.path))
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
        var serveArgs = ["serve", "--data-directory", data.path] + arguments
        if !arguments.contains("--oauth-server-key-file") && environment?["SWAN_OAUTH_SERVER_KEY"] == nil {
            let defaultKeyFile = data.deletingLastPathComponent().appending(path: "default-oauth-server-key")
            if !FileManager.default.fileExists(atPath: defaultKeyFile.path) {
                try protectedWrite(Data(repeating: 0x5A, count: 43), to: defaultKeyFile)
            }
            serveArgs.append(contentsOf: ["--oauth-server-key-file", defaultKeyFile.path])
        }
        process.arguments = serveArgs
        var processEnvironment = ProcessInfo.processInfo.environment
        processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY")
        processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY_FILE")
        if let environment {
            for (key, value) in environment {
                processEnvironment[key] = value
            }
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
        var serveArgs = ["serve", "--data-directory", data.path] + arguments
        if !arguments.contains("--oauth-server-key-file") {
            let defaultKeyFile = data.deletingLastPathComponent().appending(path: "default-oauth-server-key")
            if !FileManager.default.fileExists(atPath: defaultKeyFile.path) {
                try protectedWrite(Data(repeating: 0x5A, count: 43), to: defaultKeyFile)
            }
            serveArgs.append(contentsOf: ["--oauth-server-key-file", defaultKeyFile.path])
        }
        process.arguments = serveArgs
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY")
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
        SwanCLITestExecutable.resolved()
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
