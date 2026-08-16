import ArgumentParser
import Foundation
import SwanAccounts
@testable import swan
import XCTest

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Task 2 of the Swan account-program runtime integration: typed startup
/// configuration for `swan serve`.
///
/// The refusal assertions are split between direct static-helper tests (the
/// same pattern `DeploymentStartupInterlockTests` uses — a refusal that can
/// only be observed by spawning the executable is a refusal nobody re-checks)
/// and binary tests that prove the refusals actually stop `swan serve`
/// before any storage or listener exists.
final class ServeAccountProgramStartupConfigurationCLITests: XCTestCase {
    // MARK: - Option parsing

    func testSignupPolicyOptionParsesAllThreePoliciesAndRejectsGarbage() throws {
        for (raw, expected) in [
            ("closed", SignupPolicy.closed),
            ("inviteRequired", SignupPolicy.inviteRequired),
            ("openProtected", SignupPolicy.openProtected),
        ] {
            let parsed = try SwanCommand.parseAsRoot([
                "serve", "--enable-account-portal", "--signup-policy", raw,
            ])
            let serve = try XCTUnwrap(parsed as? SwanCommand.Serve)
            XCTAssertEqual(
                try SwanCommand.Serve.parseSignupPolicy(serve.signupPolicy),
                expected,
                raw
            )
        }

        // Omitted defaults to closed — the truthful advertisement for a
        // deployment that never enables signup.
        let defaulted = try SwanCommand.parseAsRoot(["serve"])
        let serve = try XCTUnwrap(defaulted as? SwanCommand.Serve)
        XCTAssertNil(serve.signupPolicy)
        XCTAssertEqual(
            try SwanCommand.Serve.parseSignupPolicy(serve.signupPolicy),
            .closed
        )

        XCTAssertThrowsError(
            try SwanCommand.Serve.parseSignupPolicy("open")
        ) { error in
            XCTAssertTrue(error is ValidationError, "\(error)")
        }
    }

    func testAccountProgramOptionsParse() throws {
        let parsed = try SwanCommand.parseAsRoot([
            "serve",
            "--enable-account-portal",
            "--account-portal-directory", "/tmp/portal-assets",
            "--signup-policy", "inviteRequired",
            "--email-smtp-mode", "startTLS",
            "--email-smtp-mechanism", "login",
            "--email-smtp-expected-hostname", "smtp.example.com",
            "--email-smtp-max-attempts", "5",
            "--did-web-revalidation-interval-seconds", "7200",
            "--did-web-revalidation-grace-seconds", "43200",
        ])
        let serve = try XCTUnwrap(parsed as? SwanCommand.Serve)
        XCTAssertTrue(serve.enableAccountPortal)
        XCTAssertEqual(serve.accountPortalDirectory, "/tmp/portal-assets")
        XCTAssertEqual(serve.signupPolicy, "inviteRequired")
        XCTAssertEqual(serve.emailSMTPMode, "startTLS")
        XCTAssertEqual(serve.emailSMTPMechanism, "login")
        XCTAssertEqual(serve.emailSMTPExpectedHostname, "smtp.example.com")
        XCTAssertEqual(serve.emailSMTPMaxAttempts, 5)
        XCTAssertEqual(serve.didWebRevalidationIntervalSeconds, 7200)
        XCTAssertEqual(serve.didWebRevalidationGraceSeconds, 43200)
    }

    // MARK: - Portal directory resolution

    func testAccountPortalDirectoryDefaultsToContainerPath() throws {
        let resolved = try SwanCommand.Serve.resolveAccountPortalDirectory(nil)
        XCTAssertEqual(
            resolved.path,
            SwanCommand.Serve.defaultAccountPortalDirectory
        )
        XCTAssertEqual(resolved.path, "/usr/local/share/swan/account")
    }

    func testAccountPortalDirectoryRequiresExistingDirectoryOverride() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let existing = root.appending(path: "assets")
        try FileManager.default.createDirectory(
            at: existing,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        XCTAssertEqual(
            try SwanCommand.Serve.resolveAccountPortalDirectory(existing.path).path,
            existing.path
        )

        let missing = root.appending(path: "absent")
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveAccountPortalDirectory(missing.path)
        ) { error in
            let validation = error as? ValidationError
            XCTAssertNotNil(validation, "\(error)")
            XCTAssertTrue(
                validation?.message.contains("existing directory") == true,
                "\(String(describing: validation?.message))"
            )
        }
    }

    // MARK: - HTTPS origin validation

    func testHTTPSOriginValidationReusesPortalConfigurationPolicy() throws {
        let valid = [
            "https://swan.example",
            "https://accounts.example:8443",
        ]
        for text in valid {
            let url = try XCTUnwrap(URL(string: text), text)
            XCTAssertNoThrow(
                try SwanCommand.Serve.validateHTTPSOrigin(
                    url,
                    option: "--account-portal-origin"
                ),
                text
            )
        }

        let invalid = [
            "http://swan.example",
            "https://user:pass@swan.example",
            "https://swan.example/path",
            "https://swan.example?query=1",
            "https://swan.example#fragment",
            "not-a-url",
        ]
        for text in invalid {
            let url = URL(string: text)
            if let url {
                XCTAssertThrowsError(
                    try SwanCommand.Serve.validateHTTPSOrigin(
                        url,
                        option: "--account-portal-origin"
                    ),
                    text
                ) { error in
                    XCTAssertTrue(error is ValidationError, "\(error)")
                }
            }
        }
    }

    // MARK: - SMTP: no silent Mailpit fallback

    func testAuthenticatedSMTPRequiresCompleteNonLabConfiguration() throws {
        // An explicit non-lab mode without the full credential set is a
        // refusal — never a silent fallback to Mailpit.
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
                mode: .startTLS,
                host: "smtp.example.com",
                port: 587,
                usernameFile: nil,
                passwordFile: nil,
                mechanism: .login,
                expectedHostname: "smtp.example.com",
                maximumAttempts: nil
            )
        ) { error in
            let validation = error as? ValidationError
            XCTAssertNotNil(validation, "\(error)")
            XCTAssertTrue(
                validation?.message.contains("--email-smtp-mode startTLS requires") == true,
                "\(String(describing: validation?.message))"
            )
        }

        // No mode at all selects the Mailpit laboratory default — the
        // existing `--enable-email-recovery` path.
        let mailpit = try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
            mode: nil,
            host: "mailpit",
            port: 1025,
            usernameFile: nil,
            passwordFile: nil,
            mechanism: nil,
            expectedHostname: nil,
            maximumAttempts: nil
        )
        XCTAssertNil(mailpit)
    }

    func testAuthenticatedSMTPResolvesCompleteConfigurationFromMountedFiles() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let usernameFile = root.appending(path: "smtp-username")
        let passwordFile = root.appending(path: "smtp-password")
        try protectedWrite(Data("smtp-user@example.com".utf8), to: usernameFile)
        try protectedWrite(Data("smtp-password-value".utf8), to: passwordFile)

        let configuration = try XCTUnwrap(
            try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
                mode: .implicitTLS,
                host: "smtp.example.com",
                port: 465,
                usernameFile: usernameFile.path,
                passwordFile: passwordFile.path,
                mechanism: .plain,
                expectedHostname: "smtp.example.com",
                maximumAttempts: 5
            )
        )
        XCTAssertEqual(configuration.mode, .implicitTLS)
        XCTAssertEqual(configuration.host, "smtp.example.com")
        XCTAssertEqual(configuration.port, 465)
        XCTAssertEqual(configuration.username, "smtp-user@example.com")
        XCTAssertEqual(configuration.password, "smtp-password-value")
        XCTAssertEqual(configuration.mechanism, .plain)
        XCTAssertEqual(configuration.expectedHostname, "smtp.example.com")
        XCTAssertEqual(configuration.maximumAttempts, 5)
    }

    func testSMTPModeAndMechanismParsingRejectsUnknownValues() throws {
        XCTAssertEqual(
            try SwanCommand.Serve.parseSMTPMode("startTLS"),
            .startTLS
        )
        XCTAssertEqual(
            try SwanCommand.Serve.parseSMTPMode("implicitTLS"),
            .implicitTLS
        )
        XCTAssertEqual(
            try SwanCommand.Serve.parseSMTPMode("plaintextLab"),
            .plaintextLab
        )
        XCTAssertNil(try SwanCommand.Serve.parseSMTPMode(nil))
        XCTAssertThrowsError(
            try SwanCommand.Serve.parseSMTPMode("tls")
        ) { XCTAssertTrue($0 is ValidationError) }

        XCTAssertEqual(
            try SwanCommand.Serve.parseSMTPMechanism("xoauth2"),
            .xoauth2
        )
        XCTAssertNil(try SwanCommand.Serve.parseSMTPMechanism(nil))
        XCTAssertThrowsError(
            try SwanCommand.Serve.parseSMTPMechanism("digest")
        ) { XCTAssertTrue($0 is ValidationError) }
    }

    // MARK: - Secret hygiene

    func testSMTPRefusalNeverLeaksSecretPathsOrValues() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let passwordFile = root.appending(path: "smtp-password")
        let secretValue = "super-secret-smtp-password-value"
        try protectedWrite(Data(secretValue.utf8), to: passwordFile)

        // A complete-looking startTLS configuration that is still missing the
        // username must refuse with the mode message — never the file path or
        // the password value.
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
                mode: .startTLS,
                host: "smtp.example.com",
                port: 587,
                usernameFile: nil,
                passwordFile: passwordFile.path,
                mechanism: .login,
                expectedHostname: "smtp.example.com",
                maximumAttempts: nil
            )
        ) { error in
            let message = (error as? ValidationError)?.message ?? "\(error)"
            XCTAssertFalse(message.contains(passwordFile.path), message)
            XCTAssertFalse(message.contains(secretValue), message)
            XCTAssertFalse(message.contains(root.path), message)
        }
    }

    // MARK: - Binary refusals (no storage or listener created)

    func testAccountProgramOptionsRequireExplicitOptInWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")

        let result = try runServe(
            data: data,
            arguments: ["--signup-policy", "inviteRequired"]
        )

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "account program options require --enable-account-portal"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testOpenProtectedRejectsIncompleteConfigurationWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let turnstile = root.appending(path: "turnstile-secret")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: turnstile)

        // openProtected without the Turnstile secret reference.
        let missingTurnstile = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--signup-policy", "openProtected",
        ])
        XCTAssertNotEqual(missingTurnstile.status, 0)
        XCTAssertTrue(missingTurnstile.output.isEmpty)
        XCTAssertTrue(
            missingTurnstile.error.contains(
                "--signup-policy openProtected requires an owner-only --turnstile-secret-file"
            ),
            missingTurnstile.error
        )
        XCTAssertFalse(missingTurnstile.error.contains(turnstile.path))
        XCTAssertFalse(missingTurnstile.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))

        // openProtected with the Turnstile secret but no SMTP mode.
        let missingSMTP = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--signup-policy", "openProtected",
            "--turnstile-secret-file", turnstile.path,
        ])
        XCTAssertNotEqual(missingSMTP.status, 0)
        XCTAssertTrue(missingSMTP.output.isEmpty)
        XCTAssertTrue(
            missingSMTP.error.contains(
                "--signup-policy openProtected requires --email-smtp-mode"
            ),
            missingSMTP.error
        )
        XCTAssertFalse(missingSMTP.error.contains(turnstile.path))
        XCTAssertFalse(missingSMTP.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testTurnstileSecretFileRequiresOpenProtectedPolicy() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let turnstile = root.appending(path: "turnstile-secret")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: turnstile)

        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--turnstile-secret-file", turnstile.path,
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--turnstile-secret-file requires --signup-policy openProtected"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(turnstile.path))
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testIncompleteAuthenticatedSMTPRefusesWithoutFallingBackToMailpit() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let turnstile = root.appending(path: "turnstile-secret")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: turnstile)

        // startTLS without username/password/mechanism/expected-hostname must
        // refuse — the process must not silently start with Mailpit.
        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--signup-policy", "openProtected",
            "--turnstile-secret-file", turnstile.path,
            "--email-smtp-mode", "startTLS",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--email-smtp-mode startTLS requires"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(turnstile.path))
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testAccountPortalRequiresHTTPSPublicOrigin() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")

        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--public-url", "http://swan.example",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains("--public-url must be an HTTPS origin"),
            result.error
        )
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testDidWebRevalidationBoundsRejectOutOfRangeValues() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")

        let interval = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--did-web-revalidation-interval-seconds", "0",
        ])
        XCTAssertNotEqual(interval.status, 0)
        XCTAssertTrue(interval.output.isEmpty)
        XCTAssertTrue(
            interval.error.contains(
                "--did-web-revalidation-interval-seconds must be from 1 through 86400"
            ),
            interval.error
        )

        let grace = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--did-web-revalidation-grace-seconds", "90000",
        ])
        XCTAssertNotEqual(grace.status, 0)
        XCTAssertTrue(grace.output.isEmpty)
        XCTAssertTrue(
            grace.error.contains(
                "--did-web-revalidation-grace-seconds must be from 1 through 86400"
            ),
            grace.error
        )
        for result in [interval, grace] {
            XCTAssertFalse(result.error.contains(root.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
        }
    }

    // MARK: - Helpers

    private func runServe(
        data: URL,
        arguments: [String]
    ) throws -> ProcessResult {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["serve", "--data-directory", data.path] + arguments
        var processEnvironment = ProcessInfo.processInfo.environment
        processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY")
        processEnvironment["SWAN_OAUTH_SERVER_KEY"] = base64URLEncoded(
            Data(repeating: 0x5A, count: 32)
        )
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

    private func executableURL() -> URL? {
        SwanCLITestExecutable.resolved()
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "ServeAccountProgramStartupCLI-\(UUID().uuidString)")
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
