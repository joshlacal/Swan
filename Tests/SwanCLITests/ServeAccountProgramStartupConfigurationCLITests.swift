import ArgumentParser
import Foundation
import SwanAccounts
import SwanOAuth
import SwanSQLite
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

    func testNonLabSMTPModeRequiresExplicitHostAndPort() throws {
        // A complete-looking startTLS configuration with omitted host/port
        // must refuse — never silently target mailpit:1025.
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
                mode: .startTLS,
                host: nil,
                port: nil,
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
                validation?.message.contains(
                    "--email-smtp-mode startTLS requires --email-smtp-host and --email-smtp-port"
                ) == true,
                "\(String(describing: validation?.message))"
            )
        }

        // An empty host is equally refused.
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
                mode: .implicitTLS,
                host: "   ",
                port: 465,
                usernameFile: nil,
                passwordFile: nil,
                mechanism: .plain,
                expectedHostname: "smtp.example.com",
                maximumAttempts: nil
            )
        ) { error in
            XCTAssertTrue(error is ValidationError, "\(error)")
        }

        // plaintextLab keeps the Mailpit laboratory defaults.
        let lab = try SwanCommand.Serve.resolveAuthenticatedSMTPConfiguration(
            mode: .plaintextLab,
            host: nil,
            port: nil,
            usernameFile: nil,
            passwordFile: nil,
            mechanism: nil,
            expectedHostname: nil,
            maximumAttempts: nil
        )
        let labConfiguration = try XCTUnwrap(lab)
        XCTAssertEqual(labConfiguration.host, "mailpit")
        XCTAssertEqual(labConfiguration.port, 1025)
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

    func testSMTPCredentialOptionsWithoutModeRefuseWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let username = root.appending(path: "smtp-username")
        let password = root.appending(path: "smtp-password")
        try protectedWrite(Data("smtp-user@example.com".utf8), to: username)
        try protectedWrite(Data("smtp-password-value".utf8), to: password)

        // Credential options without --email-smtp-mode must refuse — the
        // process must not silently start on the Mailpit path discarding
        // the operator's credentials.
        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--email-smtp-username-file", username.path,
            "--email-smtp-password-file", password.path,
            "--email-smtp-mechanism", "login",
            "--email-smtp-expected-hostname", "smtp.example.com",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--email-smtp-username-file, --email-smtp-password-file, --email-smtp-mechanism, --email-smtp-expected-hostname, and --email-smtp-max-attempts require --email-smtp-mode"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(username.path))
        XCTAssertFalse(result.error.contains(password.path))
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testNonLabSMTPModeWithoutHostOrPortRefusesWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let turnstile = root.appending(path: "turnstile-secret")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: turnstile)
        let username = root.appending(path: "smtp-username")
        let password = root.appending(path: "smtp-password")
        try protectedWrite(Data("smtp-user@example.com".utf8), to: username)
        try protectedWrite(Data("smtp-password-value".utf8), to: password)

        // A complete-looking startTLS configuration with omitted host/port
        // must refuse — never silently target mailpit:1025.
        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--signup-policy", "openProtected",
            "--turnstile-secret-file", turnstile.path,
            "--email-smtp-mode", "startTLS",
            "--email-smtp-username-file", username.path,
            "--email-smtp-password-file", password.path,
            "--email-smtp-mechanism", "login",
            "--email-smtp-expected-hostname", "smtp.example.com",
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--email-smtp-mode startTLS requires --email-smtp-host and --email-smtp-port"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(turnstile.path))
        XCTAssertFalse(result.error.contains(username.path))
        XCTAssertFalse(result.error.contains(password.path))
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

    // MARK: - Signup runtime secrets (Task 3)

    func testInviteRequiredRequiresAuthenticatedSMTPModeAndRejectsLabMode() throws {
        XCTAssertThrowsError(
            try SwanCommand.Serve.requireAuthenticatedSMTPForPublicSignup(
                policy: .inviteRequired,
                emailSMTPMode: nil
            )
        ) { error in
            XCTAssertTrue(
                (error as? ValidationError)?.message.contains(
                    "--signup-policy inviteRequired requires --email-smtp-mode"
                ) == true,
                "\(error)"
            )
        }
        XCTAssertThrowsError(
            try SwanCommand.Serve.requireAuthenticatedSMTPForPublicSignup(
                policy: .inviteRequired,
                emailSMTPMode: "plaintextLab"
            )
        ) { error in
            XCTAssertTrue(
                (error as? ValidationError)?.message.contains(
                    "requires authenticated startTLS or implicitTLS SMTP"
                ) == true,
                "\(error)"
            )
        }
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireAuthenticatedSMTPForPublicSignup(
                policy: .inviteRequired,
                emailSMTPMode: "startTLS"
            )
        )
    }

    /// A public signup policy without the signup HMAC secret must refuse at
    /// startup — never silently derive a weaker key.
    func testPublicSignupPolicyRequiresSignupSecretWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let turnstile = root.appending(path: "turnstile-secret")
        try protectedWrite(Data(repeating: 0x41, count: 43), to: turnstile)
        let username = root.appending(path: "smtp-username")
        let password = root.appending(path: "smtp-password")
        let accountKEK = root.appending(path: "account-kek")
        let didWeb = root.appending(path: "did-web-key")
        try protectedWrite(Data("smtp-user@example.com".utf8), to: username)
        try protectedWrite(Data("smtp-password-value".utf8), to: password)
        try protectedWrite(Data(base64URLEncoded(Data(repeating: 0x4B, count: 32)).utf8), to: accountKEK)
        try protectedWrite(Data(base64URLEncoded(Data(repeating: 0x57, count: 32)).utf8), to: didWeb)

        // inviteRequired without the signup secret.
        let invite = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--public-url", "https://swan.example",
            "--signup-policy", "inviteRequired",
            "--signup-account-kek-file", accountKEK.path,
            "--did-web-signing-key-file", didWeb.path,
            "--email-smtp-mode", "startTLS",
            "--email-smtp-host", "smtp.example.com",
            "--email-smtp-port", "587",
            "--email-smtp-username-file", username.path,
            "--email-smtp-password-file", password.path,
            "--email-smtp-mechanism", "login",
            "--email-smtp-expected-hostname", "smtp.example.com",
        ])
        XCTAssertNotEqual(invite.status, 0)
        XCTAssertTrue(invite.output.isEmpty)
        XCTAssertTrue(
            invite.error.contains(
                "--signup-policy inviteRequired requires an owner-only --signup-secret-file"
            ),
            invite.error
        )
        XCTAssertFalse(invite.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))

        // openProtected with a complete SMTP configuration but no signup
        // secret still refuses.
        let open = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--public-url", "https://swan.example",
            "--signup-policy", "openProtected",
            "--turnstile-secret-file", turnstile.path,
            "--email-smtp-mode", "startTLS",
            "--email-smtp-host", "smtp.example.com",
            "--email-smtp-port", "587",
            "--email-smtp-username-file", username.path,
            "--email-smtp-password-file", password.path,
            "--email-smtp-mechanism", "login",
            "--email-smtp-expected-hostname", "smtp.example.com",
            "--signup-account-kek-file", accountKEK.path,
            "--did-web-signing-key-file", didWeb.path,
        ])
        XCTAssertNotEqual(open.status, 0)
        XCTAssertTrue(open.output.isEmpty)
        XCTAssertTrue(
            open.error.contains(
                "--signup-policy openProtected requires an owner-only --signup-secret-file"
            ),
            open.error
        )
        XCTAssertFalse(open.error.contains(turnstile.path))
        XCTAssertFalse(open.error.contains(username.path))
        XCTAssertFalse(open.error.contains(password.path))
        XCTAssertFalse(open.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    /// A public signup policy without the account KEK must refuse at startup
    /// — the signup key store cannot be silently replaced by an in-memory
    /// fallback.
    func testPublicSignupPolicyRequiresAccountKEKWithoutCreatingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let signupSecret = root.appending(path: "signup-secret")
        let didWeb = root.appending(path: "did-web-key")
        let username = root.appending(path: "smtp-username")
        let password = root.appending(path: "smtp-password")
        try protectedWrite(Data(repeating: 0x24, count: 43), to: signupSecret)
        try protectedWrite(Data(base64URLEncoded(Data(repeating: 0x57, count: 32)).utf8), to: didWeb)
        try protectedWrite(Data("smtp-user@example.com".utf8), to: username)
        try protectedWrite(Data("smtp-password-value".utf8), to: password)

        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--public-url", "https://swan.example",
            "--signup-policy", "inviteRequired",
            "--signup-secret-file", signupSecret.path,
            "--did-web-signing-key-file", didWeb.path,
            "--email-smtp-mode", "startTLS",
            "--email-smtp-host", "smtp.example.com",
            "--email-smtp-port", "587",
            "--email-smtp-username-file", username.path,
            "--email-smtp-password-file", password.path,
            "--email-smtp-mechanism", "login",
            "--email-smtp-expected-hostname", "smtp.example.com",
        ])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--enable-account-portal requires an owner-only --signup-account-kek-file"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(signupSecret.path))
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    /// A closed policy refuses supplied signup secret/KEK options — the
    /// closed deployment never assembles a signup runtime.
    func testClosedPolicyRefusesSignupSecretAndKEKOptions() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let signupSecret = root.appending(path: "signup-secret")
        try protectedWrite(Data(repeating: 0x24, count: 43), to: signupSecret)

        let result = try runServe(data: data, arguments: [
            "--enable-account-portal",
            "--signup-secret-file", signupSecret.path,
        ])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--signup-secret-file requires --signup-policy inviteRequired or openProtected"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(signupSecret.path))
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testAccountProgramMountedSecretsRefuseEnvironmentSymlinkWrongModeAndMalformedInputsBeforeStorage() throws {
        let encode: (Data) -> Data = { [self] data in
            Data(self.base64URLEncoded(data).utf8)
        }
        let validKEK = encode(Data(repeating: 0x4B, count: 32))
        let validDidWeb = encode(Data(repeating: 0x57, count: 32))

        // Missing account KEK is the environment-only case: the account
        // program does not consult SWAN_ACCOUNT_KEK or any other process
        // environment value as a mounted-secret substitute.
        do {
            let root = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: root) }
            let didWeb = root.appending(path: "did-web-key")
            try protectedWrite(validDidWeb, to: didWeb)
            let result = try runServe(data: root.appending(path: "data"), arguments: [
                "--enable-account-portal",
                "--public-url", "https://swan.example",
                "--did-web-signing-key-file", didWeb.path,
            ])
            XCTAssertNotEqual(result.status, 0)
            XCTAssertTrue(result.error.contains("--enable-account-portal requires an owner-only --signup-account-kek-file"), result.error)
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.appending(path: "data").path))
        }

        let cases: [(String, (URL, URL) throws -> Void)] = [
            ("symlink", { [self] root, didWeb in
                let target = root.appending(path: "did-web-target")
                try self.protectedWrite(validDidWeb, to: target)
                try FileManager.default.createSymbolicLink(at: didWeb, withDestinationURL: target)
            }),
            ("wrong-mode", { [self] _, didWeb in
                try self.protectedWrite(validDidWeb, to: didWeb)
                try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: didWeb.path)
            }),
            ("malformed", { [self] _, didWeb in
                try self.protectedWrite(Data("not-a-secret".utf8), to: didWeb)
            }),
        ]
        for (name, configure) in cases {
            let root = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: root) }
            let data = root.appending(path: "data")
            let accountKEK = root.appending(path: "account-kek")
            let didWeb = root.appending(path: "did-web-key")
            try protectedWrite(validKEK, to: accountKEK)
            try configure(root, didWeb)
            let result = try runServe(data: data, arguments: [
                "--enable-account-portal",
                "--public-url", "https://swan.example",
                "--signup-account-kek-file", accountKEK.path,
                "--did-web-signing-key-file", didWeb.path,
            ])
            XCTAssertNotEqual(result.status, 0, name)
            XCTAssertTrue(result.error.contains("--did-web-signing-key-file is unavailable"), "\(name): \(result.error)")
            XCTAssertFalse(FileManager.default.fileExists(atPath: data.path), name)
        }
    }

    func testLegacySessionsRequireAccountKeyIssuerConfigurationAndAllowAppViewReuse() throws {
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveLegacySessionAccountKeySource(
                enableLegacySessions: true,
                legacySessionAccountKEKFile: nil,
                legacySessionAccountKEKID: nil,
                legacySessionAccountKeyDirectory: nil,
                appViewProxyAccountKEKFile: nil,
                appViewProxyAccountKEKID: nil,
                appViewProxyAccountKeyDirectory: nil
            )
        ) { error in
            let message = (error as? ValidationError)?.message ?? "\(error)"
            XCTAssertTrue(
                message.contains("--legacy-session-account-kek-file"),
                message
            )
        }

        let dedicated = try XCTUnwrap(
            try SwanCommand.Serve.resolveLegacySessionAccountKeySource(
                enableLegacySessions: true,
                legacySessionAccountKEKFile: "/run/secrets/swan-runtime/account-kek",
                legacySessionAccountKEKID: "primary",
                legacySessionAccountKeyDirectory: "/var/lib/swan/keys",
                appViewProxyAccountKEKFile: nil,
                appViewProxyAccountKEKID: nil,
                appViewProxyAccountKeyDirectory: nil
            )
        )
        XCTAssertFalse(dedicated.reusesAppViewProxyConfiguration)
        XCTAssertEqual(dedicated.activeKeyID, "primary")

        let reused = try XCTUnwrap(
            try SwanCommand.Serve.resolveLegacySessionAccountKeySource(
                enableLegacySessions: true,
                legacySessionAccountKEKFile: nil,
                legacySessionAccountKEKID: nil,
                legacySessionAccountKeyDirectory: nil,
                appViewProxyAccountKEKFile: "/run/secrets/swan-runtime/account-kek",
                appViewProxyAccountKEKID: "primary",
                appViewProxyAccountKeyDirectory: "/var/lib/swan/keys"
            )
        )
        XCTAssertTrue(reused.reusesAppViewProxyConfiguration)
        XCTAssertEqual(reused.activeKeyID, "primary")

        XCTAssertThrowsError(
            try SwanCommand.Serve.resolveLegacySessionAccountKeySource(
                enableLegacySessions: false,
                legacySessionAccountKEKFile: "/run/secrets/swan-runtime/account-kek",
                legacySessionAccountKEKID: nil,
                legacySessionAccountKeyDirectory: nil,
                appViewProxyAccountKEKFile: nil,
                appViewProxyAccountKEKID: nil,
                appViewProxyAccountKeyDirectory: nil
            )
        )
    }

    func testDedicatedLegacyAccountKeyConstructsIssuerWhileAppViewMayRemainDisabled() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let keyDirectory = root.appending(path: "keys")
        try FileManager.default.createDirectory(
            at: keyDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let kekFile = root.appending(path: "account-kek")
        try protectedWrite(
            Data(base64URLEncoded(Data(repeating: 0xA5, count: 32)).utf8),
            to: kekFile
        )
        let source = try XCTUnwrap(
            try SwanCommand.Serve.resolveLegacySessionAccountKeySource(
                enableLegacySessions: true,
                legacySessionAccountKEKFile: kekFile.path,
                legacySessionAccountKEKID: "primary",
                legacySessionAccountKeyDirectory: keyDirectory.path,
                appViewProxyAccountKEKFile: nil,
                appViewProxyAccountKEKID: nil,
                appViewProxyAccountKeyDirectory: nil
            )
        )
        XCTAssertFalse(source.reusesAppViewProxyConfiguration)

        // The production preflight runs before this database is opened. It
        // reads and validates both mounted secrets and pins the protected key
        // directory in one FileAccountKeyStore for later composition.
        let signingKey = root.appending(path: "legacy-signing-key")
        try protectedWrite(
            Data(base64URLEncoded(Data(repeating: 0x53, count: 32)).utf8),
            to: signingKey
        )
        let preflight = try XCTUnwrap(
            try SwanCommand.Serve.preflightLegacySessionStartupMaterial(
                enableLegacySessions: true,
                legacySessionSigningKeyFile: signingKey.path,
                accountKeySource: source,
                dataDirectory: root.appending(path: "data")
            )
        )
        XCTAssertEqual(preflight.signingKey.count, 32)
        XCTAssertEqual(preflight.accountKeyConfiguration.activeKeyID, "primary")
        XCTAssertEqual(preflight.accountKeyDirectory.path, keyDirectory.path)

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let hasher = try LibsodiumArgon2idHasher()
        let accounts = DurableAccountDirectory(
            store: control,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher)
        )
        let issuer = SwanCommand.Serve.makeLegacySessionServiceAuthIssuer(
            accounts: accounts,
            keyStore: preflight.accountKeyStore
        )
        XCTAssertTrue(issuer is LocalAccountProxyServiceTokenIssuer)
        try await control.close()
    }

    func testLegacySessionsWithoutAccountKeyIssuerRefuseBeforeStorage() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let signingKey = root.appending(path: "legacy-signing-key")
        try protectedWrite(
            Data(base64URLEncoded(Data(repeating: 0x53, count: 32)).utf8),
            to: signingKey
        )

        let result = try runServe(data: data, arguments: [
            "--enable-legacy-sessions",
            "--legacy-session-signing-key-file", signingKey.path,
        ])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.output.isEmpty)
        XCTAssertTrue(
            result.error.contains(
                "--enable-legacy-sessions requires an owner-only --legacy-session-account-kek-file"
            ),
            result.error
        )
        XCTAssertFalse(result.error.contains(signingKey.path))
        XCTAssertFalse(result.error.contains(root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    func testLegacySessionMountedSecretsAndKeyRootRefuseBeforeStorage() throws {
        struct Case {
            let name: String
            let configure: (URL, URL, URL, URL) throws -> Void
        }

        func encode(_ data: Data) -> String {
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        func write(_ data: Data, to url: URL) throws {
            try data.write(to: url)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        }

        let cases: [Case] = [
            Case(name: "missing-hmac") { _, _, _, _ in },
            Case(name: "symlinked-hmac") { root, signingKey, _, _ in
                let target = root.appending(path: "hmac-target")
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: target
                )
                try FileManager.default.createSymbolicLink(
                    at: signingKey,
                    withDestinationURL: target
                )
            },
            Case(name: "wrong-mode-hmac") { _, signingKey, _, _ in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o644],
                    ofItemAtPath: signingKey.path
                )
            },
            Case(name: "malformed-hmac") { _, signingKey, _, _ in
                try write(Data("not-a-secret".utf8), to: signingKey)
            },
            Case(name: "missing-kek") { _, signingKey, _, _ in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
            },
            Case(name: "symlinked-kek") { root, signingKey, kekFile, _ in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                let target = root.appending(path: "kek-target")
                try write(
                    Data(encode(Data(repeating: 0xA5, count: 32)).utf8),
                    to: target
                )
                try FileManager.default.createSymbolicLink(
                    at: kekFile,
                    withDestinationURL: target
                )
            },
            Case(name: "wrong-mode-kek") { _, signingKey, kekFile, _ in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                try write(
                    Data(encode(Data(repeating: 0xA5, count: 32)).utf8),
                    to: kekFile
                )
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o644],
                    ofItemAtPath: kekFile.path
                )
            },
            Case(name: "malformed-kek") { _, signingKey, kekFile, _ in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                try write(Data("malformed-kek".utf8), to: kekFile)
            },
            Case(name: "missing-key-root") { _, signingKey, kekFile, _ in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                try write(
                    Data(encode(Data(repeating: 0xA5, count: 32)).utf8),
                    to: kekFile
                )
            },
            Case(name: "symlinked-key-root") { root, signingKey, kekFile, keyDirectory in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                try write(
                    Data(encode(Data(repeating: 0xA5, count: 32)).utf8),
                    to: kekFile
                )
                let target = root.appending(path: "key-root-target")
                try FileManager.default.createDirectory(
                    at: target,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                try FileManager.default.createSymbolicLink(
                    at: keyDirectory,
                    withDestinationURL: target
                )
            },
            Case(name: "wrong-mode-key-root") { _, signingKey, kekFile, keyDirectory in
                try write(
                    Data(encode(Data(repeating: 0x53, count: 32)).utf8),
                    to: signingKey
                )
                try write(
                    Data(encode(Data(repeating: 0xA5, count: 32)).utf8),
                    to: kekFile
                )
                try FileManager.default.createDirectory(
                    at: keyDirectory,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o755]
                )
            },
        ]

        for testCase in cases {
            let root = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: root) }
            let data = root.appending(path: "data")
            let signingKey = root.appending(path: "legacy-signing-key")
            let kekFile = root.appending(path: "account-kek")
            let keyDirectory = root.appending(path: "keys")
            try testCase.configure(root, signingKey, kekFile, keyDirectory)

            let result = try runServe(data: data, arguments: [
                "--enable-legacy-sessions",
                "--legacy-session-signing-key-file", signingKey.path,
                "--legacy-session-account-kek-file", kekFile.path,
                "--legacy-session-account-key-directory", keyDirectory.path,
            ])
            XCTAssertNotEqual(result.status, 0, testCase.name)
            XCTAssertTrue(result.output.isEmpty, testCase.name)
            XCTAssertTrue(
                result.error.contains("legacy-session"),
                "\(testCase.name): \(result.error)"
            )
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: data.path),
                testCase.name
            )
            assertNoStartupStorageArtifacts(in: data, label: testCase.name)
        }
    }

    // MARK: - Helpers

    private func runServe(
        data: URL,
        arguments: [String]
    ) throws -> ProcessResult {
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
        var processEnvironment = ProcessInfo.processInfo.environment
        processEnvironment.removeValue(forKey: "SWAN_OAUTH_SERVER_KEY")
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

    private func assertNoStartupStorageArtifacts(in data: URL, label: String) {
        let artifacts = [
            SQLiteLayout.controlDatabase(in: data),
            data.appending(path: "control.sqlite-wal"),
            data.appending(path: "control.sqlite-shm"),
            SQLiteLayout.firehoseDatabase(in: data),
            data.appending(path: "firehose.sqlite-wal"),
            data.appending(path: "firehose.sqlite-shm"),
            data.appending(path: "actors"),
            data.appending(path: "repositories"),
            data.appending(path: "repos"),
        ]
        for artifact in artifacts {
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: artifact.path),
                "(label): unexpected startup artifact (artifact.lastPathComponent)"
            )
        }
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
