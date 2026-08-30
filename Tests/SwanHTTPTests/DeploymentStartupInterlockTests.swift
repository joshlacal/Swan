import ArgumentParser
import Foundation
@testable import SwanHTTP
@testable import swan
import XCTest

/// The three `swan serve` startup refusals added by the deployment-configuration
/// lane, plus the public listener budget flag that feeds them.
///
/// Every assertion here is on a pure static: the point of pulling these out of
/// `run()` is that a refusal can be pinned without opening a database, minting
/// a key store, or binding a listener. A refusal that could only be observed by
/// spawning the executable would be a refusal nobody re-checks.
final class DeploymentStartupInterlockTests: XCTestCase {
    private static func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private static func url(_ text: String) throws -> URL {
        try XCTUnwrap(URL(string: text), text)
    }

    // MARK: - What counts as an origin strangers can reach

    /// The classifier both laboratory interlocks share. The two rows that
    /// matter most are `https://swan.test` and `https://swan.example`: they are
    /// non-loopback HTTPS origins, so the naive "non-loopback HTTPS" rule would
    /// refuse the disposable interop laboratory and the serve CLI regression
    /// suite — the exact configurations these options exist for.
    func testPublicReachabilityClassifierSeparatesLabOriginsFromRealOnes() throws {
        let reachable = [
            "https://swan.catbird.blue",
            "https://swan.catbird.blue:8443",
            "https://pds.example-not-reserved.org",
            "https://93.184.216.34",
            "https://[2606:2800:220:1:248:1893:25c8:1946]",
        ]
        for text in reachable {
            XCTAssertTrue(
                SwanCommand.Serve.isPubliclyReachableHTTPSOrigin(try Self.url(text)),
                text
            )
        }

        let notReachable = [
            // Reserved names. RFC 6761 / RFC 2606 / RFC 8375 / ICANN.
            "https://swan.test",
            "https://swan.example",
            "https://swan.invalid",
            "https://swan.localhost",
            "https://swan.local",
            "https://swan.internal",
            "https://swan.home.arpa",
            "https://www.example.com",
            "https://SWAN.TEST",
            "https://swan.test.",
            // No public delegation is possible for a bare label.
            "https://swan",
            "https://localhost",
            // Literals the outbound-address policy already refuses.
            "https://127.0.0.1",
            "https://[::1]",
            "https://10.0.0.5",
            "https://172.30.0.5",
            "https://198.51.100.7",
            // Not HTTPS at all: an HTTP origin is loopback development or is
            // already refused by the interop guard.
            "http://swan.catbird.blue",
        ]
        for text in notReachable {
            XCTAssertFalse(
                SwanCommand.Serve.isPubliclyReachableHTTPSOrigin(try Self.url(text)),
                text
            )
        }
    }

    // MARK: - F17: a laboratory PLC may not sit on a public origin

    func testLaboratoryPLCIsRefusedOnAPubliclyReachableOrigin() throws {
        XCTAssertThrowsError(
            try SwanCommand.Serve.requireLaboratoryPLCStaysOffPublicOrigins(
                notificationConfigurationSelectsLaboratoryPLC: true,
                publicURL: try Self.url("https://swan.catbird.blue")
            )
        ) { error in
            let validation = error as? ValidationError
            XCTAssertNotNil(validation, "\(error)")
            XCTAssertTrue(
                validation?.message.contains("--notification-config") ?? false,
                validation?.message ?? "\(error)"
            )
            XCTAssertTrue(
                validation?.message.contains("laboratory PLC") ?? false,
                validation?.message ?? "\(error)"
            )
        }
    }

    /// The three non-refusal branches, each one a configuration that ships.
    func testLaboratoryPLCIsPermittedWhereItIsActuallyUsed() throws {
        // The interop laboratory: `laboratory: true` behind Caddy on swan.test.
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireLaboratoryPLCStaysOffPublicOrigins(
                notificationConfigurationSelectsLaboratoryPLC: true,
                publicURL: try Self.url("https://swan.test")
            )
        )
        // Loopback development.
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireLaboratoryPLCStaysOffPublicOrigins(
                notificationConfigurationSelectsLaboratoryPLC: true,
                publicURL: try Self.url("http://127.0.0.1:3000")
            )
        )
        // A production PLC policy on a production origin is the whole point.
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireLaboratoryPLCStaysOffPublicOrigins(
                notificationConfigurationSelectsLaboratoryPLC: false,
                publicURL: try Self.url("https://swan.catbird.blue")
            )
        )
    }

    /// The interlock is only worth anything if the probe actually reads the
    /// flag out of a real configuration. This asserts against the checked-in
    /// laboratory file rather than a fixture, so removing `laboratory: true`
    /// from it — or renaming the field — fails here instead of silently
    /// disarming the refusal.
    func testLaboratorySelectionIsReadFromTheCheckedInInteropConfiguration() throws {
        let laboratory = Self.packageRoot()
            .appending(path: "interop/notification-config.json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: laboratory.path))
        XCTAssertTrue(ServeNotificationRuntime.selectsLaboratoryPLC(from: laboratory))

        let root = FileManager.default.temporaryDirectory
            .appending(path: "DeploymentStartupInterlockTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        // A production configuration, and the delegation resolver's own
        // laboratory flag, which is a second way in.
        let production = root.appending(path: "production.json")
        try Data(#"{"credentialKeyPLC":{"origin":"https://plc.directory","laboratory":false}}"#.utf8)
            .write(to: production)
        XCTAssertFalse(ServeNotificationRuntime.selectsLaboratoryPLC(from: production))

        let delegation = root.appending(path: "delegation.json")
        try Data(#"{"delegationKeyPLC":{"origin":"http://reference-plc:2582","laboratory":true}}"#.utf8)
            .write(to: delegation)
        XCTAssertTrue(ServeNotificationRuntime.selectsLaboratoryPLC(from: delegation))

        // An absent or unusable file answers "no laboratory PLC" rather than
        // throwing: `ServeNotificationRuntime.load` refuses it a few lines
        // later with a message that names the flag.
        XCTAssertFalse(
            ServeNotificationRuntime.selectsLaboratoryPLC(
                from: root.appending(path: "absent.json")
            )
        )
    }

    func testNotificationConfigPreflightReadsOnceAndPinsImmutableConfiguration() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "NotificationPreflightTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let configURL = root.appending(path: "notification.json")
        let initialData = Data(#"{"credentialKeyPLC":{"origin":"https://plc.directory","laboratory":false}}"#.utf8)
        try initialData.write(to: configURL)

        guard let preflighted = try ServeNotificationRuntime.preflight(fromFile: configURL.path) else {
            XCTFail("expected preflighted configuration")
            return
        }
        XCTAssertEqual(preflighted.rawData, initialData)
        XCTAssertFalse(preflighted.selectsLaboratoryPLC)

        // Modify the file on disk to select laboratory PLC
        let modifiedData = Data(#"{"credentialKeyPLC":{"origin":"http://lab.invalid","laboratory":true}}"#.utf8)
        try modifiedData.write(to: configURL)

        // The preflighted configuration remains immutable and unaffected by subsequent file modification
        XCTAssertEqual(preflighted.rawData, initialData)
        XCTAssertFalse(preflighted.selectsLaboratoryPLC)

        // A second preflight would reflect the new file state
        let secondPreflight = try ServeNotificationRuntime.preflight(fromFile: configURL.path)
        XCTAssertEqual(secondPreflight?.selectsLaboratoryPLC, true)
    }

    // MARK: - F36: the metadata IP allowlist may not sit on a public origin

    func testMetadataIPAllowlistIsRefusedOnAPubliclyReachableOrigin() throws {
        XCTAssertThrowsError(
            try SwanCommand.Serve.requireMetadataIPAllowlistStaysOffPublicOrigins(
                allowlistedMetadataIPLiterals: ["127.0.0.1"],
                publicURL: try Self.url("https://swan.catbird.blue")
            )
        ) { error in
            let validation = error as? ValidationError
            XCTAssertNotNil(validation, "\(error)")
            XCTAssertTrue(
                validation?.message.contains("--oauth-allow-metadata-ip") ?? false,
                validation?.message ?? "\(error)"
            )
        }
    }

    func testMetadataIPAllowlistIsPermittedEmptyOrInTheLaboratory() throws {
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireMetadataIPAllowlistStaysOffPublicOrigins(
                allowlistedMetadataIPLiterals: [],
                publicURL: try Self.url("https://swan.catbird.blue")
            )
        )
        // `https://swan.example` is what the serve CLI regression suite starts
        // with an allowlisted `127.0.0.1`; refusing it would break that suite
        // and the laboratory it stands for.
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireMetadataIPAllowlistStaysOffPublicOrigins(
                allowlistedMetadataIPLiterals: ["127.0.0.1"],
                publicURL: try Self.url("https://swan.example")
            )
        )
    }

    // MARK: - F13: an advertised endpoint must have a route

    /// The no-op half. Every profile artifact that ships resolves to a surface
    /// that serves everything it advertises, so this guard costs today's
    /// deployments nothing.
    func testEveryShippedPublicProfileAdvertisesOnlyServedEndpoints() throws {
        for profileID in SwanPublicRouteSurface.registeredProfileIDs.sorted() {
            let url = Self.packageRoot().appending(path: "Profiles/\(profileID).json")
            let data = try Data(contentsOf: url)
            let surface = try SwanPublicRouteSurface.resolve(profileData: data)
            XCTAssertNoThrow(
                try SwanCommand.Serve.requireAdvertisedEndpointsAreServed(
                    profileData: data,
                    surface: surface
                ),
                profileID
            )
            // And the whole selection path agrees, which is what `serve`
            // actually calls.
            XCTAssertEqual(
                try SwanCommand.Serve.resolvePublicRouteSurface(selector: url.path),
                surface,
                profileID
            )
        }
    }

    /// The guarded half: a successor artifact mapped onto an older registry
    /// entry. This is the shape `public-data-testing-2026-08-06` already has —
    /// it aliases `PublicDataTesting20260805`'s method list — so a successor
    /// that genuinely changes its contract is one `Profiles/` file away.
    func testAProfileAdvertisingAnUnroutedEndpointIsAStartupRefusal() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "DeploymentStartupInterlockTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let surface = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: SwanPublicRouteSurface.successorProfileID)
        )
        // Guard the premise: the router genuinely installs no handler for this.
        XCTAssertFalse(surface.servedMethodNSIDs.contains("com.atproto.repo.importRepo"))

        var advertised = surface.methods.map(\.nsid)
        advertised.append("com.atproto.repo.importRepo")
        let artifact = root.appending(path: "successor.json")
        try JSONSerialization.data(
            withJSONObject: [
                "id": SwanPublicRouteSurface.successorProfileID,
                "endpoints": advertised,
            ],
            options: [.sortedKeys]
        ).write(to: artifact)

        XCTAssertThrowsError(
            try SwanCommand.Serve.resolvePublicRouteSurface(selector: artifact.path)
        ) { error in
            let validation = error as? ValidationError
            XCTAssertNotNil(validation, "\(error)")
            XCTAssertTrue(
                validation?.message.contains("com.atproto.repo.importRepo") ?? false,
                validation?.message ?? "\(error)"
            )
            XCTAssertTrue(
                validation?.message.contains("--public-profile") ?? false,
                validation?.message ?? "\(error)"
            )
        }
    }

    /// The asymmetry is deliberate and must stay one-directional: the router
    /// serves `com.atproto.identity.resolveHandle` although no profile declares
    /// it, and that is not an error.
    func testServingMoreThanTheArtifactDeclaresIsNotARefusal() throws {
        let surface = SwanPublicRouteSurface.default
        XCTAssertTrue(
            surface.servedMethodNSIDs.contains("com.atproto.identity.resolveHandle")
        )
        XCTAssertFalse(
            surface.declaredMethodNSIDs.contains("com.atproto.identity.resolveHandle")
        )
        let data = try JSONSerialization.data(
            withJSONObject: ["id": surface.profileID, "endpoints": [] as [String]],
            options: [.sortedKeys]
        )
        XCTAssertNoThrow(
            try SwanCommand.Serve.requireAdvertisedEndpointsAreServed(
                profileData: data,
                surface: surface
            )
        )
    }

    // MARK: - F05: the listener budget is finally an operator control

    func testMaxConnectionsParsesAndDefaultsToTheDocumentedBudget() throws {
        let defaulted = try XCTUnwrap(
            try SwanCommand.parseAsRoot(["serve"]) as? SwanCommand.Serve
        )
        XCTAssertEqual(defaulted.maxConnections, 256)

        let overridden = try XCTUnwrap(
            try SwanCommand.parseAsRoot([
                "serve", "--max-connections", "512",
            ]) as? SwanCommand.Serve
        )
        XCTAssertEqual(overridden.maxConnections, 512)
    }

    /// The flag is only worth having because the anonymous firehose
    /// reservation is a share of it. Pin that relationship at both the default
    /// and an operator-chosen value, so a change to either end is visible here.
    func testTheFirehoseReservationTracksTheConfiguredBudget() {
        XCTAssertEqual(
            PublicFirehoseSubscriberAdmission.reservedSubscriberSlots(listenerBudget: 256),
            64
        )
        XCTAssertEqual(
            PublicFirehoseSubscriberAdmission.reservedSubscriberSlots(listenerBudget: 512),
            128
        )
        XCTAssertEqual(
            SwanHTTPConfiguration(maximumConnections: 512).maximumConnections,
            512
        )
        // Never zero, however small the budget: a zero reservation would make
        // `subscribeRepos` permanently unavailable.
        XCTAssertEqual(
            PublicFirehoseSubscriberAdmission.reservedSubscriberSlots(listenerBudget: 1),
            1
        )
    }

    // MARK: - Legacy sessions and their signing key

    private func requireLegacySessionKey(
        enabled: Bool,
        keyFile: String?
    ) throws {
        try SwanCommand.Serve.requireLegacySessionKeyMatchesFlag(
            enableLegacySessions: enabled,
            legacySessionSigningKeyFile: keyFile
        )
    }

    /// Enabling the deployment's first bearer credential without a signing key
    /// must not boot.
    func testLegacySessionsWithoutAKeyRefusesToStart() {
        XCTAssertThrowsError(try requireLegacySessionKey(enabled: true, keyFile: nil))
    }

    /// A present-but-blank path is the same misconfiguration wearing a value —
    /// an unset environment variable interpolated into a compose file lands
    /// here, not in the `nil` case.
    func testLegacySessionsWithABlankKeyPathRefusesToStart() {
        for blank in ["", " ", "\t", "\n", "   \n "] {
            XCTAssertThrowsError(
                try requireLegacySessionKey(enabled: true, keyFile: blank),
                "blank path \(blank.debugDescription) must be refused"
            )
        }
    }

    /// The other direction, and the one a naive interlock misses: a signing
    /// secret staged on disk with the feature off means someone believes
    /// legacy login is live when `createSession` still 404s.
    func testAKeyWithoutTheFlagRefusesToStart() {
        XCTAssertThrowsError(
            try requireLegacySessionKey(enabled: false, keyFile: "/run/secrets/swan-runtime/legacy-key")
        )
    }

    /// Both coherent configurations boot. The default — feature off, no key —
    /// is what every existing deployment passes, so this pins that adding the
    /// option changed nothing for them.
    func testCoherentLegacySessionConfigurationsStart() {
        XCTAssertNoThrow(try requireLegacySessionKey(enabled: false, keyFile: nil))
        XCTAssertNoThrow(
            try requireLegacySessionKey(enabled: true, keyFile: "/run/secrets/swan-runtime/legacy-key")
        )
    }
}
