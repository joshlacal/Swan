import ArgumentParser
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanPublicWire
import SwanSQLite
@testable import swan
import XCTest

/// Public route registration used to iterate `PublicDataTesting20260727.methods`
/// as a literal. Every other consumer of a profile — the interop verifier, the
/// permissioned pins, `describeServer`'s advertisement — moved when the operator
/// selected a different one, and the public route surface did not. These tests
/// pin that the selection is now the control, and that a profile this build has
/// no registry for stops the process instead of producing a surface nobody
/// chose.
final class PublicRouteSurfaceProfileSelectionTests: XCTestCase {
    /// Declared by `public-data-testing-2026-07-30` and every later public
    /// profile, and by none of `2026-07-27`'s twelve methods. It is the
    /// cheapest observable difference between two shipped surfaces that does
    /// not depend on any runtime being assembled.
    private static let confirmEmailPath = "/xrpc/com.atproto.server.confirmEmail"
    /// Declared by every shipped public profile, so it must not move when the
    /// selection does.
    private static let getRecordPath = "/xrpc/com.atproto.repo.getRecord"

    // MARK: - The selection reaches the router

    func testRouteSurfaceFollowsTheLoadedProfile() async throws {
        let historical = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: PublicDataTesting20260727.profileID)
        )
        let successor = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: PublicDataTesting20260730.profileID)
        )
        // Guard the premise of the differential below: these two surfaces have
        // to actually disagree about this method, or the assertions would pass
        // against a router that ignored the selection entirely.
        XCTAssertFalse(historical.methods.contains { $0.nsid == "com.atproto.server.confirmEmail" })
        XCTAssertTrue(successor.methods.contains { $0.nsid == "com.atproto.server.confirmEmail" })

        try await withRouter(surface: historical) { client in
            // Not in the selected profile: no method-correct gate is installed
            // for it, so it is simply not a route this server has.
            try await client.execute(uri: Self.confirmEmailPath, method: .post) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }

        try await withRouter(surface: successor) { client in
            // In the selected profile, with no account-email runtime assembled:
            // a method-correct, fail-closed gate rather than a missing route.
            try await client.execute(uri: Self.confirmEmailPath, method: .post) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
            // ...and still method-correct, which is what distinguishes a
            // profile-declared endpoint from a route that does not exist.
            try await client.execute(uri: Self.confirmEmailPath, method: .get) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }

        // A method both profiles declare must not move when the selection does.
        for surface in [historical, successor] {
            try await withRouter(surface: surface) { client in
                try await client.execute(uri: Self.getRecordPath, method: .get) { response in
                    XCTAssertEqual(
                        response.status,
                        .serviceUnavailable,
                        surface.profileID
                    )
                }
            }
        }
    }

    /// The whole selected contract, not one sampled method: every declared
    /// query and procedure answers its own method with a fail-closed gate, and
    /// nothing the profile does not declare acquires one.
    func testEveryDeclaredMethodOfTheSelectedProfileIsGatedAndNothingElseIs() async throws {
        let selected = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: PublicDataTesting20260805.profileID)
        )
        let historical = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: PublicDataTesting20260727.profileID)
        )
        let declared = Set(selected.methods.map(\.nsid))
        // Methods the *older* profile declares are a subset here; the interesting
        // direction is the other one, so assert against a method the selected
        // profile does not declare at all.
        XCTAssertTrue(Set(historical.methods.map(\.nsid)).isSubset(of: declared))
        XCTAssertFalse(declared.contains("com.atproto.sync.listRepos"))

        try await withRouter(surface: selected) { client in
            for descriptor in selected.methods {
                let path = "/xrpc/\(descriptor.nsid)"
                switch descriptor.kind {
                case .query:
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable, path)
                    }
                    try await client.execute(uri: path, method: .post) { response in
                        XCTAssertEqual(response.status, .notFound, path)
                    }
                case .procedure:
                    try await client.execute(uri: path, method: .post) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable, path)
                    }
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .notFound, path)
                    }
                case .subscription:
                    // Subscriptions are a WebSocket upgrade, registered by the
                    // streaming runtime or not at all; the descriptor loop
                    // installs no HTTP gate for them.
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .notFound, path)
                    }
                }
            }
            // Undeclared, and inside a namespace whose wildcard guard answers
            // 404 — a profile-driven loop must not have widened it into a 503.
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.listRepos",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
    }

    /// An assembly that names no profile keeps serving exactly what it served
    /// before the selection existed.
    func testDefaultConfigurationServesTheHistoricalSurfaceUnchanged() async throws {
        XCTAssertEqual(
            SwanPublicRouteSurface.default.profileID,
            PublicDataTesting20260727.profileID
        )
        XCTAssertEqual(
            SwanPublicRouteSurface.default.methods,
            PublicDataTesting20260727.methods
        )
        // The default is built from the same constants the allow-list entry is
        // built from, so it cannot drift into naming a surface the allow-list
        // would refuse.
        let lookedUp = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: SwanPublicRouteSurface.default.profileID)
        )
        XCTAssertEqual(lookedUp, SwanPublicRouteSurface.default)
        XCTAssertEqual(
            SwanHTTPConfiguration().publicRouteSurface,
            SwanPublicRouteSurface.default
        )

        try await withRouter(surface: nil) { client in
            try await client.execute(uri: Self.confirmEmailPath, method: .post) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            try await client.execute(uri: Self.getRecordPath, method: .get) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }
    }

    // MARK: - Fail loudly for a profile with no registry

    func testStartupFailsLoudlyForAProfileWithNoRegistry() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRouteSurfaceProfileSelectionTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        // A plausible future successor that ships in `Profiles/` before anyone
        // adds its descriptor registry. This is the exact shape of the bug: the
        // artifact exists, the operator points at it, and the build has no
        // method set for it.
        let unregistered = root.appending(path: "public-data-testing-2099-01-01.json")
        try Data(#"{"id":"public-data-testing-2099-01-01","endpoints":[]}"#.utf8)
            .write(to: unregistered)

        XCTAssertNil(SwanPublicRouteSurface(profileID: "public-data-testing-2099-01-01"))
        XCTAssertThrowsError(try SwanPublicRouteSurface.load(profileURL: unregistered)) { error in
            XCTAssertEqual(
                error as? SwanPublicRouteSurfaceError,
                .unregisteredProfile(id: "public-data-testing-2099-01-01")
            )
        }

        // The CLI seam: an unusable `--public-profile` is an ArgumentParser
        // validation failure carrying the offending id, not a default surface.
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolvePublicRouteSurface(path: unregistered.path)
        ) { error in
            let validation = error as? ValidationError
            XCTAssertNotNil(validation)
            XCTAssertTrue(
                validation?.message.contains("public-data-testing-2099-01-01") ?? false,
                validation?.message ?? "\(error)"
            )
            XCTAssertTrue(
                validation?.message.contains("--public-profile") ?? false,
                validation?.message ?? "\(error)"
            )
        }
    }

    /// The permissioned family is a different contract and may not stand in for
    /// the public one, however well-formed its artifact is.
    func testPermissionedProfilesAreNotAPublicRouteSurface() throws {
        for name in [
            "permissioned-data-0016-2026-07-03",
            "permissioned-data-0016-2026-07-30",
        ] {
            XCTAssertNil(SwanPublicRouteSurface(profileID: name), name)
            let url = Self.packageRoot().appending(path: "Profiles/\(name).json")
            XCTAssertThrowsError(try SwanPublicRouteSurface.load(profileURL: url), name) { error in
                XCTAssertEqual(
                    error as? SwanPublicRouteSurfaceError,
                    .unregisteredProfile(id: name),
                    name
                )
            }
        }
    }

    func testUnreadableAndMalformedProfilesAreAlsoStartupFailures() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRouteSurfaceProfileSelectionTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let missing = root.appending(path: "absent.json")
        XCTAssertThrowsError(try SwanPublicRouteSurface.load(profileURL: missing)) { error in
            XCTAssertEqual(error as? SwanPublicRouteSurfaceError, .unreadableProfile)
        }
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolvePublicRouteSurface(path: missing.path)
        ) { XCTAssertTrue($0 is ValidationError) }

        let malformed = root.appending(path: "malformed.json")
        try Data(#"{"identifier":"public-data-testing-2026-07-27"}"#.utf8).write(to: malformed)
        XCTAssertThrowsError(try SwanPublicRouteSurface.load(profileURL: malformed)) { error in
            XCTAssertEqual(error as? SwanPublicRouteSurfaceError, .malformedProfile)
        }
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolvePublicRouteSurface(path: malformed.path)
        ) { XCTAssertTrue($0 is ValidationError) }
    }

    // MARK: - The registry agrees with what ships in Profiles/

    /// Re-derived here from the shipped artifacts rather than taken from
    /// `SwanPublicWireTests`, which asserts the same equality for an unrelated
    /// reason and could be changed by someone with no idea route selection
    /// depends on it. A registry entry that stops matching its profile would
    /// otherwise serve the wrong public surface with no signal at all.
    func testEveryRegisteredProfileServesTheEndpointsItsArtifactDeclares() throws {
        XCTAssertEqual(
            SwanPublicRouteSurface.registeredProfileIDs,
            [
                "public-data-testing-2026-07-27",
                "public-data-testing-2026-07-30",
                "public-data-testing-2026-08-05",
                "public-data-testing-2026-08-06",
            ]
        )
        for profileID in SwanPublicRouteSurface.registeredProfileIDs.sorted() {
            let url = Self.packageRoot().appending(path: "Profiles/\(profileID).json")
            let declared = try Self.declaredEndpoints(at: url)
            let surface = try SwanPublicRouteSurface.load(profileURL: url)
            XCTAssertEqual(surface.profileID, profileID)
            XCTAssertEqual(surface.methods.map(\.nsid), declared, profileID)
            XCTAssertEqual(
                Set(surface.methods.map(\.nsid)).count,
                surface.methods.count,
                profileID
            )
        }
    }

    /// `public-data-testing-2026-08-06` has no registry of its own on purpose:
    /// it is a retention successor with a byte-identical wire contract, and
    /// `Sources/SwanPublicWire/SwanPublicWire.swift` is pinned by that very
    /// profile's `generated-wire.sha256`, so declaring a duplicate there would
    /// invalidate the profile it was meant to serve. The alias is only sound
    /// while the two artifacts still agree — assert that directly.
    func testSuccessorProfileAliasStillMatchesItsPredecessorsContract() throws {
        let predecessor = try Self.declaredEndpoints(
            at: Self.packageRoot()
                .appending(path: "Profiles/public-data-testing-2026-08-05.json")
        )
        let successor = try Self.declaredEndpoints(
            at: Self.packageRoot()
                .appending(path: "Profiles/public-data-testing-2026-08-06.json")
        )
        XCTAssertEqual(successor, predecessor)
        XCTAssertEqual(successor.count, 19)

        let surface = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: SwanPublicRouteSurface.successorProfileID)
        )
        XCTAssertEqual(surface.methods, PublicDataTesting20260805.methods)
        XCTAssertEqual(surface.methods.map(\.nsid), successor)
        XCTAssertEqual(surface.profileID, "public-data-testing-2026-08-06")
    }

    // MARK: - The flag exists and defaults to today's surface

    func testServeParsesPublicProfileWithoutDisturbingTheProfileOption() throws {
        let parsed = try SwanCommand.parseAsRoot(["serve"])
        let serve = try XCTUnwrap(parsed as? SwanCommand.Serve)
        XCTAssertEqual(serve.publicProfile, "Profiles/public-data-testing-2026-07-27.json")
        XCTAssertEqual(serve.profile, "Profiles/permissioned-data-0016-2026-07-30.json")
        XCTAssertEqual(
            try SwanCommand.Serve.resolvePublicRouteSurface(path: serve.publicProfile).profileID,
            SwanPublicRouteSurface.default.profileID
        )

        let overridden = try XCTUnwrap(
            try SwanCommand.parseAsRoot([
                "serve",
                "--public-profile", "Profiles/public-data-testing-2026-08-06.json",
            ]) as? SwanCommand.Serve
        )
        XCTAssertEqual(
            overridden.publicProfile,
            "Profiles/public-data-testing-2026-08-06.json"
        )
        // `--profile` is untouched by the new option: two contract families,
        // two flags, neither able to select the other's surface.
        XCTAssertEqual(overridden.profile, "Profiles/permissioned-data-0016-2026-07-30.json")
    }

    // MARK: - Fixtures

    private struct PublicProfileArtifact: Decodable {
        let id: String
        let endpoints: [String]
    }

    private static func declaredEndpoints(at url: URL) throws -> [String] {
        try JSONDecoder()
            .decode(PublicProfileArtifact.self, from: Data(contentsOf: url))
            .endpoints
    }

    private static func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    /// A router with no public read directory, no public mutation runtime, no
    /// account-email runtime and no pipethrough, so the only thing that decides
    /// which public routes exist is the selected surface.
    ///
    /// The control database is closed on the failure path too: SQLiteNIO traps
    /// in `deinit` on a still-open connection, which turns one failed assertion
    /// into a crashed target that truncates every later test.
    private func withRouter(
        surface: SwanPublicRouteSurface?,
        _ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void
    ) async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRouteSurfaceProfileSelectionTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x63, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: Self.packageRoot()
                    .appending(path: "Profiles/permissioned-data-0016-2026-07-30.json")
            )
            let configuration = surface.map {
                SwanHTTPConfiguration(
                    host: "127.0.0.1",
                    port: 3000,
                    publicURL: URL(string: "https://swan.place")!,
                    publicRouteSurface: $0
                )
            } ?? SwanHTTPConfiguration(
                host: "127.0.0.1",
                port: 3000,
                publicURL: URL(string: "https://swan.place")!
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: configuration,
                oauthRuntime: runtime
            )
            let app = server.buildApplication(
                logger: Logger(label: "PublicRouteSurfaceProfileSelectionTests")
            )
            try await app.test(.router, body)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }
}
