import ArgumentParser
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import SwanAccounts
import SwanCore
@testable import SwanHTTP
import SwanInterop
import SwanOAuth
import SwanPublicFirehose
import SwanPublicRepository
import SwanPublicWire
import SwanSpaces
import SwanSQLite
import SwanStorage
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

    /// An assembly that names no profile serves the profile this build
    /// *attests*, not a historical one.
    ///
    /// `swan verify` and `PublicRepositoryCARReplication` both read
    /// `OfflineProtocolProfileVerifier.publicProfileID`. When the default
    /// surface named `2026-07-27` instead, an operator could run `verify` green
    /// and then `serve` with no new flag and get a process whose attested
    /// contract declared nineteen endpoints while its router served twelve,
    /// with nothing in the build reconciling the two. Pinning the default to
    /// the verifier's constant makes that disagreement impossible to
    /// reintroduce without failing here.
    func testDefaultSurfaceIsTheProfileThisBuildAttests() async throws {
        XCTAssertEqual(
            SwanPublicRouteSurface.default.profileID,
            OfflineProtocolProfileVerifier.publicProfileID
        )
        XCTAssertEqual(
            SwanPublicRouteSurface.default.profileID,
            SwanPublicRouteSurface.successorProfileID
        )
        XCTAssertEqual(
            SwanPublicRouteSurface.default.methods,
            PublicDataTesting20260805.methods
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
        // The attested surface is a strict superset of the historical one, so
        // moving the default forward removes nothing an existing deployment
        // served: it adds the six account-email gates and the subscription.
        XCTAssertTrue(
            Set(PublicDataTesting20260727.methods.map(\.nsid))
                .isSubset(of: SwanPublicRouteSurface.default.declaredMethodNSIDs)
        )

        try await withRouter(surface: nil) { client in
            // Declared by the attested profile, and no account-email runtime is
            // assembled here: a method-correct fail-closed gate, where the
            // historical default left a bare 404.
            try await client.execute(uri: Self.confirmEmailPath, method: .post) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
            try await client.execute(uri: Self.getRecordPath, method: .get) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }
    }

    /// `resolveHandle` is served by every assembly with a read directory and is
    /// declared by no profile, so it reaches registration through the named
    /// out-of-profile constant rather than through a profile's `endpoints`.
    /// Pin that it is the *only* such route: anything else added to that set
    /// would be a public route no profile can ever remove.
    func testTheOnlyRouteOutsideEveryProfileIsResolveHandle() throws {
        XCTAssertEqual(
            SwanPublicRouteSurface.outOfProfilePublicMethods,
            ["com.atproto.identity.resolveHandle"]
        )
        for profileID in SwanPublicRouteSurface.registeredProfileIDs.sorted() {
            let surface = try XCTUnwrap(SwanPublicRouteSurface(profileID: profileID))
            XCTAssertTrue(
                surface.declaredMethodNSIDs
                    .isDisjoint(with: SwanPublicRouteSurface.outOfProfilePublicMethods),
                profileID
            )
            XCTAssertEqual(
                surface.servedMethodNSIDs,
                surface.declaredMethodNSIDs.union(["com.atproto.identity.resolveHandle"]),
                profileID
            )
        }
    }

    /// The firehose gate keys on a literal, because the wire generator emits no
    /// enum for a subscription. A typo would silently disable the route.
    func testSubscribeReposLiteralMatchesTheShippedDescriptor() throws {
        XCTAssertTrue(
            SwanPublicRouteSurface.default.declaredMethodNSIDs
                .contains(publicSubscribeReposNSID)
        )
        XCTAssertEqual(
            PublicDataTesting20260805.methods
                .first { $0.nsid == publicSubscribeReposNSID }?.kind,
            .subscription
        )
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
            try SwanCommand.Serve.resolvePublicRouteSurface(selector: unregistered.path)
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
            "permissioned-data-0016-2026-08-15",
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
            try SwanCommand.Serve.resolvePublicRouteSurface(selector: missing.path)
        ) { XCTAssertTrue($0 is ValidationError) }

        let malformed = root.appending(path: "malformed.json")
        try Data(#"{"identifier":"public-data-testing-2026-07-27"}"#.utf8).write(to: malformed)
        XCTAssertThrowsError(try SwanPublicRouteSurface.load(profileURL: malformed)) { error in
            XCTAssertEqual(error as? SwanPublicRouteSurfaceError, .malformedProfile)
        }
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolvePublicRouteSurface(selector: malformed.path)
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
        // Omitted, not a path. The first version of this flag defaulted to the
        // working-directory-relative `Profiles/public-data-testing-2026-07-27
        // .json`; the runtime container's WORKDIR is the data volume and ships
        // no `Profiles/` directory, so that default turned every containerized
        // `swan serve` into an exit-64 startup refusal before any listener
        // bound. A `nil` default resolves with no filesystem access at all.
        XCTAssertNil(serve.publicProfile)
        XCTAssertEqual(serve.profile, "Profiles/permissioned-data-0016-2026-08-15.json")
        XCTAssertEqual(
            try SwanCommand.Serve.resolvePublicRouteSurface(selector: serve.publicProfile),
            SwanPublicRouteSurface.default
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
        XCTAssertEqual(overridden.profile, "Profiles/permissioned-data-0016-2026-08-15.json")
    }

    /// The deployment case the path-shaped default broke: a process whose
    /// working directory has no `Profiles/` directory at all.
    ///
    /// Every checked-in `swan serve` invocation — `docker-compose.yml`, the
    /// reference-relay compose file, the acceptance scripts, the netcup unit —
    /// passes an absolute `--profile` and no `--public-profile`, and the
    /// runtime image's `WORKDIR` is `/var/lib/swan`, the data volume. Resolving
    /// the omitted flag must therefore touch no path, and an operator who wants
    /// to pin the surface explicitly must be able to do it without a file.
    func testThePublicSurfaceIsSelectableWithNoProfilesDirectoryOnDisk() throws {
        let empty = FileManager.default.temporaryDirectory
            .appending(path: "PublicRouteSurfaceProfileSelectionTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: empty) }
        XCTAssertFalse(
            FileManager.default
                .fileExists(atPath: empty.appending(path: "Profiles").path)
        )

        // Omitted: the attested surface, no I/O.
        XCTAssertEqual(
            try SwanCommand.Serve.resolvePublicRouteSurface(selector: nil),
            SwanPublicRouteSurface.default
        )

        // A bare profile id: allow-list lookup, still no I/O. This is the form
        // a container without a mounted `Profiles/` can use.
        for profileID in SwanPublicRouteSurface.registeredProfileIDs.sorted() {
            XCTAssertFalse(SwanCommand.Serve.isProfilePath(profileID), profileID)
            let surface = try SwanCommand.Serve
                .resolvePublicRouteSurface(selector: profileID)
            XCTAssertEqual(surface.profileID, profileID)
            XCTAssertEqual(
                surface,
                try XCTUnwrap(SwanPublicRouteSurface(profileID: profileID))
            )
        }

        // A misspelled id is refused as an *id*, naming the id — not reported
        // as an unreadable file, which would send the operator looking for a
        // path they never wrote.
        XCTAssertThrowsError(
            try SwanCommand.Serve
                .resolvePublicRouteSurface(selector: "public-data-testing-2099-01-01")
        ) { error in
            let message = (error as? ValidationError)?.message ?? "\(error)"
            XCTAssertTrue(message.contains("public-data-testing-2099-01-01"), message)
            XCTAssertTrue(message.contains("no registered route surface"), message)
            XCTAssertFalse(message.contains("unreadable"), message)
        }

        // The path form is still a path, and a path that does not exist is
        // still a refusal rather than a silent default.
        XCTAssertTrue(
            SwanCommand.Serve
                .isProfilePath("Profiles/public-data-testing-2026-08-06.json")
        )
        XCTAssertThrowsError(
            try SwanCommand.Serve.resolvePublicRouteSurface(
                selector: empty.appending(path: "Profiles/absent.json").path
            )
        ) { error in
            let message = (error as? ValidationError)?.message ?? "\(error)"
            XCTAssertTrue(message.contains("unreadable"), message)
        }
    }

    // MARK: - The selection removes real handlers, not only gates

    /// The failure this family of tests exists for.
    ///
    /// The first version of this mechanism drove only the fail-closed gate
    /// loop. `registerPublicRepositoryReadEndpoints`,
    /// `registerPublicRepositoryMutationEndpoints`,
    /// `registerPublicFirehoseStreamingEndpoint` and
    /// `accountEmailXRPC.register` all installed real handlers unconditionally,
    /// so selecting a narrower profile removed nothing — the control worked in
    /// the widening direction only. It was invisible because every existing
    /// case assembled a router with no runtimes at all, which is the one
    /// configuration where the gap cannot be seen.
    ///
    /// This assembles the runtimes: a read directory, a mutation directory and
    /// signer, an account-email server, and a firehose streaming runtime. Then
    /// it selects a profile that declares fewer methods than those runtimes can
    /// serve and asserts the undeclared ones are *gone*, not merely ungated.
    func testANarrowerProfileRemovesRealHandlersNotOnlyGates() async throws {
        let narrow = try XCTUnwrap(
            SwanPublicRouteSurface(profileID: PublicDataTesting20260727.profileID)
        )
        let attested = SwanPublicRouteSurface.default
        // Premise of the differential, asserted rather than assumed: the narrow
        // profile declares neither the email methods nor the subscription, and
        // both surfaces declare the repository methods.
        XCTAssertFalse(narrow.declaredMethodNSIDs.contains(Self.requestPasswordResetNSID))
        XCTAssertTrue(attested.declaredMethodNSIDs.contains(Self.requestPasswordResetNSID))
        XCTAssertFalse(narrow.declaredMethodNSIDs.contains(publicSubscribeReposNSID))
        XCTAssertTrue(attested.declaredMethodNSIDs.contains(publicSubscribeReposNSID))

        try await withFullyWiredRouter(surface: narrow) { client in
            // The account-email runtime IS assembled. Before this fix the live
            // route was registered anyway and this POST reached the handler and
            // sent mail, while the startup log reported twelve public methods.
            try await client.execute(
                uri: Self.requestPasswordResetPath,
                method: .post,
                headers: Self.jsonHeaders,
                body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            // The firehose runtime IS assembled; the subscription is undeclared,
            // so no upgrade route exists and the `com.atproto.sync.*` guard
            // answers instead.
            try await client.execute(
                uri: "/xrpc/\(publicSubscribeReposNSID)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            // Declared by this profile, so the real handlers stay live. Each
            // probe is deliberately malformed — no required query, no JSON
            // content type — so it is refused by the route's own request
            // validation before any storage is consulted. A live route answers
            // 400; an absent one answers 404 and a 503 placeholder gate answers
            // 503, so one status distinguishes all three.
            try await client.execute(uri: Self.getRecordPath, method: .get) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
            // The write probe is anonymous, so what it proves is that a live
            // handler answered — not which request predicate it failed. The
            // mutation surface authorizes on headers alone before it admits or
            // decodes a body (`SwanPublicRepositoryMutationXRPC.swift:619-649`),
            // so a live route answers 401 here, an absent one 404, and a 503
            // placeholder gate 503. Do not "restore" this to 400 by moving the
            // decode back in front of authorization: that ordering let an
            // anonymous body hold a shared JSON write lease for the whole body
            // deadline (deep-scan F26).
            try await client.execute(
                uri: Self.putRecordPath,
                method: .post,
                headers: Self.jsonHeaders,
                body: ByteBuffer(string: "{}")
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
            // Declared by no profile at all, and still served, because it
            // reaches registration through `outOfProfilePublicMethods`.
            try await client.execute(uri: Self.resolveHandlePath, method: .get) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }

        try await withFullyWiredRouter(surface: attested) { client in
            // Same assembly, wider profile: now the email route is live.
            try await client.execute(
                uri: Self.requestPasswordResetPath,
                method: .post,
                headers: Self.jsonHeaders,
                body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
            ) { response in
                XCTAssertNotEqual(response.status, .notFound)
            }
            // ...and the subscription route exists: a non-upgrade GET is
            // answered by the route itself rather than by the namespace guard.
            try await client.execute(
                uri: "/xrpc/\(publicSubscribeReposNSID)",
                method: .get
            ) { response in
                XCTAssertNotEqual(response.status, .notFound)
            }
            try await client.execute(uri: Self.getRecordPath, method: .get) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
    }

    /// The registration functions themselves refuse to install anything outside
    /// the served set, independent of which profiles happen to ship.
    ///
    /// Every shipped profile declares all five mutation methods and all seven
    /// repository reads, so no profile pair can express "reads off, writes on".
    /// Driving the functions directly with an empty served set is the only way
    /// to pin that the filter is the gate rather than a coincidence of the
    /// current artifacts.
    func testRegistrationFunctionsInstallNothingOutsideTheServedSet() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRouteSurfaceProfileSelectionTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5A, count: 32)
            )
            let router = Router(context: SwanHTTPRequestContext.self)
            registerPublicRepositoryReadEndpoints(
                on: router,
                directory: SurfaceGateReadDirectory(),
                servedMethods: [],
                publicURL: Self.publicURL,
                handleResolution: SwanPublicHandleResolutionCapability(
                    controlStore: control
                )
            )
            registerPublicRepositoryMutationEndpoints(
                on: router,
                capability: SwanPublicRepositoryMutationCapability(
                    authorizer: try SwanOAuthResourceAuthorizer(
                        publicURL: Self.publicURL,
                        runtime: runtime,
                        accountControlStore: control
                    ),
                    directory: SurfaceGateMutationDirectory(),
                    signerProvider: SurfaceGateSignerProvider()
                ),
                servedMethods: []
            )
            Self.emailServer().register(
                on: router,
                requestBodyAdmission: .init(
                    admission: .processShared,
                    policy: .productionDefault
                ),
                servedMethods: []
            )
            // Nothing was registered above, so every one of these paths is
            // unknown to this router — including `resolveHandle`, which an
            // empty served set excludes as well. No namespace guards are
            // installed here, so a 404 can only mean "no route".
            let app = Application(router: router)
            try await app.test(.router) { client in
                for path in [
                    Self.getRecordPath,
                    Self.putRecordPath,
                    Self.resolveHandlePath,
                    "/xrpc/com.atproto.sync.getRepo",
                    "/xrpc/com.atproto.repo.uploadBlob",
                    Self.requestPasswordResetPath,
                ] {
                    for method: HTTPRequest.Method in [.get, .post] {
                        try await client.execute(uri: path, method: method) { response in
                            XCTAssertEqual(response.status, .notFound, "\(method) \(path)")
                        }
                    }
                }
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    // MARK: - Fixtures

    private static let requestPasswordResetNSID =
        "com.atproto.server.requestPasswordReset"
    private static let requestPasswordResetPath =
        "/xrpc/com.atproto.server.requestPasswordReset"
    private static let putRecordPath = "/xrpc/com.atproto.repo.putRecord"
    private static let resolveHandlePath =
        "/xrpc/com.atproto.identity.resolveHandle"
    private static let jsonHeaders: HTTPFields = [.contentType: "application/json"]

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
                    .appending(path: "Profiles/permissioned-data-0016-2026-08-15.json")
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

    // MARK: - The fully wired fixture

    private static let publicURL = URL(string: "https://swan.place")!

    private static func emailServer() -> SwanAccountEmailXRPCServer {
        SwanAccountEmailXRPCServer(
            authorizer: SurfaceGateEmailAuthorizer(),
            recovery: SurfaceGateEmailRecovery(),
            rateLimiter: SurfaceGateEmailRateLimiter(),
            loginClientIdentityPolicy: .direct
        )
    }

    /// A router with every public runtime assembled: a read directory, a
    /// mutation directory and signer, an account-email server, and a firehose
    /// streaming runtime.
    ///
    /// This is the configuration the original mechanism could not be tested in.
    /// `withRouter` above deliberately assembles none of these, which is
    /// exactly why it could not see that a narrower profile removed no real
    /// handler — the only public routes it had were the gates.
    ///
    /// Runs in `.live` mode because the account-email routes read the client
    /// peer through `SwanLoginClientIdentityPolicy`.
    private func withFullyWiredRouter(
        surface: SwanPublicRouteSurface,
        _ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void
    ) async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRouteSurfaceProfileSelectionTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
            do {
                let runtime = try SwanOAuthRuntime(
                    controlStore: control,
                    serverKey: Data(repeating: 0x64, count: 32)
                )
                let profile = try ProtocolProfile.load(
                    from: Self.packageRoot()
                        .appending(path: "Profiles/permissioned-data-0016-2026-08-15.json")
                )
                let directory = SurfaceGateReadDirectory()
                let server = SwanHTTPServer(
                    profile: profile,
                    configuration: SwanHTTPConfiguration(
                        host: "127.0.0.1",
                        port: 0,
                        publicURL: Self.publicURL,
                        publicRouteSurface: surface
                    ),
                    oauthRuntime: runtime,
                    // Required for the public *mutation* capability to form at
                    // all: `SwanHTTPServer` builds the shared resource
                    // authorizer from it, and without one public writes stay
                    // off however the profile is selected.
                    authenticatedGetSpaceDirectory: SurfaceGateSpaceDirectory(),
                    accountControlStore: control,
                    publicRepositoryReadDirectory: directory,
                    publicRepositoryMutationDirectory: SurfaceGateMutationDirectory(),
                    publicRepositoryMutationSignerProvider: SurfaceGateSignerProvider(),
                    accountEmailXRPC: Self.emailServer(),
                    publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime(
                        database: firehose,
                        hub: PublicFirehoseWakeupHub(),
                        limits: .standard,
                        logger: Logger(label: "PublicRouteSurfaceProfileSelectionTests.firehose")
                    )
                )
                let app = server.buildApplication(
                    logger: Logger(label: "PublicRouteSurfaceProfileSelectionTests.wired")
                )
                try await app.test(.live, body)
                try await firehose.close()
                try await control.close()
            } catch {
                try? await firehose.close()
                throw error
            }
        } catch {
            try? await control.close()
            throw error
        }
    }
}

// MARK: - Stubs

/// None of these are reached by the probes above: every probe is refused by its
/// route's own request validation before storage is consulted, which is what
/// makes "400" mean "the real handler is installed" and nothing more.
private enum SurfaceGateStubFailure: Error { case unused }

private struct SurfaceGateReadDirectory: PublicRepositoryReadDirectory {
    func publicRepositoryStatus(selector _: String) async throws
        -> PublicRepositoryReadStatus?
    { throw SurfaceGateStubFailure.unused }

    func describePublicRepository(selector _: String) async throws
        -> PublicRepositoryReadDescription?
    { throw SurfaceGateStubFailure.unused }

    func publicRepositoryRecord(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadRecord? {
        throw SurfaceGateStubFailure.unused
    }

    func listPublicRepositoryRecords(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadPage {
        throw SurfaceGateStubFailure.unused
    }

    func publicRepositoryCAR(selector _: String) async throws
        -> PublicRepositoryReadCAR?
    { throw SurfaceGateStubFailure.unused }

    func publicRepositoryDescriptionOutcome(selector _: String) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    { throw SurfaceGateStubFailure.unused }

    func publicRepositoryRecordOutcome(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult> {
        throw SurfaceGateStubFailure.unused
    }

    func publicRepositoryRecordsOutcome(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult> {
        throw SurfaceGateStubFailure.unused
    }

    func publicRepositoryCAROutcome(selector _: String) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR>
    { throw SurfaceGateStubFailure.unused }

    func publicRepositoryBlobOutcome(did _: String) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget>
    { throw SurfaceGateStubFailure.unused }
}

private actor SurfaceGateSpaceDirectory: AuthorizedSimpleSpaceDirectory {
    func space(
        _: SpaceURI,
        authorization _: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? { nil }

    func close() async throws {}
}

private struct SurfaceGateMutationDirectory: PublicRepositoryMutationDirectory {
    func publicRepositoryMutationTarget(selector _: String) async throws
        -> PublicRepositoryMutationTarget?
    { throw SurfaceGateStubFailure.unused }
}

private struct SurfaceGateSignerProvider: PublicRepositoryMutationSignerProvider {
    func signer(for _: String) async throws -> PublicRepositoryMutationSigner {
        throw SurfaceGateStubFailure.unused
    }
}

private struct SurfaceGateEmailAuthorizer: SwanAccountEmailResourceAuthorizing {
    func authorizeAccountEmail(
        request _: Request,
        method _: String,
        fixedPath _: String,
        now _: Date
    ) async throws -> AuthorizationContext {
        throw SwanResourceAuthorizationFailure.denied
    }

    func issueAccountEmailNonce(now _: Date) async -> String { "surface-gate-nonce" }
}

private struct SurfaceGateEmailRecovery: SwanAccountEmailXRPCRecovering {
    func requestEmailConfirmation(did _: String, now _: Date) async throws {
        throw SurfaceGateStubFailure.unused
    }

    func confirmEmail(
        did _: String,
        email _: AccountEmailAddress,
        proof _: String,
        now _: Date
    ) async throws -> AccountEmailConfirmationOutcome {
        throw SurfaceGateStubFailure.unused
    }

    func requestPasswordRecovery(
        email _: AccountEmailAddress,
        now _: Date
    ) async throws {}

    func resetPassword(
        proof _: String,
        password _: String,
        now _: Date
    ) async throws -> AccountPasswordResetOutcome {
        throw SurfaceGateStubFailure.unused
    }
}

private struct SurfaceGateEmailRateLimiter: SwanAccountEmailXRPCRateLimiting {
    func permits(
        _: SwanAccountEmailRateLimitRequest,
        now _: Date
    ) async throws -> Bool { true }
}
