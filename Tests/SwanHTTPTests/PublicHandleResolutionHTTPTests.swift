import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanPublicRepository
import SwanSQLite
import SwanStorage
import XCTest

/// `com.atproto.identity.resolveHandle` is the method every other actor on the
/// network reaches for first: a client resolving a login identifier, another
/// PDS confirming where a handle lives, an AppView binding a handle to a DID.
/// Swan answered 404 for it, which — before routing moved ahead of
/// authentication — was indistinguishable from a credential problem.
///
/// It is implemented independently of the public repository read directory on
/// purpose. Handle resolution reads one control row; it must keep working when
/// no repository generation can be admitted at all, which is exactly the state
/// the 2026-08-12 outage left every public read route in.
final class PublicHandleResolutionHTTPTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:6u6rzv6fk3ga37kgs3tybgdk"
    private static let handle = "swan.place"
    private static let otherDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
    private static let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
    private static let resolveHandlePath =
        "/xrpc/com.atproto.identity.resolveHandle"

    /// The output shape `com.atproto.identity.resolveHandle` declares. Decoded
    /// from the wire, never constructed by the test.
    private struct ResolveHandleOutput: Decodable, Equatable {
        let did: String
    }

    private struct Fixture {
        let server: SwanHTTPServer
        let control: SQLiteControlDatabase
        let root: URL
    }

    // MARK: The method itself

    func testResolveHandleAnswersUnauthenticated() async throws {
        try await withFixture(label: "answers") { _, client in
            try await client.execute(
                uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(try self.decode(response.body).did, Self.did)
                // The whole body, so a field added later cannot leak an account
                // fact that resolveHandle does not declare.
                XCTAssertEqual(
                    self.text(response.body),
                    #"{"did":"\#(Self.did)"}"#
                )
                XCTAssertEqual(
                    response.headers[.contentType],
                    "application/json"
                )
            }
        }
    }

    /// Anonymous is the only interesting case, but a caller that does present
    /// credentials must get the same answer rather than a 401 from a route that
    /// accidentally acquired an authorizer.
    func testResolveHandleIgnoresCredentialHeaders() async throws {
        var mutableHeaders = HTTPFields()
        mutableHeaders[.authorization] = "Bearer not-a-real-token"
        mutableHeaders[HTTPField.Name("DPoP")!] = "not-a-real-proof"
        let headers = mutableHeaders
        try await withFixture(label: "credentials") { _, client in
            try await client.execute(
                uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(try self.decode(response.body).did, Self.did)
            }
        }
    }

    /// Handles are case-insensitive on the wire and canonical in storage. A
    /// client that echoes a user's capitalisation must still resolve, or login
    /// breaks for anyone who typed their own handle with a capital letter.
    func testResolveHandleFoldsWireCaseToTheCanonicalHandle() async throws {
        try await withFixture(label: "case") { _, client in
            for wireHandle in ["Swan.Place", "SWAN.PLACE", "sWaN.pLaCe"] {
                try await client.execute(
                    uri: "\(Self.resolveHandlePath)?handle=\(wireHandle)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok, "for \(wireHandle)")
                    XCTAssertEqual(
                        try self.decode(response.body).did,
                        Self.did,
                        "for \(wireHandle)"
                    )
                }
            }
        }
    }

    // MARK: Refusals

    func testResolveHandleRejectsUnknownHandleWithInvalidRequest() async throws {
        try await withFixture(label: "unknown") { _, client in
            for handle in [
                // Not hosted here at all.
                "nobody.example.com",
                // Near-misses on the hosted handle.
                "swan.place.example.com",
                "wan.place",
                // The hosted account's DID is not a handle: resolveHandle
                // resolves handles and must not become a DID echo service.
                Self.did,
            ] {
                try await client.execute(
                    uri: "\(Self.resolveHandlePath)?handle=\(handle)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .badRequest, "for \(handle)")
                    XCTAssertEqual(
                        self.text(response.body),
                        #"{"error":"InvalidRequest"}"#,
                        "for \(handle)"
                    )
                }
            }
        }
    }

    /// A handle that is not a well-formed handle is a request fault. It must
    /// not reach storage, and it must never be echoed back in the response.
    func testResolveHandleRejectsMalformedAndMissingParameters() async throws {
        try await withFixture(label: "malformed") { _, client in
            for uri in [
                // No query at all.
                Self.resolveHandlePath,
                // Present but empty.
                "\(Self.resolveHandlePath)?handle=",
                // Single label — not a handle.
                "\(Self.resolveHandlePath)?handle=swan",
                // Trailing dot produces an empty final label.
                "\(Self.resolveHandlePath)?handle=swan.place.",
                // The final label must start with an ASCII letter.
                "\(Self.resolveHandlePath)?handle=swan.123",
                // Not a handle character.
                "\(Self.resolveHandlePath)?handle=swan_place.com",
                // Wrong parameter name.
                "\(Self.resolveHandlePath)?did=\(Self.did)",
                // A second, unexpected parameter alongside a valid handle.
                "\(Self.resolveHandlePath)?handle=\(Self.handle)&extra=1",
                // The same parameter twice, both the hosted handle.
                "\(Self.resolveHandlePath)?handle=\(Self.handle)&handle=\(Self.handle)",
            ] {
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .badRequest, "for \(uri)")
                    XCTAssertEqual(
                        self.text(response.body),
                        #"{"error":"InvalidRequest"}"#,
                        "for \(uri)"
                    )
                }
            }
        }
    }

    /// A deactivated, suspended, or taken-down handle is reported exactly as an
    /// unhosted one. Answering it with the DID would let an anonymous caller
    /// enumerate this host's moderation state; answering with a *distinct*
    /// error would do the same more slowly.
    func testResolveHandleDoesNotResolveNonActiveAccounts() async throws {
        // Every status a generic lifecycle write can reach. `deleting` and
        // `deleted` are unreachable this way by design — permanent deletion is
        // its own multi-resource workflow — and are covered by the capability
        // gating on `authorizesAccount`, which only `active` satisfies.
        for status: AccountControlStatus in [
            .deactivated, .suspended, .takendown, .desynchronized, .throttled,
        ] {
            try await withFixture(label: "lifecycle") { fixture, client in
                _ = try await fixture.control.transitionStatus(
                    did: Self.did,
                    to: status,
                    declaration: .init(),
                    now: Date(timeIntervalSince1970: 1_750_000_100)
                )
                try await client.execute(
                    uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .badRequest, "for \(status)")
                    XCTAssertEqual(
                        self.text(response.body),
                        #"{"error":"InvalidRequest"}"#,
                        "for \(status)"
                    )
                }
            }
        }
    }

    /// The exact path answers GET and nothing else, from its own route rather
    /// than from whatever lower-priority route would otherwise claim the verb.
    func testResolveHandleRefusesEveryOtherHTTPMethod() async throws {
        try await withFixture(label: "methods") { _, client in
            for method: HTTPRequest.Method in [
                .post, .put, .patch, .delete, .options,
            ] {
                try await client.execute(
                    uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                    method: method
                ) { response in
                    XCTAssertEqual(response.status, .notFound, "for \(method)")
                    XCTAssertEqual(
                        self.text(response.body),
                        #"{"error":"public_endpoint_unavailable"}"#,
                        "for \(method)"
                    )
                }
            }
        }
    }

    // MARK: Independence from generation admission

    func testResolveHandleDoesNotRequireGenerationAdmission() async throws {
        // Must work even when public-read admission would fail — this is why
        // it ships independently of W1. The directory here reproduces the
        // 2026-08-12 state exactly: every read refuses with a stale generation
        // pin, permanently, for every selector.
        try await withFixture(
            label: "admission",
            readDirectory: PermanentlyUnadmittablePublicReadDirectory()
        ) { _, client in
            // The control: with this directory installed the repository read
            // surface really is dark.
            for uri in [
                "/xrpc/com.atproto.repo.describeRepo?repo=\(Self.did)",
                "/xrpc/com.atproto.sync.getRepoStatus?did=\(Self.did)",
                "/xrpc/com.atproto.sync.getLatestCommit?did=\(Self.did)",
            ] {
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(
                        response.status, .serviceUnavailable, "for \(uri)"
                    )
                    XCTAssertEqual(
                        self.text(response.body),
                        #"{"error":"temporarily_unavailable"}"#,
                        "for \(uri)"
                    )
                }
            }
            // And resolveHandle still answers.
            try await client.execute(
                uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(try self.decode(response.body).did, Self.did)
            }
        }
    }

    /// resolveHandle must not reserve the shared JSON read budget. Its response
    /// is one DID; taking a multi-megabyte lease would let concurrent
    /// `listRecords` traffic starve the method every login depends on.
    func testResolveHandleAnswersWithTheJSONReadBudgetFullyReserved() async throws {
        let admission = try PublicRepositoryJSONReadAdmission(
            maximumConcurrentReads: 1,
            maximumReservedResponseBytes: PublicRepositoryJSONReadLimits
                .maximumListRecordsResponseBytes
        )
        let lease = try XCTUnwrap(admission.reserve(
            maximumResponseBytes: PublicRepositoryJSONReadLimits
                .maximumListRecordsResponseBytes
        ))
        // The control: with that lease outstanding the budget refuses every
        // further reservation, so a route that reserves cannot answer at all.
        XCTAssertNil(admission.reserve(maximumResponseBytes: 1))
        try await withFixture(
            label: "budget", jsonReadAdmission: admission
        ) { _, client in
            try await client.execute(
                uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(try self.decode(response.body).did, Self.did)
            }
        }
        // Neither taken nor leaked: the outstanding lease is still the only one.
        XCTAssertEqual(admission.snapshot.activeLeases, 1)
        lease.release()
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
    }

    // MARK: The rest of the namespace

    func testOtherIdentityMethodsReturn404NotUnauthorized() async throws {
        try await withFixture(label: "namespace") { _, client in
            for uri in [
                "/xrpc/com.atproto.identity.updateHandle",
                "/xrpc/com.atproto.identity.signPlcOperation",
                "/xrpc/com.atproto.identity.submitPlcOperation",
                "/xrpc/com.atproto.identity.requestPlcOperationSignature",
                "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
                "/xrpc/com.atproto.identity.resolveDid",
                "/xrpc/com.atproto.identity.resolveIdentity",
                // A near-miss on the implemented method is not the method.
                "/xrpc/com.atproto.identity.resolveHandles",
            ] {
                for method: HTTPRequest.Method in [.get, .post] {
                    try await client.execute(
                        uri: uri, method: method
                    ) { response in
                        XCTAssertEqual(
                            response.status, .notFound, "\(method) \(uri)"
                        )
                        // The 404 comes from the namespace guard, not from an
                        // absent route or a proxy that declined.
                        XCTAssertEqual(
                            self.text(response.body),
                            #"{"error":"public_endpoint_unavailable"}"#,
                            "\(method) \(uri)"
                        )
                    }
                }
            }
        }
    }

    /// Without a control store there is nothing to resolve against, so the
    /// route must not exist at all rather than answer "no such handle" for
    /// every handle on the service.
    func testResolveHandleIsAbsentWithoutAnAccountControlStore() async throws {
        try await withFixture(
            label: "absent", installHandleResolution: false
        ) { _, client in
            try await client.execute(
                uri: "\(Self.resolveHandlePath)?handle=\(Self.handle)",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertEqual(
                    self.text(response.body),
                    #"{"error":"public_endpoint_unavailable"}"#
                )
            }
        }
    }

    // MARK: The capability, directly

    /// The capability is the allow-list: exactly one projection of one account
    /// row escapes it. Exercising it below HTTP pins that independently of any
    /// route wiring.
    func testCapabilityResolvesOnlyActiveAccountsByCanonicalHandle() async throws {
        try await withControl { control in
            _ = try await control.createAccount(Self.registration())
            let capability = SwanPublicHandleResolutionCapability(
                controlStore: control
            )

            let resolved = try await capability.activeDID(
                forCanonicalHandle: Self.handle
            )
            XCTAssertEqual(resolved, Self.did)

            // A non-canonical spelling is not silently folded here — the HTTP
            // adapter owns folding, and the store's own input validation would
            // otherwise throw rather than answer.
            for nonCanonical in ["Swan.Place", "swan_place", "swan", ""] {
                let answer = try await capability.activeDID(
                    forCanonicalHandle: nonCanonical
                )
                XCTAssertNil(answer, "for \(nonCanonical)")
            }

            let unknown = try await capability.activeDID(
                forCanonicalHandle: "nobody.example.com"
            )
            XCTAssertNil(unknown)

            _ = try await control.transitionStatus(
                did: Self.did,
                to: .deactivated,
                declaration: .init(),
                now: Date(timeIntervalSince1970: 1_750_000_100)
            )
            let afterDeactivation = try await capability.activeDID(
                forCanonicalHandle: Self.handle
            )
            XCTAssertNil(afterDeactivation)
        }
    }

    /// One handle resolves to one DID. If a second account could occupy the
    /// same handle the store's uniqueness constraint has failed, and the route
    /// must not become the place that picks a winner.
    func testHandleUniquenessIsEnforcedBeforeResolution() async throws {
        try await withControl { control in
            _ = try await control.createAccount(Self.registration())
            var duplicateRejected = false
            do {
                _ = try await control.createAccount(
                    Self.registration(did: Self.otherDID)
                )
            } catch {
                duplicateRejected = true
            }
            XCTAssertTrue(duplicateRejected)
            let capability = SwanPublicHandleResolutionCapability(
                controlStore: control
            )
            let survivor = try await capability.activeDID(
                forCanonicalHandle: Self.handle
            )
            XCTAssertEqual(survivor, Self.did)
        }
    }

    // MARK: Fixture

    /// Runs `body` against a live router and closes the control database on
    /// every path. A leaked `SQLiteConnection` trips an assertion in its
    /// deinitializer, which aborts the whole target and truncates every result
    /// after it — a failure mode that hides real failures rather than reporting
    /// them.
    private func withFixture(
        label: String,
        installHandleResolution: Bool = true,
        readDirectory: (any PublicRepositoryReadDirectory)? = nil,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission? = nil,
        _ body: @escaping @Sendable (
            Fixture, any TestClientProtocol
        ) async throws -> Void
    ) async throws {
        let fixture = try await makeFixture(
            installHandleResolution: installHandleResolution,
            readDirectory: readDirectory,
            jsonReadAdmission: jsonReadAdmission
        )
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(
                    label: "PublicHandleResolutionHTTPTests.\(label)"
                )
            )
            try await app.test(.router) { client in
                try await body(fixture, client)
            }
        } catch {
            try? await fixture.control.close()
            try? FileManager.default.removeItem(at: fixture.root)
            throw error
        }
        try await fixture.control.close()
        try? FileManager.default.removeItem(at: fixture.root)
    }

    private func withControl(
        _ body: (SQLiteControlDatabase) async throws -> Void
    ) async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicHandleResolution-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await body(control)
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
        try await control.close()
        try? FileManager.default.removeItem(at: root)
    }

    private static func registration(
        did: String = PublicHandleResolutionHTTPTests.did
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: verifier,
            signingKey: try AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func makeFixture(
        installHandleResolution: Bool,
        readDirectory: (any PublicRepositoryReadDirectory)?,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission?
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicHandleResolutionHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(Self.registration())
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x41, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: URL(fileURLWithPath: #filePath)
                    .deletingLastPathComponent()
                    .deletingLastPathComponent()
                    .deletingLastPathComponent()
                    .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
            )
            return Fixture(
                server: SwanHTTPServer(
                    profile: profile,
                    configuration: .init(
                        publicURL: URL(string: "https://swan.example")!
                    ),
                    oauthRuntime: runtime,
                    accountControlStore: installHandleResolution ? control : nil,
                    publicRepositoryReadDirectory: readDirectory,
                    jsonReadAdmission: jsonReadAdmission
                ),
                control: control,
                root: root
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func decode(_ buffer: ByteBuffer) throws -> ResolveHandleOutput {
        try JSONDecoder().decode(
            ResolveHandleOutput.self, from: Data(buffer: buffer)
        )
    }

    private func text(_ buffer: ByteBuffer) -> String {
        String(decoding: buffer.readableBytesView, as: UTF8.self)
    }
}

/// Reproduces the 2026-08-12 production state: a read directory that can never
/// admit a generation, for any selector, for any method.
private struct PermanentlyUnadmittablePublicReadDirectory:
    PublicRepositoryReadDirectory
{
    private var refusal: any Error {
        PublicRepositoryReadError.unavailable(reason: .generationPinStale)
    }

    func publicRepositoryStatus(
        selector _: String
    ) async throws -> PublicRepositoryReadStatus? { throw refusal }

    func describePublicRepository(
        selector _: String
    ) async throws -> PublicRepositoryReadDescription? { throw refusal }

    func publicRepositoryRecord(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadRecord? { throw refusal }

    func listPublicRepositoryRecords(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadPage { throw refusal }

    func publicRepositoryCAR(
        selector _: String
    ) async throws -> PublicRepositoryReadCAR? { throw refusal }

    func publicRepositoryDescriptionOutcome(
        selector _: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    { throw refusal }

    func publicRepositoryRecordOutcome(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    { throw refusal }

    func publicRepositoryRecordsOutcome(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    { throw refusal }

    func publicRepositoryCAROutcome(
        selector _: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR>
    { throw refusal }
}
