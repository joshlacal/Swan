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
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest

/// `com.atproto.sync.getBlob` used to be registered inside the *mutation*
/// endpoint block, so `--enable-public-repository-mutations` was silently also
/// the switch for avatar and image serving: an operator who turned public
/// writes off served no images to anyone on the network, with no error and
/// nothing in the journal. These tests pin that the route is governed by the
/// public *read* directory and by nothing else.
final class PublicBlobReadRegistrationTests: XCTestCase, @unchecked Sendable {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let blobPath = "/xrpc/com.atproto.sync.getBlob"
    private static let uploadPath = "/xrpc/com.atproto.repo.uploadBlob"

    func testGetBlobIsServedWhenPublicMutationsAreDisabled() async throws {
        // Today disabling public writes silently disables avatar and image
        // serving for the entire network.
        let fixture = try await makeFixture()
        defer { fixture.scheduleCleanup() }
        XCTAssertNil(
            fixture.server.publicRepositoryMutations,
            "the fixture must have public writes genuinely disabled"
        )

        let bytes = Data("avatar-bytes-served-with-writes-off".utf8)
        let reference = try await fixture.alice.putBlob(bytes, namespace: .public)

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobReadRegistrationTests.served")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: Self.blobPath + "?did=" + Self.alice + "&cid=" + reference.cid,
                method: .get
            ) { response in
                XCTAssertNotEqual(response.status, .notFound)
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), bytes)
                XCTAssertEqual(
                    response.headers[.contentLength],
                    String(bytes.count)
                )
                XCTAssertEqual(
                    response.headers[HTTPField.Name("X-Content-Type-Options")!],
                    "nosniff"
                )
            }

            // The other half of the claim: writes really are off, so the 200
            // above cannot be explained by the mutation surface being live.
            try await client.execute(uri: Self.uploadPath, method: .post) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "public_streaming_pending"
                )
            }
        }
    }

    /// A public read directory is the single condition that installs the
    /// route. Without one, `getBlob` must stay behind its method-correct
    /// unavailable gate and must never serve a byte.
    func testGetBlobIsNotServedWhenPublicReadsAreDisabled() async throws {
        let fixture = try await makeFixture(installPublicReads: false)
        defer { fixture.scheduleCleanup() }

        let bytes = Data("must-not-be-served-without-a-read-directory".utf8)
        let reference = try await fixture.alice.putBlob(bytes, namespace: .public)

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobReadRegistrationTests.closed")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: Self.blobPath + "?did=" + Self.alice + "&cid=" + reference.cid,
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "public_streaming_pending"
                )
                XCTAssertNotEqual(Data(buffer: response.body), bytes)
            }
        }
    }

    /// Only GET is answered; every other verb gets a Swan-owned 404 and is
    /// never handed to the AppView proxy.
    ///
    /// This pins the observable contract, not the mechanism: deleting the
    /// exact-path guards that moved with the route still passes, because the
    /// `com.atproto.sync.*` wildcard produces the identical answer today. The
    /// exact-path guards remain for the reason every other read route has
    /// them — so the endpoint's own registration claims its verbs rather than
    /// relying on a wildcard staying in place.
    func testGetBlobAnswersOnlyGETOnTheReadSurface() async throws {
        let fixture = try await makeFixture()
        defer { fixture.scheduleCleanup() }
        let reference = try await fixture.alice.putBlob(
            Data("verb-guards".utf8),
            namespace: .public
        )
        let uri = Self.blobPath + "?did=" + Self.alice + "&cid=" + reference.cid

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobReadRegistrationTests.verbs")
        )
        try await app.test(.router) { client in
            for method: HTTPRequest.Method in [
                .head, .post, .put, .patch, .delete, .options,
            ] {
                try await client.execute(uri: uri, method: method) { response in
                    XCTAssertEqual(
                        response.status,
                        .notFound,
                        method.rawValue
                    )
                }
            }
        }
    }

    /// A blob this account does not host is `BlobNotFound`, not another
    /// account's bytes and not a 503 — the read surface must not blur the
    /// difference between "no such blob" and "cannot answer right now".
    func testUnknownCIDIsBlobNotFoundOnTheReadSurface() async throws {
        let fixture = try await makeFixture()
        defer { fixture.scheduleCleanup() }
        let hosted = try await fixture.alice.putBlob(
            Data("hosted".utf8),
            namespace: .public
        )
        let absent = try await fixture.alice.putBlob(
            Data("absent-from-the-public-namespace".utf8),
            namespace: .space(
                try SpaceURI(
                    authority: Self.alice,
                    spaceType: "app.swan.private",
                    skey: "absent"
                )
            )
        )
        XCTAssertNotEqual(hosted.cid, absent.cid)

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobReadRegistrationTests.missing")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: Self.blobPath + "?did=" + Self.alice + "&cid=" + absent.cid,
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertEqual(try self.errorCode(response.body), "BlobNotFound")
            }
        }
    }

    private func makeFixture(
        installPublicReads: Bool = true
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanPublicBlobReadRegistrationTests-\(UUID().uuidString)"
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let alice = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: Self.alice
            )
            let directory = PublicBlobReadOnlyDirectory(
                stores: [Self.alice: alice]
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x41, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-03.json"
                )
            )
            // No mutation directory and no signer provider: public writes are
            // off, which is the entire point of these tests.
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: runtime,
                accountControlStore: control,
                publicRepositoryReadDirectory: installPublicReads
                    ? directory
                    : nil
            )
            return Fixture(
                root: root,
                control: control,
                alice: alice,
                directory: directory,
                server: server
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func errorCode(_ buffer: ByteBuffer) throws -> String? {
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(buffer: buffer))
                as? [String: Any]
        )
        return object["error"] as? String
    }

    private func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let alice: SQLiteAccountDatabase
        let directory: PublicBlobReadOnlyDirectory
        let server: SwanHTTPServer

        func scheduleCleanup() {
            Task {
                try? await alice.close()
                try? await control.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
    }
}

/// A public *read* directory that hosts blobs and no records. It is
/// deliberately not a `PublicRepositoryMutationDirectory`: a server built on it
/// cannot form a mutation capability at all, so a `getBlob` that answers is
/// answering from the read surface.
private actor PublicBlobReadOnlyDirectory: PublicRepositoryReadDirectory {
    private let stores: [String: SQLiteAccountDatabase]

    init(stores: [String: SQLiteAccountDatabase]) {
        self.stores = stores
    }

    func publicRepositoryBlobOutcome(
        did: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget>
    {
        guard let store = stores[did] else { return .notFound }
        return .active(
            try PublicRepositoryReadBlobTarget(
                did: did, status: .active, store: store
            )
        )
    }

    func publicRepositoryStatus(
        selector _: String
    ) async throws -> PublicRepositoryReadStatus? { nil }

    func describePublicRepository(
        selector _: String
    ) async throws -> PublicRepositoryReadDescription? { nil }

    func publicRepositoryRecord(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws -> PublicRepositoryReadRecord? { nil }

    func listPublicRepositoryRecords(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws -> PublicRepositoryReadPage {
        try .init(records: [], cursor: nil)
    }

    func publicRepositoryCAR(
        selector _: String
    ) async throws -> PublicRepositoryReadCAR? { nil }

    func publicRepositoryDescriptionOutcome(
        selector _: String
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    { .notFound }

    func publicRepositoryRecordOutcome(
        selector _: String,
        path _: PublicRepositoryPath,
        expectedCID _: CID?
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    { .notFound }

    func publicRepositoryRecordsOutcome(
        selector _: String,
        collection _: String,
        limit _: Int,
        cursor _: String?,
        reverse _: Bool
    ) async throws
        -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    { .notFound }

    func publicRepositoryCAROutcome(
        selector _: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR>
    { .notFound }
}
