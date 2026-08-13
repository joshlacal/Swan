import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

/// Admission behaviour of `com.atproto.space.getBlob`.
///
/// The route reserves from the process-wide transfer budget that also serves
/// public CAR reads, public blob reads, and public blob uploads, and it holds
/// that reservation until the response writer finishes — i.e. for as long as
/// the reader takes. What it holds *across that window* is the whole finding:
/// a fixed 256 MiB ceiling makes a handful of stalled tiny reads deny every
/// other consumer of that pool.
final class SpaceBlobHTTPTests: XCTestCase, @unchecked Sendable {
    private static let author = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let path = "/xrpc/com.atproto.space.getBlob"
    /// The route's own per-request ceiling, mirrored here because these tests
    /// assert against it directly. It is `private` in `SwanSpaceBlobXRPC`.
    private static let ceilingBytes = 256 * 1_024 * 1_024
    /// Sized so exactly one ceiling-sized reservation fits per account and a
    /// second does not: 384 MiB admits 256 MiB once, and 256 + 256 overflows
    /// it. That makes "what is held across the stream" observable as a
    /// pass/fail rather than as a number nobody checks.
    private static let perAccountBudgetBytes = 384 * 1_024 * 1_024
    private static let globalBudgetBytes = 512 * 1_024 * 1_024

    // MARK: F23

    /// A 4 KiB permissioned blob must not hold 256 MiB of the transfer pool
    /// for the duration of its response.
    ///
    /// The snapshot is taken from inside the body stream, so it observes the
    /// reservation that a stalled reader would pin, not the one that existed
    /// during the open. This asserts the reserved *bytes*, so a route that
    /// merely kept succeeding without right-sizing would still fail.
    func testSmallBlobReservesItsOwnLengthRatherThanTheTransferCeiling() async throws {
        let fixture = try await Fixture.make(payload: Data(repeating: 0x2A, count: 4_096))
        addTeardownBlock { await fixture.close() }
        let observed = ReservationObserver()
        fixture.body.setOnFirstChunk { [admission = fixture.admission] in
            await observed.record(admission.snapshot)
        }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.rightSized")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: fixture.uri(),
                method: .get,
                headers: fixture.credentialHeaders()
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), fixture.payload)
                XCTAssertEqual(
                    response.headers[.contentLength],
                    String(fixture.payload.count)
                )
            }
        }

        let recorded = await observed.snapshot
        let inFlight = try XCTUnwrap(
            recorded,
            "the response must have streamed at least one chunk"
        )
        XCTAssertEqual(
            inFlight.reservedBytes,
            fixture.payload.count,
            """
            the reservation held across the response must cover the bytes this \
            response streams, not the 256 MiB permissioned transfer ceiling
            """
        )
        XCTAssertEqual(
            inFlight.activeLeases,
            1,
            "the ceiling admission lease must have been released by then"
        )
        XCTAssertEqual(fixture.admission.snapshot.reservedBytes, 0)
        XCTAssertEqual(fixture.admission.snapshot.activeLeases, 0)
    }

    /// A small read must be *admitted* when the pool has room for it but not
    /// for the ceiling.
    ///
    /// This is the half of F23 that right-sizing the held lease could not
    /// reach. Reserving the ceiling and then shrinking it keeps a stalled
    /// reader from hogging the pool, but the request still has to clear the
    /// ceiling to get in at all — so concurrency stayed pinned at two reads
    /// per account and four service-wide no matter how small the blobs were.
    ///
    /// The account is pre-loaded to leave 8 KiB free: far too little for the
    /// 256 MiB ceiling, ample for a 4 KiB blob. A route that reserves the
    /// ceiling answers this request with 503.
    func testASmallReadIsAdmittedWhenThePoolHasNoRoomForTheCeiling() async throws {
        let fixture = try await Fixture.make(payload: Data(repeating: 0x2A, count: 4_096))
        addTeardownBlock { await fixture.close() }

        let pinnedBytes = Self.perAccountBudgetBytes - 8_192
        let pinned = try XCTUnwrap(
            fixture.admission.reserve(
                accountDID: Self.author,
                maximumBytes: pinnedBytes
            ),
            "the pre-load itself must be admitted, or the test proves nothing"
        )
        defer { pinned.release() }
        XCTAssertNil(
            fixture.admission.reserve(
                accountDID: Self.author,
                maximumBytes: Self.ceilingBytes
            ),
            """
            the pre-load must leave no room for a ceiling-sized reservation, \
            or this test cannot distinguish the two admission policies
            """
        )

        let observed = ReservationObserver()
        fixture.body.setOnFirstChunk { [admission = fixture.admission] in
            await observed.record(admission.snapshot)
        }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.contendedAdmission")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: fixture.uri(),
                method: .get,
                headers: fixture.credentialHeaders()
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), fixture.payload)
            }
        }

        let recorded = await observed.snapshot
        let inFlight = try XCTUnwrap(
            recorded,
            "the response must have streamed at least one chunk"
        )
        XCTAssertEqual(
            inFlight.reservedBytes,
            pinnedBytes + fixture.payload.count,
            "the reservation must be the payload size, never the ceiling"
        )
        XCTAssertEqual(inFlight.activeLeases, 2, "the pre-load and this read")

        pinned.release()
        XCTAssertEqual(fixture.admission.snapshot.reservedBytes, 0)
        XCTAssertEqual(fixture.admission.snapshot.activeLeases, 0)
    }

    /// The reservation is sized from the metadata read, so a body that then
    /// declares a different length is not covered by it. Nothing may stream.
    ///
    /// A content-addressed store cannot legitimately produce this, which is
    /// exactly why it must fail closed rather than be assumed away: the
    /// alternative is a reservation that under-covers its transfer, which is
    /// strictly worse than reserving the ceiling.
    func testBodyDeclaringADifferentLengthThanItsMetadataIsRefused() async throws {
        let fixture = try await Fixture.make(
            payload: Data(repeating: 0x6E, count: 4_096),
            metadataSizeOverride: 1_024
        )
        addTeardownBlock { await fixture.close() }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.lengthDisagreement")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: fixture.uri(),
                method: .get,
                headers: fixture.credentialHeaders()
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }

        XCTAssertEqual(
            fixture.body.acceptedBytes,
            0,
            "no byte of a body the reservation does not cover may be written"
        )
        XCTAssertEqual(
            fixture.admission.snapshot.activeLeases,
            0,
            "the refused read must release the reservation it took"
        )
    }

    /// The denial the finding describes, reproduced against the live budget.
    ///
    /// While a 4 KiB read is stalled mid-stream, the pool must still admit a
    /// full ceiling-sized request for the same author. With the per-account
    /// budget at 384 MiB that succeeds only if the stalled read is holding
    /// its own 4 KiB; a read holding the 256 MiB ceiling leaves 128 MiB and
    /// the next request is refused outright.
    func testStalledSmallReadDoesNotDenyAFurtherReadOfTheSameAuthor() async throws {
        let fixture = try await Fixture.make(payload: Data(repeating: 0x5B, count: 4_096))
        addTeardownBlock { await fixture.close() }
        let observed = ReservationObserver()
        fixture.body.setOnFirstChunk { [admission = fixture.admission] in
            let concurrent = admission.reserve(
                accountDID: Self.author,
                maximumBytes: Self.ceilingBytes
            )
            await observed.recordConcurrentAdmission(concurrent != nil)
            concurrent?.release()
        }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.concurrent")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: fixture.uri(),
                method: .get,
                headers: fixture.credentialHeaders()
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), fixture.payload)
            }
        }

        let recorded = await observed.concurrentAdmission
        let admitted = try XCTUnwrap(
            recorded,
            "the response must have streamed at least one chunk"
        )
        XCTAssertTrue(
            admitted,
            """
            a second permissioned read of the same author must still be \
            admissible while a 4 KiB read is stalled in its response body
            """
        )
        XCTAssertEqual(fixture.admission.snapshot.activeLeases, 0)
    }

    /// The reservation is sized from the body's declared length, so a body
    /// that then delivers more than it declared would move bytes the
    /// reservation does not cover — strictly worse than reserving the
    /// ceiling. The surplus must never reach the writer.
    ///
    /// This is the brief's "a size smaller than the real payload cannot get
    /// through" case. The stub counts only the chunks the route's writer
    /// *accepted*, so the assertion is about bytes that actually moved, not
    /// about the status the harness happened to surface. The route refuses
    /// the surplus by failing the body, which the in-process router harness
    /// rethrows out of `execute`; over a real connection the peer sees the
    /// already-sent `Content-Length: 4096` framing and an aborted body, never
    /// the extra kibibyte.
    func testBodyStreamingMoreThanItDeclaredDoesNotEmitTheSurplus() async throws {
        // Two full 64 KiB chunks plus a third that is entirely surplus, so
        // the refusal happens mid-stream after real bytes have already been
        // written — not merely on an oversized first chunk.
        let declared = 128 * 1_024
        let fixture = try await Fixture.make(
            payload: Data(repeating: 0x7C, count: declared),
            declaredLengthOverride: declared,
            surplusBytes: 1_024
        )
        addTeardownBlock { await fixture.close() }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.surplus")
        )
        var refused = false
        do {
            try await app.test(.router) { client in
                _ = try await client.execute(
                    uri: fixture.uri(),
                    method: .get,
                    headers: fixture.credentialHeaders()
                ) { $0.body.readableBytes }
            }
        } catch {
            refused = true
        }
        XCTAssertTrue(
            refused,
            "a body that over-delivers must not complete its response"
        )
        XCTAssertEqual(
            fixture.body.acceptedBytes,
            declared,
            """
            a body that over-delivers must not put bytes past its declared \
            length into the response writer; the transfer reservation does \
            not cover them
            """
        )
        XCTAssertEqual(
            fixture.admission.snapshot.activeLeases,
            0,
            "an aborted transfer must still release its reservation"
        )
    }

    /// A body that under-delivers would complete a response whose framing
    /// lies about its length. It must not be finished successfully.
    func testBodyStreamingLessThanItDeclaredNeverCompletesTheResponse() async throws {
        let declared = 4_096
        let fixture = try await Fixture.make(
            payload: Data(repeating: 0x3D, count: declared - 1_024),
            declaredLengthOverride: declared
        )
        addTeardownBlock { await fixture.close() }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.short")
        )
        var refused = false
        do {
            try await app.test(.router) { client in
                _ = try await client.execute(
                    uri: fixture.uri(),
                    method: .get,
                    headers: fixture.credentialHeaders()
                ) { $0.body.readableBytes }
            }
        } catch {
            refused = true
        }
        XCTAssertTrue(
            refused,
            "a short body must not be presented as a complete transfer"
        )
        XCTAssertEqual(fixture.body.acceptedBytes, declared - 1_024)
        XCTAssertEqual(fixture.admission.snapshot.activeLeases, 0)
    }

    /// The budget is still enforced, and it is enforced *before* the payload
    /// is opened and verified: nothing above bought the route an unbounded
    /// transfer surface.
    ///
    /// Right-sizing does move one bounded, payload-free metadata query ahead
    /// of the budget check — the refusal path now touches storage, where
    /// before it did not. That query is an indexed lookup on a already
    /// authorized read, reachable only by a caller who could drive the same
    /// query through a successful request, and it is what the public blob
    /// route has always done. The assertion below is deliberately about the
    /// payload open, and the metadata count is asserted so the trade is
    /// recorded rather than discovered later.
    func testExhaustedTransferBudgetStillRefusesTheReadBeforeOpeningIt() async throws {
        let fixture = try await Fixture.make(payload: Data(repeating: 0x11, count: 4_096))
        addTeardownBlock { await fixture.close() }
        // The whole per-account budget: a right-sized route asks for only
        // 4 KiB, so leaving any slack would admit it.
        let held = try XCTUnwrap(fixture.admission.reserve(
            accountDID: Self.author,
            maximumBytes: Self.perAccountBudgetBytes
        ))
        defer { held.release() }

        let app = Application(
            router: fixture.router(),
            logger: Logger(label: "SpaceBlobHTTPTests.exhausted")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: fixture.uri(),
                method: .get,
                headers: fixture.credentialHeaders()
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "temporarily_unavailable"
                )
            }
        }
        let opened = await fixture.directory.openCount
        XCTAssertEqual(
            opened,
            0,
            "a refused read must not have opened and verified the payload"
        )
        let metadataReads = await fixture.directory.metadataCount
        XCTAssertEqual(
            metadataReads,
            1,
            """
            the declared metadata read is what sizes the reservation, so it \
            necessarily precedes the budget refusal
            """
        )
    }
}

// MARK: - Fixture

private extension SpaceBlobHTTPTests {
    func errorCode(_ body: ByteBuffer) throws -> String? {
        let object = try JSONSerialization.jsonObject(with: Data(buffer: body))
        return (object as? [String: Any])?["error"] as? String
    }

    struct Fixture: Sendable {
        let root: URL
        let control: SQLiteControlDatabase
        let space: SpaceURI
        let cid: String
        let payload: Data
        let admission: PublicRepositorySpoolAdmission
        let directory: StubSpaceBlobDirectory
        let body: StubSpaceBlobBody
        let authorizer: SwanOAuthResourceAuthorizer

        static func make(
            payload: Data,
            declaredLengthOverride: Int? = nil,
            surplusBytes: Int = 0,
            metadataSizeOverride: Int? = nil
        ) async throws -> Fixture {
            let root = FileManager.default.temporaryDirectory
                .appending(path: "SpaceBlobHTTPTests-\(UUID().uuidString)")
            let control = try await SQLiteControlDatabase(dataDirectory: root)
            do {
                let runtime = try SwanOAuthRuntime(
                    controlStore: control,
                    serverKey: Data(repeating: 0xD4, count: 32)
                )
                let authorizer = try SwanOAuthResourceAuthorizer(
                    publicURL: SpaceBlobHTTPTests.publicURL,
                    runtime: runtime,
                    accountControlStore: control
                )
                let space = try SpaceURI(
                    authority: SpaceBlobHTTPTests.author,
                    spaceType: "app.bsky.bookmarks",
                    skey: "blob-admission"
                )
                let body = StubSpaceBlobBody(
                    payload: payload,
                    declaredLength: declaredLengthOverride ?? payload.count,
                    surplusBytes: surplusBytes
                )
                let directory = StubSpaceBlobDirectory(
                    body: body,
                    metadataSizeOverride: metadataSizeOverride
                )
                let admission = try PublicRepositorySpoolAdmission(
                    maximumGlobalBytes: SpaceBlobHTTPTests.globalBudgetBytes,
                    maximumPerAccountBytes: SpaceBlobHTTPTests.perAccountBudgetBytes
                )
                return Fixture(
                    root: root,
                    control: control,
                    space: space,
                    cid: CID.fromBlob(Data("space blob admission".utf8)).string,
                    payload: payload,
                    admission: admission,
                    directory: directory,
                    body: body,
                    authorizer: authorizer
                )
            } catch {
                try? await control.close()
                try? FileManager.default.removeItem(at: root)
                throw error
            }
        }

        func close() async {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
        }

        func router() -> Router<SwanHTTP.BasicRequestContext> {
            let router = Router(context: SwanHTTP.BasicRequestContext.self)
            registerAuthenticatedGetSpaceBlobEndpoint(
                on: router,
                capability: SwanAuthenticatedSpaceBlobCapability(
                    authorizer: authorizer,
                    directory: directory,
                    credentialAuthorizer: StubSpaceCredentialVerifier(space: space),
                    streamAdmission: admission
                )
            )
            return router
        }

        func uri() -> String {
            let encodedSpace = space.rawValue
                .addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
            return "\(SpaceBlobHTTPTests.path)?space=\(encodedSpace)"
                + "&repo=\(SpaceBlobHTTPTests.author)&cid=\(cid)"
        }

        func credentialHeaders() -> HTTPFields {
            [.authorization: "Bearer stub-space-credential"]
        }
    }
}

/// Grants exactly the aggregate space read the route requires, without
/// standing up a credential authority: the finding is about admission, and a
/// real credential would only add unrelated failure modes to these tests.
private struct StubSpaceCredentialVerifier: SpaceCredentialAuthorizationVerifier {
    let space: SpaceURI

    func authorization(
        for _: String,
        expectedSpace: SpaceURI,
        now _: Date
    ) async throws -> AuthorizationContext {
        guard expectedSpace == space else {
            throw SwanError.unauthorized("credential is for another space")
        }
        return .spaceCredential(
            SpaceGrant(
                subject: "did:plc:bcdefghijklmnopqrstuvwxy",
                space: space,
                permissions: [.read],
                expiresAt: Date().addingTimeInterval(300)
            )
        )
    }
}

private actor StubSpaceBlobDirectory: AuthorizedSpaceBlobDirectory {
    private let body: StubSpaceBlobBody
    /// What the metadata read declares. Defaults to the body's own declared
    /// length — the only case a content-addressed store can produce — and is
    /// overridable so the route's disagreement guard can be exercised.
    private let metadataSize: Int
    private(set) var openCount = 0
    private(set) var metadataCount = 0

    init(body: StubSpaceBlobBody, metadataSizeOverride: Int? = nil) {
        self.body = body
        metadataSize = metadataSizeOverride ?? body.contentLength
    }

    func spaceBlobMetadata(
        space _: SpaceURI,
        author _: String,
        cid _: String,
        authorization _: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlobMetadata? {
        metadataCount += 1
        return AuthorizedSpaceBlobMetadata(size: metadataSize)
    }

    func spaceBlob(
        space _: SpaceURI,
        author _: String,
        cid _: String,
        authorization _: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlob? {
        openCount += 1
        return AuthorizedSpaceBlob(mimeType: "application/octet-stream", body: body)
    }
}

/// A body whose declared length can be set independently of the bytes it
/// delivers, so the route's own accounting is what the surplus/short tests
/// exercise.
private final class StubSpaceBlobBody: AuthorizedSpaceBlobBody, @unchecked Sendable {
    private let payload: Data
    private let surplusBytes: Int
    private let lock = NSLock()
    private var onFirstChunk: (@Sendable () async -> Void)?
    private var accepted = 0
    let contentLength: Int

    /// Bytes the route's response writer accepted, counted only after
    /// `consume` returned without throwing.
    var acceptedBytes: Int { lock.withLock { accepted } }

    init(payload: Data, declaredLength: Int, surplusBytes: Int) {
        self.payload = payload
        self.surplusBytes = surplusBytes
        contentLength = declaredLength
    }

    func setOnFirstChunk(_ hook: (@Sendable () async -> Void)?) {
        lock.withLock { onFirstChunk = hook }
    }

    func streamBody(
        maximumChunkBytes: Int,
        consume: (Data) async throws -> Void
    ) async throws {
        var emitted = payload
        if surplusBytes > 0 {
            emitted.append(Data(repeating: 0xFF, count: surplusBytes))
        }
        var offset = 0
        var isFirst = true
        while offset < emitted.count {
            let end = min(offset + maximumChunkBytes, emitted.count)
            // The hook runs *inside* the stream, while the transfer lease is
            // held, which is exactly where a stalled reader would sit.
            if isFirst {
                isFirst = false
                let hook = lock.withLock { onFirstChunk }
                await hook?()
            }
            try await consume(emitted.subdata(in: offset ..< end))
            lock.withLock { accepted += end - offset }
            offset = end
        }
    }
}

private actor ReservationObserver {
    private(set) var snapshot: PublicRepositorySpoolAdmission.Snapshot?
    private(set) var concurrentAdmission: Bool?

    func record(_ value: PublicRepositorySpoolAdmission.Snapshot) {
        guard snapshot == nil else { return }
        snapshot = value
    }

    func recordConcurrentAdmission(_ value: Bool) {
        guard concurrentAdmission == nil else { return }
        concurrentAdmission = value
    }
}
