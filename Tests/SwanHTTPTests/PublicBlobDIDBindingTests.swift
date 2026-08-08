import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanPublicRepository
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class PublicBlobDIDBindingTests: XCTestCase, @unchecked Sendable {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let carol = "did:plc:cdefghijklmnopqrstuvwxyz"
    private static let blobPath = "/xrpc/com.atproto.sync.getBlob"

    func testGetBlobUsesExactDIDAndNeverFallsBackToAnotherAccountsPublicBlob() async throws {
        let fixture = try await makeFixture()
        defer { fixture.scheduleCleanup() }

        let bytes = Data("same-cid-private-for-alice-public-for-bob".utf8)
        let privateReference = try await fixture.alice.putBlob(
            bytes,
            namespace: .space(
                try SpaceURI(
                    authority: Self.alice,
                    spaceType: "app.swan.private",
                    skey: "binding"
                )
            )
        )
        let publicReference = try await fixture.bob.putBlob(
            bytes,
            namespace: .public
        )
        XCTAssertEqual(privateReference.cid, publicReference.cid)

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobDIDBindingTests.exact-did")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: privateReference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertNotEqual(Data(buffer: response.body), bytes)
            }

            try await client.execute(
                uri: blobURI(did: Self.bob, cid: publicReference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), bytes)
            }

            try await client.execute(
                uri: blobURI(did: Self.carol, cid: publicReference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.errorCode(response.body), "RepoNotFound")
            }
        }
    }

    func testGetBlobRejectsMissingDuplicateUnknownAndNoncanonicalQueryValues() async throws {
        let fixture = try await makeFixture()
        defer { fixture.scheduleCleanup() }
        let reference = try await fixture.alice.putBlob(
            Data("query-validation".utf8),
            namespace: .public
        )
        let valid = blobURI(did: Self.alice, cid: reference.cid)
        let malformed = [
            Self.blobPath + "?cid=" + reference.cid,
            Self.blobPath + "?did=" + Self.alice,
            valid + "&did=" + Self.alice,
            valid + "&cid=" + reference.cid,
            valid + "&unknown=1",
            Self.blobPath + "?did=not-a-did&cid=" + reference.cid,
            Self.blobPath + "?did=" + Self.alice + "&cid=" + reference.cid.uppercased(),
            Self.blobPath + "?did=%GG&cid=" + reference.cid,
        ]

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobDIDBindingTests.query")
        )
        try await app.test(.router) { client in
            for uri in malformed {
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .badRequest, uri)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidRequest",
                        uri
                    )
                }
            }

            try await client.execute(
                uri: valid,
                method: .get,
                body: ByteBuffer(string: "unexpected")
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
            }

            try await client.execute(uri: valid, method: .post) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
    }

    func testGetBlobChecksRequestedAccountLifecycleBeforeReadingBytes() async throws {
        let fixture = try await makeFixture()
        defer { fixture.scheduleCleanup() }

        let bytes = Data("same-cid-different-lifecycle".utf8)
        let aliceReference = try await fixture.alice.putBlob(bytes, namespace: .public)
        let bobReference = try await fixture.bob.putBlob(bytes, namespace: .public)
        XCTAssertEqual(aliceReference.cid, bobReference.cid)

        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobDIDBindingTests.lifecycle")
        )
        try await app.test(.router) { client in
            await fixture.directory.setStatus(.deactivated, did: Self.alice)
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: aliceReference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.errorCode(response.body), "RepoDeactivated")
                XCTAssertNotEqual(Data(buffer: response.body), bytes)
            }

            // An account that was already inactive at bootstrap has no
            // preopened repository store. Keep it indistinguishable from a
            // missing repository rather than scanning or opening on demand.
            await fixture.directory.setPreopened(false, did: Self.alice)
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: aliceReference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.errorCode(response.body), "RepoNotFound")
            }
            await fixture.directory.setPreopened(true, did: Self.alice)

            await fixture.directory.setStatus(.deleted, did: Self.alice)
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: aliceReference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(try self.errorCode(response.body), "RepoNotFound")
            }

            await fixture.directory.setStatus(.active, did: Self.alice)
            let bobOnly = try await fixture.bob.putBlob(
                Data("bob-only-public".utf8),
                namespace: .public
            )
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: bobOnly.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertNotEqual(
                    Data(buffer: response.body),
                    Data("bob-only-public".utf8)
                )
            }
        }
    }

    func testGetBlobFailsClosedWhenAdmissionIsHeldAndReleasesAfterResponse() async throws {
        let maximumBytes = 256 * 1_024 * 1_024
        let admission = try PublicRepositorySpoolAdmission(
            maximumGlobalBytes: maximumBytes,
            maximumPerAccountBytes: maximumBytes,
            maximumGlobalLeases: 1,
            maximumPerAccountLeases: 1
        )
        let held = try XCTUnwrap(
            admission.reserve(
                accountDID: Self.alice,
                maximumBytes: maximumBytes
            )
        )
        let fixture = try await makeFixture(blobStreamAdmission: admission)
        defer {
            held.release()
            fixture.scheduleCleanup()
        }

        let reference = try await fixture.alice.putBlob(
            Data("admission-boundary".utf8),
            namespace: .public
        )
        let app = fixture.server.buildApplication(
            logger: Logger(label: "PublicBlobDIDBindingTests.admission")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: reference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "temporarily_unavailable"
                )
            }
        }
        XCTAssertEqual(admission.snapshot.activeLeases, 1)

        held.release()
        try await app.test(.router) { client in
            try await client.execute(
                uri: blobURI(did: Self.alice, cid: reference.cid),
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(
                    Data(buffer: response.body),
                    Data("admission-boundary".utf8)
                )
            }
        }
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
    }

    private func makeFixture(
        blobStreamAdmission: PublicRepositorySpoolAdmission? = nil
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanPublicBlobDIDBindingTests-\(UUID().uuidString)"
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let alice = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: Self.alice
            )
            let bob = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: Self.bob
            )
            let directory = PublicBlobTestDirectory(
                stores: [Self.alice: alice, Self.bob: bob]
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
            let signingKey = P256.Signing.PrivateKey()
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: runtime,
                authenticatedGetSpaceDirectory: PublicBlobNoopSpaceDirectory(),
                accountControlStore: control,
                publicRepositoryMutationDirectory: directory,
                publicRepositoryMutationSignerProvider: PublicBlobTestSignerProvider(
                    signer: P256PublicRepositoryCommitSigner(
                        privateKey: signingKey
                    )
                ),
                blobStreamAdmission: blobStreamAdmission
            )
            return Fixture(
                root: root,
                control: control,
                alice: alice,
                bob: bob,
                directory: directory,
                server: server
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func blobURI(did: String, cid: String) -> String {
        Self.blobPath + "?did=" + did + "&cid=" + cid
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
        let bob: SQLiteAccountDatabase
        let directory: PublicBlobTestDirectory
        let server: SwanHTTPServer

        func scheduleCleanup() {
            Task {
                try? await alice.close()
                try? await bob.close()
                try? await control.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
    }
}

private actor PublicBlobTestDirectory: PublicRepositoryMutationDirectory {
    private let stores: [String: SQLiteAccountDatabase]
    private var statuses: [String: AccountControlStatus]
    private var unavailableStores: Set<String> = []

    init(stores: [String: SQLiteAccountDatabase]) {
        self.stores = stores
        statuses = Dictionary(
            uniqueKeysWithValues: stores.keys.map { ($0, .active) }
        )
    }

    func setStatus(_ status: AccountControlStatus, did: String) {
        statuses[did] = status
    }

    func setPreopened(_ available: Bool, did: String) {
        if available {
            unavailableStores.remove(did)
        } else {
            unavailableStores.insert(did)
        }
    }

    func publicRepositoryMutationTarget(
        selector: String
    ) async throws -> PublicRepositoryMutationTarget? {
        guard let store = stores[selector],
              let status = statuses[selector],
              !unavailableStores.contains(selector) else {
            return nil
        }
        return try PublicRepositoryMutationTarget(
            did: selector,
            status: status,
            store: store
        )
    }
}

private actor PublicBlobNoopSpaceDirectory: AuthorizedSimpleSpaceDirectory {
    func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? {
        nil
    }

    func close() async throws {}
}

private struct PublicBlobTestSignerProvider:
    PublicRepositoryMutationSignerProvider
{
    let signer: any PublicRepositoryCommitSigner

    func signer(
        for did: String
    ) async throws -> PublicRepositoryMutationSigner {
        .init(generation: 1, signer: signer)
    }
}
