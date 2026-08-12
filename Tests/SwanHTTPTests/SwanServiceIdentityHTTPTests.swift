import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import XCTest

/// Swan's own published identity: the `did:web` document a relay, AppView, or
/// resolver fetches from `/.well-known/did.json`, and the `describeServer`
/// answer that must agree with it.
final class SwanServiceIdentityHTTPTests: XCTestCase {
    private static let swanPlace = URL(string: "https://swan.place")!

    func testWellKnownDidJSONResolvesTheServiceDID() async throws {
        try await withRunningServer(publicURL: Self.swanPlace) { client in
            try await client.execute(uri: "/.well-known/did.json", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[.contentType], "application/json")
                let doc = try JSONDecoder().decode(
                    WellKnownDIDDocument.self,
                    from: Data(buffer: response.body)
                )
                XCTAssertEqual(doc.id, "did:web:swan.place")
                XCTAssertTrue(doc.service.contains { $0.type == "AtprotoPersonalDataServer" })
                let pds = try XCTUnwrap(
                    doc.service.first { $0.type == "AtprotoPersonalDataServer" }
                )
                XCTAssertEqual(pds.id, "#atproto_pds")
                XCTAssertEqual(pds.serviceEndpoint, "https://swan.place")
                XCTAssertEqual(doc.context, ["https://www.w3.org/ns/did/v1"])
            }
        }
    }

    func testDescribeServerDoesNotClaimInviteCodesAreRequired() async throws {
        try await withRunningServer(publicURL: Self.swanPlace) { client in
            let description = try await Self.describeServer(using: client)
            XCTAssertFalse(description.inviteCodeRequired)
        }
    }

    /// A configured `true` must reach the wire. Without this the endpoint
    /// could satisfy the test above by swapping one hardcoded literal for
    /// another instead of reading configuration.
    func testDescribeServerAdvertisesInviteCodesOnlyWhenConfigured() async throws {
        try await withRunningServer(
            publicURL: Self.swanPlace,
            inviteCodeRequired: true
        ) { client in
            let description = try await Self.describeServer(using: client)
            XCTAssertTrue(description.inviteCodeRequired)
        }
    }

    /// A resolver reads `describeServer.did`, fetches the document that DID
    /// names, and compares. Two independently formatted identities would fail
    /// that comparison in production and pass every route-local test, so the
    /// agreement is checked on a ported deployment as well — that is where two
    /// plausible formattings actually diverge.
    func testDescribeServerAndDidDocumentPublishTheSameServiceDID() async throws {
        let cases: [(url: URL, port: Int, expected: String)] = [
            (Self.swanPlace, 443, "did:web:swan.place"),
            (
                try XCTUnwrap(URL(string: "https://swan.place:8443")),
                8443,
                "did:web:swan.place%3A8443"
            ),
        ]
        for testCase in cases {
            try await withRunningServer(
                publicURL: testCase.url,
                port: testCase.port
            ) { client in
                let described = try await Self.describeServer(using: client).did
                let published = try await Self.serviceDIDDocument(using: client).id
                XCTAssertEqual(described, testCase.expected)
                XCTAssertEqual(published, described)
            }
        }
    }

    /// `did:web:host` resolves to `https://host/.well-known/did.json`. A
    /// deployment on a non-default port that dropped the port would publish an
    /// identity naming a different origin than the one actually serving.
    func testServiceDIDEncodesANonDefaultPort() async throws {
        let publicURL = try XCTUnwrap(URL(string: "http://127.0.0.1:3000"))
        try await withRunningServer(publicURL: publicURL, port: 3000) { client in
            let doc = try await Self.serviceDIDDocument(using: client)
            XCTAssertEqual(doc.id, "did:web:127.0.0.1%3A3000")
            XCTAssertEqual(
                doc.service.first { $0.type == "AtprotoPersonalDataServer" }?.serviceEndpoint,
                "http://127.0.0.1:3000"
            )
            let described = try await Self.describeServer(using: client).did
            XCTAssertEqual(described, "did:web:127.0.0.1%3A3000")
        }
    }

    /// Browser-side identity resolution issues a preflight before the GET, and
    /// only those two methods are answered at all.
    func testDidDocumentIsCORSReadableAndMethodCorrect() async throws {
        try await withRunningServer(publicURL: Self.swanPlace) { client in
            let allowOrigin = try XCTUnwrap(HTTPField.Name("Access-Control-Allow-Origin"))
            try await client.execute(uri: "/.well-known/did.json", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[allowOrigin], "*")
            }
            try await client.execute(uri: "/.well-known/did.json", method: .options) { response in
                XCTAssertEqual(response.status, .noContent)
                XCTAssertEqual(response.headers[allowOrigin], "*")
            }
            for method: HTTPRequest.Method in [.post, .put, .patch, .delete] {
                try await client.execute(uri: "/.well-known/did.json", method: method) { response in
                    XCTAssertEqual(response.status, .notFound, method.rawValue)
                }
            }
        }
    }

    /// The derivation itself, on the shapes an operator can actually write
    /// into `--public-url`: an explicit default port, a trailing slash, and
    /// mixed-case host all have to normalize to one identity, because a second
    /// spelling of the same deployment is a second identity to every resolver.
    func testServiceIdentityNormalizesEquivalentPublicURLs() throws {
        let cases: [(input: String, did: String, endpoint: String)] = [
            ("https://swan.place", "did:web:swan.place", "https://swan.place"),
            ("https://swan.place:443", "did:web:swan.place", "https://swan.place"),
            ("https://swan.place/", "did:web:swan.place", "https://swan.place"),
            ("https://Swan.Place", "did:web:swan.place", "https://swan.place"),
            (
                "https://swan.place:8443",
                "did:web:swan.place%3A8443",
                "https://swan.place:8443"
            ),
            ("http://localhost:80", "did:web:localhost", "http://localhost"),
            (
                "http://127.0.0.1:3000",
                "did:web:127.0.0.1%3A3000",
                "http://127.0.0.1:3000"
            ),
        ]
        for testCase in cases {
            let url = try XCTUnwrap(URL(string: testCase.input))
            let identity = SwanServiceIdentity(publicURL: url)
            XCTAssertEqual(identity.did, testCase.did, testCase.input)
            XCTAssertEqual(identity.serviceEndpoint, testCase.endpoint, testCase.input)
        }
    }

    // MARK: - Wire mirrors

    /// Decoded from the served bytes. Petrel's `DIDDocument` keeps its stored
    /// properties internal to that module, so the assertions above read this
    /// mirror rather than re-encoding anything the server produced.
    private struct WellKnownDIDDocument: Decodable {
        let context: [String]
        let id: String
        let service: [WellKnownDIDService]

        enum CodingKeys: String, CodingKey {
            case context = "@context"
            case id, service
        }
    }

    private struct WellKnownDIDService: Decodable {
        let id: String
        let type: String
        let serviceEndpoint: String
    }

    private struct DescribeServerBody: Decodable {
        let did: String
        let availableUserDomains: [String]
        let inviteCodeRequired: Bool
        let swanProfile: String
    }

    private static func describeServer(
        using client: some TestClientProtocol
    ) async throws -> DescribeServerBody {
        try await client.execute(
            uri: "/xrpc/com.atproto.server.describeServer",
            method: .get
        ) { response in
            XCTAssertEqual(response.status, .ok)
            return try JSONDecoder().decode(
                DescribeServerBody.self,
                from: Data(buffer: response.body)
            )
        }
    }

    private static func serviceDIDDocument(
        using client: some TestClientProtocol
    ) async throws -> WellKnownDIDDocument {
        try await client.execute(uri: "/.well-known/did.json", method: .get) { response in
            XCTAssertEqual(response.status, .ok)
            return try JSONDecoder().decode(
                WellKnownDIDDocument.self,
                from: Data(buffer: response.body)
            )
        }
    }

    // MARK: - Fixture

    /// The control database must be closed on the failure path too: SQLiteNIO
    /// traps in `deinit` on a still-open connection, which turns one failed
    /// assertion into a crashed target that truncates every later test.
    private func withRunningServer(
        publicURL: URL,
        port: Int = 3000,
        inviteCodeRequired: Bool = false,
        _ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void
    ) async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanServiceIdentityHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x71, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot()
                    .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: SwanHTTPConfiguration(
                    host: "127.0.0.1",
                    port: port,
                    publicURL: publicURL,
                    inviteCodeRequired: inviteCodeRequired
                ),
                oauthRuntime: runtime
            )
            let app = server.buildApplication(
                logger: Logger(label: "SwanServiceIdentityHTTPTests")
            )
            try await app.test(.router, body)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
