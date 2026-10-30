import Foundation
import SwanCore
@testable import SwanOAuth
import SwanSpaces
import SwanStorage
import XCTest

/// The outbound `com.atproto.managedspace.checkUserAccess` client: request
/// shape, strict answer parsing, and deny-on-failure.
final class ManagedSpaceAccessCheckerTests: XCTestCase {
    private static let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let user = "did:plc:bcdefghijklmnopqrstuvwxy"

    private func space() throws -> SpaceURI {
        try SpaceURI(authority: Self.authority, spaceType: "app.bsky.bookmarks", skey: "managed")
    }

    private func query(_ url: URL) -> [String: String] {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        return Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
    }

    func testRequestCarriesClientIdOnReadsOnly() throws {
        let base = try XCTUnwrap(URL(string: "https://manager.example"))
        let read = try RemoteManagedSpaceAccessChecker.requestURL(
            base: base, space: space(), user: Self.user, access: .read,
            clientID: "https://app.example/client+metadata.json"
        )
        XCTAssertEqual(read.path, "/xrpc/com.atproto.managedspace.checkUserAccess")
        XCTAssertEqual(query(read), [
            "space": try space().rawValue,
            "user": Self.user,
            "access": "read",
            "clientId": "https://app.example/client+metadata.json",
        ])
        XCTAssertTrue(read.absoluteString.contains("client%2Bmetadata"), "`+` must not decode as a space")

        let write = try RemoteManagedSpaceAccessChecker.requestURL(
            base: base, space: space(), user: Self.user, access: .write,
            clientID: "https://app.example/client.json"
        )
        XCTAssertEqual(query(write), [
            "space": try space().rawValue,
            "user": Self.user,
            "access": "write",
        ])
    }

    func testOnlyABooleanTrueAuthorizes() {
        XCTAssertTrue(RemoteManagedSpaceAccessChecker.isAuthorized(Data(#"{"authorized":true}"#.utf8)))
        for body in [
            #"{"authorized":false}"#,
            #"{"authorized":1}"#,
            #"{"authorized":"true"}"#,
            #"{"authorized":null}"#,
            #"{}"#,
            #"[true]"#,
            #"{"authorized":true,"authorized":false}"#,
            "not json",
            "",
        ] {
            XCTAssertFalse(RemoteManagedSpaceAccessChecker.isAuthorized(Data(body.utf8)), body)
        }
    }

    func testEveryFailureDenies() async throws {
        let signer = RecordingIssuer()
        let manager = "did:web:manager.example"
        let documents = StubDocuments(documents: [
            manager: Data("""
            {"id":"\(manager)","service":[
              {"id":"#atproto_pds","serviceEndpoint":"https://127.0.0.1:9"},
              {"id":"#space","serviceEndpoint":"https://localhost:9"}
            ]}
            """.utf8),
        ])
        let checker = RemoteManagedSpaceAccessChecker(
            resolver: SwanServiceEndpointResolver(documents: documents),
            signer: signer,
            policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
            transport: NIOPeerPinnedOAuthPostTransport(
                configuration: try .init(endpointPeers: [:], allowsDynamicPeerSelection: true)
            )
        )
        // An app whose DID document cannot be fetched: denied, nothing signed.
        let unresolvable = await checker.checkUserAccess(
            space: try space(), user: Self.user, access: .read, clientID: nil,
            managingApp: "did:web:absent.example"
        )
        XCTAssertFalse(unresolvable)
        let afterUnresolvable = await signer.calls
        XCTAssertTrue(afterUnresolvable.isEmpty)

        // A named fragment the document lacks: denied.
        let missingFragment = await checker.checkUserAccess(
            space: try space(), user: Self.user, access: .write, clientID: nil,
            managingApp: "\(manager)#other"
        )
        XCTAssertFalse(missingFragment)

        // Resolvable, but the endpoint is cleartext or loopback, which the
        // outbound policy refuses: denied, after signing with the authority
        // as issuer and the app exactly as written as audience.
        for app in [manager, "\(manager)#space"] {
            let allowed = await checker.checkUserAccess(
                space: try space(), user: Self.user, access: .read, clientID: nil,
                managingApp: app
            )
            XCTAssertFalse(allowed, app)
        }
        let calls = await signer.calls
        XCTAssertEqual(calls.map(\.audience), [manager, "\(manager)#space"])
        XCTAssertTrue(calls.allSatisfy { $0.issuer == Self.authority })
        XCTAssertTrue(calls.allSatisfy { $0.method == "com.atproto.managedspace.checkUserAccess" })
        XCTAssertTrue(calls.allSatisfy { $0.requestBodyDigest == nil })
    }

    func testDenyingCheckerAlwaysDenies() async throws {
        let allowed = await DenyingManagedSpaceAccessChecker().checkUserAccess(
            space: try space(), user: Self.user, access: .read, clientID: nil,
            managingApp: "did:web:manager.example"
        )
        XCTAssertFalse(allowed)
    }
}

private struct StubDocuments: SwanDIDDocumentFetching {
    let documents: [String: Data]

    func documentJSON(forDID did: String) async throws -> Data {
        guard let document = documents[did] else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return document
    }
}

private actor RecordingIssuer: SpaceServiceAuthenticationIssuer {
    struct Call: Sendable {
        let issuer: String
        let audience: String
        let method: String
        let requestBodyDigest: String?
    }

    private(set) var calls: [Call] = []

    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID _: String,
        requestBodyDigest: String?,
        now _: Date
    ) async throws -> String {
        calls.append(.init(
            issuer: issuer, audience: audience, method: method,
            requestBodyDigest: requestBodyDigest
        ))
        return "header.payload.signature"
    }
}
