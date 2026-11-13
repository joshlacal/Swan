import Foundation
import SwanCore
@testable import SwanOAuth
import SwanSpaces
import SwanStorage
import XCTest

/// The outbound `com.atproto.managedspace.checkAccess` client: request shape,
/// strict answer parsing, and upstream-failure semantics.
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

    func testRequestCarriesOptionalRepoAndAttestedClientID() throws {
        let base = try XCTUnwrap(URL(string: "https://manager.example"))
        let delegated = try RemoteManagedSpaceAccessChecker.requestURL(
            base: base, space: space(), repo: Self.user,
            clientID: "https://app.example/client+metadata.json"
        )
        XCTAssertEqual(delegated.path, "/xrpc/com.atproto.managedspace.checkAccess")
        XCTAssertEqual(query(delegated), [
            "space": try space().rawValue,
            "repo": Self.user,
            "clientId": "https://app.example/client+metadata.json",
        ])
        XCTAssertTrue(delegated.absoluteString.contains("client%2Bmetadata"))

        let undelegated = try RemoteManagedSpaceAccessChecker.requestURL(
            base: base, space: space(), repo: nil, clientID: nil
        )
        XCTAssertEqual(query(undelegated), ["space": try space().rawValue])
    }

    func testResponseRequiresExactlyTwoBooleans() throws {
        XCTAssertEqual(
            try RemoteManagedSpaceAccessChecker.access(from: Data(#"{"read":true,"write":false}"#.utf8)),
            ManagedSpaceAccess(read: true, write: false)
        )
        for body in [
            #"{"read":true}"#,
            #"{"read":true,"write":0}"#,
            #"{"read":true,"write":false,"other":false}"#,
            #"[true,false]"#,
            "not json",
            "",
        ] {
            XCTAssertThrowsError(
                try RemoteManagedSpaceAccessChecker.access(from: Data(body.utf8)),
                body
            ) {
                XCTAssertEqual($0 as? ManagedSpaceAccessError, .upstreamFailure)
            }
        }
    }

    func testResolutionAndTransportFailuresAreUpstreamFailures() async throws {
        let signer = RecordingIssuer()
        let manager = "did:web:manager.example"
        let documents = StubDocuments(documents: [
            manager: Data("""
            {"id":"\(manager)","service":[
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
        for app in ["did:web:absent.example#space", "\(manager)#other", manager, "\(manager)#space"] {
            do {
                _ = try await checker.checkAccess(
                    space: try space(), repo: Self.user, clientID: nil, managingApp: app
                )
                XCTFail("expected upstream failure for \(app)")
            } catch {
                XCTAssertEqual(error as? ManagedSpaceAccessError, .upstreamFailure)
            }
        }
        let calls = await signer.calls
        XCTAssertEqual(calls.map(\.audience), ["\(manager)#space"])
        XCTAssertTrue(calls.allSatisfy { $0.issuer == Self.authority })
        XCTAssertTrue(calls.allSatisfy { $0.method == "com.atproto.managedspace.checkAccess" })
        XCTAssertTrue(calls.allSatisfy { $0.requestBodyDigest == nil })
    }

    func testUnavailableCheckerReportsUpstreamFailure() async throws {
        do {
            _ = try await UnavailableManagedSpaceAccessChecker().checkAccess(
                space: space(), repo: nil, clientID: nil,
                managingApp: "did:web:manager.example#space"
            )
            XCTFail("expected upstream failure")
        } catch {
            XCTAssertEqual(error as? ManagedSpaceAccessError, .upstreamFailure)
        }
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
