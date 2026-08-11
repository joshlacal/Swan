import Foundation
@testable import SwanOAuth
import XCTest

private struct StubDocuments: SwanDIDDocumentFetching {
    let json: String
    func documentJSON(forDID _: String) async throws -> Data {
        Data(json.utf8)
    }
}

private struct FailingDocuments: SwanDIDDocumentFetching {
    struct Boom: Error {}
    func documentJSON(forDID _: String) async throws -> Data {
        throw Boom()
    }
}

final class SwanServiceEndpointResolverTests: XCTestCase {
    private func resolver(_ json: String) -> SwanServiceEndpointResolver {
        SwanServiceEndpointResolver(documents: StubDocuments(json: json))
    }

    private let document = """
    {"id":"did:web:api.bsky.app","service":[
      {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://api.bsky.app"},
      {"id":"#other","type":"Other","serviceEndpoint":"https://other.example"}]}
    """

    func testSelectsServiceByFragment() async throws {
        let url = try await resolver(document).endpoint(
            did: "did:web:api.bsky.app", fragment: "bsky_appview"
        )
        XCTAssertEqual(url, URL(string: "https://api.bsky.app"))
    }

    func testAcceptsFullyQualifiedServiceID() async throws {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"did:web:x.example#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example"}]}
        """
        let url = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
        XCTAssertEqual(url, URL(string: "https://x.example"))
    }

    func testMissingFragmentIsUnresolvable() async {
        do {
            _ = try await resolver(document).endpoint(
                did: "did:web:api.bsky.app", fragment: "nope"
            )
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    func testNonHTTPSEndpointIsRejected() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"http://x.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    func testMalformedDocumentIsUnresolvable() async {
        for json in ["{}", "not json", #"{"service":[]}"#, #"{"service":"nope"}"#] {
            do {
                _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
                XCTFail("expected failure for \(json)")
            } catch {
                XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
            }
        }
    }

    func testFetchFailureIsUnresolvable() async {
        do {
            _ = try await SwanServiceEndpointResolver(documents: FailingDocuments())
                .endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }
}
