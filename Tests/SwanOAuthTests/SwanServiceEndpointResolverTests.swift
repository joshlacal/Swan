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

    // MARK: Subject binding (F07)

    /// The fetch path proves *where* the document came from, not *whose* it is.
    /// A document that names a different subject is refused even though it is
    /// otherwise well formed and its endpoint is a perfectly good https URL.
    func testDocumentForADifferentSubjectIsRejected() async {
        let json = """
        {"id":"did:web:evil.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://evil.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// The comparison is byte-exact against the DID as received. `did:web` ids
    /// carry `%3A` for a port, and the fetcher's URL derivation is the only
    /// place that decoding happens; re-normalising here would be a second,
    /// weaker grammar. So a `%3A`-bearing DID resolves only against a document
    /// whose `id` is spelled the same way.
    func testPercentEncodedPortDIDMatchesExactly() async throws {
        let json = """
        {"id":"did:web:x.example%3A8443","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example:8443"}]}
        """
        let url = try await resolver(json).endpoint(
            did: "did:web:x.example%3A8443", fragment: "bsky_appview"
        )
        XCTAssertEqual(url, URL(string: "https://x.example:8443"))
    }

    /// ...and the decoded spelling of the same authority is a different string,
    /// so it does not match. This is the deliberate consequence of refusing to
    /// normalise, asserted so a later "helpful" normalisation fails loudly.
    func testDecodedPortSpellingDoesNotMatchEncodedDocumentID() async {
        let json = """
        {"id":"did:web:x.example%3A8443","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example:8443"}]}
        """
        do {
            _ = try await resolver(json).endpoint(
                did: "did:web:x.example:8443", fragment: "bsky_appview"
            )
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// Host case is the other spelling that names the same subject and is not
    /// the same string. DNS is case-insensitive, so the document fetch itself
    /// would have succeeded; binding still refuses, because accepting it means
    /// choosing a case-folding rule here that the fetcher's URL derivation
    /// does not share. Declared as a behaviour change, not discovered as one:
    /// a caller that spells the DID in a different case than the document does
    /// gets `.unresolvableService` where it used to get the endpoint.
    func testHostCaseDifferenceDoesNotMatchDocumentID() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(
                did: "did:web:X.Example", fragment: "bsky_appview"
            )
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// A document with no `id` cannot be bound to the DID that was asked for.
    /// `id` is required by DID Core, so an absent one is a malformed document,
    /// not a permissive one — it is rejected rather than waved through.
    func testDocumentWithoutAnIDIsRejected() async {
        let json = """
        {"service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    // MARK: Duplicate service ids (F07)

    /// Two entries with the same id: taking the first makes the answer depend
    /// on array order, so an appended duplicate would silently shadow — or be
    /// shadowed by — the real entry. The ambiguity is refused instead.
    func testDuplicateServiceIDsAreRejected() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"},
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://evil.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// The same fragment written both ways ("#frag" and "did:...#frag") is the
    /// same service id, so it is the same ambiguity and is refused too.
    func testFragmentDeclaredBothShortAndFullyQualifiedIsRejected() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"},
          {"id":"did:web:x.example#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://evil.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// A duplicate on some *other* fragment does not make the requested one
    /// ambiguous. Scoping the rejection to the selection keeps a single
    /// malformed unrelated entry from denying every service in the document.
    func testDuplicateOnAnUnrelatedFragmentStillResolves() async throws {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#other","type":"Other","serviceEndpoint":"https://a.example"},
          {"id":"#other","type":"Other","serviceEndpoint":"https://b.example"},
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"}]}
        """
        let url = try await resolver(json).endpoint(
            did: "did:web:x.example", fragment: "bsky_appview"
        )
        XCTAssertEqual(url, URL(string: "https://x.example"))
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
