import Crypto
import Foundation
import XCTest

@testable import SwanOAuth

/// The production `SwanDIDDocumentFetching` conformer's pure DID → document
/// URL derivation. Every case here decides whether a hostile DID can steer a
/// peer-pinned fetch at an unintended target, so it is tested without a
/// network.
final class SwanPeerPinnedDIDDocumentFetcherTests: XCTestCase {
    func testDIDWebDocumentURLs() throws {
        let plc = URL(string: "https://plc.directory")!
        XCTAssertEqual(
            try SwanPeerPinnedDIDDocumentFetcher.documentURL(
                forDID: "did:web:api.bsky.app", plcOrigin: plc
            ).absoluteString,
            "https://api.bsky.app/.well-known/did.json"
        )
        XCTAssertEqual(
            try SwanPeerPinnedDIDDocumentFetcher.documentURL(
                forDID: "did:web:example.com:user:alice", plcOrigin: plc
            ).absoluteString,
            "https://example.com/user/alice/did.json"
        )
        XCTAssertEqual(
            try SwanPeerPinnedDIDDocumentFetcher.documentURL(
                forDID: "did:plc:abcdefghijklmnopqrstuvwx", plcOrigin: plc
            ).absoluteString,
            "https://plc.directory/did:plc:abcdefghijklmnopqrstuvwx"
        )
        // The configured origin is reused, never a second hardcoded copy.
        XCTAssertEqual(
            try SwanPeerPinnedDIDDocumentFetcher.documentURL(
                forDID: "did:plc:abcdefghijklmnopqrstuvwx",
                plcOrigin: URL(string: "https://plc.lab.example")!
            ).absoluteString,
            "https://plc.lab.example/did:plc:abcdefghijklmnopqrstuvwx"
        )
    }

    func testRejectedDIDDocumentURLs() {
        let plc = URL(string: "https://plc.directory")!
        for did in [
            "did:key:z6Mk",
            "did:web:",
            "did:web:example.com:..:secret",
            "did:web:example.com:%2e%2e",
            "did:web:example.com/evil",
            "did:web:exam ple.com",
            "did:web:example.com:a/b",
            "did:plc:ABCDEFGHIJKLMNOPQRSTUVWX",
            "did:plc:abcdefghijklmnopqrstuvw1",
            "not-a-did",
        ] {
            XCTAssertThrowsError(
                try SwanPeerPinnedDIDDocumentFetcher.documentURL(forDID: did, plcOrigin: plc),
                "expected \(did) to be refused"
            )
        }
    }
}
