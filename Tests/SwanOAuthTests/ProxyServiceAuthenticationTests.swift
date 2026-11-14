import Crypto
import Foundation
import PetrelCrypto
@testable import SwanOAuth
import XCTest

final class ProxyServiceAuthenticationTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
    private let audience = "did:web:api.bsky.app"

    private func claims(_ compact: String) throws -> [String: Any] {
        let parts = compact.split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        var b64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 {
            b64 += "="
        }
        let data = try XCTUnwrap(Data(base64Encoded: b64))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testMintsTokenForAppBskyMethod() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let compact = try ProxyServiceJWT.create(
            issuer: issuer, audience: audience, method: "app.bsky.actor.getProfile",
            eventID: "abc123", key: key, now: now, lifetime: 60
        )
        let payload = try claims(compact)
        XCTAssertEqual(payload["iss"] as? String, issuer)
        XCTAssertEqual(payload["aud"] as? String, audience)
        XCTAssertEqual(payload["lxm"] as? String, "app.bsky.actor.getProfile")
        XCTAssertEqual(payload["jti"] as? String, "abc123")
        XCTAssertEqual(payload["iat"] as? Int64, 1_700_000_000)
        XCTAssertEqual(payload["exp"] as? Int64, 1_700_000_060)
    }

    func testSignatureVerifiesAgainstIssuerKey() throws {
        let compact = try ProxyServiceJWT.create(
            issuer: issuer, audience: audience, method: "app.bsky.feed.getTimeline",
            eventID: "j1", key: key
        )
        let parts = compact.split(separator: ".")
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        var b64 = String(parts[2]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 {
            b64 += "="
        }
        let raw = try XCTUnwrap(Data(base64Encoded: b64))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: signingInput))
    }

    func testRejectsMalformedInputs() {
        // Non-NSID methods, bad DIDs, and out-of-range lifetimes must not mint.
        XCTAssertThrowsError(
            try ProxyServiceJWT.create(
                issuer: issuer, audience: audience, method: "not an nsid", eventID: "j", key: key
            )
        )
        XCTAssertThrowsError(
            try ProxyServiceJWT.create(
                issuer: "nope", audience: audience, method: "app.bsky.actor.getProfile",
                eventID: "j", key: key
            )
        )
        XCTAssertThrowsError(
            try ProxyServiceJWT.create(
                issuer: issuer, audience: "", method: "app.bsky.actor.getProfile",
                eventID: "j", key: key
            )
        )
        XCTAssertThrowsError(
            try ProxyServiceJWT.create(
                issuer: issuer, audience: audience, method: "app.bsky.actor.getProfile",
                eventID: "j", key: key, lifetime: 0
            )
        )
        XCTAssertThrowsError(
            try ProxyServiceJWT.create(
                issuer: issuer, audience: audience, method: "app.bsky.actor.getProfile",
                eventID: "j", key: key, lifetime: ServiceJWT.maximumLifetime + 1
            )
        )
    }

    func testCollectionOfMethodsAcceptedAcrossNamespaces() throws {
        for method in [
            "app.bsky.actor.getProfile", "app.bsky.feed.getTimeline",
            "tools.ozone.moderation.emitEvent", "com.atproto.repo.getRecord",
        ] {
            XCTAssertNoThrow(
                try ProxyServiceJWT.create(
                    issuer: issuer, audience: audience, method: method, eventID: "j", key: key
                )
            )
        }
    }
}
