import HTTPTypes
import XCTest

@testable import SwanHTTP

final class LoginClientIdentityPolicyTests: XCTestCase {
    func testDirectConnectionUsesSocketPeerAndIgnoresForwardingHeaders() throws {
        let policy = try SwanLoginClientIdentityPolicy()
        var headers: HTTPFields = [:]
        headers[SwanLoginClientIdentityPolicy.clientIPHeader] = "203.0.113.41"
        headers[HTTPField.Name("X-Forwarded-For")!] = "198.51.100.12"

        XCTAssertEqual(
            try policy.clientIPAddress(
                directPeer: "127.0.0.1",
                headers: headers
            ),
            "127.0.0.1"
        )
    }

    func testUntrustedProxyIgnoresForgedAndRepeatedClientHeaders() throws {
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["192.0.2.10"]
        )
        var headers: HTTPFields = [:]
        headers.append(HTTPField(
            name: SwanLoginClientIdentityPolicy.clientIPHeader,
            value: "203.0.113.41"
        ))
        headers.append(HTTPField(
            name: SwanLoginClientIdentityPolicy.clientIPHeader,
            value: "198.51.100.12"
        ))

        XCTAssertEqual(
            try policy.clientIPAddress(
                directPeer: "127.0.0.1",
                headers: headers
            ),
            "127.0.0.1"
        )
    }

    func testTrustedProxyUsesOneStrictIPv4OrIPv6ClientLiteral() throws {
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["172.30.0.2", "2001:db8::2"]
        )

        for (directPeer, literal, expected) in [
            ("172.30.0.2", "203.0.113.41", "203.0.113.41"),
            ("2001:db8::2", "2001:db8:0:0::41", "2001:db8::41"),
        ] {
            var headers: HTTPFields = [:]
            headers[SwanLoginClientIdentityPolicy.clientIPHeader] = literal
            XCTAssertEqual(
                try policy.clientIPAddress(
                    directPeer: directPeer,
                    headers: headers
                ),
                expected
            )
        }
    }

    func testTrustedProxyRejectsMissingRepeatedAndMalformedClientHeader() throws {
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["172.30.0.2"]
        )
        let invalidValues: [String?] = [
            nil,
            "203.0.113.41, 198.51.100.12",
            "203.0.113.41:443",
            "[2001:db8::41]",
            " client.example",
            "client.example",
            "2001:db8::41%en0",
            "",
        ]

        for value in invalidValues {
            var headers: HTTPFields = [:]
            if let value {
                headers[SwanLoginClientIdentityPolicy.clientIPHeader] = value
            }
            XCTAssertThrowsError(
                try policy.clientIPAddress(
                    directPeer: "172.30.0.2",
                    headers: headers
                ),
                "unexpectedly accepted \(value ?? "<missing>")"
            ) { error in
                XCTAssertEqual(
                    error as? SwanLoginClientIdentityError,
                    .unavailable
                )
            }
        }

        var repeated: HTTPFields = [:]
        repeated.append(HTTPField(
            name: SwanLoginClientIdentityPolicy.clientIPHeader,
            value: "203.0.113.41"
        ))
        repeated.append(HTTPField(
            name: SwanLoginClientIdentityPolicy.clientIPHeader,
            value: "198.51.100.12"
        ))
        XCTAssertThrowsError(
            try policy.clientIPAddress(
                directPeer: "172.30.0.2",
                headers: repeated
            )
        ) { error in
            XCTAssertEqual(
                error as? SwanLoginClientIdentityError,
                .unavailable
            )
        }
    }

    func testPolicyRejectsNonliteralTrustedProxyConfiguration() {
        for literal in [
            "",
            " caddy",
            "caddy",
            "172.30.0.2:3000",
            "[2001:db8::2]",
            "172.30.0.2,172.30.0.3",
            "2001:db8::2%en0",
        ] {
            XCTAssertThrowsError(
                try SwanLoginClientIdentityPolicy(
                    trustedProxyPeerLiterals: [literal]
                ),
                "unexpectedly accepted \(literal)"
            ) { error in
                XCTAssertEqual(
                    error as? SwanLoginClientIdentityError,
                    .invalidTrustedProxyPeer
                )
            }
        }
    }
}
