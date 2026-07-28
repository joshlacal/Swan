import Crypto
import Foundation
import XCTest
@testable import SwanOAuth
@testable import SwanSQLite
import SwanCore
import SwanStorage

final class ClientAttestationPolicyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_738_368_000)
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let clientID = "https://client.example/client-metadata.json"

    func testUntrustedInspectionRequiresExactBoundedProfileBeforeFetching() throws {
        let key = try fixedPrivateKey()
        let token = try clientAttestation(
            key: key,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now
        )

        let inspected = try PermissionedDataJWT.inspectUntrustedClientAttestation(
            token,
            authority: authority,
            now: now
        )
        XCTAssertEqual(inspected.clientID.absoluteString, clientID)
        XCTAssertEqual(inspected.keyID, "key-1")
        XCTAssertEqual(inspected.claims.jti, "typescript-shaped-nonce-001")
        XCTAssertEqual(inspected.replayExpiresAt, now.addingTimeInterval(120))

        for invalid in try invalidLocalTokens(key: key) {
            XCTAssertThrowsError(
                try PermissionedDataJWT.inspectUntrustedClientAttestation(
                    invalid,
                    authority: authority,
                    now: now
                )
            )
        }
    }

    func testAttestationConfigurationUsesImmutableBoundedDefaults() throws {
        let standard = DurableSpaceCredentialClientAttestationPolicy.Configuration.standard
        XCTAssertEqual(standard.maximumLifetime, 300)
        XCTAssertEqual(standard.clockSkew, 60)
        XCTAssertThrowsError(
            try DurableSpaceCredentialClientAttestationPolicy.Configuration(
                maximumLifetime: 601
            )
        )
        XCTAssertThrowsError(
            try DurableSpaceCredentialClientAttestationPolicy.Configuration(
                clockSkew: 121
            )
        )
        XCTAssertNoThrow(
            try DurableSpaceCredentialClientAttestationPolicy.Configuration(
                maximumLifetime: 600,
                clockSkew: 120
            )
        )
    }

    func testExactClockAndLifetimeBoundariesAreAccepted() throws {
        let key = try fixedPrivateKey()
        let issuedAt = Int64(now.timeIntervalSince1970)
        for claims in [
            [
                "iss": clientID, "sub": clientID,
                "aud": "\(authority)#atproto_space_host",
                "iat": issuedAt + 60, "exp": issuedAt + 300,
                "jti": "future-skew-boundary",
            ] as [String: Any],
            [
                "iss": clientID, "sub": clientID,
                "aud": "\(authority)#atproto_space_host",
                "iat": issuedAt - 120, "exp": issuedAt - 60,
                "jti": "expiry-skew-boundary",
            ] as [String: Any],
            [
                "iss": clientID, "sub": clientID,
                "aud": "\(authority)#atproto_space_host",
                "iat": issuedAt, "exp": issuedAt + 300,
                "jti": "maximum-lifetime-boundary",
            ] as [String: Any],
        ] {
            let token = try rawClientAttestation(
                header: [
                    "alg": "ES256",
                    "typ": PermissionedDataJWT.clientAttestationType,
                    "kid": "key-1",
                ],
                claims: claims,
                key: key
            )
            XCTAssertNoThrow(
                try PermissionedDataJWT.inspectUntrustedClientAttestation(
                    token,
                    authority: authority,
                    now: now
                )
            )
        }
    }

    func testPublishedJWKSelectionRejectsPrivateAndMismatchedMaterial() throws {
        let key = try fixedPrivateKey()
        let publicJWK = try attestationJWK(key, keyID: "key-1")
        let x = publicJWK.x
        let y = publicJWK.y
        for body in [
            #"{"keys":[{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)","kid":"key-1","d":"private-sentinel"}]}"#,
            #"{"keys":[{"kty":"EC","crv":"secp256k1","x":"\#(x)","y":"\#(y)","kid":"key-1"}]}"#,
            #"{"keys":[{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)","kid":"key-1","use":"enc"}]}"#,
            #"{"keys":[{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)","kid":"key-1","alg":"ES256K"}]}"#,
            #"{"keys":[{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)","kid":"key-1"},{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)","kid":"key-1"}]}"#,
        ] {
            XCTAssertThrowsError(
                try OAuthJSONWebKeySet.decodeValidated(Data(body.utf8))
            )
        }
    }

    func testInlineAndRemoteJWKSVerifyThenDurablyRejectReplay() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let key = try fixedPrivateKey()
        let jwk = try attestationJWK(key, keyID: "key-1")
        let inlineMetadata = try attestationMetadata(
            clientID: clientID,
            inlineKey: jwk
        )
        let inlineTransport = AttestationTransport(
            responseQueues: [
                clientID: [
                    try response(body: inlineMetadata, url: clientID),
                    try response(body: inlineMetadata, url: clientID),
                ],
            ]
        )
        let inlinePolicy = try await attestationPolicy(
            database: database,
            transport: inlineTransport
        )
        let token = try clientAttestation(
            key: key,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now
        )
        let inlineClientID = try await inlinePolicy.verifiedClientID(
            for: token,
            authority: authority,
            now: now
        )
        XCTAssertEqual(inlineClientID, clientID)
        await assertAttestationFailure(.invalid) {
            _ = try await inlinePolicy.verifiedClientID(
                for: token,
                authority: self.authority,
                now: self.now.addingTimeInterval(1)
            )
        }
        await assertAttestationFailure(.invalid) {
            _ = try await inlinePolicy.verifiedClientID(
                for: token,
                authority: self.authority,
                now: self.now.addingTimeInterval(120)
            )
        }

        let remoteClientID = "https://remote.example/client-metadata.json"
        let jwksURI = "https://keys.example/client-jwks.json"
        let remoteMetadata = try attestationMetadata(
            clientID: remoteClientID,
            jwksURI: jwksURI
        )
        let remoteJWKS = try JSONEncoder().encode(
            OAuthJSONWebKeySet(keys: [jwk])
        )
        let remoteTransport = AttestationTransport(responseQueues: [
            remoteClientID: [try response(body: remoteMetadata, url: remoteClientID)],
            jwksURI: [try response(body: remoteJWKS, url: jwksURI)],
        ])
        let remotePolicy = try await attestationPolicy(
            database: database,
            transport: remoteTransport
        )
        let remoteToken = try clientAttestation(
            key: key,
            clientID: remoteClientID,
            audience: "\(authority)#atproto_space_host",
            now: now,
            jti: "remote-jwks-nonce"
        )
        let verifiedRemoteClientID = try await remotePolicy.verifiedClientID(
            for: remoteToken,
            authority: authority,
            now: now
        )
        XCTAssertEqual(verifiedRemoteClientID, remoteClientID)
        let remoteRequestCount = await remoteTransport.requestCount()
        XCTAssertEqual(remoteRequestCount, 2)
        try await database.close()
    }

    func testCachedKeyRotationForcesAtMostOneRevalidation() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let oldKey = try fixedPrivateKey()
        let newKey = P256.Signing.PrivateKey()
        let oldMetadata = try attestationMetadata(
            clientID: clientID,
            inlineKey: try attestationJWK(oldKey, keyID: "key-1")
        )
        let newMetadata = try attestationMetadata(
            clientID: clientID,
            inlineKey: try attestationJWK(newKey, keyID: "key-1")
        )
        let transport = AttestationTransport(responseQueues: [
            clientID: [
                try response(body: oldMetadata, url: clientID),
                try response(body: newMetadata, url: clientID),
            ],
        ])
        let policy = try await attestationPolicy(
            database: database,
            transport: transport
        )
        let primingToken = try clientAttestation(
            key: oldKey,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now,
            jti: "old-key-prime"
        )
        let primedClientID = try await policy.verifiedClientID(
            for: primingToken,
            authority: authority,
            now: now
        )
        XCTAssertEqual(primedClientID, clientID)
        let rotatedToken = try clientAttestation(
            key: newKey,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now,
            jti: "new-key-after-rotation"
        )
        let rotatedClientID = try await policy.verifiedClientID(
            for: rotatedToken,
            authority: authority,
            now: now
        )
        XCTAssertEqual(rotatedClientID, clientID)
        let rotationRequestCount = await transport.requestCount()
        XCTAssertEqual(rotationRequestCount, 2)
        try await database.close()
    }

    func testFixedTypeScriptShapedES256VectorVerifies() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let jwk = try OAuthJSONWebKey(
            x: "UVw9brnjlrkE0_7Kf1T9zQzB6Ze_N13KUVrQpsO0A18",
            y: "RTa-OlDzGPv5pUdZAqIhUCvvDVfgjFOyzApW8X2fk1Q",
            keyID: "key-1"
        )
        let metadata = try attestationMetadata(
            clientID: clientID,
            inlineKey: jwk
        )
        let transport = AttestationTransport(responseQueues: [
            clientID: [try response(body: metadata, url: clientID)],
        ])
        let policy = try await attestationPolicy(
            database: database,
            transport: transport
        )
        // Frozen JSON insertion order and IEEE-P1363 low-S signature match
        // proposal-0016's TypeScript `createClientAttestation` shape.
        let vector = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0cHJvdG8tY2xpZW50LWF0dGVzdGF0aW9uK2p3dCIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2NsaWVudC5leGFtcGxlL2NsaWVudC1tZXRhZGF0YS5qc29uIiwic3ViIjoiaHR0cHM6Ly9jbGllbnQuZXhhbXBsZS9jbGllbnQtbWV0YWRhdGEuanNvbiIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fc3BhY2VfaG9zdCIsImlhdCI6MTczODM2ODAwMCwiZXhwIjoxNzM4MzY4MDYwLCJqdGkiOiJ0eXBlc2NyaXB0LXNoYXBlZC1ub25jZS0wMDEifQ.LqTJF5x2Kh8XL-KRxpfJNh9d1CRjDa9KD8C0OFljQt5UtwsXUnu9dpsd2hOSzU4KrJHmX4a_JtB-QWOqlQpE4A"
        let verified = try await policy.verifiedClientID(
            for: vector,
            authority: authority,
            now: now
        )
        XCTAssertEqual(verified, clientID)
        try await database.close()
    }

    func testBadAndHighSSignaturesAndUnknownKeyAreInvalidAfterOneRefresh() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let key = try fixedPrivateKey()
        let metadata = try attestationMetadata(
            clientID: clientID,
            inlineKey: try attestationJWK(key, keyID: "key-1")
        )
        let transport = AttestationTransport(responseQueues: [
            clientID: (0 ..< 7).map { _ in
                try! response(body: metadata, url: clientID)
            },
        ])
        let policy = try await attestationPolicy(
            database: database,
            transport: transport
        )
        let valid = try clientAttestation(
            key: key,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now
        )
        let parts = valid.split(separator: ".").map(String.init)
        var badSignature = try XCTUnwrap(Data(base64URLEncoded: parts[2]))
        badSignature[0] ^= 0x01
        let badToken = "\(parts[0]).\(parts[1]).\(badSignature.base64URLEncodedString())"
        let highSToken = "\(parts[0]).\(parts[1]).\(attestationHighS(badSignature: try XCTUnwrap(Data(base64URLEncoded: parts[2]))).base64URLEncodedString())"
        let unknownKey = try clientAttestation(
            key: key,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now,
            jti: "unknown-key-nonce",
            keyID: "unknown-key"
        )
        for token in [badToken, highSToken, unknownKey] {
            await assertAttestationFailure(.invalid) {
                _ = try await policy.verifiedClientID(
                    for: token,
                    authority: self.authority,
                    now: self.now
                )
            }
        }
        // Initial load plus exactly one forced refresh for each failure.
        let requests = await transport.requestCount()
        XCTAssertEqual(requests, 4)
        try await database.close()
    }

    func testReplayIsSingleWinnerPersistsAndStoresOnlyDigest() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverKey = Data(repeating: 0x31, count: 32)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let replay = try DurableSpaceClientAttestationReplayStore(
            controlStore: database,
            serverKey: serverKey
        )
        let expiresAt = now.addingTimeInterval(120)
        let replayClientID = clientID
        let replayAudience = "\(authority)#atproto_space_host"
        let replayNow = now
        let results = try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0 ..< 16 {
                group.addTask {
                    try await replay.claim(
                        clientID: replayClientID,
                        audience: replayAudience,
                        jti: "never-persist-this-raw-jti",
                        expiresAt: expiresAt,
                        now: replayNow
                    )
                }
            }
            var values: [Bool] = []
            for try await value in group {
                values.append(value)
            }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedReplay = try DurableSpaceClientAttestationReplayStore(
            controlStore: reopened,
            serverKey: serverKey
        )
        let duplicateAfterReopen = try await reopenedReplay.claim(
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            jti: "never-persist-this-raw-jti",
            expiresAt: expiresAt,
            now: now.addingTimeInterval(1)
        )
        XCTAssertFalse(duplicateAfterReopen)
        let differentlyScopedClaim = try await reopenedReplay.claim(
            clientID: clientID,
            audience: "did:plc:zyxwvutsrqponmlkjihgfedc#atproto_space_host",
            jti: "never-persist-this-raw-jti",
            expiresAt: expiresAt,
            now: now.addingTimeInterval(1)
        )
        XCTAssertTrue(differentlyScopedClaim)
        let reclaimedAfterCleanup = try await reopenedReplay.claim(
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            jti: "never-persist-this-raw-jti",
            expiresAt: now.addingTimeInterval(240),
            now: now.addingTimeInterval(121)
        )
        XCTAssertTrue(reclaimedAfterCleanup)
        try await reopened.close()

        for file in attestationSQLiteFiles(in: root) {
            let bytes = try Data(contentsOf: file)
            XCTAssertNil(
                bytes.range(of: Data("never-persist-this-raw-jti".utf8)),
                file.lastPathComponent
            )
            XCTAssertNil(
                bytes.range(of: Data(clientID.utf8)),
                file.lastPathComponent
            )
        }
    }

    func testLocalhostIsRejectedWithoutIOAndFailuresAreOpaque() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let transport = AttestationTransport(responseQueues: [:])
        let policy = try await attestationPolicy(
            database: database,
            transport: transport,
            allowLocalhostDevelopment: true
        )
        let token = try clientAttestation(
            key: try fixedPrivateKey(),
            clientID: "http://localhost",
            audience: "\(authority)#atproto_space_host",
            now: now,
            jti: "localhost-must-never-fetch"
        )
        await assertAttestationFailure(.invalid) {
            _ = try await policy.verifiedClientID(
                for: token,
                authority: self.authority,
                now: self.now
            )
        }
        let localhostRequestCount = await transport.requestCount()
        XCTAssertEqual(localhostRequestCount, 0)
        XCTAssertEqual(
            SpaceCredentialClientAttestationFailure.invalid.description,
            "invalid client attestation"
        )
        XCTAssertEqual(
            SpaceCredentialClientAttestationFailure.unavailable.description,
            "client attestation service unavailable"
        )
        try await database.close()
    }

    func testTransportAndReplayStoreOutagesAreTypedUnavailable() async throws {
        let root = try attestationTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let key = try fixedPrivateKey()
        let token = try clientAttestation(
            key: key,
            clientID: clientID,
            audience: "\(authority)#atproto_space_host",
            now: now,
            jti: "outage-safe-description"
        )
        let unavailableTransport = AttestationTransport(responseQueues: [:])
        let unavailablePolicy = try await attestationPolicy(
            database: database,
            transport: unavailableTransport
        )
        await assertAttestationFailure(.unavailable) {
            _ = try await unavailablePolicy.verifiedClientID(
                for: token,
                authority: self.authority,
                now: self.now
            )
        }

        let metadata = try attestationMetadata(
            clientID: clientID,
            inlineKey: try attestationJWK(key, keyID: "key-1")
        )
        let transport = AttestationTransport(responseQueues: [
            clientID: [try response(body: metadata, url: clientID)],
        ])
        let address = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let loader = try OAuthClientMetadataLoader(
            fetcher: OAuthRemoteDocumentFetcher(
                policy: try OAuthRemoteFetchPolicy(),
                resolver: AttestationResolver(address: address),
                transport: transport
            ),
            controlStore: database,
            cacheLifetime: 60
        )
        let replayOutagePolicy = try DurableSpaceCredentialClientAttestationPolicy(
            metadataLoader: loader,
            replayStore: DurableSpaceClientAttestationReplayStore(
                controlStore: FailingAttestationReplayStore(),
                serverKey: Data(repeating: 0x31, count: 32)
            )
        )
        await assertAttestationFailure(.unavailable) {
            _ = try await replayOutagePolicy.verifiedClientID(
                for: token,
                authority: self.authority,
                now: self.now
            )
        }
        try await database.close()
    }

    private func invalidLocalTokens(
        key: P256.Signing.PrivateKey
    ) throws -> [String] {
        let audience = "\(authority)#atproto_space_host"
        let issuedAt = Int64(now.timeIntervalSince1970)
        let validClaims: [String: Any] = [
            "iss": clientID,
            "sub": clientID,
            "aud": audience,
            "iat": issuedAt,
            "exp": issuedAt + 60,
            "jti": "typescript-shaped-nonce-001",
        ]
        let validHeader: [String: Any] = [
            "alg": "ES256",
            "typ": PermissionedDataJWT.clientAttestationType,
            "kid": "key-1",
        ]
        var values: [String] = []
        for header in [
            ["alg": "none", "typ": PermissionedDataJWT.clientAttestationType, "kid": "key-1"],
            ["alg": "ES256K", "typ": PermissionedDataJWT.clientAttestationType, "kid": "key-1"],
            ["alg": "ES256", "typ": "JWT", "kid": "key-1"],
            ["alg": "ES256", "typ": PermissionedDataJWT.clientAttestationType, "kid": ""],
        ] {
            values.append(try rawClientAttestation(header: header, claims: validClaims, key: key))
        }
        values.append(try rawClientAttestation(
            headerJSON: #"{"alg":"ES256","typ":"atproto-client-attestation+jwt","kid":"key-1","kid":"key-2"}"#,
            claimsJSON: jsonString(validClaims),
            key: key
        ))
        values.append(try rawClientAttestation(
            headerJSON: #"{"alg":"ES256","typ":"atproto-client-attestation+jwt","kid":"key-1","jwk":{}}"#,
            claimsJSON: jsonString(validClaims),
            key: key
        ))
        values.append(try rawClientAttestation(
            headerJSON: #"{"alg":"ES256","typ":"atproto-client-attestation+jwt","kid":"key-1","crit":["b64"]}"#,
            claimsJSON: jsonString(validClaims),
            key: key
        ))
        values.append(try rawClientAttestation(
            headerJSON: #"{"alg":"ES256","typ":"atproto-client-attestation+jwt","kid":"key-1","b64":false}"#,
            claimsJSON: jsonString(validClaims),
            key: key
        ))
        values.append(try rawClientAttestation(
            headerJSON: jsonString(validHeader),
            claimsJSON: #"{"iss":"https://client.example/client-metadata.json","sub":"https://client.example/client-metadata.json","aud":"\#(audience)","iat":\#(issuedAt),"exp":\#(issuedAt + 60),"jti":"first","jti":"second"}"#,
            key: key
        ))

        var claims = validClaims
        claims["sub"] = "https://CLIENT.example/client-metadata.json"
        values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        claims = validClaims
        claims["aud"] = [audience]
        values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        for invalidIssuer in [
            "http://client.example/client-metadata.json",
            "https://client.example:443/client-metadata.json",
            "https://user@client.example/client-metadata.json",
            "https://client.example/client-metadata.json#fragment",
            "http://localhost",
        ] {
            claims = validClaims
            claims["iss"] = invalidIssuer
            claims["sub"] = invalidIssuer
            values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        }
        for invalidJTI in ["", "line\nbreak", "delete\u{7f}", String(repeating: "j", count: 513)] {
            claims = validClaims
            claims["jti"] = invalidJTI
            values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        }
        for (claim, value) in [
            ("iat", "1738368000"),
            ("exp", "1738368060"),
            ("jti", 17),
            ("iss", 17),
            ("aud", true),
        ] as [(String, Any)] {
            claims = validClaims
            claims[claim] = value
            values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        }
        for missing in ["iss", "sub", "aud", "iat", "exp", "jti"] {
            claims = validClaims
            claims.removeValue(forKey: missing)
            values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        }
        claims = validClaims
        claims["iat"] = issuedAt + 61
        values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        claims = validClaims
        claims["exp"] = issuedAt - 61
        values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        claims = validClaims
        claims["exp"] = issuedAt + 301
        values.append(try rawClientAttestation(header: validHeader, claims: claims, key: key))
        let valid = try rawClientAttestation(
            header: validHeader,
            claims: validClaims,
            key: key
        )
        let parts = valid.split(separator: ".").map(String.init)
        values.append("\(parts[0])=.\(parts[1]).\(parts[2])")
        values.append("\(parts[0]).\(parts[1]).AA")
        values.append("\(valid).extra")
        values.append(String(repeating: "A", count: 8 * 1_024 + 1))
        return values
    }
}

private func assertAttestationFailure(
    _ expected: SpaceCredentialClientAttestationFailure,
    _ operation: () async throws -> Void
) async {
    do {
        try await operation()
        XCTFail("expected client attestation failure")
    } catch {
        XCTAssertEqual(error as? SpaceCredentialClientAttestationFailure, expected)
    }
}

private func attestationPolicy(
    database: SQLiteControlDatabase,
    transport: AttestationTransport,
    allowLocalhostDevelopment: Bool = false
) async throws -> DurableSpaceCredentialClientAttestationPolicy {
    let address = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
    let fetcher = OAuthRemoteDocumentFetcher(
        policy: try OAuthRemoteFetchPolicy(
            allowLocalhostDevelopment: allowLocalhostDevelopment
        ),
        resolver: AttestationResolver(address: address),
        transport: transport
    )
    let loader = try OAuthClientMetadataLoader(
        fetcher: fetcher,
        controlStore: database,
        cacheLifetime: 60
    )
    return try DurableSpaceCredentialClientAttestationPolicy(
        metadataLoader: loader,
        replayStore: DurableSpaceClientAttestationReplayStore(
            controlStore: database,
            serverKey: Data(repeating: 0x31, count: 32)
        )
    )
}

private func attestationJWK(
    _ key: P256.Signing.PrivateKey,
    keyID: String
) throws -> OAuthJSONWebKey {
    let bytes = key.publicKey.x963Representation
    return try OAuthJSONWebKey(
        x: Data(bytes[1 ..< 33]).base64URLEncodedString(),
        y: Data(bytes[33 ..< 65]).base64URLEncodedString(),
        keyID: keyID
    )
}

private func attestationMetadata(
    clientID: String,
    inlineKey: OAuthJSONWebKey? = nil,
    jwksURI: String? = nil
) throws -> Data {
    let metadata = try OAuthClientMetadata(
        clientID: URL(string: clientID)!,
        redirectURIs: [URL(string: "https://client.example/callback")!],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["atproto"],
        tokenEndpointAuthMethod: .privateKeyJWT,
        tokenEndpointAuthSigningAlgorithm: "ES256",
        dpopBoundAccessTokens: true,
        jwks: try inlineKey.map { try OAuthJSONWebKeySet(keys: [$0]) },
        jwksURI: jwksURI.flatMap(URL.init(string:))
    )
    return try JSONEncoder().encode(metadata)
}

private func response(body: Data, url: String) throws -> OAuthRemoteHTTPResponse {
    let address = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
    return OAuthRemoteHTTPResponse(
        status: 200,
        headers: ["content-type": ["application/json"]],
        body: body,
        responseURL: URL(string: url)!,
        connectedPeerAddress: address
    )
}

private actor AttestationResolver: OAuthHostnameResolving {
    let address: OAuthIPAddress

    init(address: OAuthIPAddress) {
        self.address = address
    }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        [address]
    }
}

private actor AttestationTransport: OAuthRemoteTransport {
    private var responseQueues: [String: [OAuthRemoteHTTPResponse]]
    private var requests = 0

    init(responseQueues: [String: [OAuthRemoteHTTPResponse]]) {
        self.responseQueues = responseQueues
    }

    func get(
        url: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
        guard var queue = responseQueues[url.absoluteString],
              !queue.isEmpty else {
            throw SwanError.unavailable("sensitive destination sentinel")
        }
        let response = queue.removeFirst()
        responseQueues[url.absoluteString] = queue
        return response
    }

    func requestCount() -> Int {
        requests
    }
}

private struct FailingAttestationReplayStore:
    SpaceClientAttestationReplayStore
{
    func claimSpaceClientAttestation(
        digest _: Data,
        expiresAt _: Date,
        now _: Date
    ) async throws -> Bool {
        throw SwanError.unavailable("raw-client-and-token-sentinel")
    }
}

private func attestationTemporaryDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "SwanClientAttestation-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: true
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: root.path
    )
    return root
}

private func attestationSQLiteFiles(in root: URL) -> [URL] {
    let urls = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isRegularFileKey]
    )?.allObjects as? [URL] ?? []
    return urls.filter {
        (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
    }
}

private func fixedPrivateKey() throws -> P256.Signing.PrivateKey {
    try P256.Signing.PrivateKey(
        rawRepresentation: Data((1 ... 32).map(UInt8.init))
    )
}

private func clientAttestation(
    key: P256.Signing.PrivateKey,
    clientID: String,
    audience: String,
    now: Date,
    lifetime: Int64 = 60,
    jti: String = "typescript-shaped-nonce-001",
    keyID: String = "key-1"
) throws -> String {
    let issuedAt = Int64(now.timeIntervalSince1970)
    return try rawClientAttestation(
        header: [
            "alg": "ES256",
            "typ": PermissionedDataJWT.clientAttestationType,
            "kid": keyID,
        ],
        claims: [
            "iss": clientID,
            "sub": clientID,
            "aud": audience,
            "iat": issuedAt,
            "exp": issuedAt + lifetime,
            "jti": jti,
        ],
        key: key
    )
}

private func rawClientAttestation(
    header: [String: Any],
    claims: [String: Any],
    key: P256.Signing.PrivateKey
) throws -> String {
    try rawClientAttestation(
        headerJSON: jsonString(header),
        claimsJSON: jsonString(claims),
        key: key
    )
}

private func rawClientAttestation(
    headerJSON: String,
    claimsJSON: String,
    key: P256.Signing.PrivateKey
) throws -> String {
    let header = Data(headerJSON.utf8).base64URLEncodedString()
    let payload = Data(claimsJSON.utf8).base64URLEncodedString()
    let signingInput = "\(header).\(payload)"
    let signature = try P256WireSignature.sign(
        Data(signingInput.utf8),
        using: key
    ).base64URLEncodedString()
    return "\(signingInput).\(signature)"
}

private func jsonString(_ object: Any) -> String {
    String(
        data: try! JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ),
        encoding: .utf8
    )!
}

private func attestationHighS(badSignature signature: Data) -> Data {
    let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]
    var highS = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    let lowS = Array(signature.suffix(32))
    for index in stride(from: 31, through: 0, by: -1) {
        var value = Int(order[index]) - Int(lowS[index]) - borrow
        if value < 0 {
            value += 256
            borrow = 1
        } else {
            borrow = 0
        }
        highS[index] = UInt8(value)
    }
    return Data(signature.prefix(32) + highS)
}
