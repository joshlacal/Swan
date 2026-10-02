import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import PetrelCrypto
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SpaceCredentialHTTPTests: XCTestCase, @unchecked Sendable {
    static let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    static let member = "did:plc:bcdefghijklmnopqrstuvwxy"
    static let outsider = "did:plc:cdefghijklmnopqrstuvwxyz"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let credentialPath = "/xrpc/com.atproto.space.getSpaceCredential"
    private static let getPath = "/xrpc/com.atproto.space.getRecord"
    private static let listPath = "/xrpc/com.atproto.space.listRecords"

    func testCredentialRenewalReportsSpaceDeletedOnlyAfterValidDelegationAndProof() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.deleted-renewal")
            )
            let missingSpace = try SpaceURI(
                authority: Self.authority,
                spaceType: fixture.publicSpace.spaceType,
                skey: "never-created"
            )
            try await app.test(.router) { client in
                let initialDelegation = try self.delegation(
                    fixture, user: Self.member, space: fixture.publicSpace
                )
                try await client.execute(
                    uri: Self.credentialPath, method: .post,
                    headers: try self.exchangeHeaders(initialDelegation),
                    body: self.exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNotNil(try self.jsonObject(response.body)["credential"] as? String)
                }

                try await fixture.directory.deleteSimpleSpace(
                    fixture.publicSpace,
                    authorization: .accountOAuthForTesting(subject: Self.authority, scopes: ["atproto"])
                )

                for (space, expectedStatus, expectedError) in [
                    (fixture.publicSpace, HTTPResponse.Status.badRequest, "SpaceDeleted"),
                    (missingSpace, HTTPResponse.Status.notFound, "SpaceNotFound"),
                ] {
                    let renewalDelegation = try self.delegation(fixture, user: Self.member, space: space)
                    try await client.execute(
                        uri: Self.credentialPath, method: .post,
                        headers: try self.exchangeHeaders(renewalDelegation),
                        body: self.exchangeBody(space: space)
                    ) { response in
                        XCTAssertEqual(response.status, expectedStatus)
                        XCTAssertEqual(try self.errorCode(response.body), expectedError)
                        XCTAssertNil(try self.jsonObject(response.body)["credential"])
                        self.assertNoStore(response)
                    }
                }

                let validDelegation = try self.delegation(
                    fixture, user: Self.member, space: fixture.publicSpace
                )
                var missingSignature = try self.exchangeHeaders(validDelegation)
                missingSignature[HTTPField.Name(SpaceHTTPSignature.signatureFieldName)!] = nil
                try await client.execute(
                    uri: Self.credentialPath, method: .post, headers: missingSignature,
                    body: self.exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "BadSpaceSignature")
                }
                try await client.execute(
                    uri: Self.credentialPath, method: .post,
                    headers: try self.exchangeHeaders("invalid-delegation"),
                    body: self.exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidDelegationToken")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testPublicAndMemberDelegationExchangeIssueCredentialsForCrossRepositoryReads() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.reads")
            )
            let publicDelegation = try delegation(
                fixture,
                user: Self.outsider,
                space: fixture.publicSpace
            )
            let caseInsensitivePublicHeaders = try exchangeHeaders(
                publicDelegation,
                authorizationScheme: "bearer"
            )
            let memberDelegation = try delegation(
                fixture,
                user: Self.member,
                space: fixture.memberSpace
            )

            let publicCredential = StringBox()
            let memberCredential = StringBox()
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: caseInsensitivePublicHeaders,
                    body: exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    XCTAssertEqual(Set(body.keys), ["credential"])
                    publicCredential.set(try XCTUnwrap(body["credential"] as? String))
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: exchangeHeaders(memberDelegation),
                    body: exchangeBody(space: fixture.memberSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    memberCredential.set(try XCTUnwrap(self.jsonObject(response.body)["credential"] as? String))
                }

                let publicToken = try XCTUnwrap(publicCredential.value)
                let memberToken = try XCTUnwrap(memberCredential.value)
                let publicReadHeaders = try credentialHeaders(publicToken)
                let memberReadHeaders = try credentialHeaders(memberToken)
                try await client.execute(
                    uri: self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public"),
                    method: .get,
                    headers: publicReadHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    XCTAssertEqual(
                        (try self.jsonObject(response.body))["uri"] as? String,
                        fixture.publicRecord.rawValue
                    )
                }
                try await client.execute(
                    uri: self.listURI(space: fixture.memberSpace, repo: Self.member),
                    method: .get,
                    headers: memberReadHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let records = try XCTUnwrap(
                        (try self.jsonObject(response.body))["records"] as? [[String: Any]]
                    )
                    XCTAssertEqual(records.count, 1)
                    XCTAssertEqual(records[0]["rkey"] as? String, "member")
                }
            }
            let inspection = try PermissionedDataJWT.inspectSpaceCredential(
                try XCTUnwrap(publicCredential.value)
            )
            XCTAssertEqual(inspection.claims.iss, Self.authority)
            XCTAssertEqual(inspection.claims.sub, fixture.publicSpace.rawValue)
            XCTAssertEqual(inspection.header.kid, "#atproto")
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testCredentialExchangeRejectsPolicyAndAttestationWithoutCredentialState() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.policy")
            )
            let outsiderMember = try delegation(fixture, user: Self.outsider, space: fixture.memberSpace)
            let outsiderAllow = try delegation(fixture, user: Self.outsider, space: fixture.allowListSpace)
            let outsiderAllowWithAttestation = try delegation(
                fixture,
                user: Self.outsider,
                space: fixture.allowListSpace
            )
            let memberManaged = try delegation(fixture, user: Self.member, space: fixture.managingSpace)
            try await app.test(.router) { client in
                for (delegation, space) in [
                    (outsiderMember, fixture.memberSpace),
                    (memberManaged, fixture.managingSpace),
                ] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(delegation),
                        body: self.exchangeBody(space: space)
                    ) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "NotAuthorized")
                    }
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(outsiderAllow),
                    body: self.exchangeBody(space: fixture.allowListSpace)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "AppNotAuthorized")
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(outsiderAllowWithAttestation),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: "not-a-verified-attestation"
                    )
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidClientAttestation")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testUnavailableAttestationPolicyMapsSanitizedServiceUnavailable() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(
                fixture,
                clientAttestationPolicy: FailingClientAttestationPolicy()
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.attestation-unavailable")
            )
            let delegation = try delegation(
                fixture,
                user: Self.outsider,
                space: fixture.publicSpace
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(delegation),
                    body: self.exchangeBody(
                        space: fixture.publicSpace,
                        clientAttestation: "opaque-sensitive-attestation"
                    )
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "temporarily_unavailable"
                    )
                    XCTAssertFalse(
                        String(buffer: response.body)
                            .contains("opaque-sensitive-attestation")
                    )
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testSignedInlineAttestationRunsAfterDelegationAndPersistsReplay() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let clientID = "https://reader.example/client-metadata.json"
            let clientKey = try P256.Signing.PrivateKey(
                rawRepresentation: Data((1 ... 32).map(UInt8.init))
            )
            let transport = CredentialAttestationTransport(
                response: try credentialAttestationResponse(
                    body: credentialAttestationMetadata(
                        clientID: clientID,
                        key: clientKey
                    ),
                    url: clientID
                )
            )
            let policy = try credentialAttestationPolicy(
                control: fixture.control,
                transport: transport
            )
            let app = try makeServer(
                fixture,
                clientAttestationPolicy: policy
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.attestation-live")
            )
            let now = Date()
            let attestation = try signedClientAttestation(
                key: clientKey,
                clientID: clientID,
                authority: Self.authority,
                now: now,
                jti: "http-inline-attestation-1"
            )
            let wrongSpaceDelegation = try delegation(
                fixture,
                user: Self.outsider,
                space: fixture.publicSpace
            )

            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders("malformed-delegation"),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: attestation
                    )
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidDelegationToken"
                    )
                }
                let malformedRequestCount = await transport.requestCount()
                XCTAssertEqual(malformedRequestCount, 0)

                let consumedWithoutAttestation = try self.delegation(
                    fixture,
                    user: Self.outsider,
                    space: fixture.allowListSpace
                )
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(consumedWithoutAttestation),
                    body: self.exchangeBody(space: fixture.allowListSpace)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "AppNotAuthorized"
                    )
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(consumedWithoutAttestation),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: attestation
                    )
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidDelegationToken"
                    )
                }
                let replayedDelegationRequestCount =
                    await transport.requestCount()
                XCTAssertEqual(replayedDelegationRequestCount, 0)

                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(wrongSpaceDelegation),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: attestation
                    )
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidDelegationToken"
                    )
                }
                let rejectedRequestCount = await transport.requestCount()
                XCTAssertEqual(rejectedRequestCount, 0)

                let acceptedDelegation = try self.delegation(
                    fixture,
                    user: Self.outsider,
                    space: fixture.allowListSpace
                )
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(acceptedDelegation),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: attestation
                    )
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNotNil(
                        try self.jsonObject(response.body)["credential"] as? String
                    )
                }
                let acceptedRequestCount = await transport.requestCount()
                XCTAssertEqual(acceptedRequestCount, 1)

                let replayDelegation = try self.delegation(
                    fixture,
                    user: Self.outsider,
                    space: fixture.allowListSpace
                )
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(replayDelegation),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: attestation
                    )
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidClientAttestation"
                    )
                }

                let consumedDelegation = try self.delegation(
                    fixture,
                    user: Self.outsider,
                    space: fixture.allowListSpace
                )
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(consumedDelegation),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: "malformed"
                    )
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidClientAttestation"
                    )
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(consumedDelegation),
                    body: self.exchangeBody(space: fixture.allowListSpace)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidDelegationToken"
                    )
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testRemoteJWKSAndTypedRealPolicyFailuresAtHTTPBoundary() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let clientID = "https://reader.example/client-metadata.json"
            let jwksURI = "https://keys.example/remote-jwks.json"
            let clientKey = P256.Signing.PrivateKey()
            let metadata = try credentialAttestationMetadata(
                clientID: clientID,
                jwksURI: jwksURI
            )
            let keySet = try JSONEncoder().encode(
                OAuthJSONWebKeySet(keys: [
                    try credentialAttestationJWK(
                        key: clientKey,
                        keyID: "key-1"
                    ),
                ])
            )
            let transport = CredentialAttestationTransport(responseQueues: [
                clientID: [
                    try credentialAttestationResponse(body: metadata, url: clientID),
                ],
                jwksURI: [
                    try credentialAttestationResponse(body: keySet, url: jwksURI),
                ],
            ])
            let app = try makeServer(
                fixture,
                clientAttestationPolicy: try credentialAttestationPolicy(
                    control: fixture.control,
                    transport: transport
                )
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.remote-jwks")
            )
            let attestation = try signedClientAttestation(
                key: clientKey,
                clientID: clientID,
                authority: Self.authority,
                now: Date(),
                jti: "remote-jwks-http-success"
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(
                        try self.delegation(
                            fixture,
                            user: Self.outsider,
                            space: fixture.allowListSpace
                        )
                    ),
                    body: self.exchangeBody(
                        space: fixture.allowListSpace,
                        clientAttestation: attestation
                    )
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNotNil(
                        try self.jsonObject(response.body)["credential"] as? String
                    )
                }
            }
            let requests = await transport.requestCount()
            XCTAssertEqual(requests, 2)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testBadSignatureUnknownKeyAndRealOutagesMapExactErrors() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let clientID = "https://reader.example/client-metadata.json"
            let publishedKey = P256.Signing.PrivateKey()
            let metadata = try credentialAttestationMetadata(
                clientID: clientID,
                key: publishedKey
            )
            let signatureTransport = CredentialAttestationTransport(
                responseQueues: [
                    clientID: [
                        try credentialAttestationResponse(body: metadata, url: clientID),
                        try credentialAttestationResponse(body: metadata, url: clientID),
                        try credentialAttestationResponse(body: metadata, url: clientID),
                    ],
                ]
            )
            let signatureApp = try makeServer(
                fixture,
                clientAttestationPolicy: try credentialAttestationPolicy(
                    control: fixture.control,
                    transport: signatureTransport
                )
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.bad-attestation")
            )
            let badSignature = try signedClientAttestation(
                key: P256.Signing.PrivateKey(),
                clientID: clientID,
                authority: Self.authority,
                now: Date(),
                jti: "bad-signature-http"
            )
            let unknownKey = try signedClientAttestation(
                key: publishedKey,
                clientID: clientID,
                authority: Self.authority,
                now: Date(),
                jti: "unknown-key-http",
                keyID: "unknown-key"
            )
            try await signatureApp.test(.router) { client in
                for token in [badSignature, unknownKey] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(
                            try self.delegation(
                                fixture,
                                user: Self.outsider,
                                space: fixture.allowListSpace
                            )
                        ),
                        body: self.exchangeBody(
                            space: fixture.allowListSpace,
                            clientAttestation: token
                        )
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        XCTAssertEqual(
                            try self.errorCode(response.body),
                            "InvalidClientAttestation"
                        )
                    }
                }
            }

            let metadataOutageTransport = CredentialAttestationTransport(
                failure: SwanError.unavailable("private metadata outage sentinel")
            )
            let metadataOutageApp = try makeServer(
                fixture,
                clientAttestationPolicy: try credentialAttestationPolicy(
                    control: fixture.control,
                    transport: metadataOutageTransport
                )
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.metadata-outage")
            )
            let uncachedClientID =
                "https://outage-reader.example/client-metadata.json"
            let outageToken = try signedClientAttestation(
                key: publishedKey,
                clientID: uncachedClientID,
                authority: Self.authority,
                now: Date(),
                jti: "metadata-outage-http"
            )
            try await metadataOutageApp.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(
                        try self.delegation(
                            fixture,
                            user: Self.outsider,
                            space: fixture.publicSpace
                        )
                    ),
                    body: self.exchangeBody(
                        space: fixture.publicSpace,
                        clientAttestation: outageToken
                    )
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "temporarily_unavailable"
                    )
                    XCTAssertFalse(
                        String(buffer: response.body).contains("outage")
                    )
                }
            }

            let replayTransport = CredentialAttestationTransport(responseQueues: [
                uncachedClientID: [
                    try credentialAttestationResponse(
                        body: credentialAttestationMetadata(
                            clientID: uncachedClientID,
                            key: publishedKey
                        ),
                        url: uncachedClientID
                    ),
                ],
            ])
            let replayOutageApp = try makeServer(
                fixture,
                clientAttestationPolicy: try credentialAttestationPolicy(
                    control: fixture.control,
                    transport: replayTransport,
                    replayControlStore:
                        FailingCredentialAttestationReplayStore()
                )
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.replay-outage")
            )
            let replayOutageToken = try signedClientAttestation(
                key: publishedKey,
                clientID: uncachedClientID,
                authority: Self.authority,
                now: Date(),
                jti: "replay-outage-http"
            )
            try await replayOutageApp.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(
                        try self.delegation(
                            fixture,
                            user: Self.outsider,
                            space: fixture.publicSpace
                        )
                    ),
                    body: self.exchangeBody(
                        space: fixture.publicSpace,
                        clientAttestation: replayOutageToken
                    )
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "temporarily_unavailable"
                    )
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testLocalhostAttestationRejectsWithoutTransportIO() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let transport = CredentialAttestationTransport(responseQueues: [:])
            let app = try makeServer(
                fixture,
                clientAttestationPolicy: try credentialAttestationPolicy(
                    control: fixture.control,
                    transport: transport,
                    allowLocalhostDevelopment: true
                )
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.localhost")
            )
            let token = try signedClientAttestation(
                key: P256.Signing.PrivateKey(),
                clientID: "http://localhost",
                authority: Self.authority,
                now: Date(),
                jti: "localhost-http-zero-io"
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(
                        try self.delegation(
                            fixture,
                            user: Self.outsider,
                            space: fixture.publicSpace
                        )
                    ),
                    body: self.exchangeBody(
                        space: fixture.publicSpace,
                        clientAttestation: token
                    )
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidClientAttestation"
                    )
                }
            }
            let requests = await transport.requestCount()
            XCTAssertEqual(requests, 0)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testAttestationReplaySurvivesControlAndServerReopen() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        let clientID = "https://reader.example/client-metadata.json"
        let clientKey = P256.Signing.PrivateKey()
        let token = try signedClientAttestation(
            key: clientKey,
            clientID: clientID,
            authority: Self.authority,
            now: Date(),
            jti: "restart-persistent-http-replay"
        )
        let initialTransport = CredentialAttestationTransport(
            response: try credentialAttestationResponse(
                body: credentialAttestationMetadata(
                    clientID: clientID,
                    key: clientKey
                ),
                url: clientID
            )
        )
        let initialApp = try makeServer(
            fixture,
            clientAttestationPolicy: try credentialAttestationPolicy(
                control: fixture.control,
                transport: initialTransport
            )
        ).buildApplication(
            logger: Logger(label: "SpaceCredentialHTTPTests.replay-initial")
        )
        try await initialApp.test(.router) { client in
            try await client.execute(
                uri: Self.credentialPath,
                method: .post,
                headers: self.exchangeHeaders(
                    try self.delegation(
                        fixture,
                        user: Self.outsider,
                        space: fixture.allowListSpace
                    )
                ),
                body: self.exchangeBody(
                    space: fixture.allowListSpace,
                    clientAttestation: token
                )
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        try await fixture.close()

        let reopened = try await fixture.reopened()
        do {
            let postRestartTransport =
                CredentialAttestationTransport(responseQueues: [:])
            let reopenedApp = try makeServer(
                reopened,
                clientAttestationPolicy: try credentialAttestationPolicy(
                    control: reopened.control,
                    transport: postRestartTransport
                )
            ).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.replay-reopen")
            )
            try await reopenedApp.test(.router) { client in
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(
                        try self.delegation(
                            reopened,
                            user: Self.outsider,
                            space: reopened.allowListSpace
                        )
                    ),
                    body: self.exchangeBody(
                        space: reopened.allowListSpace,
                        clientAttestation: token
                    )
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(
                        try self.errorCode(response.body),
                        "InvalidClientAttestation"
                    )
                }
            }
            let requests = await postRestartTransport.requestCount()
            XCTAssertEqual(requests, 0)
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    func testFailedExchangePersistsOnlyValidatedPublicMetadata() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        let clientID =
            "https://reader.example/client-metadata.json"
        let publishedKey = P256.Signing.PrivateKey()
        let privateFailureKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data((33 ... 64).map(UInt8.init))
        )
        let jti = "raw-jti-must-not-persist-http"
        let attestation = try signedClientAttestation(
            key: privateFailureKey,
            clientID: clientID,
            authority: Self.authority,
            now: Date(),
            jti: jti
        )
        let metadata = try credentialAttestationMetadata(
            clientID: clientID,
            key: publishedKey
        )
        let transport = CredentialAttestationTransport(responseQueues: [
            clientID: [
                try credentialAttestationResponse(body: metadata, url: clientID),
                try credentialAttestationResponse(body: metadata, url: clientID),
            ],
        ])
        let app = try makeServer(
            fixture,
            clientAttestationPolicy: try credentialAttestationPolicy(
                control: fixture.control,
                transport: transport
            )
        ).buildApplication(
            logger: Logger(label: "SpaceCredentialHTTPTests.persistence-boundary")
        )
        let delegation = try self.delegation(
            fixture,
            user: Self.outsider,
            space: fixture.allowListSpace
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: Self.credentialPath,
                method: .post,
                headers: self.exchangeHeaders(delegation),
                body: self.exchangeBody(
                    space: fixture.allowListSpace,
                    clientAttestation: attestation
                )
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                self.assertNoStore(response)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "InvalidClientAttestation"
                )
                let rendered = String(buffer: response.body)
                XCTAssertFalse(rendered.contains(jti))
                XCTAssertFalse(rendered.contains(clientID))
            }
        }
        let credentialHeader = try PermissionedDataJWT.createSpaceCredential(
            issuer: Self.authority,
            space: fixture.allowListSpace,
            key: fixture.authorityKey,
            confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
        ).split(separator: ".", maxSplits: 1).first.map(String.init)!
        let publicJWK = try credentialAttestationJWK(
            key: publishedKey,
            keyID: "key-1"
        )
        let liveFiles = credentialSQLiteFiles(in: fixture.root)
        let liveNames = Set(liveFiles.map(\.lastPathComponent))
        XCTAssertTrue(liveNames.contains("control.sqlite"))
        XCTAssertTrue(liveNames.contains("control.sqlite-wal"))
        XCTAssertTrue(liveNames.contains("control.sqlite-shm"))
        let liveDatabaseBytes = try liveFiles.map { try Data(contentsOf: $0) }
        try await fixture.close()

        let databaseBytes =
            liveDatabaseBytes + (try credentialSQLiteBytes(in: fixture.root))
        XCTAssertTrue(
            databaseBytes.contains { $0.range(of: Data(clientID.utf8)) != nil }
        )
        XCTAssertTrue(
            databaseBytes.contains {
                $0.range(of: Data(publicJWK.x.utf8)) != nil
            }
        )
        for bytes in databaseBytes {
            for prohibited in [
                Data(attestation.utf8),
                Data(jti.utf8),
                Data(delegation.utf8),
                privateFailureKey.rawRepresentation,
                Data(credentialHeader.utf8),
            ] {
                XCTAssertNil(bytes.range(of: prohibited))
            }
        }
    }

    func testDelegationValidationRejectsWrongIssuerKeyAudienceSpaceExpiryAndTampering() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.delegation")
            )
            let valid = try delegation(fixture, user: Self.member, space: fixture.publicSpace)
            let otherSpace = try SpaceURI(
                authority: Self.authority,
                spaceType: fixture.publicSpace.spaceType,
                skey: "other-space"
            )
            let wrongSpace = try delegation(fixture, user: Self.member, space: otherSpace)
            let wrongAudience = try signedDelegation(
                issuer: Self.member,
                audience: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey
            )
            let wrongKey = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: P256.Signing.PrivateKey()
            )
            let unknownIssuer = try signedDelegation(
                issuer: "did:plc:defghijklmnopqrstuvwxyz2",
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey
            )
            let excessiveLifetime = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                lifetime: 61
            )
            let futureIssued = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                issuedAt: Int64(Date().timeIntervalSince1970) + 120
            )
            let opaqueJTI = try signedDelegation(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                jti: "ts-nonce_01"
            )
            let expired = try PermissionedDataJWT.createDelegationToken(
                issuer: Self.member,
                audience: "\(Self.authority)#atproto_space_host",
                space: fixture.publicSpace,
                key: fixture.memberKey,
                now: Date(timeIntervalSinceNow: -180)
            )
            let tampered = tamperedToken(valid, offsetFromEnd: 5)

            try await app.test(.router) { client in
                for delegation in [
                    wrongSpace, wrongAudience, wrongKey, unknownIssuer,
                    excessiveLifetime, futureIssued, expired,
                    tampered,
                ] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(delegation),
                        body: self.exchangeBody(space: fixture.publicSpace)
                    ) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidDelegationToken")
                    }
                }

                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(opaqueJTI),
                    body: self.exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNotNil(try self.jsonObject(response.body)["credential"] as? String)
                }

                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(valid),
                    body: self.exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNotNil(try self.jsonObject(response.body)["credential"] as? String)
                }
                try await client.execute(
                    uri: Self.credentialPath,
                    method: .post,
                    headers: self.exchangeHeaders(valid),
                    body: self.exchangeBody(space: fixture.publicSpace)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidDelegationToken")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testCredentialReadRejectsWrongSpaceExpiredTamperingAndWrites() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.credential-negative")
            )
            let credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: Self.authority,
                space: fixture.publicSpace,
                key: fixture.authorityKey,
                confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
            )
            let expired = try PermissionedDataJWT.createSpaceCredential(
                issuer: Self.authority,
                space: fixture.publicSpace,
                key: fixture.authorityKey,
                confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID,
                now: Date(timeIntervalSinceNow: -7_300),
                lifetime: 60
            )
            let tampered = tamperedToken(credential, offsetFromEnd: 6)

            try await app.test(.router) { client in
                for (token, uri) in [
                    (credential, self.getURI(space: fixture.memberSpace, repo: Self.member, rkey: "member")),
                    (expired, self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public")),
                    (tampered, self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public")),
                ] {
                    try await client.execute(uri: uri, method: .get, headers: self.credentialHeaders(token)) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                        XCTAssertNil(response.headers[HTTPField.Name("DPoP-Nonce")!])
                    }
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.createRecord",
                    method: .post,
                    headers: self.credentialHeaders(credential, contentType: true),
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.publicSpace.rawValue)\",\"repo\":\"\(Self.member)\",\"collection\":\"app.bsky.feed.post\",\"rkey\":\"blocked\",\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"blocked\"}}")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.getDelegationToken?space=\(self.percentEncode(fixture.publicSpace.rawValue))",
                    method: .get,
                    headers: self.credentialHeaders(credential)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_data_pending")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testExchangeRejectsDuplicateAndOversizeBodiesAndReadNeverOpensMissingAccountDatabase() async throws {
        let fixture = try await Fixture.make()
        defer { fixture.cleanup() }
        do {
            let app = try makeServer(fixture).buildApplication(
                logger: Logger(label: "SpaceCredentialHTTPTests.bounds")
            )
            let delegation = try delegation(fixture, user: Self.outsider, space: fixture.publicSpace)
            let credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: Self.authority,
                space: fixture.publicSpace,
                key: fixture.authorityKey,
                confirmationKeyID: try SpaceCredentialSignatureTestSupport.keyID
            )
            let duplicate = "{\"space\":\"\(fixture.publicSpace.rawValue)\",\"space\":\"\(fixture.publicSpace.rawValue)\"}"
            let oversized = "{\"space\":\"\(String(repeating: "a", count: SwanSpaceCredentialHTTP.maximumJSONBytes))\"}"
            try await app.test(.router) { client in
                for body in [duplicate, oversized] {
                    try await client.execute(
                        uri: Self.credentialPath,
                        method: .post,
                        headers: self.exchangeHeaders(delegation),
                        body: ByteBuffer(string: body)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        self.assertNoStore(response)
                        XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    }
                }
            }

            let memberDatabase = SQLiteLayout.accountDatabase(
                in: fixture.root,
                did: Self.member
            )
            try FileManager.default.removeItem(at: memberDatabase)
            try await app.test(.router) { client in
                try await client.execute(
                    uri: self.getURI(space: fixture.publicSpace, repo: Self.member, rkey: "public"),
                    method: .get,
                    headers: self.credentialHeaders(credential)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "temporarily_unavailable")
                }
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: memberDatabase.path))
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    private func makeServer(
        _ fixture: Fixture,
        clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy =
            UnavailableSpaceCredentialClientAttestationPolicy()
    ) throws -> SwanHTTPServer {
        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        )
        let signing = StaticSigningKeyResolver(
            authority: Self.authority,
            key: fixture.authorityKey
        )
        let delegationKeys = try PinnedSpaceDelegationPublicKeyResolver(pins: [
            try .init(issuer: Self.member, generation: 1, publicKey: fixture.memberKey.publicKey),
            try .init(issuer: Self.outsider, generation: 1, publicKey: fixture.outsiderKey.publicKey),
        ])
        let credentialKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: Self.authority, generation: 1, publicKey: fixture.authorityKey.publicKey),
        ])
        return SwanHTTPServer(
            profile: profile,
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: fixture.directory,
            accountControlStore: fixture.control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: signing,
                delegationPublicKeys: delegationKeys,
                credentialPublicKeys: credentialKeys,
                clientAttestationPolicy: clientAttestationPolicy
            )
        )
    }

    private func delegation(
        _ fixture: Fixture,
        user: String,
        space: SpaceURI
    ) throws -> String {
        let key: P256.Signing.PrivateKey = user == Self.member
            ? fixture.memberKey
            : fixture.outsiderKey
        return try PermissionedDataJWT.createDelegationToken(
            issuer: user,
            audience: "\(space.authority)#atproto_space_host",
            space: space,
            key: key
        )
    }

    private func signedDelegation(
        issuer: String,
        audience: String,
        space: SpaceURI,
        key: P256.Signing.PrivateKey,
        issuedAt: Int64? = nil,
        lifetime: Int64 = 60,
        jti: String = UUID().uuidString
    ) throws -> String {
        struct Header: Encodable {
            let alg = "ES256"
            let typ = PermissionedDataJWT.delegationType
            let kid = PermissionedDataJWT.delegationKeyID
        }
        struct Claims: Encodable {
            let iss: String
            let aud: String
            let sub: String
            let iat: Int64
            let exp: Int64
            let jti: String
        }
        let now = issuedAt ?? Int64(Date().timeIntervalSince1970)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header()).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            iss: issuer,
            aud: audience,
            sub: space.rawValue,
            iat: now,
            exp: now + lifetime,
            jti: jti
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(
            Data(input.utf8),
            using: key
        ).base64URLEncodedString()
        return "\(input).\(signature)"
    }

    private func exchangeHeaders(
        _ token: String,
        authorizationScheme: String = "Bearer"
    ) throws -> HTTPFields {
        try SpaceCredentialSignatureTestSupport.exchangeHeaders(
            token: token,
            authorizationScheme: authorizationScheme
        )
    }

    /// Every credential read here targets the member's repo, so the signed
    /// audience defaults to that repo owner's DID.
    private func credentialHeaders(
        _ token: String,
        audience: String = SpaceCredentialHTTPTests.member,
        contentType: Bool = false
    ) throws -> HTTPFields {
        var headers = try SpaceCredentialSignatureTestSupport.headers(token: token, audience: audience)
        if contentType { headers[.contentType] = "application/json" }
        return headers
    }

    private func exchangeBody(
        space: SpaceURI,
        clientAttestation: String? = nil
    ) -> ByteBuffer {
        let fields = [
            "\"space\":\"\(space.rawValue)\"",
            clientAttestation.map { "\"clientAttestation\":\"\($0)\"" },
        ].compactMap { $0 }
        return ByteBuffer(string: "{\(fields.joined(separator: ","))}")
    }

    private func getURI(space: SpaceURI, repo: String, rkey: String) -> String {
        "\(Self.getPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)&collection=app.bsky.feed.post&rkey=\(rkey)"
    }

    private func listURI(space: SpaceURI, repo: String) -> String {
        "\(Self.listPath)?space=\(percentEncode(space.rawValue))&repo=\(repo)"
    }

    private func registration(did: String, handle: String) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func recordCBOR(_ text: String) -> Data {
        Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, UInt8(0x60 + text.utf8.count)]) + Data(text.utf8)
    }

    private func jsonObject(_ body: ByteBuffer) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
    }

    private func errorCode(_ body: ByteBuffer) throws -> String {
        try XCTUnwrap(jsonObject(body)["error"] as? String)
    }

    private func assertNoStore(
        _ response: TestResponse,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
    }

    private func percentEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private func tamperedToken(_ token: String, offsetFromEnd: Int) -> String {
        var result = token
        let index = result.index(result.endIndex, offsetBy: -offsetFromEnd)
        result.replaceSubrange(index ... index, with: result[index] == "A" ? "B" : "A")
        return result
    }
}

private struct FailingClientAttestationPolicy:
    SpaceCredentialClientAttestationPolicy
{
    func verifiedClientID(
        for _: String?,
        authority _: String,
        now _: Date
    ) async throws -> String? {
        throw SpaceCredentialClientAttestationFailure.unavailable
    }
}

private func credentialAttestationPolicy(
    control: SQLiteControlDatabase,
    transport: CredentialAttestationTransport,
    replayControlStore: (any SpaceClientAttestationReplayStore)? = nil,
    allowLocalhostDevelopment: Bool = false
) throws -> DurableSpaceCredentialClientAttestationPolicy {
    let address = OAuthIPAddress(literal: "93.184.216.34")!
    let fetcher = OAuthRemoteDocumentFetcher(
        policy: try OAuthRemoteFetchPolicy(
            allowLocalhostDevelopment: allowLocalhostDevelopment
        ),
        resolver: CredentialAttestationResolver(address: address),
        transport: transport
    )
    return try DurableSpaceCredentialClientAttestationPolicy(
        metadataLoader: OAuthClientMetadataLoader(
            fetcher: fetcher,
            controlStore: control
        ),
        replayStore: DurableSpaceClientAttestationReplayStore(
            controlStore: replayControlStore ?? control,
            serverKey: Data(repeating: 0xD4, count: 32)
        )
    )
}

private func credentialAttestationMetadata(
    clientID: String,
    key: P256.Signing.PrivateKey? = nil,
    jwksURI: String? = nil
) throws -> Data {
    let jwk: OAuthJSONWebKey?
    if let key {
        jwk = try credentialAttestationJWK(key: key, keyID: "key-1")
    } else {
        jwk = nil
    }
    return try JSONEncoder().encode(
        OAuthClientMetadata(
            clientID: URL(string: clientID)!,
            redirectURIs: [URL(string: "https://reader.example/callback")!],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: ["atproto"],
            tokenEndpointAuthMethod: .privateKeyJWT,
            tokenEndpointAuthSigningAlgorithm: "ES256",
            dpopBoundAccessTokens: true,
            jwks: try jwk.map { try OAuthJSONWebKeySet(keys: [$0]) },
            jwksURI: jwksURI.flatMap(URL.init(string:))
        )
    )
}

private func credentialAttestationJWK(
    key: P256.Signing.PrivateKey,
    keyID: String
) throws -> OAuthJSONWebKey {
    let bytes = key.publicKey.x963Representation
    return try OAuthJSONWebKey(
        x: Data(bytes[1 ..< 33]).base64URLEncodedString(),
        y: Data(bytes[33 ..< 65]).base64URLEncodedString(),
        keyID: keyID
    )
}

private func credentialAttestationResponse(
    body: Data,
    url: String
) throws -> OAuthRemoteHTTPResponse {
    OAuthRemoteHTTPResponse(
        status: 200,
        headers: ["content-type": ["application/json"]],
        body: body,
        responseURL: URL(string: url)!,
        connectedPeerAddress: OAuthIPAddress(literal: "93.184.216.34")
    )
}

private func signedClientAttestation(
    key: P256.Signing.PrivateKey,
    clientID: String,
    authority: String,
    now: Date,
    jti: String,
    keyID: String = "key-1"
) throws -> String {
    let issuedAt = Int64(now.timeIntervalSince1970)
    let header = try JSONSerialization.data(
        withJSONObject: [
            "alg": "ES256",
            "typ": PermissionedDataJWT.clientAttestationType,
            "kid": keyID,
        ],
        options: [.sortedKeys, .withoutEscapingSlashes]
    ).base64URLEncodedString()
    let claims = try JSONSerialization.data(
        withJSONObject: [
            "iss": clientID,
            "sub": clientID,
            "aud": "\(authority)#atproto_space_host",
            "iat": issuedAt,
            "exp": issuedAt + 60,
            "jti": jti,
        ],
        options: [.sortedKeys, .withoutEscapingSlashes]
    ).base64URLEncodedString()
    let input = "\(header).\(claims)"
    let signature = try P256WireSignature.sign(
        Data(input.utf8),
        using: key
    ).base64URLEncodedString()
    return "\(input).\(signature)"
}

private actor CredentialAttestationResolver: OAuthHostnameResolving {
    let address: OAuthIPAddress

    init(address: OAuthIPAddress) {
        self.address = address
    }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        [address]
    }
}

private actor CredentialAttestationTransport: OAuthRemoteTransport {
    private var responseQueues: [String: [OAuthRemoteHTTPResponse]]
    private let failure: (any Error)?
    private var requests = 0

    init(response: OAuthRemoteHTTPResponse) {
        responseQueues = [response.responseURL.absoluteString: [response]]
        failure = nil
    }

    init(responseQueues: [String: [OAuthRemoteHTTPResponse]]) {
        self.responseQueues = responseQueues
        failure = nil
    }

    init(failure: any Error) {
        responseQueues = [:]
        self.failure = failure
    }

    func get(
        url: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
        if let failure {
            throw failure
        }
        guard var queue = responseQueues[url.absoluteString],
              !queue.isEmpty else {
            throw SwanError.unavailable("credential attestation transport unavailable")
        }
        let response = queue.removeFirst()
        responseQueues[url.absoluteString] = queue
        return response
    }

    func requestCount() -> Int {
        requests
    }
}

private struct FailingCredentialAttestationReplayStore:
    SpaceClientAttestationReplayStore
{
    func claimSpaceClientAttestation(
        digest _: Data,
        expiresAt _: Date,
        now _: Date
    ) async throws -> Bool {
        throw SwanError.unavailable("private replay outage sentinel")
    }
}

private func credentialSQLiteBytes(in root: URL) throws -> [Data] {
    try credentialSQLiteFiles(in: root).map { try Data(contentsOf: $0) }
}

private func credentialSQLiteFiles(in root: URL) -> [URL] {
    let files = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isRegularFileKey]
    )?.allObjects as? [URL] ?? []
    return files.filter {
        let name = $0.lastPathComponent
        return name.hasSuffix(".sqlite")
            || name.hasSuffix(".sqlite-wal")
            || name.hasSuffix(".sqlite-shm")
    }
}

private final class StringBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: String?

    func set(_ value: String) {
        lock.lock()
        storage = value
        lock.unlock()
    }

    var value: String? {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private struct StaticSigningKeyResolver: SpaceCredentialSigningKeyResolver {
    let authority: String
    let key: P256.Signing.PrivateKey

    func signingKey(
        for authority: String
    ) async throws -> SpaceCredentialAuthoritySigningKey? {
        guard authority == self.authority else { return nil }
        return SpaceCredentialAuthoritySigningKey(
            authority: authority,
            privateKey: key
        )
    }
}

private struct Fixture: Sendable {
    let root: URL
    let publicSpace: SpaceURI
    let memberSpace: SpaceURI
    let allowListSpace: SpaceURI
    let managingSpace: SpaceURI
    let publicRecord: SpaceRecordURI
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let runtime: SwanOAuthRuntime
    let authorityKey: P256.Signing.PrivateKey
    let memberKey: P256.Signing.PrivateKey
    let outsiderKey: P256.Signing.PrivateKey

    static func make() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SpaceCredentialHTTPTests-\(UUID().uuidString)")
        let publicSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-public"
        )
        let memberSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-member"
        )
        let allowListSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-app"
        )
        let managingSpace = try SpaceURI(
            authority: SpaceCredentialHTTPTests.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "credential-managed"
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try registration(
                did: SpaceCredentialHTTPTests.authority,
                handle: "authority.example.com"
            ))
            _ = try await control.createAccount(try registration(
                did: SpaceCredentialHTTPTests.member,
                handle: "member.example.com"
            ))
            let authorityDatabase = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: SpaceCredentialHTTPTests.authority
            )
            let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: authorityDatabase)
            let controlAuthorization: AuthorizationContext = .accountOAuthForTesting(
                subject: SpaceCredentialHTTPTests.authority,
                scopes: ["atproto"]
            )
            _ = try await authority.create(
                space: publicSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open),
                authorization: controlAuthorization
            )
            _ = try await authority.create(
                space: memberSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
                authorization: controlAuthorization
            )
            _ = try await authority.addMember(
                space: memberSpace,
                member: SpaceCredentialHTTPTests.member,
                authorization: controlAuthorization
            )
            _ = try await authority.create(
                space: allowListSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(
                    readPolicy: .public,
                    writePolicy: .public,
                    appAccess: .allowList(["https://reader.example/client-metadata.json"])
                ),
                authorization: controlAuthorization
            )
            _ = try await authority.create(
                space: managingSpace,
                owner: SpaceCredentialHTTPTests.authority,
                configuration: try .init(
                    readPolicy: .managingApp,
                    readManagingApp: "did:web:managing.example#space",
                    writePolicy: .managingApp,
                    writeManagingApp: "did:web:managing.example#space",
                    appAccess: .open
                ),
                authorization: controlAuthorization
            )
            try await authorityDatabase.close()

            let memberDatabase = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: SpaceCredentialHTTPTests.member
            )
            let publicRecord = try SpaceRecordURI(
                space: publicSpace,
                author: SpaceCredentialHTTPTests.member,
                collection: "app.bsky.feed.post",
                rkey: "public"
            )
            let memberRecord = try SpaceRecordURI(
                space: memberSpace,
                author: SpaceCredentialHTTPTests.member,
                collection: "app.bsky.feed.post",
                rkey: "member"
            )
            let memberAuthorization: AuthorizationContext = .accountOAuthForTesting(
                subject: SpaceCredentialHTTPTests.member,
                scopes: [
                    "space:\(publicSpace.spaceType)?authority=\(publicSpace.authority)&skey=\(publicSpace.skey)&action=create&collection=app.bsky.feed.post",
                    "space:\(memberSpace.spaceType)?authority=\(memberSpace.authority)&skey=\(memberSpace.skey)&action=create&collection=app.bsky.feed.post",
                ]
            )
            let publicRepository = try DurableSpaceRepository(
                database: memberDatabase,
                space: publicSpace,
                author: SpaceCredentialHTTPTests.member
            )
            _ = try await publicRepository.apply(
                .put(uri: publicRecord, value: recordCBOR("public")),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                authorization: memberAuthorization
            )
            let memberRepository = try DurableSpaceRepository(
                database: memberDatabase,
                space: memberSpace,
                author: SpaceCredentialHTTPTests.member
            )
            _ = try await memberRepository.apply(
                .put(uri: memberRecord, value: recordCBOR("member")),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                authorization: memberAuthorization
            )
            try await memberDatabase.close()

            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0xC3, count: 32)
            )
            return Fixture(
                root: root,
                publicSpace: publicSpace,
                memberSpace: memberSpace,
                allowListSpace: allowListSpace,
                managingSpace: managingSpace,
                publicRecord: publicRecord,
                control: control,
                directory: directory,
                runtime: runtime,
                authorityKey: P256.Signing.PrivateKey(),
                memberKey: P256.Signing.PrivateKey(),
                outsiderKey: P256.Signing.PrivateKey()
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func close() async throws {
        try await directory.close()
        try await control.close()
    }

    func reopened() async throws -> Fixture {
        let reopenedControl = try await SQLiteControlDatabase(
            dataDirectory: root
        )
        do {
            return Fixture(
                root: root,
                publicSpace: publicSpace,
                memberSpace: memberSpace,
                allowListSpace: allowListSpace,
                managingSpace: managingSpace,
                publicRecord: publicRecord,
                control: reopenedControl,
                directory: try await .bootstrap(
                    dataDirectory: root,
                    controlStore: reopenedControl,
                    publicIdentityVerifier: nil
                ),
                runtime: try SwanOAuthRuntime(
                    controlStore: reopenedControl,
                    serverKey: Data(repeating: 0xC3, count: 32)
                ),
                authorityKey: authorityKey,
                memberKey: memberKey,
                outsiderKey: outsiderKey
            )
        } catch {
            try? await reopenedControl.close()
            throw error
        }
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }

    private static func registration(
        did: String,
        handle: String
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private static func recordCBOR(_ text: String) -> Data {
        Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74, UInt8(0x60 + text.utf8.count)]) + Data(text.utf8)
    }
}
