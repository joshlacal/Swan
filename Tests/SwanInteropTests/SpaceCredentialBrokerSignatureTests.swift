import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanInterop
import SwanOAuth
import SwanSpaces
import XCTest

/// Swan as a space-credential client (atproto#5569): a fresh P-256 key per
/// credential, a JSON delegation exchange naming that key, and an
/// `Atproto-Space-Credential` presentation signed for the operation's audience.
final class SpaceCredentialBrokerSignatureTests: XCTestCase, @unchecked Sendable {
    private static let repo = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testExchangeBindsFreshKeyAndSignsEachRequestForItsAudience() async throws {
        let fixture = try SpaceCredentialClientFixture()
        let member = try client("https://member.example", fixture: fixture)
        let authority = try client("https://authority.example", fixture: fixture)
        let repository = try client("https://repository.example", fixture: fixture)
        let recorder = InteropFixtureRecorder()
        let broker = SpaceCredentialBroker(member: member, authority: authority)
        let credential = try await broker.exchange(
            space: fixture.space,
            memberAuthorization: .dpop(accessToken: "member-oauth", proof: "member-proof"),
            recorder: recorder
        )
        let authorization = InteropAuthorization.spaceCredential(credential)
        _ = try await repository.query(
            "com.atproto.space.getRecord",
            query: ["space": fixture.space.rawValue, "repo": Self.repo, "rkey": "first"],
            authorization: authorization
        )
        _ = try await authority.query(
            "com.atproto.space.listWriters",
            query: ["space": fixture.space.rawValue],
            authorization: authorization
        )
        let requests = await fixture.requests
        XCTAssertEqual(requests.count, 4)
        XCTAssertEqual(requests[0].authorization, "DPoP member-oauth")

        let exchange = requests[1]
        XCTAssertNil(exchange.authorization)
        XCTAssertNil(exchange.audience)
        XCTAssertNil(exchange.dpop)
        XCTAssertNil(exchange.signatureInput)
        XCTAssertNil(exchange.signature)
        let exchangeBody = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(exchange.body)) as? [String: String])
        XCTAssertEqual(exchangeBody["space"], fixture.space.rawValue)
        XCTAssertEqual(exchangeBody["delegationToken"], "delegation-token")
        let keyID = try XCTUnwrap(exchangeBody["credentialKey"])
        _ = try P256DIDKey(keyID)

        let expectedAudiences = [Self.repo, fixture.space.authority]
        for (request, audience) in zip(requests.dropFirst(2), expectedAudiences) {
            let authorizationValue = try XCTUnwrap(request.authorization)
            XCTAssertTrue(authorizationValue.hasPrefix("Atproto-Space-Credential "))
            XCTAssertNil(request.dpop)
            let token = String(authorizationValue.dropFirst("Atproto-Space-Credential ".count))
            XCTAssertEqual(try PermissionedDataJWT.inspectSpaceCredential(token).claims.cnf.kid, keyID)
            XCTAssertEqual(request.audience, audience, request.url.path)
            XCTAssertEqual(
                try SpaceHTTPSignature.verify(
                    authorization: [authorizationValue],
                    audience: [try XCTUnwrap(request.audience)],
                    signatureInput: [try XCTUnwrap(request.signatureInput)],
                    signature: [try XCTUnwrap(request.signature)],
                    credentialKeyID: keyID
                ),
                keyID
            )
        }
        XCTAssertGreaterThan(credential.expiresAt, Date())

        let events = await recorder.snapshot()
        let artifact = String(decoding: try JSONEncoder().encode(events), as: UTF8.self)
        XCTAssertFalse(artifact.contains("delegation-token"))
        XCTAssertFalse(artifact.contains(try XCTUnwrap(requests[2].signature)))
        XCTAssertFalse(artifact.contains(try XCTUnwrap(requests[2].authorization)))
    }

    func testEveryExchangeGeneratesADifferentCredentialKey() async throws {
        let fixture = try SpaceCredentialClientFixture()
        let member = try client("https://member.example", fixture: fixture)
        let authority = try client("https://authority.example", fixture: fixture)
        let broker = SpaceCredentialBroker(member: member, authority: authority)
        _ = try await broker.exchange(space: fixture.space, memberAuthorization: .none)
        _ = try await broker.exchange(space: fixture.space, memberAuthorization: .none)
        let keyIDs = try await fixture.requests.filter {
            $0.url.path == "/xrpc/com.atproto.space.authorizeSpaceSync"
        }.map {
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap($0.body)) as? [String: String])
            return try XCTUnwrap(body["credentialKey"])
        }
        XCTAssertEqual(keyIDs.count, 2)
        XCTAssertNotEqual(keyIDs[0], keyIDs[1])
    }

    func testRevokedCredentialIsTerminalAndNotRetried() async throws {
        let fixture = try SpaceCredentialClientFixture(responseMode: .revokeReads)
        let member = try client("https://member.example", fixture: fixture)
        let authority = try client("https://authority.example", fixture: fixture)
        let repository = try client("https://repository.example", fixture: fixture)
        let credential = try await SpaceCredentialBroker(member: member, authority: authority)
            .exchange(space: fixture.space, memberAuthorization: .none)
        do {
            _ = try await repository.query(
                "com.atproto.space.getRecord",
                query: ["space": fixture.space.rawValue, "repo": Self.repo, "rkey": "first"],
                authorization: .spaceCredential(credential)
            )
            XCTFail("a revoked credential must surface as a terminal error")
        } catch {
            XCTAssertEqual(error as? InteropHTTPError, .spaceCredentialRevoked)
        }
        let reads = await fixture.requests.filter { $0.url.path == "/xrpc/com.atproto.space.getRecord" }
        XCTAssertEqual(reads.count, 1, "the client must not retry a revoked credential")
    }

    func testRevokedCredentialOnStreamedReadIsTerminalAndNotRetried() async throws {
        let fixture = try SpaceCredentialClientFixture(responseMode: .revokeReads)
        let member = try client("https://member.example", fixture: fixture)
        let authority = try client("https://authority.example", fixture: fixture)
        let repository = try client("https://repository.example", fixture: fixture)
        let credential = try await SpaceCredentialBroker(member: member, authority: authority)
            .exchange(space: fixture.space, memberAuthorization: .none)
        let spool = FileManager.default.temporaryDirectory
            .appending(path: "swan-revoked-stream-\(UUID().uuidString).car")
        defer { try? FileManager.default.removeItem(at: spool) }
        do {
            _ = try await repository.stream(
                "com.atproto.space.getRepo",
                query: ["space": fixture.space.rawValue, "repo": Self.repo],
                authorization: .spaceCredential(credential),
                to: spool,
                maximumResponseBytes: 1_024 * 1_024
            )
            XCTFail("a revoked credential on a streamed read must surface as a terminal error")
        } catch {
            XCTAssertEqual(error as? InteropHTTPError, .spaceCredentialRevoked)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: spool.path))
        let reads = await fixture.requests.filter { $0.url.path == "/xrpc/com.atproto.space.getRepo" }
        XCTAssertEqual(reads.count, 1, "the client must not retry a revoked credential")
        XCTAssertEqual(reads.first?.audience, Self.repo)

        // Positive control: any other 401 is returned to the caller unchanged,
        // with its body in the destination file as before.
        let blobSpool = FileManager.default.temporaryDirectory
            .appending(path: "swan-unrevoked-stream-\(UUID().uuidString).blob")
        defer { try? FileManager.default.removeItem(at: blobSpool) }
        let response = try await repository.stream(
            "com.atproto.space.getBlob",
            query: ["space": fixture.space.rawValue, "repo": Self.repo, "cid": "bafkreib"],
            authorization: .spaceCredential(credential),
            to: blobSpool,
            maximumResponseBytes: 1_024 * 1_024
        )
        XCTAssertEqual(response.status, 401)
        XCTAssertEqual(try Data(contentsOf: blobSpool), Data(#"{"error":"BadSpaceAudience"}"#.utf8))
    }

    func testRequestWithoutRepoOrSpaceCannotBeSigned() async throws {
        let fixture = try SpaceCredentialClientFixture()
        let member = try client("https://member.example", fixture: fixture)
        let authority = try client("https://authority.example", fixture: fixture)
        let credential = try await SpaceCredentialBroker(member: member, authority: authority)
            .exchange(space: fixture.space, memberAuthorization: .none)
        do {
            _ = try await authority.binaryProcedure(
                "com.atproto.space.example", body: Data(), contentType: "application/octet-stream",
                authorization: .spaceCredential(credential)
            )
            XCTFail("an unsignable request was sent")
        } catch {
            XCTAssertEqual(error as? SwanError, .malformed("space credential request names no repo or space"))
        }
    }

    func testExchangeRejectsWrongBindingWrongSpaceAndUnboundResponses() async throws {
        for mode in [SpaceCredentialClientFixture.ResponseMode.wrongBinding, .wrongSpace, .missingBinding] {
            let fixture = try SpaceCredentialClientFixture(responseMode: mode)
            let member = try client("https://member.example", fixture: fixture)
            let authority = try client("https://authority.example", fixture: fixture)
            do {
                _ = try await SpaceCredentialBroker(member: member, authority: authority).exchange(
                    space: fixture.space, memberAuthorization: .none
                )
                XCTFail("credential response with invalid binding was accepted")
            } catch {
                switch mode {
                case .missingBinding:
                    // The strict decoder deliberately replaces Codable's
                    // missing-key error with the fixed crypto diagnostic.
                    XCTAssertEqual(
                        error as? PetrelCryptoError, .malformed("invalid JSON"),
                        "unexpected missing-binding error: \(type(of: error)): \(error)"
                    )
                case .wrongBinding, .wrongSpace:
                    XCTAssertEqual(
                        error as? SwanError, .malformed("space credential response binding is invalid"),
                        "unexpected binding error: \(type(of: error)): \(error)"
                    )
                case .valid, .revokeReads:
                    XCTFail("unexpected valid fixture response mode")
                }
            }
        }
    }

    private func client(_ url: String, fixture: SpaceCredentialClientFixture) throws -> InteropXRPCClient {
        InteropXRPCClient(http: try InteropHTTPClient(
            baseURL: URL(string: url)!,
            executeHandler: { method, url, headers, body, _ in
                try await fixture.respond(method: method, url: url, headers: headers, body: body)
            }
        ))
    }
}

private actor SpaceCredentialClientFixture {
    enum ResponseMode: Sendable, Equatable {
        case valid, wrongBinding, wrongSpace, missingBinding, revokeReads
    }

    struct Request: Sendable {
        let method: InteropHTTPMethod
        let url: URL
        let authorization: String?
        let audience: String?
        let signatureInput: String?
        let signature: String?
        let dpop: String?
        let body: Data?
    }

    let space: SpaceURI
    private let responseMode: ResponseMode
    private let signingKey = P256.Signing.PrivateKey()
    private(set) var requests: [Request] = []

    init(responseMode: ResponseMode = .valid) throws {
        space = try SpaceURI(
            authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.swan.interop", skey: "proof"
        )
        self.responseMode = responseMode
    }

    func respond(method: InteropHTTPMethod, url: URL, headers: [String: String], body: Data?) throws
        -> InteropHTTPResponse {
        requests.append(Request(
            method: method,
            url: url,
            authorization: headers["Authorization"],
            audience: headers[SpaceHTTPSignature.audienceFieldName],
            signatureInput: headers[SpaceHTTPSignature.signatureInputFieldName],
            signature: headers[SpaceHTTPSignature.signatureFieldName],
            dpop: headers["DPoP"],
            body: body
        ))
        var status = 200
        let output: Data
        switch url.path {
        case "/xrpc/com.atproto.space.getDelegationToken":
            output = Data(#"{"token":"delegation-token"}"#.utf8)
        case "/xrpc/com.atproto.space.authorizeSpaceSync":
            XCTAssertNil(headers["Authorization"])
            XCTAssertNil(headers[SpaceHTTPSignature.signatureInputFieldName])
            XCTAssertNil(headers[SpaceHTTPSignature.signatureFieldName])
            let input = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(body)) as? [String: String])
            XCTAssertEqual(input["delegationToken"], "delegation-token")
            let keyID = try XCTUnwrap(input["credentialKey"])
            _ = try P256DIDKey(keyID)
            let issuedSpace = responseMode == .wrongSpace
                ? try SpaceURI(authority: space.authority, spaceType: space.spaceType, skey: "other")
                : space
            var credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: space.authority, space: issuedSpace, key: signingKey,
                confirmationKeyID: responseMode == .wrongBinding
                    ? SpaceHTTPSignature.keyID(for: P256.Signing.PrivateKey())
                    : keyID
            )
            if responseMode == .missingBinding {
                var parts = credential.split(separator: ".").map(String.init)
                var payload = try XCTUnwrap(JSONSerialization.jsonObject(
                    with: OAuthBase64URL.decode(parts[1], maxBytes: 4_096)
                ) as? [String: Any])
                payload.removeValue(forKey: "cnf")
                parts[1] = try JSONSerialization.data(withJSONObject: payload).base64URLEncodedString()
                credential = parts.joined(separator: ".")
            }
            output = try JSONEncoder().encode(["token": credential])
        case "/xrpc/com.atproto.space.getRecord" where responseMode == .revokeReads,
             "/xrpc/com.atproto.space.getRepo" where responseMode == .revokeReads:
            status = 401
            output = Data(#"{"error":"CredentialRevoked"}"#.utf8)
        case "/xrpc/com.atproto.space.getBlob" where responseMode == .revokeReads:
            // A different 401 stays an ordinary response (positive control).
            status = 401
            output = Data(#"{"error":"BadSpaceAudience"}"#.utf8)
        default:
            output = Data("{}".utf8)
        }
        return InteropHTTPResponse(
            status: status, headers: ["content-type": "application/json"], body: output,
            finalURL: url, redirectCount: 0
        )
    }
}
