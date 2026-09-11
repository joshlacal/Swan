import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanInterop
import SwanOAuth
import SwanSpaces
import XCTest

final class SpaceCredentialBrokerDPoPTests: XCTestCase, @unchecked Sendable {
    func testExchangeBindsFreshKeyAndSignsEachResourceRequest() async throws {
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
        // Reusing authorization must never reuse the proof, including when
        // only the query changes or the same credential reaches another host.
        _ = try await repository.query(
            "com.atproto.space.getRecord", query: ["rkey": "first"],
            authorization: authorization
        )
        _ = try await repository.query(
            "com.atproto.space.getRecord", query: ["rkey": "second"],
            authorization: authorization
        )
        _ = try await authority.query(
            "com.atproto.space.listRepos", authorization: authorization
        )
        _ = try await repository.binaryProcedure(
            "com.atproto.space.example", body: Data(), contentType: "application/octet-stream",
            authorization: authorization
        )
        let requests = await fixture.requests
        XCTAssertEqual(requests.count, 6)
        XCTAssertEqual(requests[0].authorization, "DPoP member-oauth")
        XCTAssertEqual(requests[0].proof, "member-proof")
        let exchange = requests[1]
        XCTAssertEqual(exchange.authorization, "Bearer delegation-token")
        let exchangeProof = try verifiedProof(exchange)
        XCTAssertEqual(exchangeProof.claims.htm, "POST")
        XCTAssertEqual(exchangeProof.claims.htu, "https://authority.example/xrpc/com.atproto.space.getSpaceCredential")
        XCTAssertNil(exchangeProof.claims.ath)
        XCTAssertNil(exchangeProof.claims.nonce)

        var proofIDs = Set([exchangeProof.claims.jti])
        for request in requests.dropFirst(2) {
            let proof = try verifiedProof(request)
            XCTAssertTrue(request.authorization?.hasPrefix("DPoP ") == true)
            let token = try XCTUnwrap(request.authorization).dropFirst(5)
            let claims = try PermissionedDataJWT.inspectSpaceCredential(String(token)).claims
            XCTAssertEqual(claims.cnf.jkt, exchangeProof.thumbprint)
            XCTAssertEqual(proof.thumbprint, exchangeProof.thumbprint)
            XCTAssertEqual(proof.claims.htm, request.method.rawValue)
            XCTAssertEqual(proof.claims.htu, "https://\(request.url.host!)\(request.url.path)")
            XCTAssertEqual(proof.claims.ath, Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString())
            XCTAssertNil(proof.claims.nonce)
            XCTAssertTrue(proofIDs.insert(proof.claims.jti).inserted)
        }
        let events = await recorder.snapshot()
        let artifact = String(decoding: try JSONEncoder().encode(events), as: UTF8.self)
        XCTAssertFalse(artifact.contains("delegation-token"))
        XCTAssertFalse(artifact.contains(try XCTUnwrap(exchange.proof)))
        XCTAssertFalse(artifact.contains(try XCTUnwrap(requests[2].authorization)))
    }

    func testEveryExchangeGeneratesADifferentCredentialKey() async throws {
        let fixture = try SpaceCredentialClientFixture()
        let member = try client("https://member.example", fixture: fixture)
        let authority = try client("https://authority.example", fixture: fixture)
        let broker = SpaceCredentialBroker(member: member, authority: authority)
        _ = try await broker.exchange(space: fixture.space, memberAuthorization: .none)
        _ = try await broker.exchange(space: fixture.space, memberAuthorization: .none)
        let requests = await fixture.requests.filter {
            $0.url.path == "/xrpc/com.atproto.space.getSpaceCredential"
        }
        XCTAssertEqual(requests.count, 2)
        XCTAssertNotEqual(try verifiedProof(requests[0]).thumbprint, try verifiedProof(requests[1]).thumbprint)
    }

    func testExchangeRejectsWrongBindingWrongSpaceAndBearerOnlyResponses() async throws {
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
                case .valid:
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

    private func verifiedProof(_ request: SpaceCredentialClientFixture.Request) throws
        -> (thumbprint: String, claims: ClientProofClaims) {
        let compact = try XCTUnwrap(request.proof)
        let header = try OAuthCompactJWT.unverifiedHeader(compact)
        let jwk = try XCTUnwrap(header.jwk)
        let verified = try OAuthCompactJWT.verify(
            compact, publicKey: jwk.publicKey(), expectedType: "dpop+jwt",
            constraints: .init(requireIssuedAt: true, maximumAge: 60)
        )
        return (jwk.thumbprint(), try OAuthCompactJWT.decodeClaims(ClientProofClaims.self, from: verified))
    }
}

private struct ClientProofClaims: Decodable {
    let htm: String
    let htu: String
    let jti: String
    let ath: String?
    let nonce: String?
}

private actor SpaceCredentialClientFixture {
    enum ResponseMode: Sendable, Equatable { case valid, wrongBinding, wrongSpace, missingBinding }
    struct Request: Sendable {
        let method: InteropHTTPMethod
        let url: URL
        let authorization: String?
        let proof: String?
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
        requests.append(Request(method: method, url: url, authorization: headers["Authorization"], proof: headers["DPoP"]))
        let output: Data
        switch url.path {
        case "/xrpc/com.atproto.space.getDelegationToken":
            output = Data(#"{"token":"delegation-token"}"#.utf8)
        case "/xrpc/com.atproto.space.getSpaceCredential":
            let proof = try XCTUnwrap(headers["DPoP"])
            let thumbprint = try XCTUnwrap(OAuthCompactJWT.unverifiedHeader(proof).jwk).thumbprint()
            let issuedSpace = responseMode == .wrongSpace
                ? try SpaceURI(authority: space.authority, spaceType: space.spaceType, skey: "other")
                : space
            var credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: space.authority, space: issuedSpace, key: signingKey,
                dpopKeyThumbprint: responseMode == .wrongBinding ? InteropDPoPKey().thumbprint : thumbprint
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
        default:
            output = Data("{}".utf8)
        }
        return InteropHTTPResponse(
            status: 200, headers: ["content-type": "application/json"], body: output,
            finalURL: url, redirectCount: 0
        )
    }
}
