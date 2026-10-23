import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
import SwanStorage
@testable import SwanOAuth
import XCTest

/// Actual disposable Axum/PostgreSQL integration. The fixture must supply a
/// fresh deletable generation; a terminal generation is never reset for a rerun.
final class ConversationSpaceDSDeletionIntegrationTests: XCTestCase, @unchecked Sendable {
    func testActualDSDeletionIsBoundedAuthorizedTerminalAndIdempotent() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let path = environment["SWAN_DS_DELETION_FIXTURE"] ?? environment["SWAN_DS_POLICY_FIXTURE"] else {
            throw XCTSkip("set SWAN_DS_DELETION_FIXTURE to a fresh disposable lifecycle fixture ready.json")
        }
        let fixture = try JSONDecoder().decode(DeletionFixture.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        guard let rawSpace = fixture.deletableSpace, let outsiderKeyPath = fixture.outsiderPrivateKeyPath else {
            throw XCTSkip("fixture must include fresh deletableSpace and outsiderPrivateKeyPath")
        }
        var origin = try XCTUnwrap(URLComponents(string: fixture.origin))
        guard ["127.0.0.1", "localhost"].contains(origin.host), origin.scheme == "http" else {
            throw SwanError.malformed("disposable fixture must use loopback HTTP")
        }
        origin.host = "localhost"
        let originURL = try XCTUnwrap(origin.url)
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: URL(fileURLWithPath: fixture.authorityPrivateKeyPath)))
        let outsiderKey = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: URL(fileURLWithPath: outsiderKeyPath)))
        let transport = NIOPeerPinnedOAuthPostTransport(configuration: try .init(endpointPeers: [originURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")): peer]))
        let signer = DeletionFixtureSigner(key: key)
        let checker = try RemoteConversationSpaceMembershipChecker(origin: originURL, audience: fixture.audience,
            signer: signer, policy: .init(allowLocalhostDevelopment: true,
                networkAllowlist: .init(addresses: [peer]), maximumBodyBytes: 8192, timeout: 5), transport: transport)
        let space = try SpaceURI(rawSpace)
        XCTAssertEqual(space.authority, fixture.authorityDID)
        try await checker.requireMembership(space: space, user: fixture.userDID, now: Date())

        let mismatched = try await rawDeletion(transport: transport, origin: originURL, peer: peer,
            space: space, generation: UUID().uuidString.lowercased(), issuer: fixture.authorityDID,
            audience: fixture.audience, key: key)
        XCTAssertEqual(mismatched.status, 400)
        XCTAssertEqual(try JSONDecoder().decode(ErrorBody.self, from: mismatched.body).error, "StorageGenerationMismatch")
        let outsider = try await rawDeletion(transport: transport, origin: originURL, peer: peer,
            space: space, generation: space.skey, issuer: fixture.outsiderDID,
            audience: fixture.audience, key: outsiderKey)
        XCTAssertEqual(outsider.status, 403)
        try await checker.requireMembership(space: space, user: fixture.userDID, now: Date())

        try await checker.deleteGeneration(space: space, now: Date())
        try await checker.deleteGeneration(space: space, now: Date())
        do {
            try await checker.requireMembership(space: space, user: fixture.userDID, now: Date())
            XCTFail("deleted generation still granted a credential")
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            XCTAssertEqual(error, .deleted)
        }
        let deletions = await signer.calls.filter { $0.method == RemoteConversationSpaceMembershipChecker.deletionMethod }
        XCTAssertEqual(deletions.count, 2)
        XCTAssertEqual(Set(deletions.map(\.eventID)).count, 2, "idempotent retries use fresh short-lived JWTs")
        XCTAssertTrue(deletions.allSatisfy { $0.issuer == fixture.authorityDID && $0.audience == fixture.audience && $0.requestBodyDigest == nil })
    }

    private func rawDeletion(
        transport: NIOPeerPinnedOAuthPostTransport, origin: URL, peer: OAuthIPAddress,
        space: SpaceURI, generation: String, issuer: String, audience: String,
        key: P256.Signing.PrivateKey
    ) async throws -> OAuthRemoteHTTPResponse {
        struct Body: Encodable { let space: String; let generation: String }
        let method = RemoteConversationSpaceMembershipChecker.deletionMethod
        let url = origin.appending(path: "xrpc/" + method)
        let token = try SpaceServiceJWT.create(issuer: issuer, audience: audience, method: method,
            eventID: UUID().uuidString.lowercased(), requestBodyDigest: nil, key: key, now: Date(), lifetime: 60)
        let response = try await transport.post(url: url, approvedPeers: [peer],
            headers: ["Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"],
            body: JSONEncoder().encode(Body(space: space.rawValue, generation: generation)),
            timeout: 5, maximumResponseBodyBytes: 8192)
        XCTAssertEqual(response.redirectCount, 0)
        XCTAssertEqual(response.responseURL, url)
        XCTAssertEqual(response.connectedPeerAddress, peer)
        XCTAssertLessThanOrEqual(response.body.count, 8192)
        return response
    }

    private struct ErrorBody: Decodable { let error: String }
    private struct DeletionFixture: Decodable {
        let origin: String, audience: String, authorityDID: String, userDID: String, outsiderDID: String
        let authorityPrivateKeyPath: String
        let deletableSpace: String?
        let outsiderPrivateKeyPath: String?
    }
}

private actor DeletionFixtureSigner: SpaceServiceAuthenticationIssuer {
    struct Call: Sendable {
        let issuer: String, audience: String, method: String, eventID: String
        let requestBodyDigest: String?
    }
    let key: P256.Signing.PrivateKey
    private(set) var calls: [Call] = []
    init(key: P256.Signing.PrivateKey) { self.key = key }
    func issue(issuer: String, audience: String, method: String, eventID: String, requestBodyDigest: String?, now: Date) async throws -> String {
        calls.append(Call(issuer: issuer, audience: audience, method: method, eventID: eventID, requestBodyDigest: requestBodyDigest))
        return try SpaceServiceJWT.create(issuer: issuer, audience: audience, method: method,
            eventID: eventID, requestBodyDigest: requestBodyDigest, key: key, now: now, lifetime: 60)
    }
}
