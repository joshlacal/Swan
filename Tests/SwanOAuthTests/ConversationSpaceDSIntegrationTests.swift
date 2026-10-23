import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
import SwanStorage
@testable import SwanOAuth
import XCTest

/// Optional test against the actual disposable Axum/PostgreSQL policy fixture.
/// It never contacts production and never reads a real account key.
final class ConversationSpaceDSIntegrationTests: XCTestCase, @unchecked Sendable {
    func testActualDeliveryServiceRequiresExactCommittedMemberAndGeneration() async throws {
        guard let path = ProcessInfo.processInfo.environment["SWAN_DS_POLICY_FIXTURE"] else {
            throw XCTSkip("set SWAN_DS_POLICY_FIXTURE to the disposable delivery-service ready.json")
        }
        struct Fixture: Decodable {
            let origin: String, audience: String, authorityDID: String, userDID: String, outsiderDID: String
            let space: String, generation: String, deletedSpace: String, removedSpace: String, authorityPrivateKeyPath: String
        }
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        var origin = try XCTUnwrap(URLComponents(string: fixture.origin))
        guard ["127.0.0.1", "localhost"].contains(origin.host), origin.scheme == "http" else {
            throw SwanError.malformed("fixture must be loopback HTTP")
        }
        origin.host = "localhost"
        let url = try XCTUnwrap(origin.url)
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: URL(fileURLWithPath: fixture.authorityPrivateKeyPath)))
        let checker = try RemoteConversationSpaceMembershipChecker(origin: url, audience: fixture.audience,
            signer: FixtureSigner(key: key), policy: .init(allowLocalhostDevelopment: true,
                networkAllowlist: .init(addresses: [peer]), maximumBodyBytes: 8192, timeout: 5),
            transport: .init(configuration: .init(endpointPeers: [url.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")): peer])))
        let space = try SpaceURI(fixture.space)
        try await checker.requireMembership(space: space, user: fixture.userDID, now: Date())
        for (uri, user) in [(fixture.space, fixture.outsiderDID), (fixture.deletedSpace, fixture.userDID), (fixture.removedSpace, fixture.userDID)] {
            do {
                try await checker.requireMembership(space: SpaceURI(uri), user: user, now: Date())
                XCTFail("uncommitted, removed, or deleted membership must not authorize a credential")
            } catch {}
        }
        let unknown = try SpaceURI(authority: fixture.authorityDID,
            spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
        do {
            try await checker.requireMembership(space: unknown, user: fixture.userDID, now: Date())
            XCTFail("an unknown immutable generation must be denied")
        } catch {}
    }
}

private struct FixtureSigner: SpaceServiceAuthenticationIssuer {
    let key: P256.Signing.PrivateKey
    func issue(issuer: String, audience: String, method: String, eventID: String, requestBodyDigest: String?, now: Date) async throws -> String {
        try SpaceServiceJWT.create(issuer: issuer, audience: audience, method: method,
            eventID: eventID, requestBodyDigest: requestBodyDigest, key: key, now: now, lifetime: 60)
    }
}
