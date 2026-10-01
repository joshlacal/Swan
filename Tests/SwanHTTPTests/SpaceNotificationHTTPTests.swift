import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import PetrelCrypto
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

final class SpaceNotificationHTTPTests: XCTestCase, @unchecked Sendable {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let writer = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testActualNotificationRouteRetainsAdmissionThroughStrictAndGeneratedDecode() async throws {
        let maximum = 16 * 1_024
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let barrier = NotificationDecodeBarrier()
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let app = try fixture.server(
                jsonWriteAdmission: admission,
                decodeObserver: { await barrier.arriveAndWait() }
            ).buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.decode-admission"))
            let body = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/notify\"}")
            try await app.test(.router) { client in
                let first = Task {
                    try await client.execute(
                        uri: "/xrpc/com.atproto.space.registerNotify", method: .post,
                        headers: try fixture.registerHeaders(for: self.writer), body: body
                    )
                }
                await barrier.waitUntilEntered()
                XCTAssertEqual(admission.snapshot, .init(
                    activeLeases: 1, reservedRequestBytes: maximum
                ))
                let second = try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify", method: .post,
                    headers: try fixture.registerHeaders(for: self.writer), body: body
                )
                XCTAssertEqual(second.status, .serviceUnavailable)
                XCTAssertEqual(try notificationErrorCode(second.body), "temporarily_unavailable")
                await barrier.release()
                let firstResponse = try await first.value
                XCTAssertEqual(firstResponse.status, .ok)
            }
            XCTAssertEqual(admission.snapshot, .init(
                activeLeases: 0, reservedRequestBytes: 0
            ))
            let registrations = await fixture.directory.registrations()
            XCTAssertEqual(registrations.count, 1)
            try await fixture.close()
        } catch {
            await barrier.release()
            try? await fixture.close()
            throw error
        }
    }

    func testCredentialOnlyWriterDiscoveryRegistrationAndServiceNotifications() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let app = try fixture.server().buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests"))
            let credentialHeaders = try fixture.credentialOnlyHeaders()
            let registerHeaders = try fixture.registerHeaders(for: writer)
            let wrongAudienceHeaders = try fixture.credentialHeaders(serviceAuth: "wrong-audience-token")
            let encodedSpace = notificationPercentEncode(fixture.space.rawValue)
            let expectedWriter = writer
            let registerBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/xrpc/com.atproto.space.notifyWrite\"}")
            let commitment = Data(repeating: 0x01, count: 32).base64EncodedString()
            let writeBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"repo\":\"\(writer)\",\"rev\":\"3l72c4e2y2222\",\"hash\":{\"$bytes\":\"\(commitment)\"}}")
            let serviceHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer writer-token"
                return fields
            }()
            let mismatchedDigestHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer mismatched-digest-token"
                return fields
            }()
            let authorityFanoutHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer authority-fanout-token"
                return fields
            }()
            let unknownRecipientHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer authority-unknown-recipient-token"
                return fields
            }()

            try await app.test(.router) { client in
                // Credential-only registerNotify must be refused: two factors required
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Service JWT addressed to another authority is refused
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(wrongAudienceHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Two-factor registerNotify succeeds
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(registerHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    let value = try notificationJSONObject(response.body)
                    XCTAssertEqual(Set(value.keys), ["expiresAt"])
                }
                // Cross-host / foreign-audience service authentication on registerNotify is rejected
                let foreignRegisterHeaders = try fixture.foreignAudienceRegisterHeaders(for: writer)
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(foreignRegisterHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // A notifyWrite request with altered body / mismatched digest is rejected
                let badCommitment = Data(repeating: 0xCC, count: 32).base64EncodedString()
                let alteredWriteBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"repo\":\"\(writer)\",\"rev\":\"2222222222222\",\"hash\":{\"$bytes\":\"\(badCommitment)\"}}")
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: serviceHeaders,
                    body: alteredWriteBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Valid notifyWrite succeeds
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: serviceHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
                // Mismatched digest in service JWT is refused with 401
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: mismatchedDigestHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // The pinned TypeScript receiver requires `iss == repo` for
                // notifyWrite. Do not accept an authority-signed surrogate:
                // it would be incompatible with that receiver and would let
                // Swan claim an unsupported cross-host delivery mode.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: authorityFanoutHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Likewise, an unbound recipient audience cannot turn an
                // authority signature into a member-writer notification.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: unknownRecipientHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Deletion remains an authority-signed control-plane message.
                // An unbound configured recipient is intentionally a no-op.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifySpaceDeleted",
                    method: .post,
                    headers: unknownRecipientHeaders,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)",
                    method: .get,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialHeaders, path: "/xrpc/com.atproto.space.listRepos", method: "GET")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try notificationJSONObject(response.body)
                    let repos = try XCTUnwrap(value["repos"] as? [[String: Any]])
                    XCTAssertEqual(repos.count, 1)
                    XCTAssertEqual(repos.first?["did"] as? String, expectedWriter)
                    XCTAssertEqual(repos.first?["rev"] as? String, "3l72c4e2y2222")
                    let rendered = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertFalse(rendered.contains("record"))
                    XCTAssertFalse(rendered.contains("credential"))
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)",
                    method: .post
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try notificationErrorCode(response.body), "permissioned_endpoint_unavailable")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(registerHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/x\"}")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try notificationErrorCode(response.body), "InvalidRequest")
                }
            }
            let registered = await fixture.directory.registrations()
            let notifications = await fixture.directory.notifications()
            XCTAssertEqual(registered.count, 1)
            XCTAssertEqual(notifications.count, 1)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Erratum 03: `registerNotify` accepts the lexicon's `service`
    /// identifier, resolves it through the subscriber's DID document, and
    /// stores the resolved endpoint beside the identity. Every refusal shape
    /// is pinned here too: no locator at all, a malformed identifier, an
    /// unresolvable one, and a server with no resolver.
    func testRegisterNotifyServiceIdentifierResolutionAndItsRefusals() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let subscriber = "did:web:events.bulleted.example"
            let document = """
            {"id":"\(subscriber)","service":[
                {"id":"#bulleted_events","serviceEndpoint":"https://events.bulleted.example"},
                {"id":"#other","serviceEndpoint":"https://other.bulleted.example"}
            ]}
            """
            let resolver = SwanServiceEndpointResolver(
                documents: StubNotificationDIDDocumentFetcher(
                    documents: [subscriber: Data(document.utf8)]
                )
            )
            let app = try fixture.server(serviceEndpointResolver: resolver)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.service"))
            let credentialHeaders = try fixture.credentialOnlyHeaders()
            let spaceURI = fixture.space.rawValue
            let registerBody: @Sendable (String) -> ByteBuffer = { fields in
                ByteBuffer(string: "{\"space\":\"\(spaceURI)\",\(fields)}")
            }
            try await app.test(.router) { client in
                let validHeaders = try fixture.registerHeaders(for: subscriber)
                // Fragment-qualified service → the matching entry's endpoint.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(validHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody("\"service\":\"\(subscriber)#bulleted_events\"")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(Set(try notificationJSONObject(response.body).keys), ["expiresAt"])
                }
                // Service header absence is rejected
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody("\"service\":\"\(subscriber)#bulleted_events\"")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Body-owner mismatch is rejected
                let mismatchedHeaders = try fixture.registerHeaders(for: "did:web:other.example")
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(mismatchedHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody("\"service\":\"\(subscriber)#bulleted_events\"")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // `service` decides when both are sent: the supplied endpoint
                // is ignored in favour of the resolved one.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(validHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody(
                        "\"service\":\"\(subscriber)#other\",\"endpoint\":\"https://attacker.example/sink\""
                    )
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Neither locator: nothing to register.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(validHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                    body: registerBody("\"repo\":\"\(self.writer)\"")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try notificationErrorCode(response.body), "InvalidRequest")
                }
                // Malformed identifiers never reach the resolver.
                for bad in ["https://not-a-did.example", "did:web:x#", "#frag", "did:web:x#a#b"] {
                    try await client.execute(
                        uri: "/xrpc/com.atproto.space.registerNotify",
                        method: .post,
                        headers: try fixture.registerHeaders(for: bad),
                        body: registerBody("\"service\":\"\(bad)\"")
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest, "service=\(bad)")
                        XCTAssertEqual(try notificationErrorCode(response.body), "InvalidRequest")
                    }
                }
                // A well-formed identifier that does not resolve — absent
                // fragment entry — is the lexicon's one named error.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try fixture.registerHeaders(for: subscriber),
                    body: registerBody("\"service\":\"\(subscriber)#missing\"")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try notificationErrorCode(response.body), "ServiceNotResolvable")
                }
            }
            let registered = await fixture.directory.registrations()
            XCTAssertEqual(registered.count, 2)
            XCTAssertEqual(
                registered.first { $0.service == "\(subscriber)#bulleted_events" }?.endpoint,
                "https://events.bulleted.example"
            )
            XCTAssertEqual(
                registered.first { $0.service == "\(subscriber)#other" }?.endpoint,
                "https://other.bulleted.example",
                "the resolved endpoint must win over the supplied one"
            )
            XCTAssertFalse(
                registered.contains { $0.endpoint.contains("attacker.example") },
                "a caller-supplied endpoint must never survive beside a service identifier"
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// `unregisterNotify` (live lexicon at bddc99fb): withdraws a subscriber
    /// by service identity, idempotently, under the same space-credential
    /// gate as `registerNotify`. Mirrors the reference handler, which deletes
    /// by (space, serviceDid) without resolving the identifier again — a
    /// subscriber whose DID document has since changed must still be able to
    /// withdraw.
    func testUnregisterNotifyWithdrawsByServiceIdempotentlyUnderCredentialGate() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let subscriber = "did:web:events.bulleted.example"
            let document = """
            {"id":"\(subscriber)","service":[
                {"id":"#a","serviceEndpoint":"https://a.bulleted.example"},
                {"id":"#b","serviceEndpoint":"https://b.bulleted.example"}
            ]}
            """
            let resolver = SwanServiceEndpointResolver(
                documents: StubNotificationDIDDocumentFetcher(
                    documents: [subscriber: Data(document.utf8)]
                )
            )
            let app = try fixture.server(serviceEndpointResolver: resolver)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.unregister"))
            let credentialHeaders = try fixture.credentialOnlyHeaders()
            let spaceURI = fixture.space.rawValue
            let body: @Sendable (String) -> ByteBuffer = { fields in
                ByteBuffer(string: "{\"space\":\"\(spaceURI)\",\(fields)}")
            }
            try await app.test(.router) { client in
                let validHeaders = try fixture.registerHeaders(for: subscriber)
                for fragment in ["#a", "#b"] {
                    try await client.execute(
                        uri: "/xrpc/com.atproto.space.registerNotify",
                        method: .post,
                        headers: try SpaceCredentialDPoPTestSupport.refreshed(validHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                        body: body("\"service\":\"\(subscriber)\(fragment)\"")
                    ) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                }
                let afterRegister = await fixture.directory.registrations()
                XCTAssertEqual(afterRegister.count, 2)

                // Missing service auth header on unregister is rejected
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.unregisterNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                    body: body("\"service\":\"\(subscriber)#a\"")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }

                // Body-owner mismatch on unregister is rejected
                let foreignHeaders = try fixture.registerHeaders(for: "did:web:foreign.example")
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.unregisterNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(foreignHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                    body: body("\"service\":\"\(subscriber)#a\"")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // Cross-host / foreign-audience service authentication on unregisterNotify is rejected
                let foreignAudienceHeaders = try fixture.foreignAudienceRegisterHeaders(for: subscriber)
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.unregisterNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(foreignAudienceHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                    body: body("\"service\":\"\(subscriber)#a\"")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }

                // Withdraw exactly one subscriber; the other survives.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.unregisterNotify",
                    method: .post,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(validHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                    body: body("\"service\":\"\(subscriber)#a\"")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(response.body.readableBytes, 0)
                }
                let remaining = await fixture.directory.registrations()
                XCTAssertEqual(remaining.map(\.service), ["\(subscriber)#b"])

                // Idempotent: withdrawing again, or a never-registered
                // service, still succeeds — no existence oracle.
                for target in ["\(subscriber)#a", "did:web:never.example#x"] {
                    let targetHeaders = try fixture.registerHeaders(for: target)
                    try await client.execute(
                        uri: "/xrpc/com.atproto.space.unregisterNotify",
                        method: .post,
                        headers: try SpaceCredentialDPoPTestSupport.refreshed(targetHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                        body: body("\"service\":\"\(target)\"")
                    ) { response in
                        XCTAssertEqual(response.status, .ok, target)
                    }
                }
                let afterIdempotent = await fixture.directory.registrations()
                XCTAssertEqual(afterIdempotent.count, 1)

                // The strict body fence: `service` is required, unknown keys
                // and the retired `endpoint` locator are refused, and a
                // malformed identifier never reaches storage.
                for bad in [
                    "\"repo\":\"\(self.writer)\"",
                    "\"endpoint\":\"https://a.bulleted.example\"",
                    "\"service\":\"https://not-a-did.example\"",
                    "\"service\":\"\(subscriber)#a\",\"extra\":1",
                ] {
                    try await client.execute(
                        uri: "/xrpc/com.atproto.space.unregisterNotify",
                        method: .post,
                        headers: try SpaceCredentialDPoPTestSupport.refreshed(validHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                        body: body(bad)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest, bad)
                        XCTAssertEqual(try notificationErrorCode(response.body), "InvalidRequest")
                    }
                }
                // No credential (JSON content type, no Authorization):
                // denied, nothing withdrawn.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.unregisterNotify",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: body("\"service\":\"\(subscriber)#b\"")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // Wrong method stays on the opaque closed shape.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.unregisterNotify",
                    method: .get,
                    headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "GET")
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try notificationErrorCode(response.body), "permissioned_endpoint_unavailable")
                }
            }
            let final = await fixture.directory.registrations()
            XCTAssertEqual(final.count, 1)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// A credential bound to a holder key registers with its DPoP proof.
    /// An OAuth-shaped token still routes to OAuth policy and is refused here.
    func testRegisterNotifyAcceptsTheDPoPSchemeCredentialPresentation() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let subscriber = "did:web:events.dpop.example"
            let document = """
            {"id":"\(subscriber)","service":[
                {"id":"#events","serviceEndpoint":"https://events.dpop.example"}
            ]}
            """
            let resolver = SwanServiceEndpointResolver(
                documents: StubNotificationDIDDocumentFetcher(
                    documents: [subscriber: Data(document.utf8)]
                )
            )
            let app = try fixture.server(serviceEndpointResolver: resolver)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.dpopScheme"))
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try fixture.dpopSchemeCredentialHeaders(for: subscriber),
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"service\":\"\(subscriber)#events\"}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // A non-credential token under DPoP is NOT routed to the
                // credential verifier: it stays with OAuth policy, which this
                // fixture leaves unconfigured for the route → denied.
                var oauthShaped: HTTPFields = [.contentType: "application/json"]
                oauthShaped[.authorization] = "DPoP not-a-credential-jwt"
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: oauthShaped,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"service\":\"\(subscriber)#events\"}")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            let registered = await fixture.directory.registrations()
            XCTAssertEqual(registered.count, 1)
            XCTAssertEqual(registered[0].service, "\(subscriber)#events")
            XCTAssertEqual(registered[0].endpoint, "https://events.dpop.example")
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// A server with NO resolver answers a service registration exactly like
    /// an unresolvable identifier — from the caller's seat that is what it is
    /// — while legacy endpoint registrations keep working untouched.
    func testRegisterNotifyServiceWithoutAResolverIsUnresolvable() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let app = try fixture.server()
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.noResolver"))
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try fixture.registerHeaders(for: "did:web:events.example"),
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"service\":\"did:web:events.example#e\"}")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try notificationErrorCode(response.body), "ServiceNotResolvable")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: try fixture.registerHeaders(for: "did:web:events.example"),
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/xrpc/com.atproto.space.notifyWrite\"}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }
            let registered = await fixture.directory.registrations()
            XCTAssertEqual(registered.count, 1)
            XCTAssertNil(registered[0].service, "a legacy registration carries no service identity")
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Erratum 03 end-to-end at the delivery seam: a `write` fanout row for a
    /// service-named registration posts the reference `notifyWrite` shape to
    /// the REGISTERED endpoint with the service identifier as the JWT
    /// audience and the space authority as issuer — no operator destination
    /// map involved. A legacy row delivers nothing, and a withdrawn
    /// registration turns the leased row into a silent no-op.
    func testFanoutTransportDeliversWriteRowsToServiceDestinations() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanNotifyDelivery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let authorityDID = authority
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authorityDID)
        defer { Task { try? await database.close() } }
        let space = try SpaceURI(authority: authorityDID, spaceType: "app.bsky.bookmarks", skey: "delivery")
        let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await lifecycle.create(
            space: space,
            owner: authorityDID,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: .accountOAuthForTesting(subject: authorityDID, scopes: ["atproto"])
        )
        let credential = AuthorizationContext.spaceCredential(.init(
            subject: writer,
            space: space,
            permissions: [.read],
            expiresAt: Date(timeIntervalSinceNow: 3_600)
        ))
        let serviceIdentity = "did:web:events.bulleted.example#bulleted_events"
        let serviceEndpoint = "https://events.bulleted.example"
        let legacyEndpoint = "https://legacy.example/sink"
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: serviceEndpoint,
                repository: nil,
                expiresAt: Date(timeIntervalSinceNow: 3_600),
                service: serviceIdentity
            ),
            authorization: credential
        )
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: legacyEndpoint,
                repository: "did:plc:other-writer",
                expiresAt: Date(timeIntervalSinceNow: 3_600),
                service: "did:web:other.example#service",
                serviceDID: "did:web:other.example"
            ),
            authorization: credential
        )

        let recordingTransport = RecordingPostTransport()
        let recordingIssuer = RecordingServiceIssuer()
        let publicAddress = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
        let transport = HTTPPermissionedSpaceNotificationFanoutTransport(
            database: database,
            destinations: try StaticSwanSpaceNotificationDestinations(),
            serviceAuthentication: recordingIssuer,
            poster: OAuthBoundedJSONPoster(
                policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                resolver: FixedHostnameResolver(answer: publicAddress),
                transport: recordingTransport
            )
        )
        let writeRow = PersistedSpaceNotificationFanout(
            id: UUID(),
            sourceIssuer: authorityDID,
            sourceEventID: UUID().uuidString.lowercased(),
            kind: .write,
            space: space,
            repository: writer,
            wireRevision: "2222222222222",
            commitment: Data(repeating: 0x2C, count: 32),
            endpoint: serviceEndpoint,
            attempts: 0
        )
        try await transport.deliver(writeRow)

        let posts = await recordingTransport.posts()
        XCTAssertEqual(posts.count, 1)
        let post = try XCTUnwrap(posts.first)
        XCTAssertEqual(
            post.url.absoluteString,
            "\(serviceEndpoint)/xrpc/com.atproto.space.notifyWrite"
        )
        let body = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: post.body) as? [String: Any]
        )
        XCTAssertEqual(body["space"] as? String, space.rawValue)
        XCTAssertEqual(body["repo"] as? String, writer)
        XCTAssertEqual(body["rev"] as? String, "2222222222222")
        XCTAssertNotNil(body["hash"], "the commit hash closes the listRepos propagation loop")
        let issued = await recordingIssuer.issued()
        XCTAssertEqual(issued.count, 1)
        XCTAssertEqual(issued.first?.issuer, authorityDID)
        XCTAssertEqual(issued.first?.audience, serviceIdentity)
        XCTAssertEqual(issued.first?.method, "com.atproto.space.notifyWrite")

        // A write row whose registration is LEGACY delivers nothing and does
        // not throw — the lease worker acknowledges it as done.
        let legacyRow = PersistedSpaceNotificationFanout(
            id: UUID(),
            sourceIssuer: authorityDID,
            sourceEventID: UUID().uuidString.lowercased(),
            kind: .write,
            space: space,
            repository: writer,
            wireRevision: "2222222222223",
            commitment: Data(repeating: 0x2D, count: 32),
            endpoint: legacyEndpoint,
            attempts: 0
        )
        try await transport.deliver(legacyRow)
        let afterLegacy = await recordingTransport.posts()
        XCTAssertEqual(afterLegacy.count, 1, "a legacy registration is not a dynamic destination")

        // Withdrawn (expired) registration: the same service row becomes a
        // safe no-op rather than a send to a stale endpoint.
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: serviceEndpoint,
                repository: nil,
                expiresAt: Date(timeIntervalSinceNow: 61),
                service: serviceIdentity
            ),
            authorization: credential
        )
        let staleRow = PersistedSpaceNotificationFanout(
            id: UUID(),
            sourceIssuer: authorityDID,
            sourceEventID: UUID().uuidString.lowercased(),
            kind: .write,
            space: space,
            repository: writer,
            wireRevision: "2222222222224",
            commitment: Data(repeating: 0x2E, count: 32),
            endpoint: serviceEndpoint,
            attempts: 0
        )
        // Not expired yet — delivers; this is the positive control that the
        // stale probe below refuses for the RIGHT reason.
        try await transport.deliver(staleRow)
        let afterStale = await recordingTransport.posts()
        XCTAssertEqual(afterStale.count, 2)

        // Withdrawn registration: the subscriber unregisters, so the stored row is removed.
        try await database.unregisterSpaceNotification(
            space: space,
            service: serviceIdentity,
            authorization: credential
        )
        let withdrawnRow = PersistedSpaceNotificationFanout(
            id: UUID(),
            sourceIssuer: authorityDID,
            sourceEventID: UUID().uuidString.lowercased(),
            kind: .write,
            space: space,
            repository: writer,
            wireRevision: "2222222222225",
            commitment: Data(repeating: 0x2F, count: 32),
            endpoint: serviceEndpoint,
            attempts: 0
        )
        try await transport.deliver(withdrawnRow)
        let afterWithdrawal = await recordingTransport.posts()
        XCTAssertEqual(
            afterWithdrawal.count, 2,
            "a withdrawn registration must be a silent no-op"
        )
    }

    func testDeletedSpaceFanoutRetainsDestinationsUntilDeliveryAndCancelsOldLeasesOnRecreate() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanDeletedNotifyDelivery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
        do {
            let now = Date()
            let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "deleted-delivery")
            let sibling = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "retained-delivery")
            let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
            let configuration = try SimpleSpaceConfiguration(
                readPolicy: .memberList, writePolicy: .memberList, appAccess: .open
            )
            let owner = AuthorizationContext.accountOAuthForTesting(subject: authority, scopes: ["atproto"])
            let service = "did:web:events.example#notifications"
            let endpoint = "https://events.example"
            for target in [space, sibling] {
                _ = try await lifecycle.create(
                    space: target, owner: authority, configuration: configuration, authorization: owner
                )
                try await database.registerSpaceNotification(
                    .init(space: target, endpoint: endpoint, repository: nil,
                          expiresAt: now.addingTimeInterval(3_600), service: service),
                    authorization: .spaceCredential(.init(
                        subject: writer, space: target, permissions: [.read],
                        expiresAt: now.addingTimeInterval(3_600)
                    ))
                )
            }
            let signer = SigningNotificationServiceIssuer()
            let posts = RecordingPostTransport(failuresRemaining: 1)
            let transport = HTTPPermissionedSpaceNotificationFanoutTransport(
                database: database,
                destinations: try StaticSwanSpaceNotificationDestinations(),
                serviceAuthentication: signer,
                poster: OAuthBoundedJSONPoster(
                    policy: try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 2),
                    resolver: FixedHostnameResolver(answer: try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))),
                    transport: posts
                )
            )
            let worker = PermissionedSpaceNotificationFanoutDeliveryWorker(database: database, transport: transport)
            _ = try await database.deleteSimpleSpace(space: space, authorization: owner, now: now)
            let pending = try await database.pendingNotificationFanout()
            XCTAssertEqual(pending.count, 1)
            let event = try XCTUnwrap(pending.first)
            XCTAssertEqual(event.kind, .deleted)
            let firstAttempt = try await worker.deliverNext(now: now)
            XCTAssertEqual(firstAttempt, .failed(eventID: event.id, attempts: 1))

            // Retrying an already committed deletion must retain the destination
            // while its failed delivery is waiting for a durable retry.
            _ = try await database.deleteSimpleSpace(space: space, authorization: owner, now: now)
            let retained = try await database.spaceNotificationRegistrationService(
                space: space, endpoint: endpoint, repository: nil
            )
            XCTAssertEqual(retained, service)
            let retainedEvents = try await database.pendingNotificationFanout()
            XCTAssertEqual(retainedEvents.map(\.id), [event.id])
            let delivered = try await worker.deliverNext(now: now.addingTimeInterval(2))
            XCTAssertEqual(delivered, .delivered(eventID: event.id))

            let captured = await posts.posts()
            XCTAssertEqual(captured.count, 2)
            let verifier = DurableSpaceServiceAuthenticationVerifier(
                publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                    PinnedSpaceServicePublicKey(issuer: authority, generation: 1, publicKey: signer.key.publicKey),
                ])
            )
            for post in captured {
                XCTAssertEqual(post.url.absoluteString, "\(endpoint)/xrpc/com.atproto.space.notifySpaceDeleted")
                let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: post.body) as? [String: String])
                XCTAssertEqual(body, ["space": space.rawValue])
                let authorization = try XCTUnwrap(post.headers["authorization"])
                XCTAssertTrue(authorization.hasPrefix("Bearer "))
                let verified = try await verifier.authenticate(
                    String(authorization.dropFirst("Bearer ".count)),
                    expectedAudience: service,
                    expectedMethod: "com.atproto.space.notifySpaceDeleted",
                    expectedRequestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space),
                    now: Date()
                )
                XCTAssertEqual(verified.issuer, authority)
                XCTAssertEqual(verified.audience, service)
                XCTAssertEqual(verified.eventID, event.id.uuidString)
            }
            let remaining = try await database.pendingNotificationFanout()
            XCTAssertTrue(remaining.isEmpty)
            let retired = try await database.isSpaceNotificationRegistrationActive(
                space: space, endpoint: endpoint, repository: nil
            )
            XCTAssertFalse(retired, "acknowledging the final deletion releases its retained registration")
            let siblingActive = try await database.isSpaceNotificationRegistrationActive(
                space: sibling, endpoint: endpoint, repository: nil
            )
            XCTAssertTrue(siblingActive)

            // An already leased deletion from the previous incarnation must
            // not target a new registration at the same space and endpoint.
            _ = try await lifecycle.create(
                space: space, owner: authority, configuration: configuration, authorization: owner
            )
            let registration = AuthorizedSpaceNotificationRegistration(
                space: space, endpoint: endpoint, repository: nil,
                expiresAt: now.addingTimeInterval(3_600), service: service
            )
            let credential = AuthorizationContext.spaceCredential(.init(
                subject: writer, space: space, permissions: [.read], expiresAt: now.addingTimeInterval(3_600)
            ))
            try await database.registerSpaceNotification(registration, authorization: credential)
            _ = try await database.deleteSimpleSpace(space: space, authorization: owner)
            let oldLeaseValue = try await database.leaseNextNotificationFanout(leaseDuration: 30)
            let oldLease = try XCTUnwrap(oldLeaseValue)
            _ = try await lifecycle.create(
                space: space, owner: authority, configuration: configuration, authorization: owner
            )
            try await database.registerSpaceNotification(registration, authorization: credential)
            try await transport.deliver(oldLease.event)
            let afterRecreate = await posts.posts()
            XCTAssertEqual(afterRecreate.count, 2, "a canceled old lease must not delete the new incarnation remotely")
            let oldCompletion = try await database.completeNotificationFanoutLease(
                eventID: oldLease.event.id, token: oldLease.token
            )
            XCTAssertFalse(oldCompletion)
            let pendingAfterRecreate = try await database.pendingNotificationFanout()
            XCTAssertTrue(pendingAfterRecreate.isEmpty)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// The route passes only the authenticated space deletion signal to its
    /// sync recipient. Repository ownership and retained member data are
    /// handled by the durable receiver, not changed by service authentication.
    func testDeletionTokenIsBoundToTheBodySpace() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let bindings = try SwanSpaceNotificationRecipientBindings(
                bindings: [NotificationServiceVerifier.boundRecipientIdentity: writer]
            )
            let app = try fixture.server(recipientBindings: bindings)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.deletionBinding"))
            let headers: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer authority-bound-recipient-token"
                return fields
            }()

            try await app.test(.router) { client in
                // Matches the bound space
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifySpaceDeleted",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // A token with mismatched req / bad digest is rejected
                var badDigestHeaders = headers
                badDigestHeaders[.authorization] = "Bearer bad-digest-token"
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifySpaceDeleted",
                    method: .post,
                    headers: badDigestHeaders,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
                // A space under a different authority is refused by the route.
                let foreign = try SpaceURI(
                    authority: writer,
                    spaceType: "app.bsky.bookmarks",
                    skey: "foreign"
                )
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifySpaceDeleted",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: "{\"space\":\"\(foreign.rawValue)\"}")
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
                }
            }

            let deletions = await fixture.directory.deletions()
            let expectedDelDigest = SpaceNotificationRequestDigest.deletion(space: fixture.space)
            XCTAssertEqual(
                deletions,
                [
                    .init(
                        space: fixture.space,
                        issuer: authority,
                        audience: writer,
                        eventID: "service-event-5",
                        requestBodyDigest: expectedDelDigest
                    ),
                ]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testRegisterNotifyRejectsMismatchedServiceJWTAudience() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        let app = try fixture.server().buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.aud"))
        let wrongAudienceHeaders = try fixture.credentialHeaders(serviceAuth: "wrong-audience-token")
        let registerBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/xrpc/com.atproto.space.notifyWrite\"}")
        try await app.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.space.registerNotify",
                method: .post,
                headers: try SpaceCredentialDPoPTestSupport.refreshed(wrongAudienceHeaders, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"),
                body: registerBody
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
                XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
            }
        }
        try await fixture.close()
    }

    func testUnregisterNotifyRejectsMismatchedServiceJWTAudience() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        let app = try fixture.server().buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.aud"))
        let wrongAudienceHeaders = try fixture.credentialHeaders(serviceAuth: "wrong-audience-token")
        let unregisterBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"service\":\"did:web:events.bulleted.example#bulleted_events\"}")
        try await app.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.space.unregisterNotify",
                method: .post,
                headers: try SpaceCredentialDPoPTestSupport.refreshed(wrongAudienceHeaders, path: "/xrpc/com.atproto.space.unregisterNotify", method: "POST"),
                body: unregisterBody
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
                XCTAssertEqual(try notificationErrorCode(response.body), "Unauthorized")
            }
        }
        try await fixture.close()
    }

    func testNotificationRecoveryServiceDrainsCommittedWriterAndAuthorityQueues() async throws {
        let fixture = try NotificationRecoveryFixture()
        let database = try await fixture.open()
        defer {
            Task { try? await database.close() }
            fixture.cleanup()
        }
        try await fixture.prepareCommittedQueues(on: database)

        let transport = NotificationRecoveryTransport()
        let service = SwanNotificationRecoveryService(
            databases: [database],
            makeOutboxTransport: { _ in transport },
            makeFanoutTransport: { _ in transport },
            configuration: try notificationRecoveryConfiguration()
        )
        let running = Task { try? await service.run() }
        defer { running.cancel() }

        for _ in 0 ..< 100 {
            let counts = await transport.counts()
            if counts.outbox == 1 && counts.fanout == 1 { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let counts = await transport.counts()
        XCTAssertEqual(counts.outbox, 1)
        XCTAssertEqual(counts.fanout, 1)
        let remainingOutbox = try await database.pendingOutbox()
        let remainingFanout = try await database.pendingNotificationFanout()
        XCTAssertTrue(remainingOutbox.isEmpty)
        XCTAssertTrue(remainingFanout.isEmpty)
        running.cancel()
        _ = await running.value
    }

    func testCommittedWriteSurvivesStopAndRecoversIdempotentlyFromPreopenedDirectory() async throws {
        let fixture = try PreopenedRecoveryFixture()
        defer { fixture.cleanup() }
        try await fixture.createCommittedWrite()

        // The first process opens the exact startup directory used by HTTP
        // writes, observes the committed event, then stops before delivery.
        let first = try await fixture.openRuntime()
        let firstDatabases = try await first.directory.notificationRecoveryDatabases()
        let firstPending = try await XCTUnwrap(firstDatabases.first).pendingOutbox()
        XCTAssertEqual(firstPending.count, 1)
        try await first.close()

        // The restarted process reopens the same durable inventory. The
        // transport records one logical receiver effect, then simulates a
        // lost acknowledgement so the stable event ID is delivered twice.
        let restarted = try await fixture.openRuntime()
        let transport = IdempotentCrashRecoveryTransport()
        let service = try await SwanNotificationRecoveryService.fromPreopenedDirectory(
            restarted.directory,
            makeOutboxTransport: { _ in transport },
            makeFanoutTransport: { _ in transport },
            configuration: try notificationRecoveryConfiguration()
        )
        let running = Task { try? await service.run() }
        defer { running.cancel() }

        for _ in 0 ..< 200 {
            let state = await transport.state()
            let restartedDatabases = try await restarted.directory.notificationRecoveryDatabases()
            let remaining = (try? await XCTUnwrap(restartedDatabases.first).pendingOutbox()) ?? []
            if state.attempts >= 2 && remaining.isEmpty { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let state = await transport.state()
        XCTAssertEqual(state.attempts, 2)
        XCTAssertEqual(state.uniqueEffects, 1)
        let restartedDatabases = try await restarted.directory.notificationRecoveryDatabases()
        let remaining = try await XCTUnwrap(restartedDatabases.first).pendingOutbox()
        XCTAssertTrue(remaining.isEmpty)
        running.cancel()
        _ = await running.value
        try await restarted.close()
    }
}

private struct NotificationHTTPFixture {
    let root: URL
    let space: SpaceURI
    let authority: String
    let writer: String
    let key: P256.Signing.PrivateKey
    let control: SQLiteControlDatabase
    let runtime: SwanOAuthRuntime
    let directory: NotificationHTTPDirectory

    static func make(authority: String, writer: String) async throws -> NotificationHTTPFixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceNotificationHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
            return NotificationHTTPFixture(
                root: root,
                space: space,
                authority: authority,
                writer: writer,
                key: P256.Signing.PrivateKey(),
                control: control,
                runtime: try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xA1, count: 32)),
                directory: NotificationHTTPDirectory(authority: authority, writer: writer)
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func server(
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil,
        decodeObserver: (@Sendable () async -> Void)? = nil,
        recipientBindings: SwanSpaceNotificationRecipientBindings = .empty,
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil,
        serviceAuthentication: (any SpaceServiceAuthenticationVerifier)? = nil,
        spacesOpenInterop: SwanSpacesOpenInteropConfiguration? = nil
    ) throws -> SwanHTTPServer {
        let serviceAuthentication = serviceAuthentication
            ?? NotificationServiceVerifier(authority: authority, writer: writer)
        let credentialKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: authority, generation: 1, publicKey: key.publicKey),
        ])
        return SwanHTTPServer(
            profile: try ProtocolProfile.load(from: notificationPackageRoot().appending(path: "Profiles/permissioned-data-0016-2026-09-19.json")),
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: URL(string: "https://swan.example")!),
            oauthRuntime: runtime,
            authenticatedGetSpaceDirectory: directory,
            accountControlStore: control,
            spaceCredentialConfiguration: .init(
                authoritySigningKeys: NotificationNoSigningKeyResolver(),
                delegationPublicKeys: UnavailableSpaceDelegationPublicKeyResolver(),
                credentialPublicKeys: credentialKeys
            ),
            spaceNotificationConfiguration: decodeObserver.map {
                SwanSpaceNotificationHTTPConfiguration(
                    serviceAuthentication: serviceAuthentication,
                    recipientBindings: recipientBindings,
                    serviceEndpointResolver: serviceEndpointResolver,
                    notificationJSONDecodeObserver: $0
                )
            } ?? .init(
                serviceAuthentication: serviceAuthentication,
                recipientBindings: recipientBindings,
                serviceEndpointResolver: serviceEndpointResolver
            ),
            spacesOpenInterop: spacesOpenInterop,
            jsonWriteAdmission: jsonWriteAdmission
        )
    }

    func credentialHeaders(serviceAuth: String? = "register-service-token") throws -> HTTPFields {
        let credential = try PermissionedDataJWT.createSpaceCredential(
            issuer: authority, space: space, key: key,
            dpopKeyThumbprint: try SpaceCredentialDPoPTestSupport.thumbprint
        )
        var headers = try SpaceCredentialDPoPTestSupport.headers(
            token: credential, path: "/xrpc/com.atproto.space.registerNotify", method: "POST"
        )
        headers[.contentType] = "application/json"
        if let serviceAuth {
            headers[.init("Atproto-Service-Auth")!] = "Bearer \(serviceAuth)"
        }
        return headers
    }

    func credentialOnlyHeaders() throws -> HTTPFields {
        try credentialHeaders(serviceAuth: nil)
    }

    func registerHeaders(for serviceDID: String? = nil) throws -> HTTPFields {
        var headers = try credentialHeaders()
        let did = serviceDID ?? writer
        headers[HTTPField.Name("atproto-service-auth")!] = "Bearer service-token:\(did)"
        return headers
    }

    func foreignAudienceRegisterHeaders(for serviceDID: String? = nil) throws -> HTTPFields {
        var headers = try credentialHeaders()
        let did = serviceDID ?? writer
        headers[HTTPField.Name("atproto-service-auth")!] = "Bearer foreign-audience-token:\(did)"
        return headers
    }

    /// The reference presentation binds the credential and request proof to
    /// the same holder key, with the credential hash in the proof's ath claim.
    func dpopSchemeCredentialHeaders(for serviceDID: String? = nil) throws -> HTTPFields {
        try registerHeaders(for: serviceDID)
    }

    func close() async throws {
        try await control.close()
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private actor NotificationDecodeBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func arriveAndWait() async {
        entered = true
        let waiters = entryWaiters
        entryWaiters.removeAll()
        waiters.forEach { $0.resume() }
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}

private struct NotificationRecoveryFixture {
    let root: URL
    let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    let writer = "did:plc:bcdefghijklmnopqrstuvwxy"
    let reader = "did:plc:cdefghijklmnopqrstuvwxyz"
    let space: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanNotificationRecoveryServiceTests-\(UUID().uuidString)")
        space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "recovery")
    }

    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
    }

    func prepareCommittedQueues(on database: SQLiteAccountDatabase) async throws {
        let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await lifecycle.create(
            space: space,
            owner: authority,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
        )
        _ = try await lifecycle.addMember(
            space: space,
            member: writer,
            authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
        )
        let now = Date()
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: "https://receiver.example/xrpc/com.atproto.space.notifyWrite",
                repository: writer,
                expiresAt: now.addingTimeInterval(3_600),
                service: "did:web:receiver.example#service",
                serviceDID: "did:web:receiver.example"
            ),
            authorization: .spaceCredential(.init(
                subject: reader,
                space: space,
                permissions: [.read],
                expiresAt: now.addingTimeInterval(3_600)
            )),
            now: now
        )
        _ = try await database.appendOplogAndOutbox(
            space: space,
            revision: 1,
            operation: Data([0xA1, 0x61, 0x61, 0x01]),
            commitment: Data(repeating: 0xA4, count: 32)
        )
        try await database.receiveSpaceWriteNotification(
            .init(
                eventID: "writer-recovery-event",
                space: space,
                repository: writer,
                wireRevision: "2222222222223",
                commitment: Data(repeating: 0xA5, count: 32),
                issuer: writer,
                audience: authority,
                requestBodyDigest: SpaceNotificationRequestDigest.write(
                    space: space,
                    repository: writer,
                    wireRevision: "2222222222223",
                    commitment: Data(repeating: 0xA5, count: 32)
                )
            ),
            now: now
        )
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private actor NotificationRecoveryTransport:
    PermissionedSpaceOutboxTransport,
    PermissionedSpaceNotificationFanoutTransport
{
    private var outboxCount = 0
    private var fanoutCount = 0

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        XCTAssertFalse(notification.payload.isEmpty)
        outboxCount += 1
    }

    func deliver(_ notification: PersistedSpaceNotificationFanout) async throws {
        XCTAssertEqual(notification.kind, .write)
        XCTAssertNil(String(describing: notification).range(of: "private record value"))
        fanoutCount += 1
    }

    func counts() -> (outbox: Int, fanout: Int) {
        (outboxCount, fanoutCount)
    }
}

private actor IdempotentCrashRecoveryTransport:
    PermissionedSpaceOutboxTransport,
    PermissionedSpaceNotificationFanoutTransport
{
    private var attempts = 0
    private var applied = Set<UUID>()

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        attempts += 1
        applied.insert(notification.id)
        if attempts == 1 {
            throw SwanError.unavailable("simulated lost delivery acknowledgement")
        }
    }

    func deliver(_: PersistedSpaceNotificationFanout) async throws {}

    func state() -> (attempts: Int, uniqueEffects: Int) {
        (attempts, applied.count)
    }
}

private struct PreopenedRecoveryFixture {
    let root: URL
    let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    let space: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPreopenedRecoveryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "preopened-recovery"
        )
    }

    func createCommittedWrite() async throws {
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try .init(
                did: authority,
                canonicalHandle: "recovery.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let database = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: authority
            )
            let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
            _ = try await lifecycle.create(
                space: space,
                owner: authority,
                configuration: try .init(readPolicy: .public, writePolicy: .public, appAccess: .open),
                authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
            )
            _ = try await database.appendOplogAndOutbox(
                space: space,
                revision: 1,
                operation: Data([0xA1, 0x61, 0x61, 0x01]),
                commitment: Data(repeating: 0xB4, count: 32)
            )
            try await database.close()
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func openRuntime() async throws -> PreopenedRecoveryRuntime {
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            return .init(
                control: control,
                directory: try await .bootstrap(
                    dataDirectory: root,
                    controlStore: control,
                    publicIdentityVerifier: nil
                )
            )
        } catch {
            try? await control.close()
            throw error
        }
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private struct PreopenedRecoveryRuntime {
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory

    func close() async throws {
        try await directory.close()
        try await control.close()
    }
}

private func notificationRecoveryConfiguration() throws -> PermissionedSpaceOutboxDeliveryConfiguration {
    try .init(
        leaseDuration: 1,
        idlePollInterval: 0.01,
        initialFailureBackoff: 0.01,
        maximumFailureBackoff: 0.01
    )
}

private actor NotificationHTTPDirectory: AuthorizedSimpleSpaceDirectory, AuthorizedSpaceNotificationDirectory {
    private let authority: String
    private let writer: String
    private var registrationsValue: [AuthorizedSpaceNotificationRegistration] = []
    private var notificationsValue: [AuthorizedSpaceWriteNotification] = []
    private var deletionsValue: [RecordedSpaceDeletion] = []

    init(authority: String, writer: String) {
        self.authority = authority
        self.writer = writer
    }

    func space(_ space: SpaceURI, authorization _: AuthorizationContext) async throws -> AuthenticatedSimpleSpaceDescription? {
        guard space.authority == authority else { return nil }
        return .init(space: space, configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open))
    }

    func close() async throws {}

    func listSpaceWriters(
        space: SpaceURI,
        limit _: Int,
        cursor _: String?,
        authorization _: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter] {
        guard space.authority == authority else { throw AuthorizedSimpleSpaceLifecycleError.notFound }
        return notificationsValue.map {
            .init(space: space, repository: $0.repository, wireRevision: $0.wireRevision, commitment: $0.commitment)
        }
    }

    func registerSpaceNotification(
        _ registration: AuthorizedSpaceNotificationRegistration,
        serviceDID: String,
        authorization _: AuthorizationContext
    ) async throws {
        registrationsValue.removeAll { $0.endpoint == registration.endpoint }
        registrationsValue.append(registration)
    }
    func unregisterSpaceNotification(
        space: SpaceURI,
        ownerServiceDID: String,
        deliveryServiceDID: String?,
        authorization _: AuthorizationContext
    ) async throws {
        guard space.authority == authority else {
            throw AuthorizedSimpleSpaceLifecycleError.notFound
        }
        let baseOwner = serviceIssuerDID(ownerServiceDID) ?? ownerServiceDID
        if let requested = deliveryServiceDID {
            if !requested.contains("#") && (requested == ownerServiceDID || requested == baseOwner) {
                registrationsValue.removeAll {
                    $0.space == space &&
                    ($0.ownerServiceDID == ownerServiceDID || $0.ownerServiceDID == baseOwner || $0.serviceDID == baseOwner) &&
                    ($0.deliveryServiceDID == requested || $0.service == requested || ($0.deliveryServiceDID == nil && $0.service == nil))
                }
            } else {
                registrationsValue.removeAll {
                    $0.space == space &&
                    ($0.ownerServiceDID == ownerServiceDID || $0.ownerServiceDID == baseOwner || $0.serviceDID == baseOwner) &&
                    ($0.deliveryServiceDID == requested || $0.service == requested)
                }
            }
        } else {
            registrationsValue.removeAll {
                $0.space == space &&
                ($0.ownerServiceDID == ownerServiceDID || $0.ownerServiceDID == baseOwner || $0.serviceDID == baseOwner) &&
                ($0.deliveryServiceDID == nil && $0.service == nil)
            }
        }
    }

    func unregisterSpaceNotification(
        space: SpaceURI,
        serviceDID: String,
        authorization: AuthorizationContext
    ) async throws {
        let baseDID = serviceIssuerDID(serviceDID) ?? serviceDID
        try await unregisterSpaceNotification(
            space: space,
            ownerServiceDID: baseDID,
            deliveryServiceDID: serviceDID,
            authorization: authorization
        )
    }

    func receiveSpaceWriteNotification(_ notification: AuthorizedSpaceWriteNotification) async throws {
        guard notification.space.authority == authority, notification.repository == writer else {
            throw SwanError.unauthorized("notification is invalid")
        }
        if !notificationsValue.contains(where: { $0.eventID == notification.eventID }) {
            notificationsValue.append(notification)
        }
    }

    func receiveSpaceDeletionNotification(
        space: SpaceURI,
        issuer: String,
        audience: String,
        eventID: String,
        requestBodyDigest: String
    ) async throws {
        deletionsValue.append(
            .init(space: space, issuer: issuer, audience: audience, eventID: eventID, requestBodyDigest: requestBodyDigest)
        )
    }

    func registrations() -> [AuthorizedSpaceNotificationRegistration] { registrationsValue }
    func notifications() -> [AuthorizedSpaceWriteNotification] { notificationsValue }
    func deletions() -> [RecordedSpaceDeletion] { deletionsValue }
}

/// The deletion arguments the route hands to the durable receiver. The route
/// is the only place a space can still be substituted, so record it exactly.
struct RecordedSpaceDeletion: Sendable, Equatable {
    let space: SpaceURI
    let issuer: String
    let audience: String
    let eventID: String
    let requestBodyDigest: String
}

private struct NotificationNoSigningKeyResolver: SpaceCredentialSigningKeyResolver {
    func signingKey(for _: String) async throws -> SpaceCredentialAuthoritySigningKey? { nil }
}

/// Canned DID documents for the register-time service resolution tests —
/// resolution logic runs for real, only the network fetch is substituted.
private struct StubNotificationDIDDocumentFetcher: SwanDIDDocumentFetching {
    let documents: [String: Data]

    func documentJSON(forDID did: String) async throws -> Data {
        guard let data = documents[did] else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return data
    }
}

/// Answers every hostname with one fixed public address, so the poster's
/// pre- and post-request DNS policy both approve the same peer.
private struct FixedHostnameResolver: OAuthHostnameResolving {
    let answer: OAuthIPAddress
    func resolve(host _: String) async throws -> [OAuthIPAddress] { [answer] }
}

private actor RecordingPostTransport: OAuthRemotePostTransport {
    struct RecordedPost: Sendable {
        let url: URL
        let headers: [String: String]
        let body: Data
    }

    private var recorded: [RecordedPost] = []
    private var failuresRemaining: Int

    init(failuresRemaining: Int = 0) {
        self.failuresRemaining = failuresRemaining
    }

    func post(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        headers: [String: String],
        body: Data,
        timeout _: TimeInterval,
        maximumResponseBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        recorded.append(.init(url: url, headers: headers, body: body))
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw SwanError.unavailable("notification delivery failed")
        }
        return .init(
            status: 200,
            headers: ["content-length": ["0"]],
            body: Data(),
            responseURL: url,
            connectedPeerAddress: approvedPeers.first
        )
    }

    func posts() -> [RecordedPost] { recorded }
}

private struct SigningNotificationServiceIssuer: SpaceServiceAuthenticationIssuer {
    let key = P256.Signing.PrivateKey()

    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        requestBodyDigest: String?,
        now: Date
    ) async throws -> String {
        try SpaceServiceJWT.create(
            issuer: issuer, audience: audience, method: method, eventID: eventID,
            requestBodyDigest: requestBodyDigest, key: key, now: now
        )
    }
}

private actor RecordingServiceIssuer: SpaceServiceAuthenticationIssuer {
    struct Issued: Sendable {
        let issuer: String
        let audience: String
        let method: String
    }

    private var recorded: [Issued] = []

    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID _: String,
        requestBodyDigest: String? = nil,
        now _: Date = Date()
    ) async throws -> String {
        recorded.append(.init(issuer: issuer, audience: audience, method: method))
        return "recorded-service-token"
    }

    func issued() -> [Issued] { recorded }
}

private struct NotificationServiceVerifier: SpaceServiceAuthenticationVerifier {
    struct TokenMeta {
        let issuer: String
        let audience: String
        let eventID: String
        let requestBodyDigest: String?
    }

    /// The pinned reference PDS registers a raw endpoint as the recipient
    /// service identity, so the binding key is not a DID.
    static let boundRecipientIdentity =
        "https://receiver.example/xrpc/com.atproto.space.notifySpaceDeleted"

    let authority: String
    let writer: String

    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        expectedRequestBodyDigest: String?,
        now _: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        let meta: TokenMeta
        if compact.hasPrefix("service-token:") {
            let issuer = String(compact.dropFirst("service-token:".count))
            meta = TokenMeta(
                issuer: issuer,
                audience: authority,
                eventID: "service-event-\(UUID().uuidString)",
                requestBodyDigest: expectedRequestBodyDigest
            )
        } else if compact.hasPrefix("foreign-audience-token:") {
            let issuer = String(compact.dropFirst("foreign-audience-token:".count))
            meta = TokenMeta(
                issuer: issuer,
                audience: "did:plc:foreignauthority99999",
                eventID: "service-event-foreign",
                requestBodyDigest: nil
            )
        } else {
            switch (compact, expectedMethod) {
            case ("register-service-token", "com.atproto.space.registerNotify"):
                meta = TokenMeta(
                    issuer: "did:web:events.bulleted.example",
                    audience: authority,
                    eventID: "service-event-reg",
                    requestBodyDigest: nil
                )
            case ("unregister-service-token", "com.atproto.space.unregisterNotify"):
                meta = TokenMeta(
                    issuer: "did:web:events.bulleted.example",
                    audience: authority,
                    eventID: "service-event-unreg",
                    requestBodyDigest: nil
                )
            case ("wrong-audience-token", "com.atproto.space.registerNotify"),
                 ("wrong-audience-token", "com.atproto.space.unregisterNotify"):
                meta = TokenMeta(
                    issuer: "did:web:events.bulleted.example",
                    audience: "did:plc:other-authority",
                    eventID: "service-event-wrong-aud",
                    requestBodyDigest: nil
                )
            case ("writer-token", "com.atproto.space.registerNotify"),
                 ("writer-token", "com.atproto.space.unregisterNotify"):
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-registration",
                    requestBodyDigest: nil
                )
            case ("writer-token", "com.atproto.space.notifyWrite"):
                let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
                let writeDigest = SpaceNotificationRequestDigest.write(
                    space: space,
                    repository: writer,
                    wireRevision: "3l72c4e2y2222",
                    commitment: Data(repeating: 0x01, count: 32)
                )
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-1",
                    requestBodyDigest: writeDigest
                )
            case ("mismatched-digest-token", "com.atproto.space.notifyWrite"):
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-bad",
                    requestBodyDigest: "mismatched-digest"
                )
            case ("bad-digest-token", "com.atproto.space.notifySpaceDeleted"):
                meta = TokenMeta(
                    issuer: authority,
                    audience: NotificationServiceVerifier.boundRecipientIdentity,
                    eventID: "service-event-bad-digest",
                    requestBodyDigest: "sha256:mismatched-digest"
                )
            case ("bad-digest-token", "com.atproto.space.notifyWrite"):
                meta = TokenMeta(
                    issuer: writer,
                    audience: authority,
                    eventID: "service-event-bad-digest",
                    requestBodyDigest: "sha256:mismatched-digest"
                )
            case ("authority-fanout-token", "com.atproto.space.notifyWrite"):
                meta = TokenMeta(
                    issuer: authority,
                    audience: "did:plc:recipientabcdefghijklmnop",
                    eventID: "service-event-2",
                    requestBodyDigest: expectedRequestBodyDigest
                )
            case ("authority-unknown-recipient-token", "com.atproto.space.notifyWrite"):
                meta = TokenMeta(
                    issuer: authority,
                    audience: "did:plc:unknownabcdefghijklmnopqr",
                    eventID: "service-event-3",
                    requestBodyDigest: expectedRequestBodyDigest
                )
            case ("authority-unknown-recipient-token", "com.atproto.space.notifySpaceDeleted"):
                let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
                meta = TokenMeta(
                    issuer: authority,
                    audience: "did:plc:unknownabcdefghijklmnopqr",
                    eventID: "service-event-4",
                    requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space)
                )
            case ("authority-bound-recipient-token", "com.atproto.space.notifySpaceDeleted"):
                let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http")
                let sibling = try? SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "http-sibling")
                let digest: String
                if let sibling, expectedRequestBodyDigest == SpaceNotificationRequestDigest.deletion(space: sibling) {
                    digest = SpaceNotificationRequestDigest.deletion(space: sibling)
                } else {
                    digest = SpaceNotificationRequestDigest.deletion(space: space)
                }
                meta = TokenMeta(
                    issuer: authority,
                    audience: NotificationServiceVerifier.boundRecipientIdentity,
                    eventID: "service-event-5",
                    requestBodyDigest: digest
                )
            default:
                throw SwanError.unauthorized("service authentication is invalid")
            }
        }

        if let expectedAudience {
            guard meta.audience == expectedAudience else {
                throw SwanError.unauthorized("service authentication audience mismatch")
            }
        }
        if let expectedRequestBodyDigest {
            guard let tokenDigest = meta.requestBodyDigest, tokenDigest == expectedRequestBodyDigest else {
                throw SwanError.unauthorized("service authentication digest mismatch")
            }
        }
        return VerifiedSpaceServiceAuthentication(
            issuer: meta.issuer,
            audience: meta.audience,
            method: expectedMethod,
            eventID: meta.eventID,
            requestBodyDigest: meta.requestBodyDigest,
            expiresAt: Date(timeIntervalSinceNow: 60)
        )
    }
}

private func notificationPackageRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}

private func notificationPercentEncode(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
}

private func notificationJSONObject(_ body: ByteBuffer) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(body.readableBytesView)) as! [String: Any]
}

private func notificationErrorCode(_ body: ByteBuffer) throws -> String {
    try XCTUnwrap(notificationJSONObject(body)["error"] as? String)
}


// MARK: - `--enable-spaces-open-interop` (SWAN-04 / SWAN-05)

extension SpaceNotificationHTTPTests {
    private struct SignedServiceKeys {
        let writer = P256.Signing.PrivateKey()
        let authority = P256.Signing.PrivateKey()

        func verifier(authority authorityDID: String, writer writerDID: String) throws
            -> DurableSpaceServiceAuthenticationVerifier
        {
            DurableSpaceServiceAuthenticationVerifier(
                publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                    try .init(issuer: writerDID, generation: 1, publicKey: writer.publicKey),
                    try .init(issuer: authorityDID, generation: 1, publicKey: authority.publicKey),
                ])
            )
        }
    }

    private func serviceHeaders(_ token: String) -> HTTPFields {
        var fields: HTTPFields = [.contentType: "application/json"]
        fields[.authorization] = "Bearer \(token)"
        return fields
    }

    /// Hand-signs an ES256 service JWT so the test can choose a lifetime the
    /// production minter refuses to produce.
    private func handSignedServiceJWT(
        issuer: String,
        audience: String,
        method: String,
        jti: String,
        iat: Int64,
        exp: Int64,
        key: P256.Signing.PrivateKey
    ) throws -> String {
        let header = try JSONSerialization.data(
            withJSONObject: ["alg": "ES256", "typ": "JWT"],
            options: [.sortedKeys]
        )
        let payload = try JSONSerialization.data(
            withJSONObject: [
                "iss": issuer, "aud": audience, "lxm": method, "jti": jti,
                "iat": NSNumber(value: iat), "exp": NSNumber(value: exp),
            ],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let input = "\(header.base64URLEncodedString()).\(payload.base64URLEncodedString())"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: key)
        return "\(input).\(signature.base64URLEncodedString())"
    }

    /// SWAN-04: an upstream writer's notifyWrite carries no `req`. Hardened
    /// Swan refuses it; the interop flag admits it once, for either audience
    /// form, within 60 s, and still refuses a `req` that does not match.
    func testOpenInteropAdmitsUnboundUpstreamNotifyWriteOnceAndKeepsBoundChecks() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let keys = SignedServiceKeys()
            let verifier = try keys.verifier(authority: authority, writer: writer)
            let hardened = try fixture.server(serviceAuthentication: verifier)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.hardened"))
            let interop = try fixture.server(
                serviceAuthentication: verifier,
                spacesOpenInterop: .standard
            ).buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.interop"))
            let method = "com.atproto.space.notifyWrite"
            let rev = "3l72c4e2y2222"
            let hash = Data(repeating: 0x02, count: 32)
            let body = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"repo\":\"\(writer)\",\"rev\":\"\(rev)\",\"hash\":{\"$bytes\":\"\(hash.base64EncodedString())\"}}")
            let digest = SpaceNotificationRequestDigest.write(
                space: fixture.space, repository: writer, wireRevision: rev, commitment: hash
            )
            @Sendable func unbound(_ jti: String, audience: String? = nil, issuer: String? = nil, key: P256.Signing.PrivateKey? = nil) throws -> String {
                try SpaceServiceJWT.create(
                    issuer: issuer ?? writer, audience: audience ?? authority, method: method,
                    eventID: jti, key: key ?? keys.writer
                )
            }
            let upstream = try unbound("upstream-1")

            try await hardened.test(.router) { client in
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(upstream), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            try await interop.test(.router) { client in
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(upstream), body: body) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Single-use jti: the identical token is refused on replay.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(upstream), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // The `#atproto_space_host` audience form is accepted too.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-2", audience: "\(self.authority)#atproto_space_host")), body: body) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Any other audience, or an issuer other than the repo, is not.
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-3", audience: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz")), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(try unbound("upstream-4", issuer: self.authority, key: keys.authority)), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // A lifetime over 60 s is refused for unbound tokens.
                let now = Int64(Date().timeIntervalSince1970)
                let long = try self.handSignedServiceJWT(
                    issuer: self.writer, audience: self.authority, method: method,
                    jti: "upstream-long", iat: now, exp: now + 90, key: keys.writer
                )
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(long), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                // A token that carries `req` must still match the body.
                let wrongReq = try SpaceServiceJWT.create(
                    issuer: self.writer, audience: self.authority, method: method,
                    eventID: "bound-wrong", requestBodyDigest: String(repeating: "A", count: 43),
                    key: keys.writer
                )
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(wrongReq), body: body) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                let bound = try SpaceServiceJWT.create(
                    issuer: self.writer, audience: self.authority, method: method,
                    eventID: "bound-right", requestBodyDigest: digest, key: keys.writer
                )
                try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(bound), body: body) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }
            let recorded = await fixture.directory.notifications()
            XCTAssertEqual(Set(recorded.map(\.eventID)), ["upstream-1", "upstream-2", "bound-right"])
            XCTAssertTrue(recorded.allSatisfy { $0.audience == self.authority && $0.requestBodyDigest == digest })
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// SWAN-04, deletion half: an unbound authority-signed notifySpaceDeleted
    /// is admitted once under the flag and refused without it.
    func testOpenInteropAdmitsUnboundNotifySpaceDeletedOnce() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let keys = SignedServiceKeys()
            let verifier = try keys.verifier(authority: authority, writer: writer)
            let method = "com.atproto.space.notifySpaceDeleted"
            let body = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\"}")
            let token = try SpaceServiceJWT.create(
                issuer: authority, audience: "did:web:replica.example#atproto_space_syncer",
                method: method, eventID: "deleted-1", key: keys.authority
            )
            try await fixture.server(serviceAuthentication: verifier)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.deleteHardened"))
                .test(.router) { client in
                    try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(token), body: body) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                    }
                }
            try await fixture.server(serviceAuthentication: verifier, spacesOpenInterop: .standard)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.deleteInterop"))
                .test(.router) { client in
                    try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(token), body: body) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    try await client.execute(uri: "/xrpc/\(method)", method: .post, headers: self.serviceHeaders(token), body: body) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                    }
                }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// SWAN-05: under the flag, registerNotify / unregisterNotify accept the
    /// space credential alone (owner = the named service's DID), header-less
    /// registration is rate-capped, and a present Atproto-Service-Auth still
    /// proves ownership. Without the flag the header stays mandatory.
    func testOpenInteropMakesAtprotoServiceAuthOptionalOnRegistrationWithCaps() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let subscriber = "did:web:syncer.example"
            let document = """
            {"id":"\(subscriber)","service":[
                {"id":"#atproto_space_syncer","serviceEndpoint":"https://syncer.example"}
            ]}
            """
            let resolver = SwanServiceEndpointResolver(
                documents: StubNotificationDIDDocumentFetcher(
                    documents: [subscriber: Data(document.utf8)]
                )
            )
            let caps = try SwanSpacesOpenInteropConfiguration(
                maximumHeaderlessRegistrationsPerSpacePerHour: 2,
                maximumHeaderlessRegistrationsPerSubjectPerHour: 2
            )
            let registerPath = "/xrpc/com.atproto.space.registerNotify"
            let unregisterPath = "/xrpc/com.atproto.space.unregisterNotify"
            let body = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"service\":\"\(subscriber)#atproto_space_syncer\"}")
            let credentialOnly = try fixture.credentialOnlyHeaders()

            try await fixture.server(serviceEndpointResolver: resolver)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.registerHardened"))
                .test(.router) { client in
                    try await client.execute(uri: registerPath, method: .post, headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialOnly, path: registerPath, method: "POST"), body: body) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                    }
                }
            try await fixture.server(serviceEndpointResolver: resolver, spacesOpenInterop: caps)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.registerInterop"))
                .test(.router) { client in
                    for _ in 0 ..< 2 {
                        try await client.execute(uri: registerPath, method: .post, headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialOnly, path: registerPath, method: "POST"), body: body) { response in
                            XCTAssertEqual(response.status, .ok)
                        }
                    }
                    // Third header-less call in the hour exceeds the cap.
                    try await client.execute(uri: registerPath, method: .post, headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialOnly, path: registerPath, method: "POST"), body: body) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable)
                    }
                    // A present header must still prove ownership of `service`.
                    let mismatched = try fixture.registerHeaders(for: "did:web:other.example")
                    try await client.execute(uri: registerPath, method: .post, headers: try SpaceCredentialDPoPTestSupport.refreshed(mismatched, path: registerPath, method: "POST"), body: body) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                    }
                    // A legacy endpoint-only registration still needs the header.
                    let endpointOnly = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://syncer.example/x\"}")
                    try await client.execute(uri: registerPath, method: .post, headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialOnly, path: registerPath, method: "POST"), body: endpointOnly) { response in
                        XCTAssertEqual(response.status, .unauthorized)
                    }
                    try await client.execute(uri: unregisterPath, method: .post, headers: try SpaceCredentialDPoPTestSupport.refreshed(credentialOnly, path: unregisterPath, method: "POST"), body: body) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                }
            let registered = await fixture.directory.registrations()
            XCTAssertTrue(registered.isEmpty)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }
}
