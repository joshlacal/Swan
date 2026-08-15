import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
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
                        headers: try fixture.bearerHeaders(), body: body
                    )
                }
                await barrier.waitUntilEntered()
                XCTAssertEqual(admission.snapshot, .init(
                    activeLeases: 1, reservedRequestBytes: maximum
                ))
                let second = try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify", method: .post,
                    headers: try fixture.bearerHeaders(), body: body
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
            let credentialHeaders = try fixture.bearerHeaders()
            let encodedSpace = notificationPercentEncode(fixture.space.rawValue)
            let expectedWriter = writer
            let registerBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"endpoint\":\"https://receiver.example/xrpc/com.atproto.space.notifyWrite\"}")
            let commitment = Data(repeating: 0xAB, count: 32).base64EncodedString()
            let writeBody = ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"repo\":\"\(writer)\",\"rev\":\"2222222222222\",\"hash\":{\"$bytes\":\"\(commitment)\"}}")
            let serviceHeaders: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer writer-token"
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
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
                    body: registerBody
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    let value = try notificationJSONObject(response.body)
                    XCTAssertEqual(Set(value.keys), ["expiresAt"])
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifyWrite",
                    method: .post,
                    headers: serviceHeaders,
                    body: writeBody
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
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
                    headers: credentialHeaders
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let value = try notificationJSONObject(response.body)
                    let repos = try XCTUnwrap(value["repos"] as? [[String: Any]])
                    XCTAssertEqual(repos.count, 1)
                    XCTAssertEqual(repos.first?["did"] as? String, expectedWriter)
                    XCTAssertEqual(repos.first?["rev"] as? String, "2222222222222")
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
                    headers: credentialHeaders,
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

    /// A `notifySpaceDeleted` service JWT carries `iss`, `aud`, `lxm`, `jti`
    /// and time claims only — no space. The route can therefore only check
    /// that the body space's authority equals the issuer
    /// (`SwanSpaceNotificationXRPC.swift:209`), so one valid token authorizes a
    /// deletion for *any* space under that authority. Adding a space claim is a
    /// wire change the pinned reference PDS does not emit and is deliberately
    /// not made here; this pins the residual so the durable participation
    /// precondition stays the control that bounds it.
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
            let credentialHeaders = try fixture.bearerHeaders()
            let spaceURI = fixture.space.rawValue
            let registerBody: @Sendable (String) -> ByteBuffer = { fields in
                ByteBuffer(string: "{\"space\":\"\(spaceURI)\",\(fields)}")
            }
            try await app.test(.router) { client in
                // Fragment-qualified service → the matching entry's endpoint.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
                    body: registerBody("\"service\":\"\(subscriber)#bulleted_events\"")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(Set(try notificationJSONObject(response.body).keys), ["expiresAt"])
                }
                // `service` decides when both are sent: the supplied endpoint
                // is ignored in favour of the resolved one.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
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
                    headers: credentialHeaders,
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
                        headers: credentialHeaders,
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
                    headers: credentialHeaders,
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

    /// Erratum 03 addendum (defect class instance #8): the reference presents
    /// a space credential under the `DPoP` scheme, and Swan's Bearer-only
    /// reader answered a conformant presentation with 401 — the reference's
    /// own recorded lesson about its `bearer_token`. The DPoP-scheme
    /// presentation registers; a DPoP-scheme OAUTH-shaped token still routes
    /// to OAuth policy and is refused here.
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
                    headers: try fixture.dpopSchemeCredentialHeaders(),
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
            let credentialHeaders = try fixture.bearerHeaders()
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
                    body: ByteBuffer(string: "{\"space\":\"\(fixture.space.rawValue)\",\"service\":\"did:web:events.example#e\"}")
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try notificationErrorCode(response.body), "ServiceNotResolvable")
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.registerNotify",
                    method: .post,
                    headers: credentialHeaders,
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
            configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
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
                repository: nil,
                expiresAt: Date(timeIntervalSinceNow: 3_600)
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

        // Withdrawal-by-replacement: the subscriber re-registers the same
        // endpoint WITHOUT a service identity, so the stored row loses it.
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: serviceEndpoint,
                repository: nil,
                expiresAt: Date(timeIntervalSinceNow: 3_600)
            ),
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

    func testDeletionTokenIsNotBoundToTheBodySpace() async throws {
        let fixture = try await NotificationHTTPFixture.make(authority: authority, writer: writer)
        defer { fixture.cleanup() }
        do {
            let bindings = try SwanSpaceNotificationRecipientBindings(
                bindings: [NotificationServiceVerifier.boundRecipientIdentity: writer]
            )
            let app = try fixture.server(recipientBindings: bindings)
                .buildApplication(logger: Logger(label: "SpaceNotificationHTTPTests.deletionBinding"))
            let sibling = try SpaceURI(
                authority: authority,
                spaceType: "app.bsky.bookmarks",
                skey: "http-sibling"
            )
            let headers: HTTPFields = {
                var fields: HTTPFields = [.contentType: "application/json"]
                fields[.authorization] = "Bearer authority-bound-recipient-token"
                return fields
            }()

            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.notifySpaceDeleted",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: "{\"space\":\"\(sibling.rawValue)\"}")
                ) { response in
                    XCTAssertEqual(response.status, .ok)
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
            XCTAssertEqual(
                deletions,
                [
                    .init(
                        space: sibling,
                        issuer: authority,
                        audience: writer,
                        eventID: "service-event-5"
                    ),
                ]
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
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
            if counts.outbox == 1 { break }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let counts = await transport.counts()
        XCTAssertEqual(counts.outbox, 1)
        XCTAssertEqual(counts.fanout, 0)
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
            if state.attempts >= 2 { break }
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
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil
    ) throws -> SwanHTTPServer {
        let credentialKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
            try .init(authority: authority, generation: 1, publicKey: key.publicKey),
        ])
        return SwanHTTPServer(
            profile: try ProtocolProfile.load(from: notificationPackageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")),
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
                    serviceAuthentication: NotificationServiceVerifier(authority: authority, writer: writer),
                    recipientBindings: recipientBindings,
                    serviceEndpointResolver: serviceEndpointResolver,
                    notificationJSONDecodeObserver: $0
                )
            } ?? .init(
                serviceAuthentication: NotificationServiceVerifier(authority: authority, writer: writer),
                recipientBindings: recipientBindings,
                serviceEndpointResolver: serviceEndpointResolver
            ),
            jsonWriteAdmission: jsonWriteAdmission
        )
    }

    func bearerHeaders() throws -> HTTPFields {
        let credential = try PermissionedDataJWT.createSpaceCredential(issuer: authority, space: space, key: key)
        var headers: HTTPFields = [.contentType: "application/json"]
        headers[.authorization] = "Bearer \(credential)"
        return headers
    }

    /// The reference presentation: the credential under the `DPoP` scheme
    /// ("a space credential is bound to a key"), proof header included.
    func dpopSchemeCredentialHeaders() throws -> HTTPFields {
        let credential = try PermissionedDataJWT.createSpaceCredential(issuer: authority, space: space, key: key)
        var headers: HTTPFields = [.contentType: "application/json"]
        headers[.authorization] = "DPoP \(credential)"
        headers[.init("DPoP")!] = "surplus-proof-swan-credentials-are-unbound"
        return headers
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
            configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
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
                expiresAt: now.addingTimeInterval(3_600)
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
                audience: authority
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
                configuration: try .init(policy: .public, appAccess: .open),
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
        return .init(space: space, configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open))
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
        authorization _: AuthorizationContext
    ) async throws {
        registrationsValue.removeAll { $0.endpoint == registration.endpoint }
        registrationsValue.append(registration)
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
        eventID: String
    ) async throws {
        deletionsValue.append(
            .init(space: space, issuer: issuer, audience: audience, eventID: eventID)
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

    func post(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        headers: [String: String],
        body: Data,
        timeout _: TimeInterval,
        maximumResponseBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        recorded.append(.init(url: url, headers: headers, body: body))
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
        now _: Date
    ) async throws -> String {
        recorded.append(.init(issuer: issuer, audience: audience, method: method))
        return "recorded-service-token"
    }

    func issued() -> [Issued] { recorded }
}

private struct NotificationServiceVerifier: SpaceServiceAuthenticationVerifier {
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
        now _: Date
    ) async throws -> VerifiedSpaceServiceAuthentication {
        guard expectedAudience == nil else {
            throw SwanError.unauthorized("service authentication is invalid")
        }
        switch (compact, expectedMethod) {
        case ("writer-token", "com.atproto.space.notifyWrite"):
            return .init(
                issuer: writer,
                audience: authority,
                method: expectedMethod,
                eventID: "service-event-1",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-fanout-token", "com.atproto.space.notifyWrite"):
            return .init(
                issuer: authority,
                audience: "did:plc:recipientabcdefghijklmnop",
                method: expectedMethod,
                eventID: "service-event-2",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-unknown-recipient-token", "com.atproto.space.notifyWrite"):
            return .init(
                issuer: authority,
                audience: "did:plc:unknownabcdefghijklmnopqr",
                method: expectedMethod,
                eventID: "service-event-3",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-unknown-recipient-token", "com.atproto.space.notifySpaceDeleted"):
            return .init(
                issuer: authority,
                audience: "did:plc:unknownabcdefghijklmnopqr",
                method: expectedMethod,
                eventID: "service-event-4",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        case ("authority-bound-recipient-token", "com.atproto.space.notifySpaceDeleted"):
            return .init(
                issuer: authority,
                audience: NotificationServiceVerifier.boundRecipientIdentity,
                method: expectedMethod,
                eventID: "service-event-5",
                expiresAt: Date(timeIntervalSinceNow: 60)
            )
        default:
            throw SwanError.unauthorized("service authentication is invalid")
        }
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
