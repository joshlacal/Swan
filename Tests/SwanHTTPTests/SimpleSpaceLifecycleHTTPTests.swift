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

final class SimpleSpaceLifecycleHTTPTests: XCTestCase, @unchecked Sendable {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let type = "app.bsky.bookmarks"
    private static let createPath = "/xrpc/com.atproto.space.createSpace"
    private static let updatePath = "/xrpc/com.atproto.space.updateSpace"
    private static let deletePath = "/xrpc/com.atproto.space.deleteSpace"
    private static let getPath = "/xrpc/com.atproto.space.getSpace"
    private static let removeWriterPath = "/xrpc/com.atproto.space.removeWriter"
    private static let putPath = "/xrpc/com.atproto.memberspace.putMember"
    private static let removePath = "/xrpc/com.atproto.memberspace.removeMember"
    private static let listPath = "/xrpc/com.atproto.memberspace.listMembers"

    func testLifecycleWriteAdmissionReturnsTemporaryUnavailableBeforeDecode() async throws {
        let maximum = authenticatedSpaceWriteMaximumJSONBytes
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(5))
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let server = try makeServer(
                fixture,
                jsonWriteAdmission: admission,
                jsonWriteBodyPolicy: policy
            )
            XCTAssertTrue(server.jsonWriteAdmission === admission)
            XCTAssertTrue(server.jsonWriteBodyPolicy === policy)
            XCTAssertTrue(
                server.authenticatedSimpleSpaceLifecycle?.jsonWriteAdmission
                    === admission
            )
            XCTAssertTrue(
                server.authenticatedSimpleSpaceLifecycle?.jsonWriteBodyPolicy
                    === policy
            )
            let held = try XCTUnwrap(
                admission.reserve(maximumRequestBytes: maximum)
            )
            let app = server.buildApplication(
                logger: Logger(label: "SimpleSpaceLifecycleWriteAdmissionTests")
            )
            try await app.test(.router) { client in
                let response = try await client.execute(
                    uri: Self.createPath,
                    method: .post,
                    headers: try self.postHeaders(
                        fixture,
                        path: Self.createPath,
                        jti: "lifecycle-write-admission"
                    ),
                    body: ByteBuffer(string: "{}")
                )
                XCTAssertEqual(response.status, .serviceUnavailable)
                XCTAssertEqual(
                    try self.errorCode(response.body),
                    "temporarily_unavailable"
                )
            }
            held.release()
            XCTAssertEqual(admission.snapshot, .init(
                activeLeases: 0,
                reservedRequestBytes: 0
            ))
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleContentLengthDeclarationPolicyRejectsBeforeAdmission() {
        let maximum = authenticatedSpaceWriteMaximumJSONBytes
        for (name, values) in contentLengthRejectionCases(maximum: maximum) {
            XCTAssertFalse(acceptsSimpleSpaceWriteContentLength(values), name)
        }
        XCTAssertTrue(acceptsSimpleSpaceWriteContentLength([]), "missing")
        XCTAssertTrue(acceptsSimpleSpaceWriteContentLength(["1"]), "valid")
        XCTAssertTrue(acceptsSimpleSpaceWriteContentLength([String(maximum)]), "boundary")
    }

    func testLifecycleOversizedDeclarationRejectsBeforeAuthorizationAndDomain() async throws {
        let maximum = authenticatedSpaceWriteMaximumJSONBytes
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: maximum
        )
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let directory = CountingSimpleSpaceDirectory(base: fixture.directory)
        do {
            let server = try makeServer(
                fixture,
                jsonWriteAdmission: admission,
                authenticatedDirectory: directory
            )
            let held = try XCTUnwrap(admission.reserve(maximumRequestBytes: maximum))
            let replayCount = try await oauthDPoPReplayCount(in: fixture.root)
            do {
                try await server.buildApplication(
                    logger: Logger(label: "SimpleSpaceLifecycleWriteAdmissionTests.oversized-socket")
                ).test(.live) { client in
                    let response = try await executeRealSocketIncompleteHTTPBody(
                        port: try XCTUnwrap(client.port),
                        path: Self.createPath,
                        headers: try self.postHeaders(
                            fixture,
                            path: Self.createPath,
                            jti: "lifecycle-oversized-socket"
                        ),
                        declaredBodyBytes: maximum + 1,
                        emittedBody: "{"
                    )
                    XCTAssertEqual(response.statusCode, 400)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                    XCTAssertEqual(response.emittedBodyBytes, 1)
                    XCTAssertEqual(
                        admission.snapshot,
                        .init(activeLeases: 1, reservedRequestBytes: maximum)
                    )
                    let finalReplayCount = try await oauthDPoPReplayCount(in: fixture.root)
                    let domainCallCount = await directory.domainCallCount
                    XCTAssertEqual(finalReplayCount, replayCount)
                    XCTAssertEqual(domainCallCount, 0)
                }
                held.release()
            } catch {
                held.release()
                throw error
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleMembershipPaginationAndWholesalePolicyUpdate() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.success"))
            let create = #"{"spaceType":"\#(Self.type)","policy":{"$type":"com.atproto.memberspace.policy"}}"#
            try await app.test(.router) { client in
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-generated"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["space"] as? String)
                }
                let space = try SpaceURI(uri)
                XCTAssertEqual(space.authority, Self.alice)
                XCTAssertEqual(space.spaceType, Self.type)
                XCTAssertFalse(space.skey.isEmpty)

                let getPath = "\(Self.getPath)?space=\(self.percentEncode(uri))"
                try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: Self.getPath, jti: "get-created")) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let object = try self.jsonObject(response.body)
                    XCTAssertEqual(Set(object.keys), ["space", "policy"])
                    XCTAssertEqual(object["space"] as? String, uri)
                    let policy = try XCTUnwrap(object["policy"] as? [String: Any])
                    XCTAssertEqual(policy["$type"] as? String, "com.atproto.memberspace.policy")
                    XCTAssertEqual(policy["publicRead"] as? Bool, false)
                    XCTAssertEqual(policy["publicWrite"] as? Bool, false)
                    XCTAssertNil(policy["allowedApps"])
                }

                // updateSpace replaces the whole policy: fields that are
                // omitted take their defaults, they are not carried over.
                let publicRead = #"{"space":"\#(uri)","policy":{"$type":"com.atproto.memberspace.policy","publicRead":true,"allowedApps":["https://client.example","https://client.example"]}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "update-public-read"), body: ByteBuffer(string: publicRead)) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
                try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: Self.getPath, jti: "get-public-read")) { response in
                    let policy = try XCTUnwrap((try self.jsonObject(response.body))["policy"] as? [String: Any])
                    XCTAssertEqual(policy["publicRead"] as? Bool, true)
                    XCTAssertEqual(policy["allowedApps"] as? [String], ["https://client.example"])
                }
                let publicWriteOnly = #"{"space":"\#(uri)","policy":{"$type":"com.atproto.memberspace.policy","publicWrite":true}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "update-public-write"), body: ByteBuffer(string: publicWriteOnly)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: Self.getPath, jti: "get-public-write")) { response in
                    let policy = try XCTUnwrap((try self.jsonObject(response.body))["policy"] as? [String: Any])
                    XCTAssertEqual(policy["publicRead"] as? Bool, false)
                    XCTAssertEqual(policy["publicWrite"] as? Bool, true)
                    XCTAssertNil(policy["allowedApps"])
                }

                let add = #"{"space":"\#(uri)","did":"\#(Self.bob)","read":true,"write":false}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(fixture, path: Self.putPath, jti: "add-member"), body: ByteBuffer(string: add)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // put is idempotent.
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(fixture, path: Self.putPath, jti: "add-member-again"), body: ByteBuffer(string: add)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let first = "\(Self.listPath)?space=\(self.percentEncode(uri))&limit=1"
                try await client.execute(uri: first, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-first")) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let body = try self.jsonObject(response.body)
                    let members = body["members"] as? [[String: Any]]
                    XCTAssertEqual(members?.first?["did"] as? String, Self.alice)
                    XCTAssertEqual(members?.first?["read"] as? Bool, true)
                    XCTAssertEqual(members?.first?["write"] as? Bool, true)
                    XCTAssertEqual(body["cursor"] as? String, Self.alice)
                }
                let second = "\(Self.listPath)?space=\(self.percentEncode(uri))&limit=1&cursor=\(self.percentEncode(Self.alice))"
                try await client.execute(uri: second, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-second")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let secondMembers = (try self.jsonObject(response.body))["members"] as? [[String: Any]]
                    XCTAssertEqual(secondMembers?.first?["did"] as? String, Self.bob)
                    XCTAssertEqual(secondMembers?.first?["read"] as? Bool, true)
                    XCTAssertEqual(secondMembers?.first?["write"] as? Bool, false)
                }
                let ownerRemoval = #"{"space":"\#(uri)","did":"\#(Self.alice)"}"#
                try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-owner"), body: ByteBuffer(string: ownerRemoval)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }

                // A policy of another `$type` drops the member list, and the
                // memberspace methods answer PolicyMismatch meanwhile.
                let personal = #"{"space":"\#(uri)","policy":{"$type":"com.atproto.personalspace.policy"}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "update-personal"), body: ByteBuffer(string: personal)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "\(Self.listPath)?space=\(self.percentEncode(uri))", method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-personal")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "PolicyMismatch")
                }
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(fixture, path: Self.putPath, jti: "add-member-personal"), body: ByteBuffer(string: add)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "PolicyMismatch")
                }
                let removeMember = #"{"space":"\#(uri)","did":"\#(Self.bob)"}"#
                try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-member-personal"), body: ByteBuffer(string: removeMember)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "PolicyMismatch")
                }
                let member = #"{"space":"\#(uri)","policy":{"$type":"com.atproto.memberspace.policy"}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "update-member-again"), body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "\(Self.listPath)?space=\(self.percentEncode(uri))", method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-after-type-change")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let members = (try self.jsonObject(response.body))["members"] as? [[String: Any]]
                    XCTAssertEqual(members?.compactMap { $0["did"] as? String }, [Self.alice])
                }

                try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-member"), body: ByteBuffer(string: removeMember)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let delete = #"{"space":"\#(uri)"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(fixture, path: Self.deletePath, jti: "delete"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(fixture, path: Self.deletePath, jti: "delete-again"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    /// October 29 createSpace takes `{spaceType, skey?, policy}`. The policy
    /// is a required open union of the three baseline policies; an unknown
    /// `$type` is UnsupportedPolicy, a malformed known one InvalidRequest.
    /// The retired simplespace routes are gone.
    func testLifecycleCreateRequiresPolicyAndRefusesUnknownVariants() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.policies"))
            try await app.test(.router) { client in
                func create(_ body: String, jti: String) async throws -> (HTTPResponse.Status, [String: Any]) {
                    var result: (HTTPResponse.Status, [String: Any]) = (.ok, [:])
                    try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: jti), body: ByteBuffer(string: body)) { response in
                        result = (response.status, (try? self.jsonObject(response.body)) ?? [:])
                    }
                    return result
                }
                let cases: [(String, String, HTTPResponse.Status, String?)] = [
                    ("missing-policy", #"{"spaceType":"\#(Self.type)","skey":"a"}"#, .badRequest, "InvalidRequest"),
                    ("missing-type", #"{"skey":"a","policy":{"$type":"com.atproto.memberspace.policy"}}"#, .badRequest, "InvalidRequest"),
                    ("legacy-type-field", #"{"type":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.memberspace.policy"}}"#, .badRequest, "InvalidRequest"),
                    ("unknown-policy", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.example.oraclePolicy"}}"#, .badRequest, "UnsupportedPolicy"),
                    ("retired-simplespace-policy", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"}}"#, .badRequest, "UnsupportedPolicy"),
                    ("untyped-policy", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{}}"#, .badRequest, "InvalidRequest"),
                    ("string-flag", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.memberspace.policy","publicRead":"true"}}"#, .badRequest, "InvalidRequest"),
                    ("numeric-flag", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.memberspace.policy","publicRead":1}}"#, .badRequest, "InvalidRequest"),
                    ("managed-without-app", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.managedspace.policy"}}"#, .badRequest, "InvalidRequest"),
                    ("managed-non-did", #"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.managedspace.policy","managingApp":"https://manager.example"}}"#, .badRequest, "InvalidRequest"),
                    ("managed", #"{"spaceType":"\#(Self.type)","skey":"managed","policy":{"$type":"com.atproto.managedspace.policy","managingApp":"did:web:manager.example#forum"}}"#, .ok, nil),
                    ("personal", #"{"spaceType":"\#(Self.type)","skey":"personal","policy":{"$type":"com.atproto.personalspace.policy"}}"#, .ok, nil),
                    ("member", #"{"spaceType":"\#(Self.type)","skey":"member","policy":{"$type":"com.atproto.memberspace.policy","publishPolicy":true,"publishMembers":true}}"#, .ok, nil),
                ]
                for (name, body, status, error) in cases {
                    let (actual, object) = try await create(body, jti: "create-\(name)")
                    XCTAssertEqual(actual, status, name)
                    XCTAssertEqual(object["error"] as? String, error, name)
                }
                // Nothing was created by a refused body: the skey is free.
                let (status, object) = try await create(#"{"spaceType":"\#(Self.type)","skey":"a","policy":{"$type":"com.atproto.memberspace.policy"}}"#, jti: "create-after-refusals")
                XCTAssertEqual(status, .ok)
                XCTAssertEqual(try SpaceURI(try XCTUnwrap(object["space"] as? String)).skey, "a")

                let managed = try SpaceURI(authority: Self.alice, spaceType: Self.type, skey: "managed")
                try await client.execute(uri: "\(Self.getPath)?space=\(self.percentEncode(managed.rawValue))", method: .get, headers: try self.getHeaders(fixture, path: Self.getPath, jti: "get-managed")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let policy = try XCTUnwrap((try self.jsonObject(response.body))["policy"] as? [String: Any])
                    XCTAssertEqual(policy["$type"] as? String, "com.atproto.managedspace.policy")
                    XCTAssertEqual(policy["managingApp"] as? String, "did:web:manager.example#forum")
                    XCTAssertEqual(policy["publishPolicy"] as? Bool, false)
                }
                try await client.execute(uri: "\(Self.listPath)?space=\(self.percentEncode(managed.rawValue))", method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "members-managed")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "PolicyMismatch")
                }

                for retired in ["createSpace", "updateSpace", "deleteSpace", "putMember", "removeMember", "getSpace", "listMembers", "checkUserAccess"] {
                    let path = "/xrpc/com.atproto.simplespace.\(retired)"
                    try await client.execute(uri: path, method: .post, headers: try self.postHeaders(fixture, path: path, jti: "retired-\(retired)"), body: ByteBuffer(string: "{}")) { response in
                        XCTAssertEqual(response.status, .notFound, retired)
                    }
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    /// getSpace is an owner-only management read. Anyone else, including a
    /// member, is told SpaceNotFound (HTTP 400), the same answer as for a
    /// space that does not exist.
    func testGetSpaceIsOwnerOnlyAndRemoveWriterIsIdempotent() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.getSpace"))
            try await app.test(.router) { client in
                let create = #"{"spaceType":"\#(Self.type)","skey":"owner-only","policy":{"$type":"com.atproto.memberspace.policy","publicRead":true}}"#
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "owner-only-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["space"] as? String)
                }
                let add = #"{"space":"\#(uri)","did":"\#(Self.bob)","read":true,"write":true}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(fixture, path: Self.putPath, jti: "owner-only-add"), body: ByteBuffer(string: add)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let getPath = "\(Self.getPath)?space=\(self.percentEncode(uri))"
                try await client.execute(uri: getPath, method: .get, headers: try self.signedHeaders(fixture.bob, fixture: fixture, path: Self.getPath, jti: "member-get", method: "GET")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                let missing = try SpaceURI(authority: Self.alice, spaceType: Self.type, skey: "missing")
                try await client.execute(uri: "\(Self.getPath)?space=\(self.percentEncode(missing.rawValue))", method: .get, headers: try self.getHeaders(fixture, path: Self.getPath, jti: "missing-get")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                let removeWriter = #"{"space":"\#(uri)","repo":"\#(Self.bob)"}"#
                for jti in ["remove-writer", "remove-writer-again"] {
                    try await client.execute(uri: Self.removeWriterPath, method: .post, headers: try self.postHeaders(fixture, path: Self.removeWriterPath, jti: jti), body: ByteBuffer(string: removeWriter)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                }
                let badWriter = #"{"space":"\#(uri)","repo":"not-a-did"}"#
                try await client.execute(uri: Self.removeWriterPath, method: .post, headers: try self.postHeaders(fixture, path: Self.removeWriterPath, jti: "remove-writer-bad"), body: ByteBuffer(string: badWriter)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                try await client.execute(uri: Self.removeWriterPath, method: .post, headers: try self.postHeaders(fixture, subject: Self.bob, path: Self.removeWriterPath, jti: "remove-writer-foreign"), body: ByteBuffer(string: removeWriter)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    /// A live space re-created is SpaceAlreadyExists; a delete→recreate cycle
    /// is a fresh create that applies the newly supplied policy.
    func testLifecycleCreateIsIdempotentAndResurrectsADeletedSpace() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.phoenix"))
            try await app.test(.router) { client in
                let create = #"{"spaceType":"\#(Self.type)","skey":"phoenix","policy":{"$type":"com.atproto.memberspace.policy"}}"#
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "phoenix-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["space"] as? String)
                }
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "phoenix-recreate"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceAlreadyExists")
                }
                let publicise = #"{"space":"\#(uri)","policy":{"$type":"com.atproto.memberspace.policy","publicRead":true}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "phoenix-publicise"), body: ByteBuffer(string: publicise)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let delete = #"{"space":"\#(uri)"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(fixture, path: Self.deletePath, jti: "phoenix-delete"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "phoenix-update-deleted"), body: ByteBuffer(string: publicise)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "phoenix-rise"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok, "a delete→recreate cycle must be a fresh create, not SpaceAlreadyExists")
                    XCTAssertEqual((try self.jsonObject(response.body))["space"] as? String, uri)
                }
                try await client.execute(uri: "\(Self.getPath)?space=\(self.percentEncode(uri))", method: .get, headers: try self.getHeaders(fixture, path: Self.getPath, jti: "phoenix-get-2")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let policy = try XCTUnwrap((try self.jsonObject(response.body))["policy"] as? [String: Any])
                    XCTAssertEqual(policy["publicRead"] as? Bool, false, "a recreate applies the supplied policy, not the pre-deletion one")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleScopesAuthorityPrivacyAndRequestValidation() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let space = try SpaceURI(authority: Self.alice, spaceType: Self.type, skey: "scoped")
            let createScope = managementScope(space, operation: "create")
            let updateScope = managementScope(space, operation: "update")
            let deleteScope = managementScope(space, operation: "delete")
            let createToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [createScope])
            let updateToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [updateScope])
            let deleteToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: [deleteScope])
            let readSelfToken = try await issueToken(fixture.runtime, subject: Self.alice, scopes: ["space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&action=read_self"])
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.scopes"))
            let create = #"{"spaceType":"\#(Self.type)","skey":"scoped","policy":{"$type":"com.atproto.memberspace.policy"}}"#
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(createToken, fixture: fixture, path: Self.createPath, jti: "scoped-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let member = #"{"space":"\#(space.rawValue)","did":"\#(Self.bob)","read":true,"write":true}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.putPath, jti: "update-scope-add"), body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let memberList = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))"
                // listMembers is a read_self owner read; Swan's scope matcher
                // lets a manage grant for the space cover it too.
                try await client.execute(uri: memberList, method: .get, headers: try self.getHeaders(updateToken, fixture: fixture, path: Self.listPath, jti: "update-scope-list")) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: memberList, method: .get, headers: try self.getHeaders(readSelfToken, fixture: fixture, path: Self.listPath, jti: "read-self-scope-list")) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(((try self.jsonObject(response.body))["members"] as? [[String: Any]])?.compactMap { $0["did"] as? String }, [Self.alice, Self.bob])
                }
                let removeMember = #"{"space":"\#(space.rawValue)","did":"\#(Self.bob)"}"#
                try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.removePath, jti: "update-scope-remove"), body: ByteBuffer(string: removeMember)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let update = #"{"space":"\#(space.rawValue)","policy":{"$type":"com.atproto.memberspace.policy","publicRead":true}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(createToken, fixture: fixture, path: Self.updatePath, jti: "wrong-manage"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "NotAuthorized")
                }
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.updatePath, jti: "right-manage"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let replayHeaders = try self.postHeaders(updateToken, fixture: fixture, path: Self.putPath, jti: "add-replay")
                try await client.execute(uri: Self.putPath, method: .post, headers: replayHeaders, body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: Self.putPath, method: .post, headers: replayHeaders, body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
                }
                let delete = #"{"space":"\#(space.rawValue)"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(deleteToken, fixture: fixture, path: Self.deletePath, jti: "delete-manage"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }

                let duplicate = #"{"did":"\#(Self.alice)","did":"\#(Self.bob)","spaceType":"\#(Self.type)"}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "duplicate-body"), body: ByteBuffer(string: duplicate)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                // The forged-Content-Length vector that used to sit here was
                // DEAD: HummingbirdTesting replaces the header with the real
                // body length, so the request always passed the declaration
                // guard and the 400 it asserted was actually
                // SpaceAlreadyExists from the deleted space above — exposed
                // the moment Erratum 03's resurrection made that a 200. The
                // declaration guard is asserted directly instead; the
                // chunked vector below still exercises the streaming limit
                // with a genuinely oversized body.
                XCTAssertFalse(acceptsSimpleSpaceWriteContentLength(["1048577"]))
                XCTAssertTrue(acceptsSimpleSpaceWriteContentLength(["1048576"]))
                // Hummingbird's router test client fragments large bodies in
                // 32 KiB chunks. This exercises the streaming body limit with
                // a real oversized payload, rather than only trusting a
                // forged Content-Length header.
                let chunkedOversized = String(repeating: " ", count: 1_048_577)
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "chunked-oversized"), body: ByteBuffer(string: chunkedOversized)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                let malformedQuery = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))&space=\(self.percentEncode(space.rawValue))"
                try await client.execute(uri: malformedQuery, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "duplicate-query")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                let malformedCursor = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))&cursor=not-a-did"
                try await client.execute(uri: malformedCursor, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "bad-cursor")) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }
                try await client.execute(uri: Self.createPath, method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                    self.assertNoStore(response)
                    XCTAssertEqual(try self.errorCode(response.body), "permissioned_endpoint_unavailable")
                }
                let wrongTarget = try self.getHeaders(fixture, path: Self.updatePath, jti: "wrong-dpop", method: "POST")
                try await client.execute(uri: Self.createPath, method: .post, headers: self.withJSON(wrongTarget), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleFailsClosedForDeactivationAndVanishedPreopenedDatabase() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.closed"))
            let create = #"{"spaceType":"\#(Self.type)","skey":"closed","policy":{"$type":"com.atproto.memberspace.policy"}}"#
            _ = try await fixture.control.transitionStatus(
                did: Self.alice,
                to: .deactivated,
                declaration: .init(),
                now: Date()
            )
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "deactivated"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            _ = try await fixture.control.transitionStatus(
                did: Self.alice,
                to: .active,
                declaration: .init(),
                now: Date()
            )
            // Deactivation revokes the entire OAuth family. Reactivation
            // therefore requires a fresh authorization grant before the
            // request can reach the preopened-database availability check.
            let reactivated = try await issueToken(fixture.runtime, subject: Self.alice, scopes: ["atproto"])
            try FileManager.default.removeItem(at: SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice))
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(reactivated, fixture: fixture, path: Self.createPath, jti: "missing-db"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertFalse(FileManager.default.fileExists(atPath: SQLiteLayout.accountDatabase(in: fixture.root, did: Self.alice).path))
                }
                try await client.execute(uri: "/xrpc/com.atproto.repo.getRecord?repo=\(Self.alice)&collection=\(Self.type)&rkey=closed", method: .get) { response in
                    XCTAssertNotEqual(response.status, .ok)
                    XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains("closed"))
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }
    func testPutMemberReplacesBothAccessValues() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.putReplaces"))
            let create = #"{"spaceType":"\#(Self.type)","policy":{"$type":"com.atproto.memberspace.policy"}}"#
            try await app.test(.router) { client in
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "put-replaces-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["space"] as? String)
                }
                // Put bob with read: true, write: false
                let put1 = #"{"space":"\#(uri)","did":"\#(Self.bob)","read":true,"write":false}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(fixture, path: Self.putPath, jti: "put-1"), body: ByteBuffer(string: put1)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let listUri = "\(Self.listPath)?space=\(self.percentEncode(uri))"
                try await client.execute(uri: listUri, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "list-1")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let members = (try self.jsonObject(response.body))["members"] as? [[String: Any]]
                    let bobMember = members?.first(where: { ($0["did"] as? String) == Self.bob })
                    XCTAssertEqual(bobMember?["read"] as? Bool, true)
                    XCTAssertEqual(bobMember?["write"] as? Bool, false)
                }
                // Re-put bob with read: false, write: true (replaces both flags)
                let put2 = #"{"space":"\#(uri)","did":"\#(Self.bob)","read":false,"write":true}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(fixture, path: Self.putPath, jti: "put-2"), body: ByteBuffer(string: put2)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: listUri, method: .get, headers: try self.getHeaders(fixture, path: Self.listPath, jti: "list-2")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let members = (try self.jsonObject(response.body))["members"] as? [[String: Any]]
                    let bobMember = members?.first(where: { ($0["did"] as? String) == Self.bob })
                    XCTAssertEqual(bobMember?["read"] as? Bool, false)
                    XCTAssertEqual(bobMember?["write"] as? Bool, true)
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }


    private func makeFixture() async throws -> SimpleSpaceFixture {
        let root = FileManager.default.temporaryDirectory.appending(path: "SimpleSpaceLifecycleHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(registration(did: Self.alice, handle: "alice.example.com"))
            _ = try await control.createAccount(registration(did: Self.bob, handle: "bob.example.com"))
            for did in [Self.alice, Self.bob] {
                let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
                try await database.close()
            }
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: nil
            )
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0x5A, count: 32))
            let alice = try await issueToken(runtime, subject: Self.alice, scopes: ["atproto"])
            let bob = try await issueToken(runtime, subject: Self.bob, scopes: ["atproto"])
            return .init(root: root, control: control, directory: directory, runtime: runtime, alice: alice, bob: bob)
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func makeServer(
        _ fixture: SimpleSpaceFixture,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy? = nil,
        authenticatedDirectory: (any AuthorizedSimpleSpaceDirectory)? = nil
    ) throws -> SwanHTTPServer {
        SwanHTTPServer(
            profile: try ProtocolProfile.load(from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-10-29.json")),
            configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: Self.publicURL),
            oauthRuntime: fixture.runtime,
            authenticatedGetSpaceDirectory: authenticatedDirectory ?? fixture.directory,
            accountControlStore: fixture.control,
            jsonWriteAdmission: jsonWriteAdmission,
            jsonWriteBodyPolicy: jsonWriteBodyPolicy
        )
    }

    private func issueToken(_ runtime: SwanOAuthRuntime, subject: String, scopes: Set<String>) async throws -> SimpleSpaceTokenMaterial {
        let key = P256.Signing.PrivateKey()
        let jwk = try makeJWK(key)
        let now = Date()
        let session = try OAuthValidatedSession(
            issuer: Self.publicURL.absoluteString,
            client: OAuthResolvedClientMetadata(
                metadata: try OAuthClientMetadata(
                    clientID: URL(string: "https://client.example/metadata")!,
                    redirectURIs: [URL(string: "https://client.example/callback")!],
                    grantTypes: ["authorization_code", "refresh_token"],
                    responseTypes: ["code"],
                    scopes: scopes.union(["atproto"]),
                    dpopBoundAccessTokens: true
                ), keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: scopes,
            dpopProof: OAuthValidatedDPoPProof(keyThumbprint: jwk.thumbprint(), jwtID: "simple-space-\(UUID().uuidString)", issuedAt: now),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(subject: subject, session: session, now: now)
        return .init(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private func postHeaders(_ fixture: SimpleSpaceFixture, path: String, jti: String) throws -> HTTPFields {
        try postHeaders(fixture, subject: Self.alice, path: path, jti: jti)
    }

    private func postHeaders(_ fixture: SimpleSpaceFixture, subject: String, path: String, jti: String) throws -> HTTPFields {
        withJSON(try signedHeaders(subject == Self.alice ? fixture.alice : fixture.bob, fixture: fixture, path: path, jti: jti, method: "POST"))
    }

    private func postHeaders(_ token: SimpleSpaceTokenMaterial, fixture: SimpleSpaceFixture, path: String, jti: String) throws -> HTTPFields {
        withJSON(try signedHeaders(token, fixture: fixture, path: path, jti: jti, method: "POST"))
    }

    private func getHeaders(_ fixture: SimpleSpaceFixture, path: String, jti: String, method: String = "GET") throws -> HTTPFields {
        try signedHeaders(fixture.alice, fixture: fixture, path: path, jti: jti, method: method)
    }

    private func getHeaders(_ token: SimpleSpaceTokenMaterial, fixture: SimpleSpaceFixture, path: String, jti: String) throws -> HTTPFields {
        try signedHeaders(token, fixture: fixture, path: path, jti: jti, method: "GET")
    }

    private func signedHeaders(_ token: SimpleSpaceTokenMaterial, fixture: SimpleSpaceFixture, path: String, jti: String, method: String) throws -> HTTPFields {
        struct Header: Encodable { let alg = "ES256"; let typ = OAuthDPoPProofValidator.proofType; let jwk: OAuthJSONWebKey }
        struct Claims: Encodable { let jti: String; let iat: Int64; let htm: String; let htu: String; let nonce: String; let ath: String }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: token.jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(jti: jti, iat: Int64(Date().timeIntervalSince1970), htm: method, htu: "\(Self.publicURL.absoluteString)\(path)", nonce: fixture.runtime.dpopNonceService.issue(), ath: Data(SHA256.hash(data: Data(token.token.utf8))).base64URLEncodedString())).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: token.key).base64URLEncodedString()
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token.token)"
        headers[HTTPField.Name("DPoP")!] = "\(input).\(signature)"
        return headers
    }

    private func withJSON(_ headers: HTTPFields) -> HTTPFields { var value = headers; value[.contentType] = "application/json"; return value }
    private func managementScope(_ space: SpaceURI, operation: String) -> String { "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&manage=\(operation)" }
    private func registration(did: String, handle: String) throws -> AccountControlRegistration { try .init(did: did, canonicalHandle: handle, passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", signingKey: try .init(purpose: .signing, generation: 1), rotationKey: try .init(purpose: .rotation, generation: 1), createdAt: Date(timeIntervalSince1970: 1_750_000_000)) }
    private func makeJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey { let value = key.publicKey.x963Representation; return try .init(x: Data(value[1 ..< 33]).base64URLEncodedString(), y: Data(value[33 ..< 65]).base64URLEncodedString()) }
    private func close(_ fixture: SimpleSpaceFixture) async throws { try await fixture.directory.close(); try await fixture.control.close() }
    private func percentEncode(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)! }
    private func jsonObject(_ body: ByteBuffer) throws -> [String: Any] { try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any]) }
    private func errorCode(_ body: ByteBuffer) throws -> String { try XCTUnwrap(jsonObject(body)["error"] as? String) }
    private func assertNoStore(_ response: TestResponse, file: StaticString = #filePath, line: UInt = #line) { XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line); XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line) }
    private func packageRoot() -> URL { URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
}

private struct SimpleSpaceTokenMaterial: Sendable { let token: String; let key: P256.Signing.PrivateKey; let jwk: OAuthJSONWebKey }
private struct SimpleSpaceFixture: Sendable { let root: URL; let control: SQLiteControlDatabase; let directory: SQLitePreMigratedAccountDirectory; let runtime: SwanOAuthRuntime; let alice: SimpleSpaceTokenMaterial; let bob: SimpleSpaceTokenMaterial }

private actor CountingSimpleSpaceDirectory:
    AuthorizedSimpleSpaceDirectory,
    AuthorizedSimpleSpaceLifecycleDirectory
{
    let base: SQLitePreMigratedAccountDirectory
    private(set) var domainCallCount = 0

    init(base: SQLitePreMigratedAccountDirectory) { self.base = base }

    func space(_ space: SpaceURI, authorization: AuthorizationContext) async throws -> AuthenticatedSimpleSpaceDescription? {
        domainCallCount += 1
        return try await base.space(space, authorization: authorization)
    }
    func close() async throws {}
    func createSimpleSpace(_ space: SpaceURI, configuration: SimpleSpaceConfiguration, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.createSimpleSpace(space, configuration: configuration, authorization: authorization)
    }
    func updateSimpleSpace(_ space: SpaceURI, configuration: SimpleSpaceConfiguration, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.updateSimpleSpace(space, configuration: configuration, authorization: authorization)
    }
    func removeSpaceWriter(_ writer: String, from space: SpaceURI, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.removeSpaceWriter(writer, from: space, authorization: authorization)
    }
    func deleteSimpleSpace(_ space: SpaceURI, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.deleteSimpleSpace(space, authorization: authorization)
    }
    func putSimpleSpaceMember(_ member: String, read: Bool, write: Bool, in space: SpaceURI, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.putSimpleSpaceMember(member, read: read, write: write, in: space, authorization: authorization)
    }
    func removeSimpleSpaceMember(_ member: String, from space: SpaceURI, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.removeSimpleSpaceMember(member, from: space, authorization: authorization)
    }
    func simpleSpaceMembers(_ space: SpaceURI, limit: Int, cursor: String?, authorization: AuthorizationContext) async throws -> AuthorizedSimpleSpaceMemberPage {
        domainCallCount += 1
        return try await base.simpleSpaceMembers(space, limit: limit, cursor: cursor, authorization: authorization)
    }
}
