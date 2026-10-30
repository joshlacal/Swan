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
    private static let createPath = "/xrpc/com.atproto.simplespace.createSpace"
    private static let updatePath = "/xrpc/com.atproto.simplespace.updateSpace"
    private static let deletePath = "/xrpc/com.atproto.simplespace.deleteSpace"
    private static let putPath = "/xrpc/com.atproto.simplespace.putMember"
    private static let addPath = "/xrpc/com.atproto.simplespace.putMember"
    private static let removePath = "/xrpc/com.atproto.simplespace.removeMember"
    private static let listPath = "/xrpc/com.atproto.simplespace.listMembers"

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

    func testLifecycleMembershipPaginationAndNonDestructiveConfigPatch() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.success"))
            let create = #"{"did":"\#(Self.alice)","spaceType":"\#(Self.type)","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
            let managingConfig = #"{"space":"PLACEHOLDER","readPolicy":{"$type":"com.atproto.simplespace.defs#managingAppPolicy","managingApp":"did:web:manager.example"},"writePolicy":{"$type":"com.atproto.simplespace.defs#managingAppPolicy","managingApp":"did:web:manager.example"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
            let publicConfig = #"{"space":"PLACEHOLDER","readPolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
            try await app.test(.router) { client in
                try await client.execute(
                    uri: Self.createPath,
                    method: .post,
                    headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-generated"),
                    body: ByteBuffer(string: create)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertNoStore(response)
                    let uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
                    let space = try SpaceURI(uri)
                    XCTAssertEqual(space.authority, Self.alice)
                    XCTAssertEqual(space.spaceType, Self.type)
                    XCTAssertFalse(space.skey.isEmpty)

                    // SWAN-24 option B: Swan does not implement managing-app
                    // evaluation, so updateSpace refuses the policy.
                    let configureManaging = managingConfig.replacingOccurrences(of: "PLACEHOLDER", with: uri)
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "configure-managing"), body: ByteBuffer(string: configureManaging)) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        XCTAssertEqual(try self.errorCode(response.body), "UnsupportedPolicy")
                    }
                    let configure = publicConfig.replacingOccurrences(of: "PLACEHOLDER", with: uri)
                    let configHeaders = try self.postHeaders(fixture, path: Self.updatePath, jti: "configure-public")
                    try await client.execute(uri: Self.updatePath, method: .post, headers: configHeaders, body: ByteBuffer(string: configure)) { response in
                        XCTAssertEqual(response.status, .ok)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    }
                    // Omit policy: appAccess changes, while the existing
                    // policy facts must remain intact.
                    let patch = #"{"space":"\#(uri)","appAccess":{"$type":"com.atproto.simplespace.defs#allowList","allowed":["https://client.example"]}}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "patch-app"), body: ByteBuffer(string: patch)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    let getPath = "/xrpc/com.atproto.simplespace.getSpace?space=\(self.percentEncode(uri))"
                    try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.simplespace.getSpace", jti: "get-patched")) { response in
                        XCTAssertEqual(response.status, .ok)
                        let object = try self.jsonObject(response.body)
                        let policy = try XCTUnwrap(object["readPolicy"] as? [String: Any])
                        XCTAssertEqual(policy["$type"] as? String, "com.atproto.simplespace.defs#publicPolicy")
                        let writePolicy = try XCTUnwrap(object["writePolicy"] as? [String: Any])
                        XCTAssertEqual(writePolicy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy")
                    }

                    // Pinned updateSpace patches each property independently:
                    // changing readPolicy must not touch writePolicy.
                    let policyOnly = #"{"space":"\#(uri)","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"}}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "policy-only-member-list"), body: ByteBuffer(string: policyOnly)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.simplespace.getSpace", jti: "get-policy-only-member-list")) { response in
                        XCTAssertEqual(response.status, .ok)
                        let object = try self.jsonObject(response.body)
                        let policy = try XCTUnwrap(object["readPolicy"] as? [String: Any])
                        XCTAssertEqual(policy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy")
                        XCTAssertEqual(Set(policy.keys), ["$type"])
                        let writePolicy = try XCTUnwrap(object["writePolicy"] as? [String: Any])
                        XCTAssertEqual(writePolicy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy")
                    }
                    let restoreManagingPolicy = #"{"space":"\#(uri)","readPolicy":{"$type":"com.atproto.simplespace.defs#managingAppPolicy","managingApp":"did:web:manager.example"}}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "policy-only-managing"), body: ByteBuffer(string: restoreManagingPolicy)) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        XCTAssertEqual(try self.errorCode(response.body), "UnsupportedPolicy")
                    }

                    let clearManagingApp = #"{"space":"\#(uri)","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"}}"#
                    try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "clear-managing"), body: ByteBuffer(string: clearManagingApp)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.simplespace.getSpace", jti: "get-cleared")) { response in
                        XCTAssertEqual(response.status, .ok)
                        let policy = try XCTUnwrap((try self.jsonObject(response.body))["readPolicy"] as? [String: Any])
                        XCTAssertEqual(policy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy")
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
                    let removeMember = #"{"space":"\#(uri)","did":"\#(Self.bob)"}"#
                    try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-member"), body: ByteBuffer(string: removeMember)) { response in
                        XCTAssertEqual(response.status, .ok)
                    }
                    // remove is idempotent.
                    try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(fixture, path: Self.removePath, jti: "remove-member-again"), body: ByteBuffer(string: removeMember)) { response in
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
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    func testLifecycleCreateDefaultsOmittedDidToTheCaller() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.didDefault"))
            try await app.test(.router) { client in
                // The reference implementation's canonical create body omits
                // `did` — it defaults to the authenticated caller, and no
                // other value is admissible anyway.
                let create = #"{"spaceType":"\#(Self.type)","skey":"did-defaulted","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-no-did"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    let uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
                    let space = try SpaceURI(uri)
                    XCTAssertEqual(space.authority, Self.alice)
                    XCTAssertEqual(space.spaceType, Self.type)
                    XCTAssertEqual(space.skey, "did-defaulted")
                }
                // An explicit foreign `did` stays indistinguishable from an
                // absent space — the authority gate is unchanged.
                let foreign = #"{"did":"\#(Self.bob)","spaceType":"\#(Self.type)","skey":"foreign-did","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-foreign-did"), body: ByteBuffer(string: foreign)) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
                }
                // `spaceType` remains the one required field.
                let missingType = #"{"skey":"typeless"}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-missing-type"), body: ByteBuffer(string: missingType)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                // The pre-October-1 field name is rejected, alone or next to
                // `spaceType`, and creates nothing.
                let legacyType = #"{"type":"\#(Self.type)","skey":"legacy-type","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-legacy-type"), body: ByteBuffer(string: legacyType)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                let bothTypes = #"{"type":"\#(Self.type)","spaceType":"\#(Self.type)","skey":"legacy-type","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-both-types"), body: ByteBuffer(string: bothTypes)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                // Nothing was created: the same skey is still free.
                let modern = #"{"spaceType":"\#(Self.type)","skey":"legacy-type","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "create-after-legacy"), body: ByteBuffer(string: modern)) { response in
                    XCTAssertEqual(response.status, .ok)
                    let uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
                    XCTAssertEqual(try SpaceURI(uri).skey, "legacy-type")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    /// The live lexicon (`bddc99fb`) lifts `policy`/`appAccess` to the
    /// createSpace/updateSpace input's top level as typed unions, and the
    /// `#managingAppPolicy` variant carries its own `managingApp`. Swan admits
    /// that shape beside the retired string/`config` dialect (shipped-surface
    /// leniency), refuses a body that mixes them, and answers the lexicon's
    /// `UnsupportedPolicy` / `UnsupportedAppAccess` for an unknown variant.
    /// A well-formed `#managingAppPolicy` is `UnsupportedPolicy` too
    /// (SWAN-24 option B); a malformed one stays `InvalidRequest`.
    /// The description read reflects the union round trip.
    func testLifecycleAdmitsTheLiveUnionDialectAndRefusesMixedOrUnknownVariants() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.union"))
            try await app.test(.router) { client in
                // Live shape: required type + policy + appAccess unions.
                // SWAN-24 option B: a well-formed managing-app policy is the
                // lexicon's UnsupportedPolicy, for read and for write.
                let managingRead = #"{"spaceType":"\#(Self.type)","skey":"union-managing","readPolicy":{"$type":"com.atproto.simplespace.defs#managingAppPolicy","managingApp":"did:web:manager.example#forum"},"writePolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "union-create-managing-read"), body: ByteBuffer(string: managingRead)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "UnsupportedPolicy")
                }
                let managingWrite = #"{"spaceType":"\#(Self.type)","skey":"union-managing","readPolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#managingAppPolicy","managingApp":"did:web:manager.example#forum"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "union-create-managing-write"), body: ByteBuffer(string: managingWrite)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "UnsupportedPolicy")
                }
                let create = #"{"spaceType":"\#(Self.type)","skey":"union","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#allowList","allowed":["https://client.example"]}}"#
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "union-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
                }
                let getPath = "/xrpc/com.atproto.simplespace.getSpace?space=\(self.percentEncode(uri))"
                try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.simplespace.getSpace", jti: "union-get")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let object = try self.jsonObject(response.body)
                    XCTAssertEqual(Set(object.keys), ["uri", "readPolicy", "writePolicy", "appAccess"])
                    let readPolicy = try XCTUnwrap(object["readPolicy"] as? [String: Any])
                    XCTAssertEqual(readPolicy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy")
                    let writePolicy = try XCTUnwrap(object["writePolicy"] as? [String: Any])
                    XCTAssertEqual(writePolicy["$type"] as? String, "com.atproto.simplespace.defs#publicPolicy")
                    let appAccess = try XCTUnwrap(object["appAccess"] as? [String: Any])
                    XCTAssertEqual(appAccess["$type"] as? String, "com.atproto.simplespace.defs#allowList")
                    XCTAssertEqual(appAccess["allowed"] as? [String], ["https://client.example"])
                }
                let update = #"{"space":"\#(uri)","readPolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "union-update"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.simplespace.getSpace", jti: "union-get-2")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let object = try self.jsonObject(response.body)
                    XCTAssertEqual((object["readPolicy"] as? [String: Any])?["$type"] as? String, "com.atproto.simplespace.defs#publicPolicy")
                    XCTAssertEqual((object["writePolicy"] as? [String: Any])?["$type"] as? String, "com.atproto.simplespace.defs#publicPolicy")
                    XCTAssertEqual((object["appAccess"] as? [String: Any])?["$type"] as? String, "com.atproto.simplespace.defs#open")
                }
                let badPolicy = #"{"spaceType":"\#(Self.type)","skey":"bad-policy","readPolicy":{"$type":"com.atproto.simplespace.defs#oraclePolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "union-bad-policy"), body: ByteBuffer(string: badPolicy)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "UnsupportedPolicy")
                }
                let badAccess = #"{"spaceType":"\#(Self.type)","skey":"bad-access","readPolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#denyList","denied":[]}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "union-bad-access"), body: ByteBuffer(string: badAccess)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
                let emptyManaging = #"{"spaceType":"\#(Self.type)","skey":"empty-managing","readPolicy":{"$type":"com.atproto.simplespace.defs#managingAppPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "union-empty-managing"), body: ByteBuffer(string: emptyManaging)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
            }
            try await close(fixture)
        } catch {
            try? await close(fixture)
            throw error
        }
    }

    /// Erratum 03 addendum (instance #10), CURRENT official HEAD semantics
    /// (`bddc99fb`): re-creating a LIVE space still throws
    /// SpaceAlreadyExists, but a delete→recreate cycle (bulleted.app's own
    /// recovery path) is a FRESH create — upstream's deleteSpace removes the
    /// config row its conflict check reads, so the recreate succeeds with
    /// the NEWLY SUPPLIED configuration, not the pre-deletion one.
    func testLifecycleCreateIsIdempotentAndResurrectsADeletedSpace() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.phoenix"))
            try await app.test(.router) { client in
                let create = #"{"spaceType":"\#(Self.type)","skey":"phoenix","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "phoenix-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
                }
                // Re-creating the LIVE space: SpaceAlreadyExists, per the
                // current official HEAD.
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "phoenix-recreate"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceAlreadyExists")
                }
                // Distinguish the stored configuration from create defaults so
                // the recreate below can prove it applies the SUPPLIED config.
                let publicise = #"{"space":"\#(uri)","readPolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(fixture, path: Self.updatePath, jti: "phoenix-publicise"), body: ByteBuffer(string: publicise)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // Delete, then recreate: a FRESH create — same URI, but the
                // pre-deletion "public" policy is gone; the create's default
                // configuration (member-list) applies.
                let delete = #"{"space":"\#(uri)"}"#
                try await client.execute(uri: Self.deletePath, method: .post, headers: try self.postHeaders(fixture, path: Self.deletePath, jti: "phoenix-delete"), body: ByteBuffer(string: delete)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "phoenix-rise"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok, "a delete→recreate cycle must be a fresh create, not SpaceAlreadyExists")
                    XCTAssertEqual((try self.jsonObject(response.body))["uri"] as? String, uri)
                }
                let getPath = "/xrpc/com.atproto.simplespace.getSpace?space=\(self.percentEncode(uri))"
                try await client.execute(uri: getPath, method: .get, headers: try self.getHeaders(fixture, path: "/xrpc/com.atproto.simplespace.getSpace", jti: "phoenix-get-2")) { response in
                    XCTAssertEqual(response.status, .ok)
                    let readPolicy = try XCTUnwrap((try self.jsonObject(response.body))["readPolicy"] as? [String: Any])
                    XCTAssertEqual(readPolicy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy", "a recreate applies the supplied configuration, not the pre-deletion one")
                    let writePolicy = try XCTUnwrap((try self.jsonObject(response.body))["writePolicy"] as? [String: Any])
                    XCTAssertEqual(writePolicy["$type"] as? String, "com.atproto.simplespace.defs#memberListPolicy")
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
            let app = try makeServer(fixture).buildApplication(logger: Logger(label: "SimpleSpaceLifecycleHTTPTests.scopes"))
            let create = #"{"did":"\#(Self.alice)","spaceType":"\#(Self.type)","skey":"scoped","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
            try await app.test(.router) { client in
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(createToken, fixture: fixture, path: Self.createPath, jti: "scoped-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let member = #"{"space":"\#(space.rawValue)","did":"\#(Self.bob)","read":true,"write":true}"#
                try await client.execute(uri: Self.putPath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.putPath, jti: "update-scope-add"), body: ByteBuffer(string: member)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let memberList = "\(Self.listPath)?space=\(self.percentEncode(space.rawValue))"
                try await client.execute(uri: memberList, method: .get, headers: try self.getHeaders(updateToken, fixture: fixture, path: Self.listPath, jti: "update-scope-list")) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(((try self.jsonObject(response.body))["members"] as? [[String: Any]])?.compactMap { $0["did"] as? String }, [Self.alice, Self.bob])
                }
                let removeMember = #"{"space":"\#(space.rawValue)","did":"\#(Self.bob)"}"#
                try await client.execute(uri: Self.removePath, method: .post, headers: try self.postHeaders(updateToken, fixture: fixture, path: Self.removePath, jti: "update-scope-remove"), body: ByteBuffer(string: removeMember)) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                let update = #"{"space":"\#(space.rawValue)","readPolicy":{"$type":"com.atproto.simplespace.defs#publicPolicy"}}"#
                try await client.execute(uri: Self.updatePath, method: .post, headers: try self.postHeaders(createToken, fixture: fixture, path: Self.updatePath, jti: "wrong-manage"), body: ByteBuffer(string: update)) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                    XCTAssertEqual(try self.errorCode(response.body), "Unauthorized")
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

                let foreign = try self.postHeaders(fixture, subject: Self.bob, path: Self.createPath, jti: "foreign-authority")
                try await client.execute(uri: Self.createPath, method: .post, headers: foreign, body: ByteBuffer(string: create.replacingOccurrences(of: Self.alice, with: Self.alice))) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(try self.errorCode(response.body), "SpaceNotFound")
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
            let create = #"{"did":"\#(Self.alice)","spaceType":"\#(Self.type)","skey":"closed","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
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
            let create = #"{"did":"\#(Self.alice)","spaceType":"\#(Self.type)","readPolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"writePolicy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#
            try await app.test(.router) { client in
                var uri = ""
                try await client.execute(uri: Self.createPath, method: .post, headers: try self.postHeaders(fixture, path: Self.createPath, jti: "put-replaces-create"), body: ByteBuffer(string: create)) { response in
                    XCTAssertEqual(response.status, .ok)
                    uri = try XCTUnwrap((try self.jsonObject(response.body))["uri"] as? String)
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
            profile: try ProtocolProfile.load(from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-10-01.json")),
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
    func updateSimpleSpace(_ space: SpaceURI, patch: SimpleSpaceConfigurationPatch, authorization: AuthorizationContext) async throws {
        domainCallCount += 1
        try await base.updateSimpleSpace(space, patch: patch, authorization: authorization)
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
