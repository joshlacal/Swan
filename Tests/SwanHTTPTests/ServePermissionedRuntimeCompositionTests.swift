import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import Petrel
import SQLiteNIO
import XCTest
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
@testable import swan
import SwanSQLite
import SwanSpaces
import SwanSpacesWire
import SwanStorage

final class ServePermissionedRuntimeCompositionTests: XCTestCase, @unchecked Sendable {
    private let localDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private let remoteDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let managingAudience = "did:web:configured-managing.example"
    private let recipientService = "did:web:configured-recipient.example"

    /// The order is deliberate: creation rows establish only the durable facts
    /// consumed by later rows, and destructive rows run last. Set equality
    /// below ensures this execution order cannot omit or invent a profile NSID.
    private enum SemanticInvariant: Sendable {
        case jsonKey(String)
        case jsonString(String, String)
        case jsonNonEmptyString(String)
        case jsonArray(String, minimumCount: Int)
        case jsonArrayContains(String, field: String, value: String)
        case jsonNestedString(String, String, String)
        case jsonBoolean(String, Bool)
        case jsonEmptyObject
        case emptyBody
        case blob(Data)
        case car
    }

    private struct SemanticCase: Sendable {
        let nsid: String
        let method: HTTPRequest.Method
        let uri: String
        let body: String?
        let authorization: SemanticAuthorization
        let invariant: SemanticInvariant
    }

    private enum SemanticAuthorization: Sendable {
        case oauth
        case credential
        case delegation
        case notifyWrite
        case notifyDeleted
        case checkUserAccess
    }

    func testExactServeCompositionRetainsConfigurationAndInstallsAllRoutes() async throws {
        let fixture = try await Fixture.make(localDID: localDID)
        defer { fixture.cleanup() }
        do {
            let remoteKey = P256.Signing.PrivateKey()
            let notification = try makeNotificationRuntime(
                root: fixture.root,
                issuer: remoteDID,
                key: remoteKey.publicKey
            )
            let composition = try await ServePermissionedRuntime.compose(
                local: fixture.localRuntime,
                notification: notification
            )

            XCTAssertEqual(
                composition.notificationConfiguration?.recipientBindings
                    .account(forServiceIdentity: recipientService),
                localDID
            )
            XCTAssertEqual(
                composition.checkUserAccessConfiguration?.managingServiceAudience,
                managingAudience
            )

            let server = composition.makeServer(
                profile: try ProtocolProfile.load(
                    from: packageRoot().appending(
                        path: "Profiles/permissioned-data-0016-2026-08-15.json"
                    )
                ),
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: fixture.oauthRuntime,
                directory: fixture.directory,
                accountControlStore: fixture.control
            )

            XCTAssertNotNil(server.authenticatedGetSpace)
            XCTAssertNotNil(server.authenticatedSpaceRecords)
            XCTAssertNotNil(server.authenticatedSpaceList)
            XCTAssertNotNil(server.authenticatedSimpleSpaceLifecycle)
            XCTAssertNotNil(server.authenticatedSpaceCredentialExchange)
            XCTAssertNotNil(server.authenticatedSpaceDelegationMinting)
            XCTAssertNotNil(server.authenticatedSpaceRepositorySync)
            XCTAssertNotNil(server.authenticatedSpaceBlobs)
            XCTAssertNotNil(server.authenticatedSpaceNotifications)
            XCTAssertNotNil(server.simpleSpaceCheckUserAccess)
            XCTAssertNotNil(server.publicRepositoryReadDirectory)

            let app = server.buildApplication(
                logger: Logger(label: "ServePermissionedRuntimeCompositionTests")
            )
            try await app.test(.router) { client in
                for path in [
                    "/xrpc/com.atproto.repo.describeRepo",
                    "/xrpc/com.atproto.repo.getRecord",
                    "/xrpc/com.atproto.repo.listRecords",
                    // A read, installed by the read directory. It used to sit
                    // in the deferred list below because it was registered
                    // from the mutation block, which meant this composition —
                    // public reads on, public writes off — served no blobs.
                    "/xrpc/com.atproto.sync.getBlob",
                    "/xrpc/com.atproto.sync.getLatestCommit",
                    "/xrpc/com.atproto.sync.getRepo",
                    "/xrpc/com.atproto.sync.getRepoStatus",
                ] {
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .badRequest, path)
                        XCTAssertNotEqual(response.status, .serviceUnavailable, path)
                    }
                }
                for (path, method): (String, HTTPRequest.Method) in [
                    ("/xrpc/com.atproto.repo.createRecord", .post),
                    ("/xrpc/com.atproto.repo.uploadBlob", .post),
                ] {
                    try await client.execute(uri: path, method: method) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable, path)
                    }
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testActiveProfileExecutesExactSemanticMatrixAndRejectsInvalidAndWrongMethods() async throws {
        let fixture = try await Fixture.make(localDID: localDID, installSemanticState: true)
        defer { fixture.cleanup() }
        do {
            let notification = try makeNotificationRuntime(
                root: fixture.root,
                issuer: localDID,
                key: fixture.localKey.publicKey
            )
            let composition = try await ServePermissionedRuntime.compose(
                local: fixture.localRuntime,
                notification: notification
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-08-15.json"
                )
            )
            let server = composition.makeServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: fixture.oauthRuntime,
                directory: fixture.directory,
                accountControlStore: fixture.control
            )
            let space = try XCTUnwrap(fixture.semanticSpace)
            let lifecycle = try XCTUnwrap(fixture.lifecycleSpace)
            let blobPayload = try XCTUnwrap(fixture.blobPayload)
            let blobCID = try XCTUnwrap(fixture.blobCID)
            let encodedSpace = percentEncode(space.rawValue)
            let encodedLifecycle = percentEncode(lifecycle.rawValue)
            let recordPrefix = "{\"space\":\"\(space.rawValue)\",\"repo\":\"\(localDID)\",\"collection\":\"app.bsky.feed.post\""
            let cases: [SemanticCase] = [
                .init(nsid: "com.atproto.simplespace.createSpace", method: .post, uri: "/xrpc/com.atproto.simplespace.createSpace", body: "{\"did\":\"\(localDID)\",\"type\":\"app.bsky.bookmarks\",\"skey\":\"\(lifecycle.skey)\"}", authorization: .oauth, invariant: .jsonString("uri", lifecycle.rawValue)),
                .init(nsid: "com.atproto.simplespace.updateSpace", method: .post, uri: "/xrpc/com.atproto.simplespace.updateSpace", body: "{\"space\":\"\(lifecycle.rawValue)\",\"policy\":\"public\"}", authorization: .oauth, invariant: .emptyBody),
                .init(nsid: "com.atproto.simplespace.addMember", method: .post, uri: "/xrpc/com.atproto.simplespace.addMember", body: "{\"space\":\"\(lifecycle.rawValue)\",\"did\":\"\(remoteDID)\"}", authorization: .oauth, invariant: .emptyBody),
                .init(nsid: "com.atproto.simplespace.listMembers", method: .get, uri: "/xrpc/com.atproto.simplespace.listMembers?space=\(encodedLifecycle)", body: nil, authorization: .oauth, invariant: .jsonArrayContains("members", field: "did", value: remoteDID)),
                .init(nsid: "com.atproto.simplespace.getSpace", method: .get, uri: "/xrpc/com.atproto.simplespace.getSpace?space=\(encodedSpace)", body: nil, authorization: .oauth, invariant: .jsonString("uri", space.rawValue)),
                .init(nsid: "com.atproto.space.listSpaces", method: .get, uri: "/xrpc/com.atproto.space.listSpaces", body: nil, authorization: .oauth, invariant: .jsonArrayContains("spaces", field: "uri", value: lifecycle.rawValue)),
                .init(nsid: "com.atproto.space.getDelegationToken", method: .get, uri: "/xrpc/com.atproto.space.getDelegationToken?space=\(encodedSpace)", body: nil, authorization: .oauth, invariant: .jsonNonEmptyString("token")),
                .init(nsid: "com.atproto.space.getSpaceCredential", method: .post, uri: "/xrpc/com.atproto.space.getSpaceCredential", body: "{\"space\":\"\(space.rawValue)\"}", authorization: .delegation, invariant: .jsonNonEmptyString("credential")),
                .init(nsid: "com.atproto.space.createRecord", method: .post, uri: "/xrpc/com.atproto.space.createRecord", body: recordPrefix + ",\"rkey\":\"matrix-created\",\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"matrix-create\"}}", authorization: .oauth, invariant: .jsonNonEmptyString("cid")),
                .init(nsid: "com.atproto.space.putRecord", method: .post, uri: "/xrpc/com.atproto.space.putRecord", body: recordPrefix + ",\"rkey\":\"seed\",\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"matrix-put\"}}", authorization: .oauth, invariant: .jsonNonEmptyString("cid")),
                .init(nsid: "com.atproto.space.applyWrites", method: .post, uri: "/xrpc/com.atproto.space.applyWrites", body: "{\"space\":\"\(space.rawValue)\",\"repo\":\"\(localDID)\",\"writes\":[{\"$type\":\"com.atproto.space.applyWrites#create\",\"collection\":\"app.bsky.feed.post\",\"rkey\":\"matrix-batch\",\"value\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"matrix-batch\"}}]}", authorization: .oauth, invariant: .jsonArrayContains("results", field: "uri", value: "\(space.rawValue)/\(localDID)/app.bsky.feed.post/matrix-batch")),
                .init(nsid: "com.atproto.space.getRecord", method: .get, uri: "/xrpc/com.atproto.space.getRecord?space=\(encodedSpace)&repo=\(localDID)&collection=app.bsky.feed.post&rkey=seed", body: nil, authorization: .oauth, invariant: .jsonNestedString("value", "text", "matrix-put")),
                .init(nsid: "com.atproto.space.listRecords", method: .get, uri: "/xrpc/com.atproto.space.listRecords?space=\(encodedSpace)&repo=\(localDID)&collection=app.bsky.feed.post", body: nil, authorization: .oauth, invariant: .jsonArrayContains("records", field: "rkey", value: "matrix-created")),
                .init(nsid: "com.atproto.space.listBlobs", method: .get, uri: "/xrpc/com.atproto.space.listBlobs?space=\(encodedSpace)&repo=\(localDID)", body: nil, authorization: .oauth, invariant: .jsonKey("cids")),
                .init(nsid: "com.atproto.space.getLatestCommit", method: .get, uri: "/xrpc/com.atproto.space.getLatestCommit?space=\(encodedSpace)&repo=\(localDID)", body: nil, authorization: .oauth, invariant: .jsonKey("commit")),
                .init(nsid: "com.atproto.space.listRepoOps", method: .get, uri: "/xrpc/com.atproto.space.listRepoOps?space=\(encodedSpace)&repo=\(localDID)&excludeValues=true", body: nil, authorization: .oauth, invariant: .jsonArray("ops", minimumCount: 1)),
                .init(nsid: "com.atproto.space.getRepo", method: .get, uri: "/xrpc/com.atproto.space.getRepo?space=\(encodedSpace)&repo=\(localDID)", body: nil, authorization: .oauth, invariant: .car),
                .init(nsid: "com.atproto.space.getBlob", method: .get, uri: "/xrpc/com.atproto.space.getBlob?space=\(encodedSpace)&repo=\(localDID)&cid=\(blobCID)", body: nil, authorization: .oauth, invariant: .blob(blobPayload)),
                .init(nsid: "com.atproto.space.registerNotify", method: .post, uri: "/xrpc/com.atproto.space.registerNotify", body: "{\"space\":\"\(space.rawValue)\",\"endpoint\":\"https://receiver.example/xrpc/com.atproto.space.notifyWrite\"}", authorization: .credential, invariant: .jsonNonEmptyString("expiresAt")),
                .init(nsid: "com.atproto.space.unregisterNotify", method: .post, uri: "/xrpc/com.atproto.space.unregisterNotify", body: "{\"space\":\"\(space.rawValue)\",\"service\":\"did:web:receiver.example#notify\"}", authorization: .credential, invariant: .emptyBody),
                .init(nsid: "com.atproto.space.notifyWrite", method: .post, uri: "/xrpc/com.atproto.space.notifyWrite", body: "{\"space\":\"\(space.rawValue)\",\"repo\":\"\(localDID)\",\"rev\":\"222222222222z\",\"hash\":{\"$bytes\":\"\(Data(repeating: 0x31, count: 32).base64EncodedString())\"}}", authorization: .notifyWrite, invariant: .emptyBody),
                .init(nsid: "com.atproto.space.listRepos", method: .get, uri: "/xrpc/com.atproto.space.listRepos?space=\(encodedSpace)", body: nil, authorization: .credential, invariant: .jsonArrayContains("repos", field: "did", value: localDID)),
                .init(nsid: "com.atproto.simplespace.checkUserAccess", method: .get, uri: "/xrpc/com.atproto.simplespace.checkUserAccess?space=\(encodedSpace)&user=\(remoteDID)", body: nil, authorization: .checkUserAccess, invariant: .jsonBoolean("authorized", false)),
                .init(nsid: "com.atproto.space.deleteRecord", method: .post, uri: "/xrpc/com.atproto.space.deleteRecord", body: recordPrefix + ",\"rkey\":\"delete-me\"}", authorization: .oauth, invariant: .jsonEmptyObject),
                .init(nsid: "com.atproto.simplespace.removeMember", method: .post, uri: "/xrpc/com.atproto.simplespace.removeMember", body: "{\"space\":\"\(lifecycle.rawValue)\",\"did\":\"\(remoteDID)\"}", authorization: .oauth, invariant: .emptyBody),
                .init(nsid: "com.atproto.simplespace.deleteSpace", method: .post, uri: "/xrpc/com.atproto.simplespace.deleteSpace", body: "{\"space\":\"\(lifecycle.rawValue)\"}", authorization: .oauth, invariant: .emptyBody),
                .init(nsid: "com.atproto.space.notifySpaceDeleted", method: .post, uri: "/xrpc/com.atproto.space.notifySpaceDeleted", body: "{\"space\":\"\(lifecycle.rawValue)\"}", authorization: .notifyDeleted, invariant: .emptyBody),
            ]

            let profileSet = Set(profile.endpoints)
            let generatedSet = Set(PermissionedData0016.methods.map(\.nsid))
            let matrixSet = Set(cases.map(\.nsid))
            XCTAssertEqual(profile.endpoints.count, 27)
            XCTAssertEqual(PermissionedData0016.methods.count, 27)
            XCTAssertEqual(cases.count, 27)
            XCTAssertEqual(profileSet, generatedSet)
            XCTAssertEqual(profileSet, matrixSet)
            XCTAssertEqual(matrixSet.count, cases.count, "matrix contains a duplicate NSID")

            let credential = try PermissionedDataJWT.createSpaceCredential(
                issuer: localDID,
                space: space,
                key: fixture.localKey
            )
            let app = server.buildApplication(
                logger: Logger(label: "ServePermissionedRuntimeCompositionTests.semantic")
            )
            let tokenCapture = SemanticTokenCapture()
            try await app.test(.router) { client in
                for (index, testCase) in cases.enumerated() {
                    let path = "/xrpc/\(testCase.nsid)"
                    let headers = try self.semanticHeaders(
                        testCase.authorization,
                        fixture: fixture,
                        space: space,
                        path: path,
                        method: testCase.method,
                        jti: "matrix-valid-\(index)",
                        credential: credential,
                        hasBody: testCase.body != nil
                    )
                    try await client.execute(
                        uri: testCase.uri,
                        method: testCase.method,
                        headers: headers,
                        body: testCase.body.map(ByteBuffer.init(string:))
                    ) { response in
                        XCTAssertEqual(response.status, .ok, testCase.nsid)
                        try self.assertSemanticInvariant(
                            testCase.invariant,
                            response: response,
                            nsid: testCase.nsid
                        )
                        if testCase.nsid == ComAtprotoSpaceGetDelegationToken.typeIdentifier {
                            await tokenCapture.setDelegation(
                                try XCTUnwrap(self.jsonObject(response.body)["token"] as? String)
                            )
                        } else if testCase.nsid == ComAtprotoSpaceGetSpaceCredential.typeIdentifier {
                            await tokenCapture.setCredential(
                                try XCTUnwrap(self.jsonObject(response.body)["credential"] as? String)
                            )
                        } else if testCase.nsid == ComAtprotoSpaceGetLatestCommit.typeIdentifier {
                            let commit = try XCTUnwrap(
                                self.jsonObject(response.body)["commit"] as? [String: Any]
                            )
                            await tokenCapture.setLatestRevision(
                                try XCTUnwrap(commit["rev"] as? String)
                            )
                        } else if testCase.nsid == ComAtprotoSpaceListRepoOps.typeIdentifier {
                            let ops = try XCTUnwrap(
                                self.jsonObject(response.body)["ops"] as? [[String: Any]]
                            )
                            await tokenCapture.setOplogRevisions(
                                try ops.map { try XCTUnwrap($0["rev"] as? String) }
                            )
                        } else if testCase.nsid == ComAtprotoSpaceGetRepo.typeIdentifier {
                            await tokenCapture.setRecoveryCAR(Data(buffer: response.body))
                        }
                    }

                    let invalid = self.semanticInvalidRequest(for: testCase)
                    let invalidHeaders = try self.semanticHeaders(
                        testCase.authorization,
                        fixture: fixture,
                        space: space,
                        path: path,
                        method: testCase.method,
                        jti: "matrix-invalid-\(index)",
                        credential: credential,
                        hasBody: invalid.body != nil
                    )
                    try await client.execute(
                        uri: invalid.uri,
                        method: testCase.method,
                        headers: invalidHeaders,
                        body: invalid.body.map(ByteBuffer.init(string:))
                    ) { response in
                        XCTAssertEqual(response.status, invalid.status, testCase.nsid)
                        XCTAssertEqual(try self.errorCode(response.body), invalid.code, testCase.nsid)
                        self.assertSemanticSecretsAbsent(
                            response.body,
                            nsid: testCase.nsid,
                            sensitiveMaterial: self.semanticSensitiveMaterial(
                                headers: invalidHeaders,
                                fixture: fixture,
                                credential: credential
                            )
                        )
                    }

                    let wrongMethod: HTTPRequest.Method = testCase.method == .get ? .post : .get
                    let wrongHeaders = try self.semanticHeaders(
                        testCase.authorization,
                        fixture: fixture,
                        space: space,
                        path: path,
                        method: wrongMethod,
                        jti: "matrix-wrong-method-\(index)",
                        credential: credential,
                        hasBody: false
                    )
                    try await client.execute(
                        uri: path,
                        method: wrongMethod,
                        headers: wrongHeaders
                    ) { response in
                        XCTAssertEqual(response.status, .notFound, testCase.nsid)
                        XCTAssertEqual(
                            try self.errorCode(response.body),
                            "permissioned_endpoint_unavailable",
                            testCase.nsid
                        )
                        self.assertSemanticSecretsAbsent(
                            response.body,
                            nsid: testCase.nsid,
                            sensitiveMaterial: self.semanticSensitiveMaterial(
                                headers: wrongHeaders,
                                fixture: fixture,
                                credential: credential
                            )
                        )
                    }
                }
            }

            let issued = await tokenCapture.values()
            let delegationToken = try XCTUnwrap(issued.delegation)
            let verifiedDelegation = try await DurableSpaceDelegationVerifier(
                publicKeys: try PinnedSpaceDelegationPublicKeyResolver(pins: [
                    try .init(
                        issuer: localDID,
                        generation: 1,
                        publicKey: fixture.localKey.publicKey
                    ),
                ])
            ).verifiedDelegation(
                for: delegationToken,
                expectedSpace: space
            )
            XCTAssertEqual(verifiedDelegation.issuer, localDID)
            XCTAssertEqual(
                verifiedDelegation.audience,
                "\(localDID)#atproto_space_host"
            )
            let credentialToken = try XCTUnwrap(issued.credential)
            let credentialAuthorization = try await DurableSpaceCredentialVerifier(
                publicKeys: try PinnedSpaceCredentialPublicKeyResolver(pins: [
                    try .init(
                        authority: localDID,
                        keyID: PermissionedDataJWT.spaceCredentialFallbackKeyID,
                        generation: 1,
                        publicKey: fixture.localKey.publicKey
                    ),
                ])
            ).authorization(for: credentialToken, expectedSpace: space)
            guard case let .spaceCredential(grant) = credentialAuthorization else {
                return XCTFail("issued credential did not verify as a space credential")
            }
            XCTAssertEqual(grant.space, space)
            let latestRevision = try XCTUnwrap(issued.latestRevision)
            _ = try TID(tidString: latestRevision)
            XCTAssertFalse(issued.oplogRevisions.isEmpty)
            for revision in issued.oplogRevisions {
                _ = try TID(tidString: revision)
            }
            XCTAssertEqual(issued.oplogRevisions.last, latestRevision)
            let verifiedRecovery = try SpaceCARCodec.verifyRecovery(
                try XCTUnwrap(issued.recoveryCAR),
                space: space,
                author: localDID,
                publicKey: fixture.localKey.publicKey
            )
            XCTAssertEqual(verifiedRecovery.wireRevision.toString(), latestRevision)
            let recoveryKeys = Set(
                verifiedRecovery.records.map {
                    "\($0.uri.collection)/\($0.uri.rkey)"
                }
            )
            XCTAssertTrue(recoveryKeys.contains("app.bsky.feed.post/seed"))
            XCTAssertTrue(recoveryKeys.contains("app.bsky.feed.post/matrix-created"))
            XCTAssertTrue(recoveryKeys.contains("app.bsky.feed.post/matrix-batch"))

            // Test-only route-owner mutation witness. The same predicate that
            // validates every real success above must reject a replacement
            // owner returning either common generic failure shape.
            for testCase in cases {
                XCTAssertFalse(semanticContractMatches(
                    status: .badRequest,
                    contentType: "application/json",
                    body: Data(#"{"error":"InvalidRequest"}"#.utf8),
                    invariant: testCase.invariant
                ), "\(testCase.nsid) accepted a generic 400 owner")
                XCTAssertFalse(semanticContractMatches(
                    status: .unauthorized,
                    contentType: "application/json",
                    body: Data(#"{"error":"Unauthorized"}"#.utf8),
                    invariant: testCase.invariant
                ), "\(testCase.nsid) accepted a generic 401 owner")
            }

            let database = try await SQLiteAccountDatabase(
                dataDirectory: fixture.root,
                did: localDID
            )
            do {
                let authorization = AuthorizationContext.accountOAuthForTesting(
                    subject: localDID,
                    scopes: fixture.semanticScopes
                )
                let repository = try DurableSpaceRepository(
                    database: database,
                    space: space,
                    author: localDID
                )
                let created = try await repository.record(
                    try SpaceRecordURI(
                        space: space,
                        author: localDID,
                        collection: "app.bsky.feed.post",
                        rkey: "matrix-created"
                    ),
                    authorization: authorization
                )
                XCTAssertNotNil(created, "createRecord did not leave its durable fact")
                let deleted = try await repository.record(
                    try SpaceRecordURI(
                        space: space,
                        author: localDID,
                        collection: "app.bsky.feed.post",
                        rkey: "delete-me"
                    ),
                    authorization: authorization
                )
                XCTAssertNil(deleted, "deleteRecord did not remove its durable fact")
                try await database.close()
            } catch {
                try? await database.close()
                throw error
            }

            let evidenceConnection = try await SQLiteConnection.open(
                storage: .file(
                    path: SQLiteLayout.accountDatabase(
                        in: fixture.root,
                        did: localDID
                    ).path
                )
            )
            do {
                let registrations = try await evidenceConnection.query(
                    """
                    SELECT endpoint
                    FROM permissioned_space_notification_registrations
                    WHERE space_uri = ?
                    """,
                    [.text(space.rawValue)]
                )
                XCTAssertEqual(
                    registrations.first?.column("endpoint")?.string,
                    "https://receiver.example/xrpc/com.atproto.space.notifyWrite"
                )
                let writers = try await evidenceConnection.query(
                    """
                    SELECT repo_did, wire_revision
                    FROM permissioned_space_writers
                    WHERE space_uri = ?
                    """,
                    [.text(space.rawValue)]
                )
                XCTAssertEqual(writers.first?.column("repo_did")?.string, localDID)
                XCTAssertEqual(
                    writers.first?.column("wire_revision")?.string,
                    "222222222222z"
                )
                let lifecycleRows = try await evidenceConnection.query(
                    """
                    SELECT policy, revision, is_deleted
                    FROM permissioned_simple_space_authorities
                    WHERE space_uri = ?
                    """,
                    [.text(lifecycle.rawValue)]
                )
                XCTAssertEqual(
                    lifecycleRows.first?.column("policy")?.string,
                    "public",
                    "updateSpace did not durably replace the default member-list policy"
                )
                XCTAssertGreaterThan(
                    lifecycleRows.first?.column("revision")?.integer ?? 0,
                    1,
                    "lifecycle revision did not advance beyond creation"
                )
                XCTAssertEqual(lifecycleRows.first?.column("is_deleted")?.integer, 1)
                let members = try await evidenceConnection.query(
                    """
                    SELECT member_did
                    FROM permissioned_simple_space_members
                    WHERE space_uri = ? AND member_did = ?
                    """,
                    [.text(lifecycle.rawValue), .text(remoteDID)]
                )
                XCTAssertTrue(members.isEmpty)
                let tombstones = try await evidenceConnection.query(
                    """
                    SELECT authority_did
                    FROM permissioned_space_recipient_tombstones
                    WHERE space_uri = ?
                    """,
                    [.text(lifecycle.rawValue)]
                )
                XCTAssertEqual(
                    tombstones.first?.column("authority_did")?.string,
                    localDID
                )
                try await evidenceConnection.close()
            } catch {
                try? await evidenceConnection.close()
                throw error
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testExactServeCompositionRejectsConflictingPinnedLocalIdentity() async throws {
        let fixture = try await Fixture.make(localDID: localDID)
        defer { fixture.cleanup() }
        do {
            let notification = try makeNotificationRuntime(
                root: fixture.root,
                issuer: localDID,
                key: P256.Signing.PrivateKey().publicKey
            )
            do {
                _ = try await ServePermissionedRuntime.compose(
                    local: fixture.localRuntime,
                    notification: notification
                )
                XCTFail("conflicting pinned/local key material must fail startup")
            } catch {}
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testExactServeCompositionRetainsExplicitAttestationPolicy() async throws {
        let fixture = try await Fixture.make(localDID: localDID)
        defer { fixture.cleanup() }
        do {
            let marker = "https://composed-reader.example/client-metadata.json"
            let policy = CompositionAttestationPolicy(marker: marker)
            let composition = try await ServePermissionedRuntime.compose(
                local: fixture.localRuntime,
                notification: nil,
                clientAttestationPolicy: policy
            )
            let exchange = try XCTUnwrap(
                composition.credentialExchangeConfiguration
            )
            let resolved = try await exchange.clientAttestationPolicy
                .verifiedClientID(
                    for: "opaque-test-proof",
                    authority: localDID,
                    now: Date(timeIntervalSince1970: 1_750_000_000)
            )
            XCTAssertEqual(resolved, marker)
            let invocationCount = await policy.invocationCount()
            XCTAssertEqual(invocationCount, 1)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testManagingServiceAudienceMustBeExplicit() async throws {
        let fixture = try await Fixture.make(localDID: localDID)
        defer { fixture.cleanup() }
        do {
            let notification = try makeNotificationRuntime(
                root: fixture.root,
                issuer: remoteDID,
                key: P256.Signing.PrivateKey().publicKey,
                includeManagingAudience: false
            )
            let composition = try await ServePermissionedRuntime.compose(
                local: fixture.localRuntime,
                notification: notification
            )
            XCTAssertNotNil(composition.notificationConfiguration)
            XCTAssertNil(composition.checkUserAccessConfiguration)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testNotificationConfigurationRejectsUnknownKeysRecursively() throws {
        let encoded = P256.Signing.PrivateKey().publicKey.x963Representation
            .base64URLEncodedString()
        let credential: [String: Any] = [
            "issuer": remoteDID,
            "generation": 1,
            "algorithm": "ES256",
            "publicKey": encoded,
        ]
        let service: [String: Any] = [
            "issuer": remoteDID,
            "generation": 1,
            "algorithm": "ES256",
            "publicKey": encoded,
        ]
        let destination: [String: Any] = [
            "key": remoteDID,
            "endpoint": "http://localhost:3000",
            "audience": managingAudience,
            "finalPeer": "127.0.0.1",
        ]
        let recipient: [String: Any] = [
            "serviceIdentity": recipientService,
            "recipientAccount": localDID,
        ]
        let base: [String: Any] = [
            "credentialPublicKeys": [credential],
            "delegationPublicKeys": [credential],
            "servicePublicKeys": [service],
            "authorityDestinations": [destination],
            "registrationDestinations": [],
            "recipientServiceBindings": [recipient],
            "managingServiceAudience": managingAudience,
        ]
        var cases: [(String, [String: Any])] = []

        var root = base
        root["token"] = "must-not-be-accepted"
        cases.append(("top-level", root))

        var credentials = credential
        credentials["privateKey"] = "must-not-be-accepted"
        var credentialConfig = base
        credentialConfig["credentialPublicKeys"] = [credentials]
        cases.append(("credential key", credentialConfig))

        var delegations = credential
        delegations["token"] = "must-not-be-accepted"
        var delegationConfig = base
        delegationConfig["delegationPublicKeys"] = [delegations]
        cases.append(("delegation key", delegationConfig))

        var services = service
        services["privateKey"] = "must-not-be-accepted"
        var serviceConfig = base
        serviceConfig["servicePublicKeys"] = [services]
        cases.append(("service key", serviceConfig))

        var authority = destination
        authority["token"] = "must-not-be-accepted"
        var authorityConfig = base
        authorityConfig["authorityDestinations"] = [authority]
        cases.append(("authority destination", authorityConfig))

        var registration = destination
        registration["privateKey"] = "must-not-be-accepted"
        var registrationConfig = base
        registrationConfig["registrationDestinations"] = [registration]
        cases.append(("registration destination", registrationConfig))

        var recipientWithUnknownKey = recipient
        recipientWithUnknownKey["token"] = "must-not-be-accepted"
        var recipientConfig = base
        recipientConfig["recipientServiceBindings"] = [recipientWithUnknownKey]
        cases.append(("recipient binding", recipientConfig))

        var plcConfig = base
        plcConfig["credentialKeyPLC"] = [
            "origin": "https://plc.example",
            "laboratory": false,
            "privateKey": "must-not-be-accepted",
        ]
        cases.append(("PLC configuration", plcConfig))

        var delegationPLCConfig = base
        delegationPLCConfig["delegationKeyPLC"] = [
            "origin": "https://plc.example",
            "laboratory": false,
            "allowedIssuers": [remoteDID],
            "privateKey": "must-not-be-accepted",
        ]
        cases.append(("delegation PLC configuration", delegationPLCConfig))

        for (label, object) in cases {
            let url = FileManager.default.temporaryDirectory.appending(
                path: "swan-notification-shape-\(UUID().uuidString).json"
            )
            defer { try? FileManager.default.removeItem(at: url) }
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                .write(to: url)
            XCTAssertThrowsError(
                try ServeNotificationRuntime.load(
                    from: url,
                    continuityStore: TestPLCCredentialKeyContinuityStore()
                ),
                "\(label) must reject unknown keys"
            )
        }
    }

    func testLocalRuntimeCanEnableManagingAppAndNotificationCapabilitiesWithoutPinnedFile() async throws {
        let fixture = try await Fixture.make(localDID: localDID)
        defer { fixture.cleanup() }
        do {
            let composition = try await ServePermissionedRuntime.compose(
                local: fixture.localRuntime,
                notification: nil,
                managingServiceAudience: managingAudience
            )
            let server = composition.makeServer(
                profile: try ProtocolProfile.load(
                    from: packageRoot().appending(
                        path: "Profiles/permissioned-data-0016-2026-08-15.json"
                    )
                ),
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: fixture.oauthRuntime,
                directory: fixture.directory,
                accountControlStore: fixture.control
            )

            // Local account keys are a complete closed-world verifier for
            // inbound notification service JWTs. A notification JSON file is
            // only needed when outbound destinations or remote pins are
            // selected; it must not be required merely to expose the local
            // endpoint contracts.
            XCTAssertNotNil(composition.notificationConfiguration)
            XCTAssertNotNil(composition.checkUserAccessConfiguration)
            XCTAssertNotNil(server.authenticatedSpaceNotifications)
            XCTAssertNotNil(server.simpleSpaceCheckUserAccess)

            let app = server.buildApplication(
                logger: Logger(label: "ServePermissionedRuntimeCompositionTests.local")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.simplespace.getSpace",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(response.body), "InvalidRequest")
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testExplicitManagingAudienceCannotConflictWithPinnedConfiguration() async throws {
        let fixture = try await Fixture.make(localDID: localDID)
        defer { fixture.cleanup() }
        do {
            let notification = try makeNotificationRuntime(
                root: fixture.root,
                issuer: remoteDID,
                key: P256.Signing.PrivateKey().publicKey
            )
            do {
                _ = try await ServePermissionedRuntime.compose(
                    local: fixture.localRuntime,
                    notification: notification,
                    managingServiceAudience: "did:web:another-managing.example"
                )
                XCTFail("conflicting managing audience must fail startup")
            } catch {}
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testAccountBackedES256AndPinnedTypeScriptES256KVerifyInExactComposition() async throws {
        let local = "did:plc:cdefghijklmnopqrstuvwxyz"
        let fixture = try await Fixture.make(localDID: local)
        defer { fixture.cleanup() }
        do {
            let notification = try makeTypeScriptNotificationRuntime(root: fixture.root)
            let composition = try await ServePermissionedRuntime.compose(
                local: fixture.localRuntime,
                notification: notification
            )
            let localSpace = try SpaceURI(
                authority: local,
                spaceType: "app.bsky.bookmarks",
                skey: "local-composed"
            )
            let remoteSpace = try SpaceURI(
                authority: localDID,
                spaceType: "app.bsky.bookmarks",
                skey: "ts-golden"
            )
            let now = Date(timeIntervalSince1970: 1_750_000_010)
            let credentials = try XCTUnwrap(composition.credentialConfiguration)

            let localCredential = try PermissionedDataJWT.createSpaceCredential(
                issuer: local,
                space: localSpace,
                key: fixture.localKey,
                now: now
            )
            _ = try await DurableSpaceCredentialVerifier(
                publicKeys: credentials.credentialPublicKeys
            ).authorization(for: localCredential, expectedSpace: localSpace, now: now)
            _ = try await DurableSpaceCredentialVerifier(
                publicKeys: credentials.credentialPublicKeys
            ).authorization(
                for: Self.remoteCredential,
                expectedSpace: remoteSpace,
                now: now
            )

            let localDelegation = try PermissionedDataJWT.createDelegationToken(
                issuer: local,
                audience: "\(local)#atproto_space_host",
                space: localSpace,
                key: fixture.localKey,
                now: now
            )
            _ = try await DurableSpaceDelegationVerifier(
                publicKeys: credentials.delegationPublicKeys
            ).verifiedDelegation(for: localDelegation, expectedSpace: localSpace, now: now)
            _ = try await DurableSpaceDelegationVerifier(
                publicKeys: credentials.delegationPublicKeys
            ).verifiedDelegation(
                for: Self.remoteDelegation,
                expectedSpace: remoteSpace,
                now: now
            )

            let localService = try SpaceServiceJWT.create(
                issuer: local,
                audience: localDID,
                method: "com.atproto.space.notifyWrite",
                eventID: "local-composed-service",
                key: fixture.localKey,
                now: now
            )
            let service = try XCTUnwrap(composition.notificationConfiguration)
                .serviceAuthentication
            _ = try await service.authenticate(
                localService,
                expectedAudience: localDID,
                expectedMethod: "com.atproto.space.notifyWrite",
                now: now
            )
            _ = try await service.authenticate(
                Self.remoteService,
                expectedAudience: localDID,
                expectedMethod: "com.atproto.space.notifyWrite",
                now: now
            )
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    private func makeNotificationRuntime(
        root: URL,
        issuer: String,
        key: P256.Signing.PublicKey,
        includeManagingAudience: Bool = true
    ) throws -> ServeNotificationRuntime {
        let config = root.appending(path: "notification-\(UUID().uuidString).json")
        let encoded = key.x963Representation.base64URLEncodedString()
        var object: [String: Any] = [
            "credentialPublicKeys": [[
                "issuer": issuer,
                "generation": 1,
                "algorithm": "ES256",
                "publicKey": encoded,
            ]],
            "delegationPublicKeys": [[
                "issuer": issuer,
                "generation": 1,
                "algorithm": "ES256",
                "publicKey": encoded,
            ]],
            "servicePublicKeys": [[
                "issuer": issuer,
                "generation": 1,
                "algorithm": "ES256",
                "publicKey": encoded,
            ]],
            "authorityDestinations": [[
                "key": issuer,
                "endpoint": "http://localhost:3000",
                "audience": managingAudience,
                "finalPeer": "127.0.0.1",
            ]],
            "registrationDestinations": [],
            "recipientServiceBindings": [[
                "serviceIdentity": recipientService,
                "recipientAccount": localDID,
            ]],
        ]
        if includeManagingAudience {
            object["managingServiceAudience"] = managingAudience
        }
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: config)
        return try ServeNotificationRuntime.load(
            from: config,
            continuityStore: TestPLCCredentialKeyContinuityStore()
        )
    }

    private func makeTypeScriptNotificationRuntime(root: URL) throws -> ServeNotificationRuntime {
        let config = root.appending(path: "typescript-notification.json")
        let object: [String: Any] = [
            "credentialPublicKeys": [[
                "issuer": localDID,
                "keyID": PermissionedDataJWT.spaceCredentialFallbackKeyID,
                "generation": 1,
                "algorithm": "ES256K",
                "publicKey": "AsYEf5RB7X1tMEVAbpXAfNhcd45LjO88p6usCblccJ7l",
            ]],
            "delegationPublicKeys": [[
                "issuer": remoteDID,
                "generation": 1,
                "algorithm": "ES256K",
                "publicKey": "Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY",
            ]],
            "servicePublicKeys": [[
                "issuer": remoteDID,
                "generation": 1,
                "algorithm": "ES256K",
                "publicKey": "AoS_dWImK71pQAhXSPO-avpSrjFxVRgezjG2Y1HM_6Sw",
            ]],
            "authorityDestinations": [[
                "key": localDID,
                "endpoint": "http://localhost:3000",
                "audience": managingAudience,
                "finalPeer": "127.0.0.1",
            ]],
            "registrationDestinations": [],
            "recipientServiceBindings": [],
            "managingServiceAudience": managingAudience,
        ]
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: config)
        return try ServeNotificationRuntime.load(
            from: config,
            continuityStore: TestPLCCredentialKeyContinuityStore()
        )
    }

    private static let remoteDelegation =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fc3BhY2VfaG9zdCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAwMDYwLCJqdGkiOiJ0cy1ub25jZV8wMSJ9.CiWW_bplyq9ZtybzoUL9f7J_lqlcFKkmAbY2YsVlf5Bly4Ufue7e9QN6_8PioonLWqKnmm6T-RW3Mq2C_JTC6A"
    private static let remoteCredential =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDA3MjAwLCJqdGkiOiJ0cy1jcmVkZW50aWFsLW5vbmNlXzAxIn0.kgRbwHruWKzbsHZlMjmSFYmz1dKBjpP0eQBvJLRYlzMAClhsOpYnRYpe2fBMGtuciGngcQgEwWYSjHpa9YmIEQ"
    private static let remoteService =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NTAwMDAwMDAsImlzcyI6ImRpZDpwbGM6YmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5IiwiYXVkIjoiZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3giLCJleHAiOjE3NTAwMDAwNjAsImx4bSI6ImNvbS5hdHByb3RvLnNwYWNlLm5vdGlmeVdyaXRlIiwianRpIjoicGlubmVkLXRzLW5vdGlmeS0wMDEifQ.o782N9f1U23FL8bWXqQiNDBjp7c-5Cxj4IIlvqLdEUZFC4K0C-vUz-AN8PuGZINo1K2Y6_DY-qJmgak6Fk-aPA"

    private func semanticInvalidRequest(
        for testCase: SemanticCase
    ) -> (
        uri: String,
        body: String?,
        status: HTTPResponse.Status,
        code: String
    ) {
        let path = "/xrpc/\(testCase.nsid)"
        if testCase.method == .post {
            return (path, "{}", .badRequest, "InvalidRequest")
        }
        if testCase.nsid == ComAtprotoSimplespaceCheckUserAccess.typeIdentifier {
            // This endpoint deliberately makes malformed queries
            // indistinguishable from authorization denial.
            return (path, nil, .unauthorized, "Unauthorized")
        }
        if testCase.nsid == ComAtprotoSpaceListSpaces.typeIdentifier {
            return ("\(path)?unknown=matrix-invalid", nil, .badRequest, "InvalidRequest")
        }
        return (path, nil, .badRequest, "InvalidRequest")
    }

    private func semanticHeaders(
        _ authorization: SemanticAuthorization,
        fixture: Fixture,
        space: SpaceURI,
        path: String,
        method: HTTPRequest.Method,
        jti: String,
        credential: String,
        hasBody: Bool
    ) throws -> HTTPFields {
        var headers: HTTPFields
        switch authorization {
        case .oauth:
            headers = try signedHeaders(
                fixture: fixture,
                path: path,
                method: method.rawValue,
                jti: jti
            )
        case .credential:
            headers = [.authorization: "Bearer \(credential)"]
        case .delegation:
            let delegation = try PermissionedDataJWT.createDelegationToken(
                issuer: space.authority,
                audience: "\(space.authority)#atproto_space_host",
                space: space,
                key: fixture.localKey
            )
            headers = [.authorization: "Bearer \(delegation)"]
        case .notifyWrite:
            let notifyWrite = try SpaceServiceJWT.create(
                issuer: space.authority,
                audience: localDID,
                method: ComAtprotoSpaceNotifyWrite.typeIdentifier,
                eventID: jti,
                key: fixture.localKey
            )
            headers = [.authorization: "Bearer \(notifyWrite)"]
        case .notifyDeleted:
            let notifyDeleted = try SpaceServiceJWT.create(
                issuer: space.authority,
                audience: recipientService,
                method: ComAtprotoSpaceNotifySpaceDeleted.typeIdentifier,
                eventID: jti,
                key: fixture.localKey
            )
            headers = [.authorization: "Bearer \(notifyDeleted)"]
        case .checkUserAccess:
            let checkUserAccess = try SpaceServiceJWT.create(
                issuer: space.authority,
                audience: managingAudience,
                method: ComAtprotoSimplespaceCheckUserAccess.typeIdentifier,
                eventID: jti,
                key: fixture.localKey
            )
            headers = [.authorization: "Bearer \(checkUserAccess)"]
        }
        if hasBody { headers[.contentType] = "application/json" }
        return headers
    }

    private func signedHeaders(
        fixture: Fixture,
        path: String,
        method: String,
        jti: String
    ) throws -> HTTPFields {
        struct Header: Encodable {
            let alg = "ES256"
            let typ = OAuthDPoPProofValidator.proofType
            let jwk: OAuthJSONWebKey
        }
        struct Claims: Encodable {
            let jti: String
            let iat: Int64
            let htm: String
            let htu: String
            let nonce: String
            let ath: String
        }
        let token = try XCTUnwrap(fixture.semanticToken)
        let key = try XCTUnwrap(fixture.semanticTokenKey)
        let jwk = try XCTUnwrap(fixture.semanticTokenJWK)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            jti: jti,
            iat: Int64(Date().timeIntervalSince1970),
            htm: method,
            htu: "https://swan.example\(path)",
            nonce: fixture.oauthRuntime.dpopNonceService.issue(),
            ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(
            Data(input.utf8),
            using: key
        ).base64URLEncodedString()
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token)"
        headers[HTTPField.Name("DPoP")!] = "\(input).\(signature)"
        return headers
    }

    private func assertSemanticInvariant(
        _ invariant: SemanticInvariant,
        response: TestResponse,
        nsid: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        XCTAssertTrue(
            semanticContractMatches(
                status: response.status,
                contentType: response.headers[.contentType],
                body: Data(buffer: response.body),
                invariant: invariant
            ),
            "\(nsid) did not satisfy its semantic contract",
            file: file,
            line: line
        )
        switch invariant {
        case let .jsonKey(key):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertNotNil(try jsonObject(response.body)[key], nsid, file: file, line: line)
        case let .jsonString(key, expected):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertEqual(try jsonObject(response.body)[key] as? String, expected, nsid, file: file, line: line)
        case let .jsonNonEmptyString(key):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertFalse((try jsonObject(response.body)[key] as? String)?.isEmpty ?? true, nsid, file: file, line: line)
        case let .jsonArray(key, minimumCount):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertGreaterThanOrEqual(
                (try jsonObject(response.body)[key] as? [Any])?.count ?? -1,
                minimumCount,
                nsid,
                file: file,
                line: line
            )
        case let .jsonArrayContains(key, field, expected):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            let values = try jsonObject(response.body)[key] as? [[String: Any]]
            XCTAssertTrue(
                values?.contains { $0[field] as? String == expected } ?? false,
                nsid,
                file: file,
                line: line
            )
        case let .jsonNestedString(parent, key, expected):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertEqual(
                (try jsonObject(response.body)[parent] as? [String: Any])?[key] as? String,
                expected,
                nsid,
                file: file,
                line: line
            )
        case let .jsonBoolean(key, value):
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertEqual(try jsonObject(response.body)[key] as? Bool, value, nsid, file: file, line: line)
        case .jsonEmptyObject:
            XCTAssertEqual(response.headers[.contentType], "application/json", nsid, file: file, line: line)
            XCTAssertTrue(try jsonObject(response.body).isEmpty, nsid, file: file, line: line)
        case .emptyBody:
            XCTAssertEqual(response.body.readableBytes, 0, nsid, file: file, line: line)
        case let .blob(expected):
            XCTAssertEqual(response.headers[.contentType], "application/octet-stream", nsid, file: file, line: line)
            XCTAssertEqual(Data(buffer: response.body), expected, nsid, file: file, line: line)
        case .car:
            XCTAssertEqual(response.headers[.contentType], "application/vnd.ipld.car", nsid, file: file, line: line)
            XCTAssertEqual(
                try CARReader(data: Data(buffer: response.body)).roots.count,
                2,
                nsid,
                file: file,
                line: line
            )
        }
        XCTAssertEqual(response.headers[.cacheControl], "no-store", nsid, file: file, line: line)
    }

    private func semanticContractMatches(
        status: HTTPResponse.Status,
        contentType: String?,
        body: Data,
        invariant: SemanticInvariant
    ) -> Bool {
        guard status == .ok else { return false }
        switch invariant {
        case let .jsonKey(key):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any] else { return false }
            return object[key] != nil
        case let .jsonString(key, expected):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any] else { return false }
            return object[key] as? String == expected
        case let .jsonNonEmptyString(key):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any] else { return false }
            return !(object[key] as? String ?? "").isEmpty
        case let .jsonArray(key, minimumCount):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any] else { return false }
            return (object[key] as? [Any])?.count ?? -1 >= minimumCount
        case let .jsonArrayContains(key, field, expected):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any],
                  let values = object[key] as? [[String: Any]] else {
                return false
            }
            return values.contains { $0[field] as? String == expected }
        case let .jsonNestedString(parent, key, expected):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any] else { return false }
            return (object[parent] as? [String: Any])?[key] as? String == expected
        case let .jsonBoolean(key, value):
            guard contentType == "application/json",
                  let object = try? JSONSerialization.jsonObject(with: body)
                    as? [String: Any] else { return false }
            return object[key] as? Bool == value
        case .jsonEmptyObject:
            return contentType == "application/json"
                && ((try? JSONSerialization.jsonObject(with: body) as? [String: Any])?.isEmpty == true)
        case .emptyBody:
            return body.isEmpty
        case let .blob(expected):
            return contentType == "application/octet-stream" && body == expected
        case .car:
            return contentType == "application/vnd.ipld.car"
                && (try? CARReader(data: body).roots.count) == 2
        }
    }

    private func jsonObject(_ body: ByteBuffer) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(buffer: body))
                as? [String: Any]
        )
    }

    private func errorCode(_ body: ByteBuffer) throws -> String {
        try XCTUnwrap(jsonObject(body)["error"] as? String)
    }

    private func assertSemanticSecretsAbsent(
        _ body: ByteBuffer,
        nsid: String,
        sensitiveMaterial: [Data],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let response = Data(buffer: body)
        for (index, secret) in sensitiveMaterial.enumerated() where !secret.isEmpty {
            XCTAssertNil(
                response.range(of: secret),
                "\(nsid) leaked sensitive material \(index)",
                file: file,
                line: line
            )
        }
    }

    private func semanticSensitiveMaterial(
        headers: HTTPFields,
        fixture: Fixture,
        credential: String
    ) -> [Data] {
        var values = [
            credential,
            "matrix-private-record-sentinel",
            "delete-me",
            "matrix-create",
            "matrix-put",
            "matrix-batch",
        ]
        if let accessToken = fixture.semanticToken {
            values.append(accessToken)
        }
        if let authorization = headers[.authorization] {
            values.append(authorization)
            if let token = authorization.split(separator: " ", maxSplits: 1).last {
                values.append(String(token))
            }
        }
        if let dpop = headers[HTTPField.Name("DPoP")!] {
            values.append(dpop)
        }
        var material = values.map { Data($0.utf8) }
        if let blobPayload = fixture.blobPayload {
            material.append(blobPayload)
        }
        return material
    }

    private func percentEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private actor CompositionAttestationPolicy:
    SpaceCredentialClientAttestationPolicy
{
    let marker: String
    private var count = 0

    init(marker: String) {
        self.marker = marker
    }

    func verifiedClientID(
        for _: String?,
        authority _: String,
        now _: Date
    ) async throws -> String? {
        count += 1
        return marker
    }

    func invocationCount() -> Int {
        count
    }
}

/// Explicitly test-scoped continuity storage for synchronous configuration
/// parsing tests. The production `serve` path always supplies
/// `SQLiteControlDatabase`.
private actor TestPLCCredentialKeyContinuityStore:
    PLCCredentialKeyContinuityStore
{
    private var checkpoints:
        [String: PLCCredentialKeyContinuityCheckpoint] = [:]

    func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint {
        if let existing = checkpoints[advance.checkpoint.issuer],
           existing.terminalCID != advance.checkpoint.terminalCID,
           !advance.auditCIDs.contains(existing.terminalCID) {
            throw PLCCredentialKeyContinuityStoreError.continuityViolation
        }
        checkpoints[advance.checkpoint.issuer] = advance.checkpoint
        return advance.checkpoint
    }

    func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        checkpoints[issuer]
    }
}

private actor SemanticTokenCapture {
    private var delegation: String?
    private var credential: String?
    private var latestRevision: String?
    private var oplogRevisions: [String] = []
    private var recoveryCAR: Data?

    func setDelegation(_ value: String) {
        delegation = value
    }

    func setCredential(_ value: String) {
        credential = value
    }

    func setLatestRevision(_ value: String) {
        latestRevision = value
    }

    func setOplogRevisions(_ value: [String]) {
        oplogRevisions = value
    }

    func setRecoveryCAR(_ value: Data) {
        recoveryCAR = value
    }

    func values() -> (
        delegation: String?,
        credential: String?,
        latestRevision: String?,
        oplogRevisions: [String],
        recoveryCAR: Data?
    ) {
        (delegation, credential, latestRevision, oplogRevisions, recoveryCAR)
    }
}

private struct Fixture {
    let root: URL
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let oauthRuntime: SwanOAuthRuntime
    let localRuntime: ServeLocalSpaceRuntime
    let localKey: P256.Signing.PrivateKey
    let semanticSpace: SpaceURI?
    let lifecycleSpace: SpaceURI?
    let semanticScopes: Set<String>
    let semanticToken: String?
    let semanticTokenKey: P256.Signing.PrivateKey?
    let semanticTokenJWK: OAuthJSONWebKey?
    let blobCID: String?
    let blobPayload: Data?

    static func make(
        localDID: String,
        installSemanticState: Bool = false
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "ServePermissionedRuntimeCompositionTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let kek = Data(repeating: 0x5A, count: 32)
            let keyStore = try FileAccountKeyStore(
                root: root.appending(path: "keys"),
                configuration: try .init(activeKeyID: "composition", activeKey: kek)
            )
            let keys = try await AccountKeyProvisioner(keyStore: keyStore)
                .provisionInitial(accountDID: localDID)
            let localKey = try P256.Signing.PrivateKey(
                rawRepresentation: try await keyStore.key(for: keys.signingReference)
            )
            _ = try await control.createAccount(try .init(
                did: localDID,
                canonicalHandle: "composition.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(
                    purpose: .signing,
                    generation: keys.signingReference.generation
                ),
                rotationKey: .init(
                    purpose: .rotation,
                    generation: keys.rotationReference.generation
                ),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let database = try await SQLiteAccountDatabase(
                dataDirectory: root,
                did: localDID
            )
            let semanticSpace: SpaceURI?
            let lifecycleSpace: SpaceURI?
            let semanticScopes: Set<String>
            let blobCID: String?
            let blobPayload: Data?
            do {
                if installSemanticState {
                let space = try SpaceURI(
                    authority: localDID,
                    spaceType: "app.bsky.bookmarks",
                    skey: "semantic-matrix"
                )
                let lifecycle = try SpaceURI(
                    authority: localDID,
                    spaceType: "app.bsky.bookmarks",
                    skey: "semantic-lifecycle"
                )
                let base = "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)"
                let scopes: Set<String> = [
                    "atproto",
                    "space:*?authority=*&skey=*&action=read",
                    "\(base)&action=read",
                    "\(base)&action=create&collection=app.bsky.feed.post",
                    "\(base)&action=update&collection=app.bsky.feed.post",
                    "\(base)&action=delete&collection=app.bsky.feed.post",
                ]
                let authorization = AuthorizationContext.accountOAuthForTesting(
                    subject: localDID,
                    scopes: scopes
                )
                _ = try await database.createSimpleSpace(
                    space: space,
                    owner: localDID,
                    configuration: .init(policy: .public, appAccess: .open),
                    authorization: authorization
                )
                let repository = try DurableSpaceRepository(
                    database: database,
                    space: space,
                    author: localDID
                )
                let seed = try SpaceRecordURI(
                    space: space,
                    author: localDID,
                    collection: "app.bsky.feed.post",
                    rkey: "seed"
                )
                let deleteMe = try SpaceRecordURI(
                    space: space,
                    author: localDID,
                    collection: "app.bsky.feed.post",
                    rkey: "delete-me"
                )
                _ = try await repository.apply(
                    .put(
                        uri: seed,
                        value: Self.recordCBOR("matrix-private-record-sentinel")
                    ),
                    expectedRevision: 0,
                    requestID: UUID(),
                    wireRevision: try TID(tidString: "2222222222222"),
                    authorization: authorization
                )
                _ = try await repository.apply(
                    .put(uri: deleteMe, value: Self.recordCBOR("delete-me")),
                    expectedRevision: 1,
                    requestID: UUID(),
                    wireRevision: try TID(tidString: "2222222222223"),
                    authorization: authorization
                )
                let payload = Data("matrix-private-blob-sentinel".utf8)
                let blob = try await database.putBlob(payload, namespace: .space(space))
                semanticSpace = space
                lifecycleSpace = lifecycle
                semanticScopes = scopes
                blobCID = blob.cid
                blobPayload = payload
                } else {
                    semanticSpace = nil
                    lifecycleSpace = nil
                    semanticScopes = []
                    blobCID = nil
                    blobPayload = nil
                }
                try await database.close()
            } catch {
                try? await database.close()
                throw error
            }
            let mountedKEK = root.appending(path: "mounted-kek")
            try kek.base64URLEncodedString().data(using: .utf8)!.write(to: mountedKEK)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: mountedKEK.path
            )
            let localRuntime = try await ServeLocalSpaceRuntime.make(
                keyDirectory: root.appending(path: "keys"),
                kekFile: mountedKEK,
                kekID: "composition",
                controlStore: control
            )
            let oauthRuntime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0xA2, count: 32)
            )
            let semanticMaterial = installSemanticState
                ? try await issueToken(
                    runtime: oauthRuntime,
                    subject: localDID,
                    scopes: semanticScopes
                )
                : nil
            return Fixture(
                root: root,
                control: control,
                directory: try await .bootstrap(
                    dataDirectory: root,
                    controlStore: control,
                    publicIdentityVerifier: nil
                ),
                oauthRuntime: oauthRuntime,
                localRuntime: localRuntime,
                localKey: localKey,
                semanticSpace: semanticSpace,
                lifecycleSpace: lifecycleSpace,
                semanticScopes: semanticScopes,
                semanticToken: semanticMaterial?.token,
                semanticTokenKey: semanticMaterial?.key,
                semanticTokenJWK: semanticMaterial?.jwk,
                blobCID: blobCID,
                blobPayload: blobPayload
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

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }

    private struct TokenMaterial {
        let token: String
        let key: P256.Signing.PrivateKey
        let jwk: OAuthJSONWebKey
    }

    private static func issueToken(
        runtime: SwanOAuthRuntime,
        subject: String,
        scopes: Set<String>
    ) async throws -> TokenMaterial {
        let key = P256.Signing.PrivateKey()
        let representation = key.publicKey.x963Representation
        let jwk = try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
        let now = Date()
        let session = try OAuthValidatedSession(
            issuer: "https://swan.example",
            client: OAuthResolvedClientMetadata(
                metadata: try OAuthClientMetadata(
                    clientID: URL(string: "https://client.example/metadata")!,
                    redirectURIs: [URL(string: "https://client.example/callback")!],
                    grantTypes: ["authorization_code", "refresh_token"],
                    responseTypes: ["code"],
                    scopes: scopes,
                    dpopBoundAccessTokens: true
                ),
                keySet: nil
            ),
            redirectURI: URL(string: "https://client.example/callback")!,
            scopes: scopes,
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: jwk.thumbprint(),
                jwtID: "semantic-issue-\(UUID().uuidString)",
                issuedAt: now
            ),
            now: now
        )
        let tokens = try await runtime.tokenService.issue(
            subject: subject,
            session: session,
            now: now
        )
        return .init(token: tokens.accessToken, key: key, jwk: jwk)
    }

    private static func recordCBOR(_ text: String) -> Data {
        precondition(text.utf8.count < 256)
        let stringPrefix: [UInt8] = text.utf8.count < 24
            ? [UInt8(0x60 + text.utf8.count)]
            : [0x78, UInt8(text.utf8.count)]
        return Data([0xa1, 0x64, 0x74, 0x65, 0x78, 0x74] + stringPrefix)
            + Data(text.utf8)
    }
}
