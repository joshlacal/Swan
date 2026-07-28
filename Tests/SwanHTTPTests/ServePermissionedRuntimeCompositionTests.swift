import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
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

final class ServePermissionedRuntimeCompositionTests: XCTestCase {
    private let localDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private let remoteDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let managingAudience = "did:web:configured-managing.example"
    private let recipientService = "did:web:configured-recipient.example"

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
                        path: "Profiles/permissioned-data-0016-2026-07-03.json"
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

            let app = server.buildApplication(
                logger: Logger(label: "ServePermissionedRuntimeCompositionTests")
            )
            try await app.test(.router) { client in
                for descriptor in PermissionedData0016.methods {
                    let method: HTTPRequest.Method = descriptor.kind == .query ? .get : .post
                    try await client.execute(
                        uri: "/xrpc/\(descriptor.nsid)",
                        method: method
                    ) { response in
                        XCTAssertNotEqual(response.status, .notFound, descriptor.nsid)
                        XCTAssertNotEqual(response.status, .serviceUnavailable, descriptor.nsid)
                    }
                }
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
        return try ServeNotificationRuntime.load(from: config)
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
        return try ServeNotificationRuntime.load(from: config)
    }

    private static let remoteDelegation =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWRlbGVnYXRpb24rand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eSIsImF1ZCI6ImRpZDpwbGM6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4I2F0cHJvdG9fc3BhY2VfaG9zdCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDAwMDYwLCJqdGkiOiJ0cy1ub25jZV8wMSJ9.CiWW_bplyq9ZtybzoUL9f7J_lqlcFKkmAbY2YsVlf5Bly4Ufue7e9QN6_8PioonLWqKnmm6T-RW3Mq2C_JTC6A"
    private static let remoteCredential =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0Iiwia2lkIjoiI2F0cHJvdG8ifQ.eyJpc3MiOiJkaWQ6cGxjOmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eCIsInN1YiI6ImF0Oi8vZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3gvc3BhY2UvYXBwLmJza3kuYm9va21hcmtzL3RzLWdvbGRlbiIsImlhdCI6MTc1MDAwMDAwMCwiZXhwIjoxNzUwMDA3MjAwLCJqdGkiOiJ0cy1jcmVkZW50aWFsLW5vbmNlXzAxIn0.kgRbwHruWKzbsHZlMjmSFYmz1dKBjpP0eQBvJLRYlzMAClhsOpYnRYpe2fBMGtuciGngcQgEwWYSjHpa9YmIEQ"
    private static let remoteService =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NTAwMDAwMDAsImlzcyI6ImRpZDpwbGM6YmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5IiwiYXVkIjoiZGlkOnBsYzphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3giLCJleHAiOjE3NTAwMDAwNjAsImx4bSI6ImNvbS5hdHByb3RvLnNwYWNlLm5vdGlmeVdyaXRlIiwianRpIjoicGlubmVkLXRzLW5vdGlmeS0wMDEifQ.o782N9f1U23FL8bWXqQiNDBjp7c-5Cxj4IIlvqLdEUZFC4K0C-vUz-AN8PuGZINo1K2Y6_DY-qJmgak6Fk-aPA"

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private struct Fixture {
    let root: URL
    let control: SQLiteControlDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let oauthRuntime: SwanOAuthRuntime
    let localRuntime: ServeLocalSpaceRuntime
    let localKey: P256.Signing.PrivateKey

    static func make(localDID: String) async throws -> Fixture {
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
            try await database.close()
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
            return Fixture(
                root: root,
                control: control,
                directory: try await .bootstrap(
                    dataDirectory: root,
                    controlStore: control
                ),
                oauthRuntime: try SwanOAuthRuntime(
                    controlStore: control,
                    serverKey: Data(repeating: 0xA2, count: 32)
                ),
                localRuntime: localRuntime,
                localKey: localKey
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
}
