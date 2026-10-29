import Crypto
import Foundation
import Petrel
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest

/// SW-B: `swan account adopt-recreated-space` through the real binary. The
/// command must verify the presented credential the way `serve` verifies a
/// presented credential: the authority's revocations apply, an authority
/// hosted on this Swan is verified with its local account key under
/// `--enable-local-space-interop`, and `--enable-spaces-open-interop` is
/// accepted.
final class RecreatedSpaceAdoptionCLITests: XCTestCase {
    private let receiver = "did:plc:receiverabcdefghijklmnop"
    private let remoteAuthority = "did:plc:authorityabcdefghijklmno"
    private let localAuthority = "did:plc:localauthorityabcdefghij"
    private let passwordVerifier =
        "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"

    func testCommandRefusesARevokedCredentialAndAdoptsWithAPinnedKey() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try dataDirectory(in: root)
        let space = try SpaceURI(authority: remoteAuthority, spaceType: "com.example.forum", skey: "cli")
        let authorityKey = P256.Signing.PrivateKey()
        try await registerAccount(receiver, in: data)
        try await closeReceiverSpace(space, in: data)
        let notification = try notificationConfig(in: root, credentialPins: [
            (remoteAuthority, authorityKey.publicKey),
        ])

        let revoked = try credential(for: space, signedBy: authorityKey)
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        do {
            try await DurableSpaceCredentialRevocations(store: control).record(
                space: space,
                credentialIDs: [try PermissionedDataJWT.inspectSpaceCredential(revoked).claims.jti]
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
        let refused = try runAdopt(root: root, data: data, space: space, credential: revoked, arguments: [
            "--notification-config", notification.path,
        ])
        XCTAssertNotEqual(refused.status, 0)
        XCTAssertTrue(refused.error.contains("space credential was revoked"), refused.error)
        let retained = try await tombstoneEventID(space, in: data)
        XCTAssertEqual(retained, "deletion-1")

        let adopted = try runAdopt(
            root: root, data: data, space: space,
            credential: try credential(for: space, signedBy: authorityKey),
            arguments: ["--notification-config", notification.path, "--enable-spaces-open-interop"]
        )
        XCTAssertEqual(adopted.status, 0, adopted.error)
        let outcome = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(adopted.output.utf8)) as? [String: Any]
        )
        XCTAssertEqual(outcome["adopted"] as? Bool, true)
        XCTAssertEqual(outcome["deletionEventID"] as? String, "deletion-1")
        let cleared = try await tombstoneEventID(space, in: data)
        XCTAssertNil(cleared)
    }

    func testCommandVerifiesAnAuthorityHostedHereOnlyWithLocalSpaceInterop() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = try dataDirectory(in: root)
        let space = try SpaceURI(authority: localAuthority, spaceType: "com.example.forum", skey: "local")
        let kek = Data(repeating: 0x61, count: 32)
        let keyStore = try FileAccountKeyStore(
            root: data.appending(path: "keys"),
            configuration: try .init(activeKeyID: "primary", activeKey: kek)
        )
        // ServeLocalSpaceRuntime refuses to start unless every active
        // account has key metadata, so the receiver gets keys too.
        var authoritySigning: P256.Signing.PrivateKey?
        for did in [receiver, localAuthority] {
            let signing = P256.Signing.PrivateKey()
            try await keyStore.createBatch([
                try AccountKeyMaterial(
                    reference: try AccountKeyReference(accountDID: did, purpose: .signing, generation: 1),
                    key: signing.rawRepresentation
                ),
                try AccountKeyMaterial(
                    reference: try AccountKeyReference(accountDID: did, purpose: .rotation, generation: 1),
                    key: P256.Signing.PrivateKey().rawRepresentation
                ),
            ])
            try await registerAccount(did, in: data)
            if did == localAuthority { authoritySigning = signing }
        }
        try await closeReceiverSpace(space, in: data)
        let notification = try notificationConfig(in: root, credentialPins: [])
        let mountedKEK = root.appending(path: "mounted-kek")
        try protectedWrite(Data(base64URLEncoded(kek).utf8), to: mountedKEK)
        let signer = try XCTUnwrap(authoritySigning)

        let withoutLocal = try runAdopt(
            root: root, data: data, space: space,
            credential: try credential(for: space, signedBy: signer),
            arguments: ["--notification-config", notification.path]
        )
        XCTAssertNotEqual(withoutLocal.status, 0, "no pin or local key should verify the co-hosted authority")
        XCTAssertTrue(withoutLocal.error.contains("unavailable"), withoutLocal.error)
        let retained = try await tombstoneEventID(space, in: data)
        XCTAssertEqual(retained, "deletion-1")

        let withLocal = try runAdopt(
            root: root, data: data, space: space,
            credential: try credential(for: space, signedBy: signer),
            arguments: [
                "--notification-config", notification.path,
                "--enable-local-space-interop",
                "--space-account-kek-file", mountedKEK.path,
            ]
        )
        XCTAssertEqual(withLocal.status, 0, withLocal.error)
        XCTAssertFalse(withLocal.error.contains(mountedKEK.path))
        let cleared = try await tombstoneEventID(space, in: data)
        XCTAssertNil(cleared)
    }

    func testSpaceKeyOptionsRequireLocalSpaceInteropBeforeTouchingData() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let space = try SpaceURI(authority: remoteAuthority, spaceType: "com.example.forum", skey: "opts")
        let result = try runAdopt(
            root: root, data: data, space: space, credential: "unused",
            arguments: [
                "--notification-config", root.appending(path: "notification.json").path,
                "--space-account-kek-file", root.appending(path: "mounted-kek").path,
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(
            result.error.contains("space account key options require --enable-local-space-interop"),
            result.error
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: data.path))
    }

    // MARK: - Fixture

    private func registerAccount(_ did: String, in data: URL) async throws {
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        do {
            _ = try await control.createAccount(AccountControlRegistration(
                did: did,
                canonicalHandle: "\(did.dropFirst("did:plc:".count).prefix(12)).example.com",
                passwordVerifier: passwordVerifier,
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
            ))
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    /// The receiver writes into `space` from its own repository, then the
    /// authority's deletion notice closes the receiver's replicated state.
    private func closeReceiverSpace(_ space: SpaceURI, in data: URL) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: data, did: receiver)
        do {
            let value = Data([0xA1, 0x61, 0x61, 0x01])
            let uri = try SpaceRecordURI(space: space, author: receiver, collection: "app.bsky.feed.post", rkey: "own")
            _ = try await database.apply(
                space: space, author: receiver, expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            try await database.receiveSpaceDeletionNotification(
                space: space, issuer: space.authority, audience: receiver, eventID: "deletion-1",
                requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space),
                now: Date().addingTimeInterval(-600)
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func tombstoneEventID(_ space: SpaceURI, in data: URL) async throws -> String? {
        let database = try await SQLiteAccountDatabase(dataDirectory: data, did: receiver)
        do {
            let tombstone = try await database.recipientSpaceDeletionTombstone(space)
            try await database.close()
            return tombstone?.deletionEventID
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// A credential the authority issued after the deletion, for `space`.
    private func credential(for space: SpaceURI, signedBy key: P256.Signing.PrivateKey) throws -> String {
        try PermissionedDataJWT.createSpaceCredential(
            issuer: space.authority, space: space, key: key,
            confirmationKeyID: SpaceHTTPSignature.keyID(for: P256.Signing.PrivateKey()),
            now: Date().addingTimeInterval(-60)
        )
    }

    private func notificationConfig(
        in root: URL,
        credentialPins: [(String, P256.Signing.PublicKey)]
    ) throws -> URL {
        let url = root.appending(path: "notification.json")
        let configuration: [String: Any] = [
            "credentialPublicKeys": credentialPins.map { issuer, key in
                [
                    "issuer": issuer,
                    "generation": 1,
                    "algorithm": "ES256",
                    "publicKey": base64URLEncoded(key.x963Representation),
                ] as [String: Any]
            },
            "delegationPublicKeys": [],
            "servicePublicKeys": [],
            "authorityDestinations": [],
            "registrationDestinations": [],
        ]
        try JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys]).write(to: url)
        return url
    }

    private func runAdopt(
        root: URL,
        data: URL,
        space: SpaceURI,
        credential: String,
        arguments: [String]
    ) throws -> AdoptProcessResult {
        let credentialFile = root.appending(path: "credential-\(UUID().uuidString)")
        try protectedWrite(Data((credential + "\n").utf8), to: credentialFile)
        let operatorSecret = root.appending(path: "operator-secret")
        if !FileManager.default.fileExists(atPath: operatorSecret.path) {
            try protectedWrite(Data("operator-secret-for-tests\n".utf8), to: operatorSecret)
        }
        let process = Process()
        process.executableURL = try SwanCLITestExecutable.require()
        process.arguments = [
            "account", "adopt-recreated-space",
            "--data-directory", data.path,
            "--did", receiver,
            "--space", space.rawValue,
            "--credential-file", credentialFile.path,
            "--operator-secret-file", operatorSecret.path,
        ] + arguments
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "SWAN_OPERATOR_SECRET")
        process.environment = environment
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        let outputData = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return AdoptProcessResult(
            status: process.terminationStatus,
            output: String(decoding: outputData, as: UTF8.self),
            error: String(decoding: errorData, as: UTF8.self)
        )
    }

    private func dataDirectory(in root: URL) throws -> URL {
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return data
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAdoptRecreatedSpaceCLI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func protectedWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct AdoptProcessResult {
    let status: Int32
    let output: String
    let error: String
}
