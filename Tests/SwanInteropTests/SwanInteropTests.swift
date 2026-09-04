import Crypto
import Foundation
import NIOCore
import Petrel
import PetrelCrypto
import PetrelRepo
import SwanCore
@testable import SwanInterop
import SwanOAuth
import SwanSQLite
import SwanSpaces
import XCTest

final class SwanInteropTests: XCTestCase {
    private static let artifactRecordCID =
        "bafyreidqz2dr7cr5h62etpb4hlhgkr6o6aw7y5h74sgzcjjsu4sl7w7fxe"
    private static let artifactReadCID =
        "bafyreibtcy2i3ow7w6yry7boui2zjfaz4i7z7keyvuwbtd4zsylzckuzeu"

    func testCheckedInProfileAndArtifactsVerifyOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )

        XCTAssertTrue(report.isValid, "\(report.diagnostics)")
        XCTAssertEqual(report.profileID, OfflineProtocolProfileVerifier.stableProfileID)
    }

    func testLegacyPermissionedProfileArtifactsRemainByteExact() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let expected = [
            (
                "Profiles/permissioned-data-0016-2026-07-03.json",
                "30a696e78f62b11f22dd669f6ebb9f7e08d6c1d3346ebd71ad5cf0cd49b3f4d0"
            ),
            (
                "Profiles/permissioned-data-0016-2026-07-03.lexicons.sha256",
                "9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
            ),
            (
                "Profiles/permissioned-data-0016-2026-07-03.generated-wire.sha256",
                "c1d5697f351a4209c7f8a9faaf460d423f9f44f37845ae2c92e150e78c552609"
            ),
            (
                "Profiles/permissioned-data-0016-2026-07-30.json",
                "431294d96a4a82f15fe5cd0807d89dbcd76d1768a1762d2a0c6a5905e8083988"
            ),
            (
                "Profiles/permissioned-data-0016-2026-07-30.lexicons.sha256",
                "9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
            ),
            (
                "Profiles/permissioned-data-0016-2026-07-30.generated-wire.sha256",
                "80f9f7b93127826d95d516a4a9d18b7ca245d82fc74f8fa484bbf3423d1f51db"
            ),
            (
                "Profiles/permissioned-data-0016-2026-08-15.json",
                "b3edfc13675d4273cf036f1f74391795b3f1307d4b1fd24ad021f26fa60e4023"
            ),
            (
                "Profiles/permissioned-data-0016-2026-08-15.lexicons.sha256",
                "873fb88439cadd447ee6a90f9fadb262fa84bdb6689735b53e667db13d7219c3"
            ),
            (
                "Profiles/permissioned-data-0016-2026-08-15.generated-wire.sha256",
                "7e7fe09868a7fcda0c6ab824ebe19e7f64ba147db63fd02a27762ed538e02704"
            ),
        ]

        for (path, checksum) in expected {
            let data = try Data(contentsOf: packageRoot.appending(path: path))
            XCTAssertEqual(
                SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
                checksum,
                path
            )
        }

        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: packageRoot.appending(
                path: "Profiles/permissioned-data-0016-2026-07-03.json"
            ),
            sourceRoot: packageRoot
        )
        XCTAssertEqual(report.profileID, "permissioned-data-0016-2026-07-03")
        XCTAssertEqual(
            report.diagnostics,
            [.init(.unsupportedProfileID, artifact: "profile")]
        )

        let report815 = OfflineProtocolProfileVerifier.verify(
            profileURL: packageRoot.appending(
                path: "Profiles/permissioned-data-0016-2026-08-15.json"
            ),
            sourceRoot: packageRoot
        )
        XCTAssertEqual(report815.profileID, "permissioned-data-0016-2026-08-15")
        XCTAssertEqual(
            report815.diagnostics,
            [.init(.unsupportedProfileID, artifact: "profile")]
        )
    }

    func testInvalidRevisionPinFailsWithTypedDiagnostic() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.replaceInProfile(
            "1caad93dbb1f445396f6abf3b97eb4040345e78e",
            with: String(repeating: "g", count: 40)
        )

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .invalidRevisionPin })
    }

    func testUnexpectedButWellFormedPinFailsImmutableProfileVerification() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.replaceInProfile(
            "9d787ebff231ff8f4e01c63717e9f5bcd6e1bc33",
            with: String(repeating: "a", count: 40)
        )

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .immutableProfilePinMismatch })
    }

    func testLexiconManifestChecksumMismatchFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.append("# mutated", to: fixture.lexiconManifestURL)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.diagnostics, [.init(.lexiconManifestDigestMismatch, artifact: "lexicon manifest")])
    }

    func testMalformedProfileFailsWithoutLeakingItsContents() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try Data("{ this is not JSON and contains secret-value }".utf8).write(to: fixture.profileURL)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.diagnostics, [.init(.malformedProfile, artifact: "profile")])
        XCTAssertFalse(report.diagnostics[0].description.contains("secret-value"))
    }

    func testGeneratedWireSourceDriftFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.append("\n// drift", to: fixture.generatedWireSourceURL)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .generatedWireSourceChecksumMismatch })
    }

    func testUnexpectedGeneratedWireSourceFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let unexpected = fixture.root.appending(path: "Sources/SwanSpacesWire/Generated/Injected.swift")
        try FileManager.default.createDirectory(at: unexpected.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("enum Injected {}".utf8).write(to: unexpected)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .generatedWireSourceSetMismatch })
    }

    func testInternalGeneratedWireSymlinkFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.replaceGeneratedWireSourceWithInternalSymlink()

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .generatedWireSourceSymlink })
    }

    func testDuplicateGeneratedWireManifestEntryIsRejected() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let text = try String(contentsOf: fixture.generatedWireManifestURL, encoding: .utf8)
        let firstEntry = try XCTUnwrap(text.split(separator: "\n").first)
        try fixture.replaceGeneratedWireManifest(Data((text + "\(firstEntry)\n").utf8))

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .malformedGeneratedWireManifest })
    }

    func testUnsafeGeneratedWireManifestPathIsRejected() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let text = try String(contentsOf: fixture.generatedWireManifestURL, encoding: .utf8)
        let mutated = text.replacingOccurrences(
            of: "Sources/SwanSpacesWire/",
            with: "Sources/SwanSpacesWire/../SwanSpacesWire/"
        )
        try fixture.replaceGeneratedWireManifest(Data(mutated.utf8))

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .malformedGeneratedWireManifest })
    }

    func testUppercaseGeneratedWireManifestChecksumIsRejected() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let text = try String(contentsOf: fixture.generatedWireManifestURL, encoding: .utf8)
        let checksumEnd = try XCTUnwrap(text.firstIndex(of: " "))
        let lowercaseHex = try XCTUnwrap(text[..<checksumEnd].firstIndex(of: "a"))
        var mutated = text
        mutated.replaceSubrange(lowercaseHex...lowercaseHex, with: "A")
        try fixture.replaceGeneratedWireManifest(Data(mutated.utf8))

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .malformedGeneratedWireManifest })
    }

    func testLaboratoryCacheRequiresMatchingArchiveAndPDSSource() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-lab-cache-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let archiveData = Data("pinned archive fixture".utf8)
        let archiveDigest = SHA256.hash(data: archiveData).map { String(format: "%02x", $0) }.joined()
        let pin = ReferenceSourcePin(
            repository: URL(string: "https://example.invalid/reference")!,
            commit: "fixture",
            archiveSHA256: archiveDigest
        )
        try archiveData.write(to: root.appending(path: "atproto-fixture.tar.gz"))
        let source = root.appending(path: "atproto-fixture", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: source.appending(path: "services/pds", directoryHint: .isDirectory),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: source.appending(path: "packages/pds", directoryHint: .isDirectory),
            withIntermediateDirectories: true
        )
        for path in ["package.json", "pnpm-lock.yaml", "services/pds/Dockerfile", "packages/pds/package.json"] {
            try Data("{}".utf8).write(to: source.appending(path: path))
        }

        XCTAssertTrue(InteropLaboratory.validate(cacheDirectory: root, pin: pin).isValid)

        try Data("mutated".utf8).write(to: root.appending(path: "atproto-fixture.tar.gz"))
        XCTAssertEqual(
            InteropLaboratory.validate(cacheDirectory: root, pin: pin).diagnostics,
            [.invalidReferenceArchive]
        )
    }

    func testSanitizedScenarioArtifactHasNoCredentialFields() throws {
        let artifact = try SanitizedScenarioArtifact(
            scenario: "reference-matrix",
            faultModes: [.delayed, .corrupted]
        )
        let encoded = try JSONEncoder().encode(artifact)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let keys = Set(object.keys.map { $0.lowercased() })
        XCTAssertTrue(keys.isDisjoint(with: ["password", "authorization", "access_token", "refresh_token", "dpop", "private_key", "ikm"]))
        XCTAssertEqual(object["status"] as? String, "planned-not-executed")
        XCTAssertTrue((object["fixturePolicy"] as? String ?? "").hasPrefix("summary-only"))
    }

    func testPermissionedRoundTripArtifactCarriesCommitmentsOnly() throws {
        let artifact = LiveInteropPermissionedRoundTripArtifact(
            scenario: "permissioned-cross-host",
            member: "member-host",
            authority: "authority-host",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.artifactRecordCID,
            readCID: Self.artifactRecordCID,
            writeResponseSHA256: String(repeating: "a", count: 64),
            readResponseSHA256: String(repeating: "b", count: 64),
            converged: true,
            status: "passed",
            errorCode: nil,
            events: []
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(artifact)) as? [String: Any]
        )
        XCTAssertEqual(object["writeCID"] as? String, Self.artifactRecordCID)
        XCTAssertEqual(object["readCID"] as? String, Self.artifactRecordCID)
        XCTAssertEqual(object["status"] as? String, "passed")
        let keys = Set(Self.sanitizedKeys(in: object).map { $0.lowercased() })
        for forbidden in ["access_token", "refresh_token", "dpop", "private_key", "record_value"] {
            XCTAssertFalse(keys.contains { $0.contains(forbidden) }, "artifact leaked forbidden key: \(forbidden)")
        }
    }

    func testLiveRoundTripRejectsSelectorBodyMismatchBeforeNetwork() async throws {
        let url = URL(string: "https://127.0.0.1:1")!
        let client = try InteropXRPCClient(baseURL: url, timeout: 0.2)
        let producer = LiveInteropHost(label: "producer", client: client)
        let consumer = LiveInteropHost(label: "consumer", client: client)
        let publicArtifact = await LiveInteropRunner.publicPutAndRead(
            scenario: "selector-mismatch",
            producer: producer,
            consumer: consumer,
            repository: "did:plc:abcdefghijklmnopqrstuvwx",
            collection: "app.bsky.feed.post",
            rkey: "expected",
            putBody: Data(#"{"repo":"did:plc:abcdefghijklmnopqrstuvwx","collection":"app.bsky.feed.post","rkey":"other"}"#.utf8)
        )
        XCTAssertEqual(publicArtifact.status, "failed")
        XCTAssertEqual(publicArtifact.errorCode, "InvalidRequest")
        XCTAssertTrue(publicArtifact.events.isEmpty)

        let space = try SpaceURI(
            authority: "did:plc:abcdefghijklmnopqrstuvwx",
            spaceType: "app.swan.interop",
            skey: "selector-mismatch"
        )
        let permissionedArtifact = await LiveInteropRunner.permissionedCreateAndRead(
            scenario: "permissioned-selector-mismatch",
            member: producer,
            authority: consumer,
            broker: SpaceCredentialBroker(member: client, authority: client),
            space: space,
            createBody: Data(#"{"space":"wrong-space","repo":"did:plc:abcdefghijklmnopqrstuvwx","collection":"app.bsky.feed.post","rkey":"r1"}"#.utf8),
            readQuery: [
                "space": space.rawValue,
                "repo": "did:plc:abcdefghijklmnopqrstuvwx",
                "collection": "app.bsky.feed.post",
                "rkey": "r1",
            ],
            readHost: consumer
        )
        XCTAssertEqual(permissionedArtifact.status, "failed")
        XCTAssertEqual(permissionedArtifact.errorCode, "InvalidRequest")
        XCTAssertTrue(permissionedArtifact.events.isEmpty)
    }

    func testLiveRoundTripMaterializesRepositoryPlaceholderBeforeNetwork() async throws {
        let url = URL(string: "https://127.0.0.1:1")!
        let client = try InteropXRPCClient(baseURL: url, timeout: 0.2)
        let producer = LiveInteropHost(label: "producer", client: client)
        let consumer = LiveInteropHost(label: "consumer", client: client)
        let artifact = await LiveInteropRunner.publicPutAndRead(
            scenario: "repository-placeholder",
            producer: producer,
            consumer: consumer,
            repository: "did:plc:abcdefghijklmnopqrstuvwx",
            collection: "app.bsky.feed.post",
            rkey: "placeholder",
            putBody: Data(#"{"repo":"{{REPOSITORY_DID}}","collection":"app.bsky.feed.post","rkey":"placeholder"}"#.utf8)
        )
        XCTAssertEqual(artifact.status, "failed")
        XCTAssertNotEqual(artifact.errorCode, "InvalidRequest")
        XCTAssertTrue(artifact.events.isEmpty)
    }

    func testXRPCPathUsesNSIDAndCanonicalQueryOrdering() throws {
        let client = try InteropXRPCClient(
            baseURL: URL(string: "https://swan.test")!,
            timeout: 1
        )

        XCTAssertEqual(
            try client.xrpcPath(
                "com.atproto.repo.getRecord",
                query: ["rkey": "3k", "repo": "did:plc:alice"]
            ),
            "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&rkey=3k"
        )
        XCTAssertEqual(
            try client.xrpcPath(
                "com.atproto.sync.getBlob",
                query: [
                    "cid": "bafkreiblob",
                    "did": "did:plc:alice",
                ]
            ),
            "/xrpc/com.atproto.sync.getBlob?cid=bafkreiblob&did=did:plc:alice"
        )
    }

    func testXRPCClientRejectsPlaintextCredentialTransportForNonLoopback() async throws {
        let insecureClient = try InteropXRPCClient(
            baseURL: URL(string: "http://example.com")!,
            timeout: 1
        )
        do {
            _ = try await insecureClient.query(
                "com.atproto.repo.getRecord",
                query: ["repo": "did:plc:alice", "rkey": "3k"],
                authorization: .bearer(token: "secret")
            )
            XCTFail("plain HTTP bearer unexpectedly succeeded")
        } catch let error as InteropHTTPError {
            XCTAssertEqual(error, .invalidURL)
        }

        do {
            _ = try await insecureClient.procedure(
                "com.atproto.repo.createRecord",
                body: Data(),
                authorization: .dpop(accessToken: "token", proof: "proof")
            )
            XCTFail("plain HTTP DPoP unexpectedly succeeded")
        } catch let error as InteropHTTPError {
            XCTAssertEqual(error, .invalidURL)
        }

        do {
            _ = try await insecureClient.binaryProcedure(
                "com.atproto.repo.uploadBlob",
                body: Data([0x01]),
                contentType: "application/octet-stream",
                authorization: .service(token: "service-jwt")
            )
            XCTFail("plain HTTP service token unexpectedly succeeded")
        } catch let error as InteropHTTPError {
            XCTAssertEqual(error, .invalidURL)
        }

        // .none authorization over plain HTTP remains permitted
        do {
            _ = try await insecureClient.query(
                "com.atproto.repo.getRecord",
                query: ["repo": "did:plc:alice", "rkey": "3k"],
                authorization: .none
            )
        } catch let error as InteropHTTPError {
            XCTAssertNotEqual(error, .invalidURL)
        } catch {
            // Network connection error is fine, not invalidURL
        }

        // Loopback HTTP and HTTPS are permitted for credentials
        for loopbackURL in [
            URL(string: "http://127.0.0.1:8080")!,
            URL(string: "http://localhost:8080")!,
            URL(string: "https://example.com")!,
        ] {
            let client = try InteropXRPCClient(
                baseURL: loopbackURL,
                timeout: 0.1
            )
            do {
                _ = try await client.query(
                    "com.atproto.repo.getRecord",
                    query: [:],
                    authorization: .bearer(token: "secret")
                )
            } catch let error as InteropHTTPError {
                XCTAssertNotEqual(error, .invalidURL)
            } catch {
                // Network connection error is fine, not invalidURL
            }
        }
    }

    func testStreamingCARClientAllowsThePinned512MiBBoundSeparatelyFromJSON() throws {
        let http = try InteropHTTPClient(
            baseURL: URL(string: "https://pds.test")!,
            timeout: 1
        )
        XCTAssertEqual(http.maximumResponseBytes, 2 * 1_024 * 1_024)
        XCTAssertEqual(http.maximumStreamingResponseBytes, 512 * 1_024 * 1_024)
    }

    func testInteropHTTPClientPinsOriginPortAndRejectsAuthorityConfusion() async throws {
        let expectedURL = URL(string: "https://pds.test:8443/xrpc/com.atproto.server.describeServer")!
        let handler: InteropHTTPExecuteHandler = { _, url, _, _, _ in
            XCTAssertEqual(url, expectedURL)
            return InteropHTTPResponse(
                status: 200,
                headers: [:],
                body: Data(),
                finalURL: url,
                redirectCount: 0
            )
        }
        let client = try InteropHTTPClient(
            baseURL: URL(string: "https://pds.test:8443")!,
            timeout: 1,
            executeHandler: handler
        )

        _ = try await client.execute(
            method: .get,
            path: "/xrpc/com.atproto.server.describeServer"
        )
        for path in [
            "https://pds.test:443/xrpc/com.atproto.server.describeServer",
            "https://attacker@pds.test:8443/xrpc/com.atproto.server.describeServer",
            "https://pds.test:8443/xrpc/com.atproto.server.describeServer#fragment",
        ] {
            do {
                _ = try await client.execute(method: .get, path: path)
                XCTFail("expected origin validation failure for \(path)")
            } catch let error as InteropHTTPError {
                XCTAssertEqual(error, .invalidURL)
            }
        }
    }

    func testStreamingResponseBufferIsDrainedThroughAtMost64KiBChunks() throws {
        let byteCount = 3 * 64 * 1_024 + 17
        var buffer = ByteBufferAllocator().buffer(capacity: byteCount)
        buffer.writeRepeatingByte(0x42, count: byteCount)
        var chunkCounts: [Int] = []

        let drained = try InteropStreamingBodyChunker.drain(buffer) { chunk in
            chunkCounts.append(chunk.count)
        }

        XCTAssertEqual(drained, byteCount)
        XCTAssertEqual(chunkCounts.reduce(0, +), byteCount)
        XCTAssertEqual(chunkCounts, [64 * 1_024, 64 * 1_024, 64 * 1_024, 17])
    }

    func testLiveReplicaRejectsReorderingAndVerifiesReaderCommitBeforePublication() async throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "replica"
        )
        let uri = try SpaceRecordURI(
            space: space,
            author: "did:plc:alice",
            collection: "app.bsky.feed.post",
            rkey: "r1"
        )
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        let cid = CID.fromDAGCBOR(value).string
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/r1/\(cid)")
        let key = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: "did:plc:alice",
                rev: "222222222222a",
                ikm: Data(repeating: 0x41, count: 32)
            ),
            commitment: hash.commitment,
            key: key
        )
        let replica = try SpaceReplica(space: space, author: "did:plc:alice")
        let synchronizer = IncrementalSynchronizer(replica: replica)
        let entry = InteropRepositoryOperation(
            revision: 1,
            wireRevision: "222222222222a",
            uri: uri,
            cid: cid,
            value: value,
            commitment: hash.commitment
        )
        let state = try await synchronizer.apply(
            [entry],
            terminalCommit: commit,
            publicKey: key.publicKey
        )
        XCTAssertEqual(state.revision, 1)
        XCTAssertEqual(state.commitment, hash.commitment)

        do {
            _ = try await replica.apply([entry])
            XCTFail("duplicate delivery must not be published")
        } catch let error as SpaceReplica.Error {
            XCTAssertEqual(error, .staleRevision)
        }
        let afterDuplicate = await replica.state()
        XCTAssertEqual(afterDuplicate, state)
    }

    func testLiveReplicaDoesNotAdvanceWhenTerminalCommitVerificationFails() async throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "atomic-terminal"
        )
        let uri = try SpaceRecordURI(
            space: space,
            author: "did:plc:alice",
            collection: "app.bsky.feed.post",
            rkey: "r1"
        )
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        let cid = CID.fromDAGCBOR(value).string
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/r1/\(cid)")
        let key = P256.Signing.PrivateKey()
        let forgedCommit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: "did:plc:alice",
                rev: "222222222222a",
                ikm: Data(repeating: 0x41, count: 32)
            ),
            commitment: Data(repeating: 0x99, count: 32),
            key: key
        )
        let replica = try SpaceReplica(space: space, author: "did:plc:alice")
        let synchronizer = IncrementalSynchronizer(replica: replica)
        let entry = InteropRepositoryOperation(
            revision: 1,
            wireRevision: "222222222222a",
            uri: uri,
            cid: cid,
            value: value,
            commitment: hash.commitment
        )

        do {
            _ = try await synchronizer.apply(
                [entry],
                terminalCommit: forgedCommit,
                publicKey: key.publicKey
            )
            XCTFail("a mismatched terminal commit must be rejected")
        } catch let error as SpaceReplica.Error {
            XCTAssertEqual(error, .commitmentMismatch)
        }
        let afterFailure = await replica.state()
        XCTAssertEqual(afterFailure.revision, 0)
        XCTAssertTrue(afterFailure.records.isEmpty)
        XCTAssertEqual(afterFailure.commitment, LtHash().commitment)
    }

    func testLiveReplicaRejectsSignedTerminalRevisionMismatchWithoutAdvancing() async throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "terminal-revision"
        )
        let uri = try SpaceRecordURI(
            space: space,
            author: "did:plc:alice",
            collection: "app.bsky.feed.post",
            rkey: "r1"
        )
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        let cid = CID.fromDAGCBOR(value).string
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/r1/\(cid)")
        let key = P256.Signing.PrivateKey()
        let wrongRevisionCommit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: "did:plc:alice",
                rev: "222222222222b",
                ikm: Data(repeating: 0x42, count: 32)
            ),
            commitment: hash.commitment,
            key: key
        )
        let replica = try SpaceReplica(space: space, author: "did:plc:alice")
        let entry = InteropRepositoryOperation(
            revision: 1,
            wireRevision: "222222222222a",
            uri: uri,
            cid: cid,
            value: value,
            commitment: hash.commitment
        )

        do {
            _ = try await IncrementalSynchronizer(replica: replica).apply(
                [entry],
                terminalCommit: wrongRevisionCommit,
                publicKey: key.publicKey
            )
            XCTFail("a terminal commit for a different wire revision must be rejected")
        } catch let error as SpaceReplica.Error {
            XCTAssertEqual(error, .terminalRevisionMismatch)
        }
        let afterFailure = await replica.state()
        XCTAssertEqual(afterFailure.revision, 0)
        XCTAssertTrue(afterFailure.records.isEmpty)
        XCTAssertEqual(afterFailure.commitment, LtHash().commitment)
    }

    func testCARConsumerVerifiesTwoRootRecoveryFromAFileSpool() throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "car"
        )
        let uri = try SpaceRecordURI(
            space: space,
            author: "did:plc:alice",
            collection: "app.bsky.feed.post",
            rkey: "r1"
        )
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        let cid = CID.fromDAGCBOR(value).string
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/r1/\(cid)")
        let key = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: "did:plc:alice",
                rev: "222222222222a",
                ikm: Data(repeating: 0x42, count: 32)
            ),
            commitment: hash.commitment,
            key: key
        )
        let car = try SpaceCARCodec.encode(
            commit: commit,
            records: [SpaceRecord(uri: uri, value: value, cid: cid, revision: 1)]
        )
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-car-consumer-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try car.data.write(to: root, options: .atomic)
        let recovery = try SwanCARConsumer(maximumBytes: car.data.count + 1).verify(
            fileURL: root,
            space: space,
            author: "did:plc:alice",
            publicKey: key.publicKey
        )
        XCTAssertEqual(recovery.records.count, 1)
        XCTAssertEqual(recovery.commitment, hash.commitment)
        let algorithmBoundRecovery = try SwanCARConsumer(maximumBytes: car.data.count + 1).verify(
            fileURL: root,
            space: space,
            author: "did:plc:alice",
            verificationKey: .p256(key.publicKey)
        )
        XCTAssertEqual(algorithmBoundRecovery.records, recovery.records)
        XCTAssertEqual(algorithmBoundRecovery.commitment, recovery.commitment)
    }

    func testStreamingCARConsumerReturnsSummaryAndCleansSQLiteStagingOnSuccessAndError() async throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "streaming-car"
        )
        let repeatedValue = Data([0xa1, 0x61, 0x78, 0x01])
        let middleValue = Data([0xa1, 0x61, 0x78, 0x02])
        let values = [repeatedValue, middleValue, repeatedValue]
        let records = try zip(["r1", "r2", "r3"], values).map { pair in
            let (rkey, value) = pair
            let uri = try SpaceRecordURI(
                space: space,
                author: "did:plc:alice",
                collection: "app.bsky.feed.post",
                rkey: rkey
            )
            return SpaceRecord(
                uri: uri,
                value: value,
                cid: CID.fromDAGCBOR(value).string,
                revision: 1
            )
        }
        var hash = LtHash()
        for record in records {
            hash.add(
                element: "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
            )
        }
        let key = P256.Signing.PrivateKey()
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: "did:plc:alice",
                rev: "222222222222a",
                ikm: Data(repeating: 0x42, count: 32)
            ),
            commitment: hash.commitment,
            key: key
        )
        let car = try SpaceCARCodec.encode(
            commit: commit,
            records: records
        )
        let root = FileManager.default.temporaryDirectory.appending(
            path: "swan-streaming-car-consumer-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let carURL = root.appending(path: "recovery.car")
        try car.data.write(to: carURL)

        let consumer = try SwanCARConsumer(
            maximumBytes: car.data.count,
            stagingDirectory: root
        )
        let summary = try await consumer.verifyStreaming(
            fileURL: carURL,
            space: space,
            author: "did:plc:alice",
            publicKey: key.publicKey
        )
        XCTAssertEqual(summary.recordCount, 3)
        XCTAssertEqual(summary.commitment, hash.commitment)
        XCTAssertTrue(try recoveryStagingDirectories(in: root).isEmpty)

        var corrupt = car.data
        corrupt[corrupt.index(before: corrupt.endIndex)] ^= 0x01
        try corrupt.write(to: carURL)
        do {
            _ = try await consumer.verifyStreaming(
                fileURL: carURL,
                space: space,
                author: "did:plc:alice",
                publicKey: key.publicKey
            )
            XCTFail("corrupt streamed recovery was accepted")
        } catch let error as SpaceCARStreamingError {
            XCTAssertEqual(error, .blockCIDMismatch)
        }
        XCTAssertTrue(try recoveryStagingDirectories(in: root).isEmpty)
    }

    func testDPoPClientProofIsStrictlySignedAndFresh() throws {
        let key = InteropDPoPKey()
        let target = URL(string: "https://swan.example/xrpc/com.atproto.space.listSpaces")!
        let proof = try key.proof(
            method: "GET",
            target: target,
            nonce: "nonce.fixture",
            accessToken: "opaque-access-token",
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let verified = try OAuthCompactJWT.verify(
            proof,
            publicKey: try key.publicJWK.publicKey(),
            expectedType: OAuthDPoPProofValidator.proofType,
            constraints: .init(
                now: Date(timeIntervalSince1970: 1_750_000_000),
                clockSkew: 0,
                requireIssuedAt: true
            )
        )
        XCTAssertEqual(verified.header.jwk?.thumbprint(), try key.thumbprint)
        XCTAssertNotEqual(
            proof,
            try key.proof(
                method: "GET",
                target: target,
                nonce: "nonce.fixture",
                accessToken: "opaque-access-token",
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
    }
    func testSwanOAuthLabClientRejectsInsecurePlaintextTransport() throws {
        let clientID = URL(string: "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")!
        let redirectURI = URL(string: "http://127.0.0.1/callback")!
        XCTAssertThrowsError(
            try SwanOAuthLabClient(
                issuer: URL(string: "http://example.com")!,
                clientID: clientID,
                redirectURI: redirectURI
            )
        ) { error in
            XCTAssertEqual(error as? InteropHTTPError, .invalidURL)
        }
    }


    func testOAuthLabQueryPathEscapesNestedClientMetadataURL() throws {
        let clientID = URL(string: "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")!
        let path = try SwanOAuthLabClient.queryPath(
            "/oauth/authorize",
            [
                URLQueryItem(name: "client_id", value: clientID.absoluteString),
                URLQueryItem(name: "request_uri", value: "urn:ietf:params:oauth:request_uri:fixture"),
            ]
        )

        XCTAssertEqual(
            path,
            "/oauth/authorize?client_id=http%3A%2F%2Flocalhost%3Fscope%3Datproto%26redirect_uri%3Dhttp%253A%252F%252F127.0.0.1%252Fcallback&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Afixture"
        )
        let components = try XCTUnwrap(URLComponents(string: path))
        XCTAssertEqual(components.queryItems?.count, 2)
        XCTAssertEqual(components.queryItems?.first?.value, clientID.absoluteString)
        XCTAssertEqual(
            components.queryItems?.last?.value,
            "urn:ietf:params:oauth:request_uri:fixture"
        )
    }

    func testOAuthLabRedirectTargetRejectsUserInfoAuthority() throws {
        let expected = try XCTUnwrap(URL(string: "https://client.example/callback"))
        let userInfo = try XCTUnwrap(URL(string: "https://attacker@client.example/callback"))
        let passwordInfo = try XCTUnwrap(URL(string: "https://client:secret@client.example/callback"))

        XCTAssertFalse(SwanOAuthLabClient.sameRedirectTarget(userInfo, expected: expected))
        XCTAssertFalse(SwanOAuthLabClient.sameRedirectTarget(passwordInfo, expected: expected))
        XCTAssertTrue(SwanOAuthLabClient.sameRedirectTarget(expected, expected: expected))
    }

    func testReferenceOAuthProviderUsesSameOriginJSONCSRFAndEphemeralBearer() async throws {
        let requests = ReferenceOAuthMockRequests()
        let issuer = URL(string: "https://reference.example")!
        let clientID = URL(string: "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")!
        let redirectURI = URL(string: "http://127.0.0.1/callback")!
        let csrf = "0123456789abcdef01234567"
        let state = "reference-state"
        let handler: InteropHTTPExecuteHandler = { method, url, headers, body, _ in
            await requests.append(.init(method: method, url: url, headers: headers, body: body))
            switch (method, url.path) {
            case (.post, "/oauth/par") where headers["DPoP"] == nil:
                return .init(
                    status: 401,
                    headers: ["dpop-nonce": "par-nonce"],
                    body: Data(),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.post, "/oauth/par"):
                return .init(
                    status: 201,
                    headers: [:],
                    body: Data(#"{"request_uri":"urn:ietf:params:oauth:request_uri:fixture"}"#.utf8),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.get, "/oauth/authorize"):
                return .init(
                    status: 200,
                    headers: ["set-cookie": "csrf-token=\(csrf); Path=/; Secure"],
                    body: Data("<html><body>client-side provider</body></html>".utf8),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.post, "/@atproto/oauth-provider/~api/sign-in"):
                let json = try XCTUnwrap(body).jsonObject()
                XCTAssertEqual(json["locale"] as? String, "en")
                XCTAssertEqual(json["username"] as? String, "member.example")
                XCTAssertEqual(json["password"] as? String, "correct horse battery staple")
                XCTAssertEqual(json["remember"] as? Bool, false)
                return .init(
                    status: 200,
                    headers: ["set-cookie": "csrf-token=\(csrf); Path=/; Secure"],
                    body: Data(#"{"account":{"did":"did:plc:reference-member"},"ephemeralToken":"ephemeral-token"}"#.utf8),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.post, "/@atproto/oauth-provider/~api/consent"):
                XCTAssertEqual(headers["Authorization"], "Bearer ephemeral-token")
                XCTAssertEqual(headers["X-CSRF-Token"], csrf)
                XCTAssertEqual(headers["Origin"], "https://reference.example")
                XCTAssertEqual(headers["Sec-Fetch-Mode"], "same-origin")
                XCTAssertEqual(headers["Sec-Fetch-Site"], "same-origin")
                let referer = try XCTUnwrap(headers["Referer"])
                let refererURL = try XCTUnwrap(URL(string: referer))
                XCTAssertEqual(refererURL.path, "/oauth/authorize")
                XCTAssertEqual(
                    URLComponents(url: refererURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_uri" })?.value,
                    "urn:ietf:params:oauth:request_uri:fixture"
                )
                let json = try XCTUnwrap(body).jsonObject()
                XCTAssertEqual(json["did"] as? String, "did:plc:reference-member")
                XCTAssertEqual(json["scope"] as? String, "atproto")
                return .init(
                    status: 200,
                    headers: [:],
                    body: Data("{\"url\":\"https://reference.example/oauth/authorize/redirect?redirect_mode=query&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&iss=https%3A%2F%2Freference.example&code=reference-code&state=\(state)\"}".utf8),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.get, "/oauth/authorize/redirect"):
                XCTAssertEqual(headers["Accept"], "text/html")
                XCTAssertEqual(headers["Sec-Fetch-Mode"], "navigate")
                XCTAssertEqual(headers["Sec-Fetch-Site"], "same-origin")
                XCTAssertEqual(headers["Sec-Fetch-Dest"], "document")
                XCTAssertEqual(headers["Cookie"], "csrf-token=\(csrf)")
                let referer = try XCTUnwrap(headers["Referer"])
                let refererURL = try XCTUnwrap(URL(string: referer))
                XCTAssertEqual(refererURL.path, "/oauth/authorize")
                XCTAssertEqual(
                    URLComponents(url: refererURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "request_uri" })?.value,
                    "urn:ietf:params:oauth:request_uri:fixture"
                )
                return .init(
                    status: 303,
                    headers: ["location": "http://127.0.0.1/callback?code=reference-code&state=\(state)&iss=https%3A%2F%2Freference.example"],
                    body: Data(),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.post, "/oauth/token") where headers["DPoP"] == nil:
                return .init(
                    status: 401,
                    headers: ["dpop-nonce": "token-nonce"],
                    body: Data(),
                    finalURL: url,
                    redirectCount: 0
                )
            case (.post, "/oauth/token"):
                return .init(
                    status: 200,
                    headers: [:],
                    body: Data(#"{"access_token":"access-token","refresh_token":"refresh-token","scope":"atproto","sub":"did:plc:reference-member","expires_in":300}"#.utf8),
                    finalURL: url,
                    redirectCount: 0
                )
            default:
                XCTFail("unexpected reference OAuth request: \(method.rawValue) \(url.path)")
                return .init(status: 500, headers: [:], body: Data(), finalURL: url, redirectCount: 0)
            }
        }

        let client = try SwanOAuthLabClient(
            issuer: issuer,
            clientID: clientID,
            redirectURI: redirectURI,
            executeHandler: handler
        )
        let token = try await client.authorizationCode(
            handle: "member.example",
            password: "correct horse battery staple",
            scopes: ["atproto"],
            state: state
        )
        XCTAssertEqual(token.accessToken, "access-token")
        XCTAssertEqual(token.subject, "did:plc:reference-member")

        let recorded = await requests.snapshot()
        XCTAssertEqual(recorded.filter { $0.url.path == "/@atproto/oauth-provider/~api/sign-in" }.count, 1)
        XCTAssertEqual(recorded.filter { $0.url.path == "/@atproto/oauth-provider/~api/consent" }.count, 1)
        XCTAssertEqual(recorded.filter { $0.url.path == "/oauth/authorize/redirect" }.count, 1)
    }

    func testLiveFixtureRecordingStripsSelectorsAndKeepsOnlyResponseDigests() async throws {
        let recorder = InteropFixtureRecorder()
        let response = InteropHTTPResponse(
            status: 200,
            headers: ["content-type": "application/json"],
            body: Data(#"{"cid":"bafkreigh2akiscaildc3"}"#.utf8),
            finalURL: URL(string: "https://swan.example")!,
            redirectCount: 0
        )
        await recorder.record(
            host: "swan",
            method: "GET",
            path: "/xrpc/com.atproto.repo.getRecord?repo=did%3Aplc%3Aalice&collection=app.bsky.feed.post&rkey=secret",
            requestBody: Data(#"{"password":"never-record"}"#.utf8),
            response: response
        )
        let events = await recorder.snapshot()
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].path, "/xrpc/com.atproto.repo.getRecord?keys=collection,repo,rkey")
        XCTAssertEqual(events[0].requestBytes, 27)
        XCTAssertEqual(events[0].responseBytes, response.body.count)
        XCTAssertFalse(events[0].path.contains("alice"))
        XCTAssertFalse(events[0].path.contains("secret"))
        XCTAssertFalse(events[0].responseSHA256.isEmpty)
    }

    func testSerializedPermissionedSyncCARAndErrorArtifactsContainNoSensitiveSentinels() async throws {
        let recorder = InteropFixtureRecorder()
        let recordValue = "permissioned-record-value-sentinel"
        let accessToken = "access-token-sentinel"
        let jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZW1iZXIifQ.signaturevalue"
        let dpopProof = "dpop-proof-sentinel"
        let selector = "did:plc:owner-only-selector-sentinel"
        let cursor = "owner-only-cursor-sentinel"
        let ownerOnlyPath = "file:///var/db/swan/owner-only-secret-path-sentinel.car"
        let responseError = "QWxwaGEyMzQ1Njc4OUFCQ0RFRkdISg"

        await recorder.record(
            host: "member-host",
            method: "GET",
            path: "/xrpc/com.atproto.sync.getOps?repo=\(selector)&cursor=\(cursor)",
            response: InteropHTTPResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data("{\"ops\":[{\"record\":\"\(recordValue)\",\"access_token\":\"\(accessToken)\",\"dpop\":\"\(dpopProof)\",\"jwt\":\"\(jwt)\"}]}".utf8),
                finalURL: URL(string: "https://member.example")!,
                redirectCount: 0
            )
        )
        await recorder.record(
            host: "authority-host",
            method: "GET",
            path: "/xrpc/com.atproto.sync.getRepo?did=\(selector)",
            response: InteropHTTPResponse(
                status: 200,
                headers: ["content-type": "application/vnd.ipld.car"],
                body: Data("CAR:\(recordValue):\(jwt)".utf8),
                finalURL: URL(string: "https://authority.example")!,
                redirectCount: 0
            )
        )
        await recorder.record(
            host: "owner-only-secret-host-sentinel",
            method: "GET",
            path: ownerOnlyPath,
            response: InteropHTTPResponse(
                status: 403,
                headers: ["content-type": "application/json"],
                body: Data("{\"error\":\"\(responseError)\",\"message\":\"\(recordValue)\"}".utf8),
                finalURL: nil,
                redirectCount: 0
            )
        )
        let events = await recorder.snapshot()

        let successful = LiveInteropPermissionedRoundTripArtifact(
            scenario: "permissioned-sync-car",
            member: "member-host",
            authority: "authority-host",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.artifactRecordCID,
            readCID: Self.artifactReadCID,
            writeResponseSHA256: String(repeating: "a", count: 64),
            readResponseSHA256: String(repeating: "b", count: 64),
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.artifactRecordCID,
            syncCommitVerified: true,
            syncValuesIncluded: false,
            fullCARStatus: 200,
            fullCARRecordCount: 1,
            fullCARCommitment: String(repeating: "c", count: 64),
            fullCARVerified: true,
            converged: true,
            status: "passed",
            errorCode: nil,
            events: Array(events.prefix(2))
        )
        let failed = LiveInteropPermissionedRoundTripArtifact(
            scenario: "permissioned-response-error",
            member: "member-host",
            authority: "authority-host",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 403,
            writeCID: Self.artifactRecordCID,
            readCID: nil,
            writeResponseSHA256: String(repeating: "a", count: 64),
            readResponseSHA256: String(repeating: "d", count: 64),
            converged: false,
            status: "failed",
            errorCode: "\(responseError)-\(jwt)",
            events: [events[2]]
        )

        let serialized = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode([successful, failed])
        )
        let serializedStrings = Self.serializedStrings(in: serialized)
        for sentinel in [recordValue, accessToken, jwt, dpopProof, selector, cursor, ownerOnlyPath, responseError] {
            XCTAssertFalse(
                serializedStrings.contains(where: { $0.contains(sentinel) }),
                "serialized artifact leaked sentinel: \(sentinel)"
            )
        }
        XCTAssertTrue(serializedStrings.contains("<redacted>"))
        XCTAssertTrue(serializedStrings.contains("<invalid-path>"))
    }

    func testDuplicatedFaultModeProbesEachEndpointTwice() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "duplication-matrix",
            faultModes: [.duplicated],
            runtime: runtime
        )
        XCTAssertEqual(artifact.faultModes, ["duplicated"])
        XCTAssertEqual(artifact.hostResults.count, 2)

        for host in artifact.hostResults {
            let grouped = Dictionary(grouping: host.endpointResults, by: \.path)
            XCTAssertTrue(
                grouped.values.allSatisfy { $0.count == 2 },
                "Expected duplicated probe to produce two requests per endpoint on \(host.host)"
            )
            XCTAssertTrue(
                host.endpointResults.contains(where: { $0.transportError == "network" }),
                "Expected duplicated probe to include network failure on unreachable test host for \(host.host)"
            )
        }
    }

    func testReorderedFaultModeReversesEndpointExecutionOrder() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let normal = await InteropScenarioRunner.execute(
            scenario: "baseline-matrix",
            faultModes: [],
            runtime: runtime
        )
        let reordered = await InteropScenarioRunner.execute(
            scenario: "reordered-matrix",
            faultModes: [.reordered],
            runtime: runtime
        )

        XCTAssertEqual(normal.hostResults.count, 2)
        XCTAssertEqual(reordered.hostResults.count, 2)

        for (normalHost, reorderedHost) in zip(normal.hostResults, reordered.hostResults) {
            let normalPaths = normalHost.endpointResults.map(\.path)
            let reorderedPaths = reorderedHost.endpointResults.map(\.path)
            XCTAssertEqual(reorderedPaths.count, normalPaths.count)
            XCTAssertEqual(reorderedPaths, normalPaths.reversed(), "\(normalHost.host) and \(reorderedHost.host) order should be reversed")
        }
    }

    func testCorruptedFaultModeCapturesUnsuccessfulCorruptionVariants() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "corruption-matrix",
            faultModes: [.corrupted],
            runtime: runtime
        )
        XCTAssertEqual(artifact.faultModes, ["corrupted"])

        for host in artifact.hostResults {
            let grouped = Dictionary(grouping: host.endpointResults, by: \.path)
            XCTAssertTrue(
                grouped.values.allSatisfy { $0.count == 2 },
                "Expected corrupted fault mode to include baseline and malformed request for each endpoint on \(host.host)"
            )
            XCTAssertTrue(
                host.endpointResults.contains {
                    $0.mode == "corrupted" &&
                    ($0.responseSummary["status"] != nil || $0.responseSummary["error"] != nil)
                }
            )
        }
    }

    func testInteropScenarioRunnerSummarizesCrossHostConvergence() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "convergence-matrix",
            faultModes: [],
            runtime: runtime
        )

        XCTAssertFalse(artifact.convergence.isEmpty)
        let describe = artifact.convergence.first {
            $0.path == "/xrpc/com.atproto.server.describeServer" && $0.mode == "normal"
        }
        XCTAssertNotNil(describe)
        XCTAssertGreaterThan(describe!.swanProbeCount, 0)
        XCTAssertEqual(describe!.swanProbeCount, describe!.referenceProbeCount)
        XCTAssertEqual(describe!.swanTransportError, true)
        XCTAssertEqual(describe!.referenceTransportError, true)
    }

    func testConvergenceSummaryDetectsStrictMismatch() {
        let key = InteropScenarioRunner.EndpointResultKey(mode: "normal", method: "GET", path: "/xrpc/com.atproto.server.describeServer")
        let buckets: [String: [InteropScenarioRunner.EndpointResultKey: [EndpointResult]]] = [
            "swan": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 200,
                        requestSummary: ["host": "swan"],
                        responseSummary: ["status": "200"]
                    )
                ]
            ],
            "reference-pds": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 503,
                        requestSummary: ["host": "pds"],
                        responseSummary: ["status": "503", "error": "temporarily_unavailable"]
                    )
                ]
            ],
        ]

        var unexpectedFailure = false
        var warnings: [String] = []
        let convergence = InteropScenarioRunner.summarizeCrossHostConvergence(
            from: buckets,
            strictConvergence: true,
            allowedConvergenceDivergences: [],
            hasUnexpectedFailure: &unexpectedFailure,
            warnings: &warnings
        )

        XCTAssertEqual(convergence.count, 1)
        XCTAssertFalse(convergence[0].firstProbeAligned)
        XCTAssertFalse(convergence[0].allowedMismatch)
        XCTAssertTrue(unexpectedFailure)
        XCTAssertEqual(warnings.count, 1)
    }

    func testConvergenceSummaryAllowsConfiguredMismatch() {
        let key = InteropScenarioRunner.EndpointResultKey(mode: "normal", method: "GET", path: "/xrpc/com.atproto.server.describeServer")
        let buckets: [String: [InteropScenarioRunner.EndpointResultKey: [EndpointResult]]] = [
            "swan": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 200,
                        requestSummary: ["host": "swan"],
                        responseSummary: ["status": "200"]
                    )
                ]
            ],
            "reference-pds": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 503,
                        requestSummary: ["host": "pds"],
                        responseSummary: ["status": "503", "error": "temporarily_unavailable"]
                    )
                ]
            ],
        ]

        var unexpectedFailure = false
        var warnings: [String] = []
        let convergence = InteropScenarioRunner.summarizeCrossHostConvergence(
            from: buckets,
            strictConvergence: true,
            allowedConvergenceDivergences: ["/xrpc/com.atproto.server.describeServer"],
            hasUnexpectedFailure: &unexpectedFailure,
            warnings: &warnings
        )

        XCTAssertEqual(convergence.count, 1)
        XCTAssertTrue(convergence[0].allowedMismatch)
        XCTAssertFalse(unexpectedFailure)
        XCTAssertTrue(warnings.isEmpty)
    }

    func testInteropScenarioRunnerProducesSanitizedProbeFixture() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "reference-matrix",
            faultModes: [.offline, .corrupted],
            runtime: runtime
        )
        XCTAssertEqual(artifact.scenario, "reference-matrix")
        XCTAssertEqual(artifact.faultModes, ["offline", "corrupted"])
        XCTAssertEqual(artifact.status, "failed")
        XCTAssertEqual(artifact.hostResults.count, 2)
        let encoded = try JSONEncoder().encode(artifact)
        let decoded = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        let forbidden: Set<String> = ["password", "authorization", "access_token", "refresh_token", "dpop", "private_key", "ikm"]
        let containsForbidden = decoded.flatMap {
            Self.sanitizedKeys(in: $0).contains { key in
                forbidden.contains(where: { key.lowercased().contains($0) })
            }
        } ?? false
        XCTAssertFalse(containsForbidden)
    }

    func testDisconnectedFaultModeIsAcceptedInScenarioExecution() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "disconnect-matrix",
            faultModes: [.disconnected],
            runtime: runtime
        )
        XCTAssertEqual(artifact.faultModes, ["disconnected"])
        XCTAssertEqual(artifact.hostResults.count, 2)
        XCTAssertEqual(artifact.status, "passed")
        for host in artifact.hostResults {
            XCTAssertTrue(host.endpointResults.contains { $0.transportError == "network" })
        }
    }

    func testLocalSemanticInteropExercisesDurableConvergenceRecoveryAndIsolation() async throws {
        let artifact = await LocalSemanticInteropRunner.execute(
            scenario: "local-semantic-matrix"
        )

        XCTAssertEqual(artifact.implementation, "swan-durable-to-swan-durable")
        XCTAssertEqual(artifact.status, "passed", "\(artifact)")
        XCTAssertEqual(artifact.operationCount, 4)
        XCTAssertEqual(artifact.recordCount, 1)
        XCTAssertEqual(artifact.checks.count, 18)
        XCTAssertTrue(artifact.checks.allSatisfy(\.passed))
        XCTAssertNotNil(artifact.sourceCommitment)
        XCTAssertEqual(artifact.sourceCommitment, artifact.consumerCommitment)
        XCTAssertEqual(artifact.sourceCommitment, artifact.fullRecoveryCommitment)
        XCTAssertNotNil(artifact.carDigest)
        XCTAssertNil(artifact.errorCode)

        let encoded = try JSONEncoder().encode(artifact)
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let forbidden: Set<String> = [
            "password", "authorization", "access_token", "refresh_token",
            "dpop", "private_key", "ikm", "secret", "record_value",
        ]
        XCTAssertFalse(
            Self.sanitizedKeys(in: decoded).contains { key in
                forbidden.contains(where: { key.lowercased().contains($0) })
            }
        )
    }

    func testPublicRepositoryRemoteVerifierUsesRepositorySignatureBytes() async throws {
        let signingKey = P256.Signing.PrivateKey()
        let verifier = PermissionedDataPublicRepositoryCommitVerifier(
            key: .p256(signingKey.publicKey)
        )
        let unsigned = Data("repository-commit-bytes".utf8)
        let signature = try P256WireSignature.sign(unsigned, using: signingKey)

        try await verifier.verify(
            signature: signature,
            unsignedCommitBytes: unsigned,
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
        XCTAssertEqual(verifier.signingAlgorithm, .p256)
        XCTAssertTrue(verifier.verificationIdentity.hasPrefix("p256-sha256:"))
    }

    func testPublicRepositoryCARFileSourceIsBoundedAndEOFIsNil() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "swan-car-source-\(UUID().uuidString).car")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data([1, 2, 3, 4, 5]).write(to: url)

        let source = try FilePublicRepositoryCARByteSource(url: url)
        let first = try await source.read(maximumBytes: 2)
        let second = try await source.read(maximumBytes: 2)
        let third = try await source.read(maximumBytes: 2)
        let end = try await source.read(maximumBytes: 2)
        XCTAssertEqual(first, Data([1, 2]))
        XCTAssertEqual(second, Data([3, 4]))
        XCTAssertEqual(third, Data([5]))
        XCTAssertNil(end)
        try await source.close()
    }

    func testPublicRepositoryImportArtifactContainsNoSecretFields() throws {
        let artifact = PublicRepositoryCARImportArtifact(
            remoteHost: "pds.test",
            repositoryDID: "did:plc:abcdefghijklmnopqrstuvwx",
            httpStatus: 200,
            baseCommitCID: "bafybase",
            importedCommitCID: "bafycommit",
            importedDataCID: "bafydata",
            importedRevision: "2222222222222",
            reachableBlockCount: 3,
            recordCount: 1,
            status: "passed",
            errorCode: nil
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(artifact)) as? [String: Any]
        )
        let forbidden = ["password", "token", "private", "secret", "value", "path"]
        XCTAssertFalse(Self.sanitizedKeys(in: object).contains { key in
            forbidden.contains { key.lowercased().contains($0) }
        })
    }

    func testPublicBlobPromotionBindsRequestDIDToManagedAccountBeforeNetwork() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(
                path: "swan-blob-promotion-did-" + UUID().uuidString,
                directoryHint: .isDirectory
            )
        defer { try? FileManager.default.removeItem(at: root) }

        let accountDID = "did:plc:abcdefghijklmnopqrstuvwx"
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: accountDID)
        let promoter = try RemotePublicRepositoryBlobPromoter(
            client: InteropXRPCClient(baseURL: URL(string: "https://pds.test")!)
        )

        do {
            _ = try await promoter.promoteReferencedBlobs(
                in: database,
                did: "did:plc:zyxwvutsrqponmlkjihgfedc"
            )
            XCTFail("a valid but different repository DID must be rejected")
        } catch let error as PublicRepositoryBlobPromotionError {
            XCTAssertEqual(error, .invalidRepositoryDID)
        }
        try await database.close()
    }

    func testPublicRepositoryImportFailsClosedWithoutSpoolAdmissionBeforeNetwork() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(
                path: "swan-public-import-admission-" + UUID().uuidString,
                directoryHint: .isDirectory
            )
        defer { try? FileManager.default.removeItem(at: root) }

        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let signingKey = P256.Signing.PrivateKey()
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: signingKey
        )
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )
        defer { Task { try? await database.close() } }
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: signingKey.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )

        let importer = try RemotePublicRepositoryCARImporter(
            client: InteropXRPCClient(baseURL: URL(string: "https://pds.test")!)
        )
        do {
            _ = try await importer.importRepository(
                did: did,
                database: database,
                verifier: PermissionedDataPublicRepositoryCommitVerifier(
                    key: .p256(signingKey.publicKey)
                ),
                requestID: "no-spool-admission"
            )
            XCTFail("public CAR import must require shared spool admission")
        } catch let error as PublicRepositoryCARReplicationError {
            XCTAssertEqual(error, .spoolUnavailable)
        }
    }

    private static func sanitizedKeys(in value: Any) -> [String] {
        switch value {
        case let object as [String: Any]:
            return object.keys.flatMap { key in
                [key] + sanitizedKeys(in: object[key]!)
            }
        case let array as [Any]:
            return array.flatMap(sanitizedKeys(in:))
        default:
            return []
        }
    }

    private static func serializedStrings(in value: Any) -> [String] {
        switch value {
        case let value as String:
            return [value]
        case let object as [String: Any]:
            return object.values.flatMap(serializedStrings(in:))
        case let array as [Any]:
            return array.flatMap(serializedStrings(in:))
        default:
            return []
        }
    }
}

private func recoveryStagingDirectories(in root: URL) throws -> [URL] {
    try FileManager.default.contentsOfDirectory(
        at: root,
        includingPropertiesForKeys: nil
    ).filter {
        $0.lastPathComponent.hasPrefix("swan-space-recovery-")
    }
}

private struct ReferenceOAuthMockRequest: Sendable {
    let method: InteropHTTPMethod
    let url: URL
    let headers: [String: String]
    let body: Data?
}

private actor ReferenceOAuthMockRequests {
    private var values: [ReferenceOAuthMockRequest] = []

    func append(_ value: ReferenceOAuthMockRequest) {
        values.append(value)
    }

    func snapshot() -> [ReferenceOAuthMockRequest] {
        values
    }
}

private extension Data {
    func jsonObject() throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: self) as? [String: Any])
    }
}

private final class ProfileFixture {
    let root: URL
    let profileURL: URL
    let lexiconManifestURL: URL
    let generatedWireManifestURL: URL
    let generatedWireSourceURL: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "swan-profile-verifier-\(UUID().uuidString)", directoryHint: .isDirectory)
        let profiles = root.appending(path: "Profiles", directoryHint: .isDirectory)
        let sources = root.appending(path: "Sources", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: profiles, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: sources, withIntermediateDirectories: true)

        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let profileName = "permissioned-data-0016-2026-09-10.json"
        let lexiconName = "permissioned-data-0016-2026-09-10.lexicons.sha256"
        profileURL = profiles.appending(path: profileName)
        lexiconManifestURL = profiles.appending(path: lexiconName)
        generatedWireManifestURL = profiles.appending(path: "permissioned-data-0016-2026-09-10.generated-wire.sha256")
        generatedWireSourceURL = sources.appending(path: "SwanSpacesWire/SwanSpacesWire.swift")

        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Profiles/\(profileName)"),
            to: profileURL
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Profiles/\(lexiconName)"),
            to: lexiconManifestURL
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Profiles/permissioned-data-0016-2026-09-10.generated-wire.sha256"),
            to: generatedWireManifestURL
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "PetrelManifest.json"),
            to: root.appending(path: "PetrelManifest.json")
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Sources/SwanSpacesWire"),
            to: sources.appending(path: "SwanSpacesWire", directoryHint: .isDirectory)
        )
    }

    func replaceInProfile(_ old: String, with new: String) throws {
        let text = try String(contentsOf: profileURL, encoding: .utf8)
        XCTAssertTrue(text.contains(old))
        try text.replacingOccurrences(of: old, with: new).data(using: .utf8)!.write(to: profileURL)
    }

    func append(_ text: String, to url: URL) throws {
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(text.utf8))
    }

    func replaceGeneratedWireManifest(_ data: Data) throws {
        try data.write(to: generatedWireManifestURL)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        try replaceInProfile(
            "9b3df8b2b04445a3c2a623fc556469b6aa430a0901ead90709abf3f4fd7af876",
            with: digest
        )
    }

    func replaceGeneratedWireSourceWithInternalSymlink() throws {
        let trustedTarget = root.appending(path: "TrustedGeneratedWire.swift")
        try FileManager.default.copyItem(at: generatedWireSourceURL, to: trustedTarget)
        try FileManager.default.removeItem(at: generatedWireSourceURL)
        try FileManager.default.createSymbolicLink(at: generatedWireSourceURL, withDestinationURL: trustedTarget)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}
