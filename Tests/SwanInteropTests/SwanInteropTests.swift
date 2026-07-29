import Foundation
import XCTest
import Crypto
import Petrel
@testable import SwanInterop
import SwanCore
import SwanOAuth
import SwanSpaces

final class SwanInteropTests: XCTestCase {
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
            "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354",
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
            of: "Sources/SwanSpacesWire/Generated/",
            with: "Sources/SwanSpacesWire/Generated/../Generated/"
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
            writeCID: "bafywrite",
            readCID: "bafywrite",
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
        XCTAssertEqual(object["writeCID"] as? String, "bafywrite")
        XCTAssertEqual(object["readCID"] as? String, "bafywrite")
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

    func testStreamingCARClientAllowsThePinned512MiBBoundSeparatelyFromJSON() throws {
        let http = try InteropHTTPClient(
            baseURL: URL(string: "https://pds.test")!,
            timeout: 1
        )
        XCTAssertEqual(http.maximumResponseBytes, 2 * 1_024 * 1_024)
        XCTAssertEqual(http.maximumStreamingResponseBytes, 512 * 1_024 * 1_024)
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
        let profileName = "permissioned-data-0016-2026-07-03.json"
        let lexiconName = "permissioned-data-0016-2026-07-03.lexicons.sha256"
        profileURL = profiles.appending(path: profileName)
        lexiconManifestURL = profiles.appending(path: lexiconName)
        generatedWireManifestURL = profiles.appending(path: "permissioned-data-0016-2026-07-03.generated-wire.sha256")
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
            at: packageRoot.appending(path: "Profiles/permissioned-data-0016-2026-07-03.generated-wire.sha256"),
            to: generatedWireManifestURL
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
            "c1d5697f351a4209c7f8a9faaf460d423f9f44f37845ae2c92e150e78c552609",
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
