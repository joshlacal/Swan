import Foundation
import Crypto
@testable import SwanInterop
import SwanSpaces
import SwanStorage
import Petrel
import XCTest

final class PermissionedRecoveryAcceptanceArtifactTests: XCTestCase {
    func testWriteOnlyApplyWritesUsesMockedTransportAndVerifiesTerminalWitness() async throws {
        let space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.swan.interop",
            skey: "replica"
        )
        let repository = "did:plc:alice"
        let collection = "app.bsky.feed.post"
        let rkey = "mock-write"
        let body = Data(#"{"space":"\#(space.rawValue)","repo":"\#(repository)","writes":[{"$type":"com.atproto.space.applyWrites#create","collection":"\#(collection)","rkey":"\#(rkey)","value":{"$type":"app.bsky.feed.post","text":"private-value"}}]}"#.utf8)
        let recordValue = Data([0xa1, 0x61, 0x78, 0x01])
        let cid = CID.fromDAGCBOR(recordValue)
        let expectedURI = "\(space.rawValue)/\(repository)/\(collection)/\(rkey)"
        let revision = "3lqjz7x4abc2m"
        let ikm = Data(repeating: 0x22, count: 32)
        let signingKey = P256.Signing.PrivateKey()
        let context = try SpaceCommitContext(
            space: space,
            author: repository,
            rev: revision,
            ikm: ikm
        )
        let envelope = try SpaceCommitCodec.sign(
            context: context,
            commitment: Data(repeating: 0x11, count: 32),
            key: signingKey
        )
        let createResult = ComAtprotoSpaceApplyWrites.CreateResult(
            uri: try ATProtocolURI(uriString: expectedURI),
            cid: cid,
            validationStatus: nil
        )
        let applyOutput = ComAtprotoSpaceApplyWrites.Output(
            results: [.comAtprotoSpaceApplyWritesCreateResult(createResult)]
        )
        let signedCommit = ComAtprotoSpaceDefs.SignedCommit(
            ver: envelope.ver,
            hash: Bytes(data: envelope.commitment),
            ikm: Bytes(data: envelope.context.ikm),
            sig: Bytes(data: envelope.contextSignature),
            mac: Bytes(data: envelope.contentBinding),
            rev: try TID(tidString: revision)
        )
        let op = ComAtprotoSpaceListRepoOps.OpEntry(
            rev: try TID(tidString: revision),
            collection: try NSID(nsidString: collection),
            rkey: try RecordKey(keyString: rkey),
            cid: cid,
            prev: nil,
            value: nil
        )
        let listOutput = ComAtprotoSpaceListRepoOps.Output(
            ops: [op],
            commit: signedCommit,
            cursor: nil
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let applyResponseBody = try encoder.encode(applyOutput)
        let listResponseBody = try encoder.encode(listOutput)
        let transport = MockWriteOnlyTransport(
            applyResponseBody: applyResponseBody,
            listResponseBody: listResponseBody
        )
        let http = try InteropHTTPClient(
            baseURL: URL(string: "https://member.test")!,
            timeout: 1,
            executeHandler: { method, url, headers, requestBody, limit in
                try await transport.execute(
                    method: method,
                    url: url,
                    headers: headers,
                    body: requestBody,
                    limit: limit
                )
            }
        )
        let client = InteropXRPCClient(http: http)
        let host = LiveInteropHost(
            label: "mock-member",
            client: client,
            authorizationProvider: { _, _, _ in .bearer(token: "mock-token") },
            permissionedCommitVerificationKey: .p256(signingKey.publicKey)
        )
        let recorder = InteropFixtureRecorder()

        let artifact = await LiveInteropRunner.permissionedWriteOnlyApplyWrites(
            scenario: "mock-transport-write-only",
            member: host,
            space: space,
            repository: repository,
            body: body,
            recorder: recorder
        )

        XCTAssertEqual(artifact.applyStatus, 200)
        XCTAssertEqual(artifact.witnessStatus, 200)
        XCTAssertEqual(artifact.terminalRevision, revision)
        XCTAssertEqual(artifact.operationCount, 1)
        XCTAssertEqual(artifact.status, "passed")
        XCTAssertNil(artifact.errorCode)

        let calls = await transport.snapshot()
        XCTAssertEqual(calls.map(\.method), [.post, .get])
        XCTAssertEqual(calls.map(\.path), [
            "/xrpc/com.atproto.space.applyWrites",
            "/xrpc/com.atproto.space.listRepoOps",
        ])
        XCTAssertEqual(calls[0].body, body)
        XCTAssertNil(calls[1].body)
        XCTAssertEqual(calls[0].headers["authorization"], "Bearer mock-token")
        XCTAssertEqual(calls[1].headers["authorization"], "Bearer mock-token")
        let events = await recorder.snapshot()
        XCTAssertEqual(events.map(\.path), calls.map(\.path))
        let serialized = String(decoding: try JSONEncoder().encode(events), as: UTF8.self)
        XCTAssertFalse(serialized.contains("private-value"))
        XCTAssertFalse(serialized.contains("mock-token"))
    }

    func testWriteOnlyApplyWritesArtifactRetainsOnlyTerminalWitness() throws {
        let privateValue = "private-value-must-not-leak"
        let artifact = PermissionedWriteOnlyApplyWritesArtifact(
            scenario: "recovery-seed-advance",
            applyStatus: 200,
            witnessStatus: 200,
            terminalRevision: "3lqjz7x4abc2m",
            operationCount: 3,
            responseDigest: String(repeating: "a", count: 64),
            status: "passed",
            errorCode: nil
        )

        XCTAssertEqual(artifact.applyStatus, 200)
        XCTAssertEqual(artifact.witnessStatus, 200)
        XCTAssertEqual(artifact.profileID, OfflineProtocolProfileVerifier.stableProfileID)
        XCTAssertTrue(artifact.fixturePolicy.hasPrefix("summary-only"))
        XCTAssertEqual(artifact.terminalRevision, "3lqjz7x4abc2m")
        XCTAssertEqual(artifact.operationCount, 3)
        XCTAssertEqual(artifact.status, "passed")
        let serialized = String(
            decoding: try JSONEncoder().encode(artifact),
            as: UTF8.self
        ).lowercased()
        for forbidden in [
            privateValue, "access_token", "refresh_token", "password", "dpop",
            "authorization", "did:", "https://", "value",
        ] {
            XCTAssertFalse(serialized.contains(forbidden), forbidden)
        }
    }

    func testWriteOnlyRecorderNeverPersistsApplyWritesValue() async throws {
        let privateValue = "private-value-must-not-leak"
        let recorder = InteropFixtureRecorder()
        await recorder.record(
            host: "member",
            method: "POST",
            path: "/xrpc/com.atproto.space.applyWrites",
            requestBody: Data("{\"value\":\"\(privateValue)\"}".utf8),
            response: InteropHTTPResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data("{\"results\":[]}".utf8),
                finalURL: nil,
                redirectCount: 0
            )
        )
        let events = await recorder.snapshot()
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].path, "/xrpc/com.atproto.space.applyWrites")
        let serialized = String(
            decoding: try JSONEncoder().encode(events),
            as: UTF8.self
        )
        XCTAssertFalse(serialized.contains(privateValue))
        XCTAssertFalse(serialized.contains("value"))
    }

    func testArtifactRetainsOnlyCanonicalRecoveryEvidence() throws {
        let digest = String(repeating: "a", count: 64)
        let artifact = PermissionedRecoveryAcceptanceArtifact(
            scenario: "retention-gap-corruption",
            gapStatus: 409,
            gapErrorCode: "full_repo_recovery_required",
            priorHeadGeneration: 1,
            priorHeadRevision: "3lqjz7x4abc2k",
            priorCommitment: digest,
            replacementHeadGeneration: 2,
            replacementHeadRevision: "3lqjz7x4abc2m",
            replacementCommitment: String(repeating: "b", count: 64),
            replacementRecordCount: 3,
            replacementCASAdvanced: true,
            corruptionRejected: true,
            corruptErrorCode: "CARBlockCIDMismatch",
            finalHeadGeneration: 2,
            finalHeadRevision: "3lqjz7x4abc2m",
            finalCommitment: String(repeating: "b", count: 64),
            lastValidHeadPreserved: true,
            status: "passed",
            errorCode: nil
        )

        XCTAssertEqual(artifact.profileID, OfflineProtocolProfileVerifier.stableProfileID)
        XCTAssertEqual(artifact.gapErrorCode, "full_repo_recovery_required")
        XCTAssertEqual(artifact.priorCommitment, digest)
        XCTAssertTrue(artifact.replacementCASAdvanced)
        XCTAssertEqual(artifact.corruptErrorCode, "CARBlockCIDMismatch")
        XCTAssertTrue(artifact.lastValidHeadPreserved)
        XCTAssertFalse(artifact.gapFallbackUsed)

        let serialized = String(
            decoding: try JSONEncoder().encode(artifact),
            as: UTF8.self
        ).lowercased()
        for forbidden in [
            "receiverdid", "repositorydid", "spaceuri", "authorization",
            "access_token", "refresh_token", "password", "private_key",
            "verifieridentity", "requestdigest", "statemarker",
        ] {
            XCTAssertFalse(serialized.contains(forbidden), forbidden)
        }
    }

    func testArtifactLabelsExplicitFullCARFallbackSeparatelyFromRetentionGap() throws {
        let artifact = PermissionedRecoveryAcceptanceArtifact(
            scenario: "reference-full-car-fallback",
            gapStatus: 200,
            gapErrorCode: nil,
            gapFallbackUsed: true,
            priorHeadGeneration: 1,
            priorHeadRevision: "3lqjz7x4abc2k",
            priorCommitment: String(repeating: "a", count: 64),
            replacementHeadGeneration: 2,
            replacementHeadRevision: "3lqjz7x4abc2m",
            replacementCommitment: String(repeating: "b", count: 64),
            replacementRecordCount: 3,
            replacementCASAdvanced: true,
            corruptionRejected: true,
            corruptErrorCode: "CARBlockCIDMismatch",
            finalHeadGeneration: 2,
            finalHeadRevision: "3lqjz7x4abc2m",
            finalCommitment: String(repeating: "b", count: 64),
            lastValidHeadPreserved: true,
            status: "passed",
            errorCode: nil
        )

        XCTAssertTrue(artifact.gapFallbackUsed)
        XCTAssertEqual(artifact.gapStatus, 200)
        XCTAssertNil(artifact.gapErrorCode)
        let serialized = String(
            decoding: try JSONEncoder().encode(artifact),
            as: UTF8.self
        )
        XCTAssertTrue(serialized.contains("gapFallbackUsed"))
    }

    func testArtifactRedactsNoncanonicalPeerEvidence() {
        let opaque =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.c2lnbmF0dXJl"
        let artifact = PermissionedRecoveryAcceptanceArtifact(
            scenario: opaque,
            gapStatus: 200,
            gapErrorCode: opaque,
            priorHeadGeneration: 0,
            priorHeadRevision: opaque,
            priorCommitment: opaque,
            replacementHeadGeneration: 0,
            replacementHeadRevision: opaque,
            replacementCommitment: opaque,
            replacementRecordCount: -1,
            replacementCASAdvanced: false,
            corruptionRejected: false,
            corruptErrorCode: opaque,
            finalHeadGeneration: 0,
            finalHeadRevision: opaque,
            finalCommitment: opaque,
            lastValidHeadPreserved: false,
            status: opaque,
            errorCode: opaque
        )

        XCTAssertEqual(artifact.scenario, "<redacted>")
        XCTAssertEqual(artifact.gapErrorCode, "<redacted>")
        XCTAssertNil(artifact.priorHeadGeneration)
        XCTAssertNil(artifact.priorHeadRevision)
        XCTAssertNil(artifact.priorCommitment)
        XCTAssertNil(artifact.replacementHeadGeneration)
        XCTAssertNil(artifact.replacementHeadRevision)
        XCTAssertNil(artifact.replacementCommitment)
        XCTAssertNil(artifact.replacementRecordCount)
        XCTAssertEqual(artifact.corruptErrorCode, "<redacted>")
        XCTAssertEqual(artifact.status, "failed")
        XCTAssertEqual(artifact.errorCode, "<redacted>")
    }

    func testRecoveryFailureCodesDoNotReflectArbitraryErrors() {
        XCTAssertEqual(
            PermissionedRecoveryFailureCode.code(
                for: PermissionedRemoteReplicaRecoveryError.corruptReplica
            ),
            "RecoveryCorruptReplica"
        )
        XCTAssertEqual(
            PermissionedRecoveryFailureCode.code(for: SecretError()),
            "RecoveryFailed"
        )
        XCTAssertTrue(
            PermissionedRecoveryFailureCode
                .isInjectedFinalByteCorruptionRejection(
                    SpaceCARStreamingError.blockCIDMismatch
                )
        )
        XCTAssertFalse(
            PermissionedRecoveryFailureCode
                .isInjectedFinalByteCorruptionRejection(
                    PermissionedRemoteReplicaRecoveryError.corruptReplica
                )
        )
        XCTAssertFalse(
            PermissionedRecoveryFailureCode
                .isInjectedFinalByteCorruptionRejection(SecretError())
        )
    }

    private struct SecretError: Error, CustomStringConvertible {
        var description: String { "access_token=must-not-leak" }
    }
}

private actor MockWriteOnlyTransport {
    struct Call: Sendable {
        let method: InteropHTTPMethod
        let path: String
        let headers: [String: String]
        let body: Data?
    }

    private let applyResponseBody: Data
    private let listResponseBody: Data
    private var calls: [Call] = []

    init(applyResponseBody: Data, listResponseBody: Data) {
        self.applyResponseBody = applyResponseBody
        self.listResponseBody = listResponseBody
    }

    func execute(
        method: InteropHTTPMethod,
        url: URL,
        headers: [String: String],
        body: Data?,
        limit: Int
    ) throws -> InteropHTTPResponse {
        calls.append(
            Call(
                method: method,
                path: url.path,
                headers: headers.reduce(into: [String: String]()) { result, item in
                    result[item.key.lowercased()] = item.value
                },
                body: body
            )
        )
        let responseBody: Data
        switch (method, url.path) {
        case (.post, "/xrpc/com.atproto.space.applyWrites"):
            responseBody = applyResponseBody
        case (.get, "/xrpc/com.atproto.space.listRepoOps"):
            responseBody = listResponseBody
        default:
            throw InteropHTTPError.unexpectedStatus(404)
        }
        guard responseBody.count <= limit else {
            throw InteropHTTPError.responseTooLarge
        }
        return InteropHTTPResponse(
            status: 200,
            headers: ["content-type": "application/json"],
            body: responseBody,
            finalURL: url,
            redirectCount: 0
        )
    }

    func snapshot() -> [Call] { calls }
}
