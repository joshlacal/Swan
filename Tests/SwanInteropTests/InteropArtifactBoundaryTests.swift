import Foundation
import XCTest
@testable import SwanInterop

final class InteropArtifactBoundaryTests: XCTestCase {
    private static let recordCID =
        "bafyreidqz2dr7cr5h62etpb4hlhgkr6o6aw7y5h74sgzcjjsu4sl7w7fxe"
    private static let secondRecordCID =
        "bafyreibtcy2i3ow7w6yry7boui2zjfaz4i7z7keyvuwbtd4zsylzckuzeu"
    private static let blobCID =
        "bafkreih2fsgmj4ubo2565vfxg3pvngruy6ong4r6t3cc7ftuwtkgvrvyxa"
    private static let opaqueCredential =
        "QWxwaGEyMzQ1Njc4OUFCQ0RFRkdISktMTU5PUFFSU1RVVldYWVo"

    func testPeerControlledCIDMustBeCanonicalBeforeRunnerUsesIt() {
        let nonCanonicalRecordCID =
            "b" + Self.recordCID.dropFirst().uppercased()

        XCTAssertEqual(
            LiveInteropRunner.canonicalRecordCID(
                from: Data(#"{"cid":"\#(Self.recordCID)"}"#.utf8)
            ),
            Self.recordCID
        )
        XCTAssertNil(
            LiveInteropRunner.canonicalRecordCID(
                from: Data(#"{"cid":"\#(nonCanonicalRecordCID)"}"#.utf8)
            )
        )
        XCTAssertNil(
            LiveInteropRunner.canonicalRecordCID(
                from: Data(#"{"cid":"\#(Self.opaqueCredential)"}"#.utf8)
            )
        )
        XCTAssertNil(
            LiveInteropRunner.canonicalRecordCID(
                from: Data(#"{"cid":"\#(Self.blobCID)"}"#.utf8)
            ),
            "a record response must not accept a canonical raw-blob CID"
        )

        XCTAssertEqual(
            LiveInteropRunner.canonicalBlobCID(
                from: Data(#"{"blob":{"ref":{"$link":"\#(Self.blobCID)"}}}"#.utf8)
            ),
            Self.blobCID
        )
        XCTAssertNil(
            LiveInteropRunner.canonicalBlobCID(
                from: Data(#"{"blob":{"ref":{"$link":"\#(Self.opaqueCredential)"}}}"#.utf8)
            )
        )
        XCTAssertNil(
            LiveInteropRunner.canonicalBlobCID(
                from: Data(#"{"blob":{"ref":{"$link":"\#(Self.recordCID)"}}}"#.utf8)
            ),
            "a blob response must not accept a canonical DAG-CBOR record CID"
        )
    }

    func testArtifactInitializersRejectOpaqueCIDAndDigestValues() throws {
        let event = InteropFixtureEvent(
            host: "member",
            method: "GET",
            path: "/xrpc/com.atproto.space.getRecord",
            status: 200,
            requestBytes: 0,
            responseBytes: 1,
            responseSHA256: Self.opaqueCredential,
            responseError: Self.opaqueCredential
        )
        let publicArtifact = LiveInteropPublicRoundTripArtifact(
            scenario: "public-boundary",
            producer: "producer",
            consumer: "consumer",
            putStatus: 200,
            readStatus: 200,
            putCID: Self.opaqueCredential,
            readCID: Self.opaqueCredential,
            putResponseSHA256: Self.opaqueCredential,
            readResponseSHA256: Self.opaqueCredential,
            blobUploadStatus: 200,
            blobDownloadStatus: 200,
            blobCID: Self.opaqueCredential,
            blobBytes: 1,
            blobVerified: false,
            converged: false,
            status: "failed",
            errorCode: Self.opaqueCredential,
            events: [event]
        )
        let permissionedArtifact = LiveInteropPermissionedRoundTripArtifact(
            scenario: "permissioned-boundary",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.opaqueCredential,
            readCID: Self.opaqueCredential,
            writeResponseSHA256: Self.opaqueCredential,
            readResponseSHA256: Self.opaqueCredential,
            syncStatus: 200,
            syncOpsCount: 1,
            syncOperationCID: Self.opaqueCredential,
            syncCommitment: Self.opaqueCredential,
            fullCARCommitment: Self.opaqueCredential,
            converged: false,
            status: "failed",
            errorCode: Self.opaqueCredential,
            events: [event]
        )
        let fixture = SanitizedFixture(
            scenario: "summary-boundary",
            requestSummary: ["authorization": Self.opaqueCredential],
            responseSummary: ["json-key-0": Self.opaqueCredential],
            commitmentHex: Self.opaqueCredential,
            expectedError: Self.opaqueCredential
        )

        XCTAssertNil(publicArtifact.putCID)
        XCTAssertNil(publicArtifact.readCID)
        XCTAssertNil(publicArtifact.blobCID)
        XCTAssertNil(publicArtifact.putResponseSHA256)
        XCTAssertNil(publicArtifact.readResponseSHA256)
        XCTAssertNil(permissionedArtifact.writeCID)
        XCTAssertNil(permissionedArtifact.readCID)
        XCTAssertNil(permissionedArtifact.syncOperationCID)
        XCTAssertNil(permissionedArtifact.syncCommitment)
        XCTAssertNil(permissionedArtifact.fullCARCommitment)
        XCTAssertNil(fixture.commitmentHex)
        XCTAssertEqual(event.responseSHA256, "<redacted>")

        let encodedArtifacts: [Data] = [
            try JSONEncoder().encode(publicArtifact),
            try JSONEncoder().encode(permissionedArtifact),
            try JSONEncoder().encode(fixture),
        ]
        for encoded in encodedArtifacts {
            let object = try JSONSerialization.jsonObject(with: encoded)
            let stringsAndKeys = try boundedStringsAndKeys(in: object)
            XCTAssertFalse(
                stringsAndKeys.contains(where: { $0.contains(Self.opaqueCredential) }),
                "serialized artifact retained an opaque peer-controlled value"
            )
        }
    }

    func testArtifactInitializersRetainOnlyCanonicalCIDAndLowercaseDigestFormats() {
        let artifact = LiveInteropPermissionedRoundTripArtifact(
            scenario: "canonical-boundary",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.secondRecordCID,
            writeResponseSHA256: String(repeating: "a", count: 64),
            readResponseSHA256: String(repeating: "B", count: 64),
            syncOperationCID: Self.recordCID,
            syncCommitment: String(repeating: "c", count: 64),
            fullCARCommitment: String(repeating: "D", count: 64),
            converged: false,
            status: "failed",
            errorCode: nil,
            events: []
        )

        XCTAssertEqual(artifact.writeCID, Self.recordCID)
        XCTAssertEqual(artifact.readCID, Self.secondRecordCID)
        XCTAssertEqual(artifact.syncOperationCID, Self.recordCID)
        XCTAssertEqual(artifact.writeResponseSHA256, String(repeating: "a", count: 64))
        XCTAssertNil(artifact.readResponseSHA256)
        XCTAssertEqual(artifact.syncCommitment, String(repeating: "c", count: 64))
        XCTAssertNil(artifact.fullCARCommitment)
    }

    func testDecodedArtifactCannotReserializeOpaquePeerValues() throws {
        let valid = LiveInteropPermissionedRoundTripArtifact(
            scenario: "decode-boundary",
            member: "member",
            authority: "authority",
            credentialIssued: true,
            writeStatus: 200,
            readStatus: 200,
            writeCID: Self.recordCID,
            readCID: Self.recordCID,
            writeResponseSHA256: String(repeating: "a", count: 64),
            readResponseSHA256: String(repeating: "b", count: 64),
            syncOperationCID: Self.recordCID,
            syncCommitment: String(repeating: "c", count: 64),
            fullCARCommitment: String(repeating: "c", count: 64),
            converged: true,
            status: "passed",
            errorCode: nil,
            events: [
                InteropFixtureEvent(
                    host: "member",
                    method: "GET",
                    path: "/xrpc/com.atproto.space.getRecord",
                    status: 200,
                    requestBytes: 0,
                    responseBytes: 1,
                    responseSHA256: String(repeating: "d", count: 64)
                )
            ]
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: JSONEncoder().encode(valid)
            ) as? [String: Any]
        )
        for key in [
            "writeCID", "readCID", "writeResponseSHA256",
            "readResponseSHA256", "syncOperationCID", "syncCommitment",
            "fullCARCommitment", "errorCode",
        ] {
            object[key] = Self.opaqueCredential
        }
        object["events"] = [[
            "host": "member",
            "method": "GET",
            "path": "/xrpc/com.atproto.space.getRecord",
            "status": 200,
            "requestBytes": 0,
            "responseBytes": 1,
            "responseSHA256": Self.opaqueCredential,
            "responseError": Self.opaqueCredential,
        ]]

        let decoded = try JSONDecoder().decode(
            LiveInteropPermissionedRoundTripArtifact.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
        let reserialized = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(decoded)
        )
        let stringsAndKeys = try boundedStringsAndKeys(in: reserialized)
        XCTAssertFalse(
            stringsAndKeys.contains(where: { $0.contains(Self.opaqueCredential) })
        )
        XCTAssertNil(decoded.writeCID)
        XCTAssertNil(decoded.syncCommitment)
        XCTAssertEqual(decoded.events.first?.responseSHA256, "<redacted>")
    }

    func testResponseSummaryPersistsCategoriesAndCountsNotPeerHeaderValuesOrJSONNames() throws {
        let sanitized = FixtureSanitizer.sanitize([
            "status": "200",
            "response-bytes": "42",
            "content-type": "application/json; profile=\"\(Self.opaqueCredential)\"",
            "cache-control": "private=\"\(Self.opaqueCredential)\"",
            "json-keys": "1",
            "json-key-0": Self.opaqueCredential,
        ])

        XCTAssertEqual(sanitized["status"], "200")
        XCTAssertEqual(sanitized["response-bytes"], "42")
        XCTAssertEqual(sanitized["content-type"], "json")
        XCTAssertEqual(sanitized["cache-control"], "other")
        XCTAssertEqual(sanitized["json-keys"], "1")
        XCTAssertNil(sanitized["json-key-0"])

        let encoded = try JSONEncoder().encode(sanitized)
        let object = try JSONSerialization.jsonObject(with: encoded)
        let stringsAndKeys = try boundedStringsAndKeys(in: object)
        XCTAssertFalse(stringsAndKeys.contains(where: { $0.contains(Self.opaqueCredential) }))
    }

    private func boundedStringsAndKeys(
        in value: Any,
        depth: Int = 0,
        budget: inout Int
    ) throws -> [String] {
        guard depth <= 16, budget > 0 else {
            throw ScanError.boundExceeded
        }
        budget -= 1
        switch value {
        case let value as String:
            return [value]
        case let object as [String: Any]:
            var output: [String] = []
            for (key, nested) in object {
                output.append(key)
                output.append(contentsOf: try boundedStringsAndKeys(
                    in: nested,
                    depth: depth + 1,
                    budget: &budget
                ))
            }
            return output
        case let array as [Any]:
            var output: [String] = []
            for nested in array {
                output.append(contentsOf: try boundedStringsAndKeys(
                    in: nested,
                    depth: depth + 1,
                    budget: &budget
                ))
            }
            return output
        default:
            return []
        }
    }

    private func boundedStringsAndKeys(in value: Any) throws -> [String] {
        var budget = 4_096
        return try boundedStringsAndKeys(in: value, budget: &budget)
    }

    private enum ScanError: Error {
        case boundExceeded
    }
}
