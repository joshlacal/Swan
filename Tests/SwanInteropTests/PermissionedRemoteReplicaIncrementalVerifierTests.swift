import Crypto
import Foundation
import Petrel
@testable import SwanInterop
import SwanOAuth
import SwanSpaces
import SwanSpacesWire
import SwanStorage
import XCTest

final class PermissionedRemoteReplicaIncrementalVerifierTests: XCTestCase {
    func testVerifiesOrderedMultiRevisionDeltaFromDurableBase() throws {
        let fixture = try Fixture()
        let verified = try PermissionedRemoteReplicaIncrementalVerifier.verify(
            operations: fixture.operations,
            commit: fixture.commit,
            base: fixture.base,
            target: fixture.target,
            verificationKey: .p256(fixture.key.publicKey)
        )

        XCTAssertEqual(verified.operations.count, 2)
        XCTAssertEqual(
            verified.operations.map(\.wireRevision),
            [fixture.firstRevision, fixture.secondRevision]
        )
        XCTAssertEqual(verified.terminalHead.recordCount, 2)
        XCTAssertEqual(
            verified.terminalHead.wireRevision,
            fixture.secondRevision
        )
        XCTAssertEqual(
            verified.terminalHead.commitment,
            fixture.commit.hash.data
        )
    }

    func testRejectsReorderedRevisionBeforeCryptographicAcceptance() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try PermissionedRemoteReplicaIncrementalVerifier.verify(
            operations: fixture.operations.reversed(),
            commit: fixture.commit,
            base: fixture.base,
            target: fixture.target,
            verificationKey: .p256(fixture.key.publicKey)
        )) { error in
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaIncrementalVerificationError,
                .invalidRevisionOrder
            )
        }
    }

    func testRejectsValueCIDMismatch() throws {
        let fixture = try Fixture()
        let first = fixture.operations[0]
        let corrupt = ComAtprotoSpaceListRepoOps.OpEntry(
            rev: first.rev,
            collection: first.collection,
            rkey: first.rkey,
            cid: first.cid,
            prev: first.prev,
            value: .object(["text": .string("different")])
        )
        XCTAssertThrowsError(try PermissionedRemoteReplicaIncrementalVerifier.verify(
            operations: [corrupt, fixture.operations[1]],
            commit: fixture.commit,
            base: fixture.base,
            target: fixture.target,
            verificationKey: .p256(fixture.key.publicKey)
        )) { error in
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaIncrementalVerificationError,
                .valueCIDMismatch
            )
        }
    }

    func testRejectsLatestCommitMixedHead() throws {
        let fixture = try Fixture()
        let page = try PermissionedRemoteReplicaFreshnessWitness(
            wireRevision: fixture.secondRevision,
            commitment: fixture.commit.hash.data
        )
        let latest = try PermissionedRemoteReplicaFreshnessWitness(
            wireRevision: try TID(tidString: "222222222222d"),
            commitment: fixture.commit.hash.data
        )
        XCTAssertThrowsError(
            try PermissionedRemoteReplicaIncrementalVerifier.requireSameHead(
                page, latest
            )
        ) { error in
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaIncrementalVerificationError,
                .mixedHead
            )
        }
    }
}

private struct Fixture {
    let target: PermissionedRemoteReplicaTarget
    let base: PermissionedRemoteReplicaIncrementalBaseState
    let operations: [ComAtprotoSpaceListRepoOps.OpEntry]
    let commit: ComAtprotoSpaceDefs.SignedCommit
    let key: P256.Signing.PrivateKey
    let firstRevision: TID
    let secondRevision: TID

    init() throws {
        let receiver = "did:plc:receiverabcdefghijkl"
        let repository = "did:plc:repositoryabcdefghij"
        let space = try SpaceURI(
            authority: repository,
            spaceType: "app.bsky.bookmarks",
            skey: "incremental"
        )
        target = try PermissionedRemoteReplicaTarget(
            receiverDID: receiver,
            space: space,
            repositoryDID: repository
        )
        let initialRevision = try TID(tidString: "222222222222a")
        firstRevision = try TID(tidString: "222222222222b")
        secondRevision = try TID(tidString: "222222222222c")
        let empty = LtHash()
        let head = try PermissionedRemoteReplicaHead(
            target: target,
            generation: 1,
            wireRevision: initialRevision,
            historyFloorWireRevision: initialRevision,
            ltHash: empty.serialized,
            commitment: empty.commitment,
            stateMarker: Data(repeating: 0x31, count: 32)
        )
        base = try PermissionedRemoteReplicaIncrementalBaseState(
            head: head,
            recordCount: 0
        )

        let firstValue: ATProtocolValueContainer = .object([
            "text": .string("one"),
        ])
        let secondValue: ATProtocolValueContainer = .object([
            "text": .string("two"),
        ])
        let firstBytes = try DAGCBOR.encodeValue(firstValue.toCBORValue())
        let secondBytes = try DAGCBOR.encodeValue(secondValue.toCBORValue())
        let firstCID = CID.fromDAGCBOR(firstBytes)
        let secondCID = CID.fromDAGCBOR(secondBytes)
        operations = [
            .init(
                rev: firstRevision,
                collection: try NSID(nsidString: "app.bsky.feed.post"),
                rkey: try RecordKey(keyString: "one"),
                cid: firstCID,
                prev: nil,
                value: firstValue
            ),
            .init(
                rev: secondRevision,
                collection: try NSID(nsidString: "app.bsky.feed.post"),
                rkey: try RecordKey(keyString: "two"),
                cid: secondCID,
                prev: nil,
                value: secondValue
            ),
        ]
        var finalHash = LtHash()
        finalHash.add(element: "app.bsky.feed.post/one/\(firstCID.string)")
        finalHash.add(element: "app.bsky.feed.post/two/\(secondCID.string)")
        key = P256.Signing.PrivateKey()
        let envelope = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: space,
                author: repository,
                rev: secondRevision.toString(),
                ikm: Data(repeating: 0x42, count: 32)
            ),
            commitment: finalHash.commitment,
            key: key
        )
        commit = .init(
            ver: envelope.ver,
            hash: Bytes(data: envelope.commitment),
            ikm: Bytes(data: envelope.context.ikm),
            sig: Bytes(data: envelope.contextSignature),
            mac: Bytes(data: envelope.contentBinding),
            rev: try TID(tidString: envelope.context.rev)
        )
    }
}
